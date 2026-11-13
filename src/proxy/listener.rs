//! Config-gated connection listener.
//!
//! `server.io_backend = "tokio"` (the default) keeps the portable tokio accept
//! path. `"io_uring"` upgrades the listener to a Linux io_uring multishot
//! accept thread; if the ring cannot be created (old kernel, seccomp, missing
//! privileges) the listener silently falls back to tokio with a warning.

use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

use crate::config::ListenerIoBackend;

/// A listener that can accept connections over either backend.
pub struct ConnectionListener {
    inner: Inner,
    backend: ListenerIoBackend,
}

enum Inner {
    Tokio(TcpListener),
    #[cfg(all(feature = "io-uring", target_os = "linux"))]
    Uring(UringListener),
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
struct UringListener {
    // Kept alive for the lifetime of the accept thread: the raw fd passed to
    // io_uring must stay valid while a multishot accept is armed.
    listener: TcpListener,
    accepted: tokio::sync::mpsc::Receiver<std::os::unix::io::RawFd>,
    acceptor: Option<crate::waf::io::network::MultishotAcceptor>,
}

impl ConnectionListener {
    /// Wrap an already-bound listener, applying the configured backend. Any
    /// io_uring setup failure falls back to the tokio backend.
    pub fn from_tokio(listener: TcpListener, backend: ListenerIoBackend) -> Self {
        match backend {
            ListenerIoBackend::Tokio => Self {
                inner: Inner::Tokio(listener),
                backend: ListenerIoBackend::Tokio,
            },
            ListenerIoBackend::IoUring => Self::try_uring(listener),
        }
    }

    #[cfg(all(feature = "io-uring", target_os = "linux"))]
    fn try_uring(listener: TcpListener) -> Self {
        Self::try_uring_with(listener, |fd| {
            crate::waf::io::network::start_multishot_accept(fd)
        })
    }

    #[cfg(all(feature = "io-uring", target_os = "linux"))]
    fn try_uring_with<F>(listener: TcpListener, start: F) -> Self
    where
        F: FnOnce(
            std::os::unix::io::RawFd,
        ) -> anyhow::Result<(
            tokio::sync::mpsc::Receiver<std::os::unix::io::RawFd>,
            crate::waf::io::network::MultishotAcceptor,
        )>,
    {
        use std::os::unix::io::AsRawFd;

        match start(listener.as_raw_fd()) {
            Ok((accepted, acceptor)) => {
                tracing::info!("listener using io_uring multishot accept");
                Self {
                    inner: Inner::Uring(UringListener {
                        listener,
                        accepted,
                        acceptor: Some(acceptor),
                    }),
                    backend: ListenerIoBackend::IoUring,
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "io_uring listener setup failed; falling back to the tokio listener"
                );
                Self {
                    inner: Inner::Tokio(listener),
                    backend: ListenerIoBackend::Tokio,
                }
            }
        }
    }

    #[cfg(not(all(feature = "io-uring", target_os = "linux")))]
    fn try_uring(listener: TcpListener) -> Self {
        warn!(
            "server.io_backend = io_uring requested, but this build/target does not \
             include the io-uring feature; falling back to the tokio listener"
        );
        Self {
            inner: Inner::Tokio(listener),
            backend: ListenerIoBackend::Tokio,
        }
    }

    /// Backend actually in use after any fallback.
    pub fn backend(&self) -> ListenerIoBackend {
        self.backend
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match &self.inner {
            Inner::Tokio(listener) => listener.local_addr(),
            #[cfg(all(feature = "io-uring", target_os = "linux"))]
            Inner::Uring(uring) => uring.listener.local_addr(),
        }
    }

    /// Accept the next connection.
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        match &mut self.inner {
            Inner::Tokio(listener) => listener.accept().await,
            #[cfg(all(feature = "io-uring", target_os = "linux"))]
            Inner::Uring(uring) => uring.accept().await,
        }
    }

    /// Stop the io_uring accept thread (if any) and wait for it to exit.
    /// Tokio listeners need no explicit shutdown.
    pub fn shutdown(&mut self) {
        #[cfg(all(feature = "io-uring", target_os = "linux"))]
        if let Inner::Uring(uring) = &mut self.inner {
            if let Some(acceptor) = uring.acceptor.take() {
                acceptor.shutdown();
            }
        }
    }
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
impl UringListener {
    async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        let fd = self.accepted.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "io_uring accept thread stopped")
        })?;

        let std_stream =
            unsafe { <std::net::TcpStream as std::os::unix::io::FromRawFd>::from_raw_fd(fd) };
        std_stream.set_nonblocking(true)?;
        let stream = TcpStream::from_std(std_stream)?;
        let remote = stream.peer_addr()?;
        Ok((stream, remote))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tokio_backend_accepts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener = ConnectionListener::from_tokio(listener, ListenerIoBackend::Tokio);
        assert_eq!(listener.backend(), ListenerIoBackend::Tokio);

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (stream, remote) = listener.accept().await.unwrap();
        let _client = client.await.unwrap();
        assert_eq!(remote.ip(), stream.peer_addr().unwrap().ip());
        listener.shutdown();
    }

    #[tokio::test]
    async fn io_uring_request_falls_back_or_uses_uring() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener = ConnectionListener::from_tokio(listener, ListenerIoBackend::IoUring);

        // Unless the build/target lacks the feature, the backend is exactly what
        // was requested or a logged fallback. Either way accepting must work.
        let _ = listener.backend();

        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            // Keep the connection open until the server accepted it.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(stream);
        });
        let (_stream, _remote) = listener.accept().await.unwrap();
        let _ = client.await;
        listener.shutdown();
    }

    #[test]
    fn default_backend_is_tokio() {
        assert_eq!(ListenerIoBackend::default(), ListenerIoBackend::Tokio);
    }

    #[cfg(all(feature = "io-uring", target_os = "linux"))]
    #[tokio::test]
    async fn io_uring_setup_failure_falls_back_without_panicking() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener = ConnectionListener::try_uring_with(listener, |_fd| {
            Err(anyhow::anyhow!("simulated seccomp denial"))
        });
        assert_eq!(listener.backend(), ListenerIoBackend::Tokio);

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (_stream, _remote) = listener.accept().await.unwrap();
        let _ = client.await;
    }

    #[cfg(all(feature = "io-uring", target_os = "linux"))]
    #[tokio::test]
    async fn io_uring_shutdown_stops_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut listener = ConnectionListener::from_tokio(listener, ListenerIoBackend::IoUring);
        if listener.backend() != ListenerIoBackend::IoUring {
            eprintln!("skipping: io_uring unavailable in this environment");
            return;
        }
        listener.shutdown();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
            .await
            .expect("accept must not hang after shutdown");
        assert!(result.is_err());
    }
}
