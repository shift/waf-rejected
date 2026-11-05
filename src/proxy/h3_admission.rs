//! Global admission control for HTTP/3 request handlers.
//!
//! HTTP/3 accepts a request resolver per stream; spawning a Tokio task for
//! every resolver without a bound lets a single client create unbounded tasks
//! and request-body buffers. This module caps the number of request handlers
//! that may hold a permit at once, before the request body is read.
//!
//! Excess requests wait briefly (asynchronous, so no worker is blocked) and are
//! then rejected with `503`. An optional per-client cap rejects a single peer
//! with `429` without waiting. Permits are RAII guards, so a finished,
//! panicking or cancelled request always returns its permit; [`shutdown`]
//! closes the semaphore so waiters fail immediately and already-admitted
//! requests release their permits as they finish.
//!
//! [`shutdown`]: H3Admission::shutdown

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::metrics::Metrics;

/// Upper bound on tracked client entries. Entries with no live holders are
/// pruned when the map is full, so this only bounds a pathological fan-out.
const MAX_TRACKED_CLIENTS: usize = 4096;

/// Why an HTTP/3 request was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3AdmissionRejection {
    /// The per-client concurrency limit was reached.
    ClientLimit { limit: usize },
    /// The global permit wait exceeded the configured timeout (or the
    /// admission controller is shutting down).
    Timeout { waited_ms: u64 },
}

impl std::fmt::Display for H3AdmissionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientLimit { limit } => {
                write!(f, "per-client HTTP/3 concurrency limit reached ({limit})")
            }
            Self::Timeout { waited_ms } => {
                write!(f, "HTTP/3 admission wait exceeded {waited_ms} ms")
            }
        }
    }
}

struct Inner {
    global: Arc<Semaphore>,
    per_client_limit: Option<usize>,
    clients: Mutex<HashMap<IpAddr, Weak<Semaphore>>>,
    timeout: Duration,
    metrics: Arc<Metrics>,
}

/// Shared HTTP/3 admission controller.
#[derive(Clone)]
pub struct H3Admission {
    inner: Arc<Inner>,
}

/// RAII guard for one admitted HTTP/3 request. Dropping it releases the global
/// (and optional per-client) permit and updates the in-flight gauge.
pub struct H3AdmissionGuard {
    _global: OwnedSemaphorePermit,
    _client: Option<OwnedSemaphorePermit>,
    metrics: Arc<Metrics>,
}

impl Drop for H3AdmissionGuard {
    fn drop(&mut self) {
        self.metrics.h3_admission_finished();
    }
}

impl H3Admission {
    /// Build a controller. `max_inflight` is clamped to at least one.
    pub fn new(
        max_inflight: usize,
        max_per_client: usize,
        timeout: Duration,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                global: Arc::new(Semaphore::new(max_inflight.max(1))),
                per_client_limit: (max_per_client > 0).then_some(max_per_client),
                clients: Mutex::new(HashMap::new()),
                timeout,
                metrics,
            }),
        }
    }

    /// Acquire admission for one request. The returned guard must be held for
    /// the lifetime of the request handler.
    pub async fn acquire(&self, client: IpAddr) -> Result<H3AdmissionGuard, H3AdmissionRejection> {
        let client_permit = match self.inner.per_client_limit {
            Some(limit) => Some(self.acquire_client(client, limit)?),
            None => None,
        };

        let global = match self.inner.global.clone().try_acquire_owned() {
            Ok(permit) => {
                self.inner.metrics.h3_admission_admitted();
                permit
            }
            Err(_) => {
                self.inner.metrics.h3_admission_waited();
                match tokio::time::timeout(
                    self.inner.timeout,
                    self.inner.global.clone().acquire_owned(),
                )
                .await
                {
                    Ok(Ok(permit)) => {
                        self.inner.metrics.h3_admission_admitted();
                        permit
                    }
                    Ok(Err(_)) | Err(_) => {
                        self.inner.metrics.h3_admission_rejected_timeout();
                        return Err(H3AdmissionRejection::Timeout {
                            waited_ms: self.inner.timeout.as_millis().min(u64::MAX as u128) as u64,
                        });
                    }
                }
            }
        };

        self.inner.metrics.h3_admission_started();
        Ok(H3AdmissionGuard {
            _global: global,
            _client: client_permit,
            metrics: Arc::clone(&self.inner.metrics),
        })
    }

    fn acquire_client(
        &self,
        client: IpAddr,
        limit: usize,
    ) -> Result<OwnedSemaphorePermit, H3AdmissionRejection> {
        let semaphore = {
            let mut clients = self
                .inner
                .clients
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = clients.get(&client).and_then(Weak::upgrade) {
                existing
            } else {
                if clients.len() >= MAX_TRACKED_CLIENTS {
                    clients.retain(|_, weak| weak.strong_count() > 0);
                }
                let semaphore = Arc::new(Semaphore::new(limit));
                clients.insert(client, Arc::downgrade(&semaphore));
                semaphore
            }
        };

        match semaphore.try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(_) => {
                self.inner.metrics.h3_admission_rejected_client_limit();
                Err(H3AdmissionRejection::ClientLimit { limit })
            }
        }
    }

    /// Stop accepting new requests. Waiters fail immediately; admitted
    /// requests keep their permits until they finish and are then released.
    pub fn shutdown(&self) {
        self.inner.global.close();
        if let Ok(mut clients) = self.inner.clients.lock() {
            clients.clear();
        }
    }

    #[cfg(test)]
    fn available_permits(&self) -> usize {
        self.inner.global.available_permits()
    }

    #[cfg(test)]
    fn in_flight(&self) -> u64 {
        self.inner.metrics.h3_inflight()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, last])
    }

    fn controller(max_inflight: usize, max_per_client: usize, timeout_ms: u64) -> H3Admission {
        H3Admission::new(
            max_inflight,
            max_per_client,
            Duration::from_millis(timeout_ms),
            Arc::new(Metrics::new()),
        )
    }

    #[tokio::test]
    async fn saturation_times_out_then_releases_the_permit() {
        let admission = controller(1, 0, 20);
        let held = admission.acquire(ip(1)).await.unwrap();
        assert_eq!(admission.available_permits(), 0);
        assert_eq!(admission.in_flight(), 1);

        let rejected = admission.acquire(ip(1)).await;
        assert!(matches!(
            rejected,
            Err(H3AdmissionRejection::Timeout { .. })
        ));

        drop(held);
        assert_eq!(admission.available_permits(), 1);
        assert_eq!(admission.in_flight(), 0);
        assert!(admission.acquire(ip(1)).await.is_ok());
    }

    #[tokio::test]
    async fn per_client_limit_rejects_only_that_client() {
        let admission = controller(4, 1, 1000);
        let _first = admission.acquire(ip(1)).await.unwrap();

        let rejected = admission.acquire(ip(1)).await;
        assert!(matches!(
            rejected,
            Err(H3AdmissionRejection::ClientLimit { limit: 1 })
        ));

        // A different client still has capacity.
        assert!(admission.acquire(ip(2)).await.is_ok());
    }

    #[tokio::test]
    async fn shutdown_fails_waiters_and_admitted_requests_release_permits() {
        let admission = controller(1, 0, 5000);
        let held = admission.acquire(ip(1)).await.unwrap();

        let waiter = {
            let admission = admission.clone();
            tokio::spawn(async move { admission.acquire(ip(1)).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;

        admission.shutdown();
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter must wake on shutdown")
            .expect("waiter task must not panic");
        assert!(matches!(result, Err(H3AdmissionRejection::Timeout { .. })));

        drop(held);
        assert_eq!(admission.available_permits(), 1);
        assert_eq!(admission.in_flight(), 0);
    }
}
