//! End-to-end tests for the experimental native Coraza sidecar.
//!
//! These tests start the real Go sidecar process, a real `WafProxyService` and
//! a mock upstream. They are ignored by default because the sidecar binary is
//! built separately. Run them with:
//!
//! ```sh
//! CORAZA_SIDECAR_BIN=target/native/coraza-sidecar \
//!   cargo test --test integration --features wasm-reactor,coraza-native \
//!   native_coraza -- --ignored --nocapture
//! ```

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use waf_ingress::config::CorazaBackend;
use waf_ingress::metrics::Metrics;
use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rules_from_binary(bin: &Path) -> Option<PathBuf> {
    // Nix installs the rules next to the binary under share/waf/coraza.
    let prefix = bin.parent()?.parent()?;
    let candidate = prefix.join("share/waf/coraza/crs/crs.conf");
    candidate.is_file().then_some(candidate)
}

fn locate_sidecar() -> Option<(PathBuf, PathBuf)> {
    if let Ok(bin) = std::env::var("CORAZA_SIDECAR_BIN") {
        let bin = PathBuf::from(bin);
        if bin.is_file() {
            let rules = std::env::var("CORAZA_SIDECAR_RULES")
                .map(PathBuf::from)
                .ok()
                .or_else(|| rules_from_binary(&bin))
                .unwrap_or_else(|| manifest_dir().join("wasm/coraza_reactor/rules/crs/crs.conf"));
            return Some((bin, rules));
        }
    }

    let local = manifest_dir().join("target/native/coraza-sidecar");
    if local.is_file() {
        return Some((
            local,
            manifest_dir().join("wasm/coraza_reactor/rules/crs/crs.conf"),
        ));
    }

    // Try the Nix package before falling back to a local Go build.
    if let Ok(output) = Command::new("nix")
        .args([
            "build",
            ".#coraza-native-sidecar",
            "--no-link",
            "--print-out-paths",
        ])
        .current_dir(manifest_dir())
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout);
            let bin = PathBuf::from(path.lines().next().unwrap_or_default().trim())
                .join("bin/coraza-sidecar");
            if bin.is_file() {
                if let Some(rules) = rules_from_binary(&bin) {
                    return Some((bin, rules));
                }
            }
        }
    }

    let out = manifest_dir().join("target/native/coraza-sidecar-e2e");
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        _ => "amd64",
    };
    let status = Command::new("go")
        .args(["build", "-trimpath", "-o"])
        .arg(&out)
        .arg(".")
        .current_dir(manifest_dir().join("native/coraza-sidecar"))
        .env("GOOS", "linux")
        .env("GOARCH", arch)
        .env("CGO_ENABLED", "0")
        .env("GOFLAGS", "-mod=vendor")
        .status()
        .ok()?;
    status.success().then(|| {
        (
            out,
            manifest_dir().join("wasm/coraza_reactor/rules/crs/crs.conf"),
        )
    })
}

fn wait_for_socket(path: &Path, child: &mut Child) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return true;
        }
        if let Ok(Some(status)) = child.try_wait() {
            eprintln!("sidecar exited before becoming ready: {status}");
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

struct Sidecar {
    bin: PathBuf,
    rules: PathBuf,
    socket: PathBuf,
    child: Option<Child>,
}

impl Sidecar {
    fn start(bin: PathBuf, rules: PathBuf, socket: PathBuf) -> Self {
        let mut sidecar = Self {
            bin,
            rules,
            socket,
            child: None,
        };
        sidecar.spawn();
        sidecar
    }

    fn spawn(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let child = Command::new(&self.bin)
            .arg("--socket")
            .arg(&self.socket)
            .arg("--rules")
            .arg(&self.rules)
            .arg("--max-body")
            .arg("65536")
            .arg("--timeout")
            .arg("5s")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn coraza sidecar");
        self.child = Some(child);
        assert!(
            wait_for_socket(&self.socket, self.child.as_mut().unwrap()),
            "sidecar did not create {}",
            self.socket.display()
        );
    }

    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(&self.socket);
    }

    fn restart(&mut self) {
        self.kill();
        self.spawn();
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        self.kill();
    }
}

async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|_req: Request<hyper::body::Incoming>| async {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from_static(b"upstream-ok")))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });
    addr
}

async fn spawn_proxy(
    upstream: SocketAddr,
    backend: CorazaBackend,
    socket: &Path,
    fail_mode: &str,
) -> (SocketAddr, Arc<Metrics>) {
    let mut config = Config {
        upstream_uri: format!("http://{upstream}"),
        ..Config::default()
    };
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.fail_mode = fail_mode.to_string();
    config.waf.coraza.enabled = true;
    config.waf.coraza.backend = backend;
    config.waf.coraza.native_socket_path = Some(socket.display().to_string());
    config.waf.coraza.eval_timeout_ms = 5_000;
    config.waf.coraza.pool_size = 2;

    let service = Arc::new(WafProxyService::new(config).expect("proxy starts"));
    let metrics = service.metrics();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });
    (addr, metrics)
}

struct Case {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    body: Option<&'static [u8]>,
    content_type: Option<&'static str>,
    expected: StatusCode,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "benign",
            method: "GET",
            path: "/hello?id=42",
            body: None,
            content_type: None,
            expected: StatusCode::OK,
        },
        Case {
            name: "sqli-query",
            method: "GET",
            path: "/?id=1%20UNION%20SELECT%20*%20FROM%20users",
            body: None,
            content_type: None,
            expected: StatusCode::FORBIDDEN,
        },
        Case {
            name: "xss-query",
            method: "GET",
            path: "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
            body: None,
            content_type: None,
            expected: StatusCode::FORBIDDEN,
        },
        Case {
            name: "path-traversal",
            method: "GET",
            path: "/download?file=../../../../etc/passwd",
            body: None,
            content_type: None,
            expected: StatusCode::FORBIDDEN,
        },
        Case {
            name: "sqli-body",
            method: "POST",
            path: "/login",
            body: Some(b"id=1 UNION SELECT * FROM users"),
            content_type: Some("application/x-www-form-urlencoded"),
            expected: StatusCode::FORBIDDEN,
        },
        Case {
            name: "xss-body",
            method: "POST",
            path: "/comment",
            body: Some(b"<script>alert(1)</script>"),
            content_type: Some("application/x-www-form-urlencoded"),
            expected: StatusCode::FORBIDDEN,
        },
        Case {
            name: "grpc",
            method: "POST",
            path: "/helloworld.Greeter/SayHello",
            body: Some(b"\x00\x00\x00\x00\x05hello"),
            content_type: Some("application/grpc+proto"),
            expected: StatusCode::OK,
        },
    ]
}

async fn send(proxy: SocketAddr, case: &Case) -> StatusCode {
    let client = reqwest::Client::new();
    let mut request = client.request(
        case.method.parse().unwrap(),
        format!("http://{proxy}{}", case.path),
    );
    if let Some(content_type) = case.content_type {
        request = request.header("content-type", content_type);
    }
    if case.name == "grpc" {
        request = request.header("te", "trailers");
    }
    if let Some(body) = case.body {
        request = request.body(body.to_vec());
    }
    request.send().await.expect("proxy response").status()
}

#[tokio::test]
#[ignore = "requires the native Coraza sidecar binary"]
async fn native_sidecar_end_to_end() {
    let Some((bin, rules)) = locate_sidecar() else {
        eprintln!("skipping: native Coraza sidecar binary not found");
        return;
    };

    let socket =
        std::env::temp_dir().join(format!("coraza-native-e2e-{}.sock", std::process::id()));
    let mut sidecar = Sidecar::start(bin, rules, socket.clone());
    let upstream = spawn_upstream().await;

    let (native, native_metrics) =
        spawn_proxy(upstream, CorazaBackend::Native, &socket, "closed").await;
    let (wasm, _) = spawn_proxy(upstream, CorazaBackend::Wasm, &socket, "closed").await;
    let (fail_open, _) = spawn_proxy(upstream, CorazaBackend::Native, &socket, "open").await;

    for case in cases() {
        let native_status = send(native, &case).await;
        let wasm_status = send(wasm, &case).await;
        assert_eq!(
            native_status, case.expected,
            "native decision for {}",
            case.name
        );
        assert_eq!(
            native_status, wasm_status,
            "native/wasm decision mismatch for {}",
            case.name
        );
    }

    let rendered = native_metrics.render_prometheus();
    assert!(
        rendered.contains("waf_coraza_evaluations_total 7"),
        "native metrics did not record every evaluation:\n{rendered}"
    );
    assert!(
        rendered.contains("waf_coraza_blocks_total 5"),
        "native metrics did not record blocks:\n{rendered}"
    );

    // Kill the sidecar: the fail-closed proxy must return 503, the fail-open
    // proxy must continue to the upstream.
    sidecar.kill();
    let benign = &cases()[0];
    assert_eq!(
        send(native, benign).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "fail-closed proxy must return 503 while the sidecar is down"
    );
    assert_eq!(
        send(fail_open, benign).await,
        StatusCode::OK,
        "fail-open proxy must allow while the sidecar is down"
    );

    // Restart and verify both proxies recover without restarting the proxy.
    sidecar.restart();
    assert_eq!(
        send(native, benign).await,
        StatusCode::OK,
        "fail-closed proxy must recover after sidecar restart"
    );
    assert_eq!(
        send(fail_open, benign).await,
        StatusCode::OK,
        "fail-open proxy must keep working after sidecar restart"
    );
}
