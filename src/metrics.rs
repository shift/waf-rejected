//! Lightweight runtime metrics exposed by the health service.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Process-wide counters for the proxy.
#[derive(Debug)]
pub struct Metrics {
    start_time: Instant,
    requests_total: AtomicU64,
    allowed_total: AtomicU64,
    blocked_total: AtomicU64,
    upstream_errors_total: AtomicU64,
    webtransport_sessions_total: AtomicU64,
    webtransport_allowed_total: AtomicU64,
    webtransport_blocked_total: AtomicU64,
    webtransport_streams_total: AtomicU64,
    webtransport_datagrams_total: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            requests_total: AtomicU64::new(0),
            allowed_total: AtomicU64::new(0),
            blocked_total: AtomicU64::new(0),
            upstream_errors_total: AtomicU64::new(0),
            webtransport_sessions_total: AtomicU64::new(0),
            webtransport_allowed_total: AtomicU64::new(0),
            webtransport_blocked_total: AtomicU64::new(0),
            webtransport_streams_total: AtomicU64::new(0),
            webtransport_datagrams_total: AtomicU64::new(0),
        }
    }

    pub fn record_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_allowed(&self) {
        self.allowed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_blocked(&self) {
        self.blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_error(&self) {
        self.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_webtransport_session(&self) {
        self.webtransport_sessions_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_webtransport_allowed(&self) {
        self.webtransport_allowed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_webtransport_blocked(&self) {
        self.webtransport_blocked_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_webtransport_stream(&self) {
        self.webtransport_streams_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_webtransport_datagram(&self) {
        self.webtransport_datagrams_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Render Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        format!(
            "# HELP waf_requests_total Total requests received.\n\
             # TYPE waf_requests_total counter\n\
             waf_requests_total {}\n\
             # HELP waf_allowed_total Requests allowed by the WAF.\n\
             # TYPE waf_allowed_total counter\n\
             waf_allowed_total {}\n\
             # HELP waf_blocked_total Requests blocked or rate limited by the WAF.\n\
             # TYPE waf_blocked_total counter\n\
             waf_blocked_total {}\n\
             # HELP waf_upstream_errors_total Upstream connection/read failures.\n\
             # TYPE waf_upstream_errors_total counter\n\
             waf_upstream_errors_total {}\n\
             # HELP waf_webtransport_sessions_total WebTransport sessions accepted.\n\
             # TYPE waf_webtransport_sessions_total counter\n\
             waf_webtransport_sessions_total {}\n\
             # HELP waf_webtransport_allowed_total WebTransport sessions allowed by the WAF.\n\
             # TYPE waf_webtransport_allowed_total counter\n\
             waf_webtransport_allowed_total {}\n\
             # HELP waf_webtransport_blocked_total WebTransport sessions or payloads blocked.\n\
             # TYPE waf_webtransport_blocked_total counter\n\
             waf_webtransport_blocked_total {}\n\
             # HELP waf_webtransport_streams_total WebTransport streams inspected.\n\
             # TYPE waf_webtransport_streams_total counter\n\
             waf_webtransport_streams_total {}\n\
             # HELP waf_webtransport_datagrams_total WebTransport datagrams inspected.\n\
             # TYPE waf_webtransport_datagrams_total counter\n\
             waf_webtransport_datagrams_total {}\n\
             # HELP waf_uptime_seconds Process uptime in seconds.\n\
             # TYPE waf_uptime_seconds gauge\n\
             waf_uptime_seconds {}\n",
            self.requests_total.load(Ordering::Relaxed),
            self.allowed_total.load(Ordering::Relaxed),
            self.blocked_total.load(Ordering::Relaxed),
            self.upstream_errors_total.load(Ordering::Relaxed),
            self.webtransport_sessions_total.load(Ordering::Relaxed),
            self.webtransport_allowed_total.load(Ordering::Relaxed),
            self.webtransport_blocked_total.load(Ordering::Relaxed),
            self.webtransport_streams_total.load(Ordering::Relaxed),
            self.webtransport_datagrams_total.load(Ordering::Relaxed),
            self.uptime_seconds(),
        )
    }
}
