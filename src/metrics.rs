//! Lightweight runtime metrics exposed by the health service.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Upper bounds (seconds) for the request-duration histogram.
const DURATION_BUCKETS: [f64; 11] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Process-wide counters for the proxy.
#[derive(Debug)]
pub struct Metrics {
    start_time: Instant,
    requests_total: AtomicU64,
    allowed_total: AtomicU64,
    blocked_total: AtomicU64,
    auth_failures_total: AtomicU64,
    rate_limited_total: AtomicU64,
    upstream_errors_total: AtomicU64,
    webtransport_sessions_total: AtomicU64,
    webtransport_allowed_total: AtomicU64,
    webtransport_blocked_total: AtomicU64,
    webtransport_streams_total: AtomicU64,
    webtransport_datagrams_total: AtomicU64,
    duration_buckets: [AtomicU64; 11],
    duration_inf: AtomicU64,
    duration_sum_nanos: AtomicU64,
    duration_count: AtomicU64,
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
            auth_failures_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            upstream_errors_total: AtomicU64::new(0),
            webtransport_sessions_total: AtomicU64::new(0),
            webtransport_allowed_total: AtomicU64::new(0),
            webtransport_blocked_total: AtomicU64::new(0),
            webtransport_streams_total: AtomicU64::new(0),
            webtransport_datagrams_total: AtomicU64::new(0),
            duration_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            duration_inf: AtomicU64::new(0),
            duration_sum_nanos: AtomicU64::new(0),
            duration_count: AtomicU64::new(0),
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

    pub fn record_auth_failure(&self) {
        self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rate_limited(&self) {
        self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_error(&self) {
        self.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Observe one request duration in the histogram.
    pub fn record_request_duration(&self, duration: Duration) {
        let seconds = duration.as_secs_f64();
        self.duration_count.fetch_add(1, Ordering::Relaxed);
        self.duration_sum_nanos.fetch_add(
            duration.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );

        for (index, bound) in DURATION_BUCKETS.iter().enumerate() {
            if seconds <= *bound {
                self.duration_buckets[index].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.duration_inf.fetch_add(1, Ordering::Relaxed);
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
        let mut out = String::with_capacity(4096);
        out.push_str(&format!(
            "# HELP waf_requests_total Total requests received.\n\
             # TYPE waf_requests_total counter\n\
             waf_requests_total {}\n\
             # HELP waf_allowed_total Requests allowed by the WAF.\n\
             # TYPE waf_allowed_total counter\n\
             waf_allowed_total {}\n\
             # HELP waf_blocked_total Requests blocked or rate limited by the WAF.\n\
             # TYPE waf_blocked_total counter\n\
             waf_blocked_total {}\n\
             # HELP waf_auth_failures_total Requests rejected by API-key authentication.\n\
             # TYPE waf_auth_failures_total counter\n\
             waf_auth_failures_total {}\n\
             # HELP waf_rate_limited_total Requests rejected by rate limiting.\n\
             # TYPE waf_rate_limited_total counter\n\
             waf_rate_limited_total {}\n\
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
             waf_webtransport_datagrams_total {}\n",
            self.requests_total.load(Ordering::Relaxed),
            self.allowed_total.load(Ordering::Relaxed),
            self.blocked_total.load(Ordering::Relaxed),
            self.auth_failures_total.load(Ordering::Relaxed),
            self.rate_limited_total.load(Ordering::Relaxed),
            self.upstream_errors_total.load(Ordering::Relaxed),
            self.webtransport_sessions_total.load(Ordering::Relaxed),
            self.webtransport_allowed_total.load(Ordering::Relaxed),
            self.webtransport_blocked_total.load(Ordering::Relaxed),
            self.webtransport_streams_total.load(Ordering::Relaxed),
            self.webtransport_datagrams_total.load(Ordering::Relaxed),
        ));

        out.push_str(
            "# HELP waf_request_duration_seconds Request processing duration in seconds.\n\
             # TYPE waf_request_duration_seconds histogram\n",
        );
        let mut cumulative = 0u64;
        for (index, bound) in DURATION_BUCKETS.iter().enumerate() {
            cumulative =
                cumulative.saturating_add(self.duration_buckets[index].load(Ordering::Relaxed));
            out.push_str(&format!(
                "waf_request_duration_seconds_bucket{{le=\"{}\"}} {}\n",
                format_bucket(*bound),
                cumulative
            ));
        }
        let total = cumulative.saturating_add(self.duration_inf.load(Ordering::Relaxed));
        out.push_str(&format!(
            "waf_request_duration_seconds_bucket{{le=\"+Inf\"}} {}\n",
            total
        ));
        out.push_str(&format!(
            "waf_request_duration_seconds_sum {}\n",
            self.duration_sum_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
        ));
        out.push_str(&format!(
            "waf_request_duration_seconds_count {}\n",
            self.duration_count.load(Ordering::Relaxed)
        ));

        out.push_str(&format!(
            "# HELP waf_uptime_seconds Process uptime in seconds.\n\
             # TYPE waf_uptime_seconds gauge\n\
             waf_uptime_seconds {}\n",
            self.uptime_seconds(),
        ));

        out
    }
}

fn format_bucket(bound: f64) -> String {
    if bound.fract() == 0.0 {
        format!("{:.0}", bound)
    } else {
        let mut value = format!("{}", bound);
        if value.contains('.') {
            while value.ends_with('0') {
                value.pop();
            }
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_line<'a>(text: &'a str, prefix: &str) -> &'a str {
        text.lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("missing line starting with {prefix}"))
    }

    #[test]
    fn render_includes_security_counters() {
        let metrics = Metrics::new();
        metrics.record_auth_failure();
        metrics.record_auth_failure();
        metrics.record_rate_limited();

        let rendered = metrics.render_prometheus();
        assert_eq!(
            find_line(&rendered, "waf_auth_failures_total "),
            "waf_auth_failures_total 2"
        );
        assert_eq!(
            find_line(&rendered, "waf_rate_limited_total "),
            "waf_rate_limited_total 1"
        );
    }

    #[test]
    fn render_duration_histogram_is_cumulative_and_valid() {
        let metrics = Metrics::new();
        metrics.record_request_duration(Duration::from_micros(500));
        metrics.record_request_duration(Duration::from_millis(7));
        metrics.record_request_duration(Duration::from_millis(80));
        metrics.record_request_duration(Duration::from_secs(10));

        let rendered = metrics.render_prometheus();

        assert_eq!(
            find_line(
                &rendered,
                "waf_request_duration_seconds_bucket{le=\"0.001\"}"
            ),
            "waf_request_duration_seconds_bucket{le=\"0.001\"} 1"
        );
        assert_eq!(
            find_line(
                &rendered,
                "waf_request_duration_seconds_bucket{le=\"0.01\"}"
            ),
            "waf_request_duration_seconds_bucket{le=\"0.01\"} 2"
        );
        assert_eq!(
            find_line(&rendered, "waf_request_duration_seconds_bucket{le=\"0.1\"}"),
            "waf_request_duration_seconds_bucket{le=\"0.1\"} 3"
        );
        assert_eq!(
            find_line(
                &rendered,
                "waf_request_duration_seconds_bucket{le=\"+Inf\"}"
            ),
            "waf_request_duration_seconds_bucket{le=\"+Inf\"} 4"
        );
        assert_eq!(
            find_line(&rendered, "waf_request_duration_seconds_count "),
            "waf_request_duration_seconds_count 4"
        );

        let sum = find_line(&rendered, "waf_request_duration_seconds_sum ");
        let sum: f64 = sum.rsplit(' ').next().unwrap().parse().unwrap();
        assert!((sum - 10.0875).abs() < 0.001, "unexpected sum {sum}");

        for prefix in [
            "# HELP waf_auth_failures_total",
            "# TYPE waf_auth_failures_total counter",
            "# HELP waf_rate_limited_total",
            "# TYPE waf_rate_limited_total counter",
            "# TYPE waf_request_duration_seconds histogram",
            "# TYPE waf_uptime_seconds gauge",
        ] {
            assert!(rendered.contains(prefix), "missing {prefix}");
        }
    }
}
