//! Lightweight runtime metrics exposed by the health service.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Upper bounds (seconds) for the request-duration histogram.
const DURATION_BUCKETS: [f64; 11] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Upper bounds (seconds) for the Coraza evaluation-duration histogram.
const CORAZA_DURATION_BUCKETS: [f64; 11] = DURATION_BUCKETS;

/// Upper bounds (bytes) for the Coraza inspected-body-size histogram.
const CORAZA_BODY_BYTES_BUCKETS: [f64; 8] = [
    0.0, 1024.0, 4096.0, 8192.0, 16384.0, 32768.0, 65536.0, 131072.0,
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
    coraza_evaluations_total: AtomicU64,
    coraza_blocks_total: AtomicU64,
    coraza_errors_total: AtomicU64,
    coraza_duration_buckets: [AtomicU64; 11],
    coraza_duration_inf: AtomicU64,
    coraza_duration_sum_nanos: AtomicU64,
    coraza_duration_count: AtomicU64,
    coraza_body_truncated_total: AtomicU64,
    coraza_body_rejected_total: AtomicU64,
    coraza_body_inspected_buckets: [AtomicU64; 8],
    coraza_body_inspected_inf: AtomicU64,
    coraza_body_inspected_sum: AtomicU64,
    coraza_body_inspected_count: AtomicU64,
    crs_prefilter_evaluations_total: AtomicU64,
    crs_prefilter_hits_total: AtomicU64,
    crs_prefilter_withheld_total: AtomicU64,
    crs_prefilter_duration_sum_nanos: AtomicU64,
    crs_prefilter_duration_count: AtomicU64,
    admission_queued_total: AtomicU64,
    admission_queue_depth: AtomicU64,
    admission_admitted_total: AtomicU64,
    admission_rejected_queue_full_total: AtomicU64,
    admission_rejected_timeout_total: AtomicU64,
    admission_wait_buckets: [AtomicU64; 11],
    admission_wait_inf: AtomicU64,
    admission_wait_sum_nanos: AtomicU64,
    admission_wait_count: AtomicU64,
    admission_cheap_inflight: AtomicU64,
    admission_heavy_inflight: AtomicU64,
    grpc_allow_total: AtomicU64,
    grpc_block_total: AtomicU64,
    grpc_error_total: AtomicU64,
    grpc_content_scan_total: AtomicU64,
    grpc_content_block_total: AtomicU64,
    graphql_allow_total: AtomicU64,
    graphql_block_total: AtomicU64,
    graphql_error_total: AtomicU64,
    allow_cache_hits_total: AtomicU64,
    allow_cache_misses_total: AtomicU64,
    allow_cache_evictions_total: AtomicU64,
    allow_cache_expired_total: AtomicU64,
    allow_cache_skipped_total: AtomicU64,
    allow_cache_invalidations_total: AtomicU64,
    allow_cache_entries: AtomicU64,
    fast_allow_hits_total: AtomicU64,
    fast_allow_blocks_total: AtomicU64,
    fast_allow_fallthrough_total: AtomicU64,
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
            coraza_evaluations_total: AtomicU64::new(0),
            coraza_blocks_total: AtomicU64::new(0),
            coraza_errors_total: AtomicU64::new(0),
            coraza_duration_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            coraza_duration_inf: AtomicU64::new(0),
            coraza_duration_sum_nanos: AtomicU64::new(0),
            coraza_duration_count: AtomicU64::new(0),
            coraza_body_truncated_total: AtomicU64::new(0),
            coraza_body_rejected_total: AtomicU64::new(0),
            coraza_body_inspected_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            coraza_body_inspected_inf: AtomicU64::new(0),
            coraza_body_inspected_sum: AtomicU64::new(0),
            coraza_body_inspected_count: AtomicU64::new(0),
            crs_prefilter_evaluations_total: AtomicU64::new(0),
            crs_prefilter_hits_total: AtomicU64::new(0),
            crs_prefilter_withheld_total: AtomicU64::new(0),
            crs_prefilter_duration_sum_nanos: AtomicU64::new(0),
            crs_prefilter_duration_count: AtomicU64::new(0),
            admission_queued_total: AtomicU64::new(0),
            admission_queue_depth: AtomicU64::new(0),
            admission_admitted_total: AtomicU64::new(0),
            admission_rejected_queue_full_total: AtomicU64::new(0),
            admission_rejected_timeout_total: AtomicU64::new(0),
            admission_wait_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            admission_wait_inf: AtomicU64::new(0),
            admission_wait_sum_nanos: AtomicU64::new(0),
            admission_wait_count: AtomicU64::new(0),
            admission_cheap_inflight: AtomicU64::new(0),
            admission_heavy_inflight: AtomicU64::new(0),
            grpc_allow_total: AtomicU64::new(0),
            grpc_block_total: AtomicU64::new(0),
            grpc_error_total: AtomicU64::new(0),
            grpc_content_scan_total: AtomicU64::new(0),
            grpc_content_block_total: AtomicU64::new(0),
            graphql_allow_total: AtomicU64::new(0),
            graphql_block_total: AtomicU64::new(0),
            graphql_error_total: AtomicU64::new(0),
            allow_cache_hits_total: AtomicU64::new(0),
            allow_cache_misses_total: AtomicU64::new(0),
            allow_cache_evictions_total: AtomicU64::new(0),
            allow_cache_expired_total: AtomicU64::new(0),
            allow_cache_skipped_total: AtomicU64::new(0),
            allow_cache_invalidations_total: AtomicU64::new(0),
            allow_cache_entries: AtomicU64::new(0),
            fast_allow_hits_total: AtomicU64::new(0),
            fast_allow_blocks_total: AtomicU64::new(0),
            fast_allow_fallthrough_total: AtomicU64::new(0),
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

    /// Record one Coraza reactor evaluation and its duration.
    pub fn record_coraza_evaluation(&self, duration: Duration) {
        self.coraza_evaluations_total
            .fetch_add(1, Ordering::Relaxed);
        let seconds = duration.as_secs_f64();
        self.coraza_duration_count.fetch_add(1, Ordering::Relaxed);
        self.coraza_duration_sum_nanos.fetch_add(
            duration.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );

        for (index, bound) in CORAZA_DURATION_BUCKETS.iter().enumerate() {
            if seconds <= *bound {
                self.coraza_duration_buckets[index].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.coraza_duration_inf.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one CRS literal-prefilter evaluation.
    pub fn record_crs_prefilter(&self, duration: Duration, hit: bool, withheld: bool) {
        self.crs_prefilter_evaluations_total
            .fetch_add(1, Ordering::Relaxed);
        if hit {
            self.crs_prefilter_hits_total
                .fetch_add(1, Ordering::Relaxed);
        }
        if withheld {
            self.crs_prefilter_withheld_total
                .fetch_add(1, Ordering::Relaxed);
        }
        self.crs_prefilter_duration_sum_nanos.fetch_add(
            duration.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        self.crs_prefilter_duration_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_coraza_block(&self) {
        self.coraza_blocks_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_coraza_error(&self) {
        self.coraza_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one body that was truncated to the configured inspection prefix.
    pub fn record_coraza_body_truncated(&self) {
        self.coraza_body_truncated_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record one body rejected by the oversize policy before evaluation.
    pub fn record_coraza_body_rejected(&self) {
        self.coraza_body_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Observe the number of body bytes actually handed to Coraza.
    pub fn record_coraza_body_inspected_bytes(&self, bytes: usize) {
        let value = bytes as f64;
        self.coraza_body_inspected_count
            .fetch_add(1, Ordering::Relaxed);
        self.coraza_body_inspected_sum
            .fetch_add(bytes.min(u64::MAX as usize) as u64, Ordering::Relaxed);

        for (index, bound) in CORAZA_BODY_BYTES_BUCKETS.iter().enumerate() {
            if value <= *bound {
                self.coraza_body_inspected_buckets[index].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.coraza_body_inspected_inf
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn admission_queued(&self) {
        self.admission_queued_total.fetch_add(1, Ordering::Relaxed);
        self.admission_queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub fn admission_dequeued(&self) {
        self.admission_queue_depth.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn admission_admitted(&self) {
        self.admission_admitted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn admission_rejected_queue_full(&self) {
        self.admission_rejected_queue_full_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn admission_rejected_timeout(&self) {
        self.admission_rejected_timeout_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Observe how long a heavy request waited for an admission permit.
    pub fn record_admission_wait(&self, duration: Duration) {
        let seconds = duration.as_secs_f64();
        self.admission_wait_count.fetch_add(1, Ordering::Relaxed);
        self.admission_wait_sum_nanos.fetch_add(
            duration.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        for (index, bound) in DURATION_BUCKETS.iter().enumerate() {
            if seconds <= *bound {
                self.admission_wait_buckets[index].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.admission_wait_inf.fetch_add(1, Ordering::Relaxed);
    }

    pub fn admission_cheap_started(&self) {
        self.admission_cheap_inflight
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn admission_cheap_finished(&self) {
        self.admission_cheap_inflight
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub fn admission_heavy_started(&self) {
        self.admission_heavy_inflight
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn admission_heavy_finished(&self) {
        self.admission_heavy_inflight
            .fetch_sub(1, Ordering::Relaxed);
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

    pub fn record_grpc_allow(&self) {
        self.grpc_allow_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_grpc_block(&self) {
        self.grpc_block_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_grpc_error(&self) {
        self.grpc_error_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one gRPC field-content scan (one synthetic evaluation).
    pub fn record_grpc_content_scan(&self) {
        self.grpc_content_scan_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one gRPC request blocked by field-content scanning.
    pub fn record_grpc_content_block(&self) {
        self.grpc_content_block_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_graphql_allow(&self) {
        self.graphql_allow_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_graphql_block(&self) {
        self.graphql_block_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_graphql_error(&self) {
        self.graphql_error_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one allow-verdict cache lookup that hit a live entry.
    pub fn record_allow_cache_hit(&self) {
        self.allow_cache_hits_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one allow-verdict cache lookup that did not hit a live entry.
    pub fn record_allow_cache_miss(&self) {
        self.allow_cache_misses_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one entry evicted because a shard was at capacity.
    pub fn record_allow_cache_eviction(&self) {
        self.allow_cache_evictions_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one entry dropped because its TTL elapsed.
    pub fn record_allow_cache_expired(&self) {
        self.allow_cache_expired_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one request the cache declined to key (for example an
    /// over-cap body).
    pub fn record_allow_cache_skipped(&self) {
        self.allow_cache_skipped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one full cache invalidation (policy generation change).
    pub fn record_allow_cache_invalidation(&self) {
        self.allow_cache_invalidations_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Publishes the current number of live cache entries as a gauge.
    pub fn set_allow_cache_entries(&self, entries: usize) {
        self.allow_cache_entries
            .store(entries.min(u64::MAX as usize) as u64, Ordering::Relaxed);
    }

    pub fn record_fast_allow_hit(&self) {
        self.fast_allow_hits_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fast_allow_block(&self) {
        self.fast_allow_blocks_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fast_allow_fallthrough(&self) {
        self.fast_allow_fallthrough_total
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

        out.push_str(&format!(
            "# HELP waf_coraza_evaluations_total Coraza reactor evaluations.\n\
             # TYPE waf_coraza_evaluations_total counter\n\
             waf_coraza_evaluations_total {}\n\
             # HELP waf_coraza_blocks_total Requests blocked by the Coraza reactor.\n\
             # TYPE waf_coraza_blocks_total counter\n\
             waf_coraza_blocks_total {}\n\
             # HELP waf_coraza_errors_total Coraza reactor evaluation failures.\n\
             # TYPE waf_coraza_errors_total counter\n\
             waf_coraza_errors_total {}\n",
            self.coraza_evaluations_total.load(Ordering::Relaxed),
            self.coraza_blocks_total.load(Ordering::Relaxed),
            self.coraza_errors_total.load(Ordering::Relaxed),
        ));

        out.push_str(&format!(
            "# HELP waf_crs_prefilter_evaluations_total CRS literal-prefilter evaluations.\n\
             # TYPE waf_crs_prefilter_evaluations_total counter\n\
             waf_crs_prefilter_evaluations_total {}\n\
             # HELP waf_crs_prefilter_hits_total CRS prefilter evaluations that found an indicator.\n\
             # TYPE waf_crs_prefilter_hits_total counter\n\
             waf_crs_prefilter_hits_total {}\n\
             # HELP waf_crs_prefilter_withheld_total Bodies withheld from CRS after a clean prefilter.\n\
             # TYPE waf_crs_prefilter_withheld_total counter\n\
             waf_crs_prefilter_withheld_total {}\n\
             # HELP waf_crs_prefilter_duration_seconds_total Time spent in the CRS prefilter.\n\
             # TYPE waf_crs_prefilter_duration_seconds_total counter\n\
             waf_crs_prefilter_duration_seconds_total {}\n",
            self.crs_prefilter_evaluations_total.load(Ordering::Relaxed),
            self.crs_prefilter_hits_total.load(Ordering::Relaxed),
            self.crs_prefilter_withheld_total.load(Ordering::Relaxed),
            self.crs_prefilter_duration_sum_nanos.load(Ordering::Relaxed) as f64 / 1e9,
        ));

        out.push_str(&format!(
            "# HELP waf_coraza_body_truncated_total Bodies truncated to the configured inspection prefix.\n\
             # TYPE waf_coraza_body_truncated_total counter\n\
             waf_coraza_body_truncated_total {}\n\
             # HELP waf_coraza_body_rejected_total Bodies rejected by the oversize policy before evaluation.\n\
             # TYPE waf_coraza_body_rejected_total counter\n\
             waf_coraza_body_rejected_total {}\n",
            self.coraza_body_truncated_total.load(Ordering::Relaxed),
            self.coraza_body_rejected_total.load(Ordering::Relaxed),
        ));

        out.push_str(
            "# HELP waf_coraza_body_inspected_bytes Body bytes handed to Coraza per evaluation.\n\
             # TYPE waf_coraza_body_inspected_bytes histogram\n",
        );
        let mut body_cumulative = 0u64;
        for (index, bound) in CORAZA_BODY_BYTES_BUCKETS.iter().enumerate() {
            body_cumulative = body_cumulative
                .saturating_add(self.coraza_body_inspected_buckets[index].load(Ordering::Relaxed));
            out.push_str(&format!(
                "waf_coraza_body_inspected_bytes_bucket{{le=\"{}\"}} {}\n",
                format_bucket(*bound),
                body_cumulative
            ));
        }
        let body_total =
            body_cumulative.saturating_add(self.coraza_body_inspected_inf.load(Ordering::Relaxed));
        out.push_str(&format!(
            "waf_coraza_body_inspected_bytes_bucket{{le=\"+Inf\"}} {}\n",
            body_total
        ));
        out.push_str(&format!(
            "waf_coraza_body_inspected_bytes_sum {}\n",
            self.coraza_body_inspected_sum.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "waf_coraza_body_inspected_bytes_count {}\n",
            self.coraza_body_inspected_count.load(Ordering::Relaxed)
        ));

        out.push_str(&format!(
            "# HELP waf_admission_queued_total Heavy inspections that had to wait for a permit.\n\
             # TYPE waf_admission_queued_total counter\n\
             waf_admission_queued_total {}\n\
             # HELP waf_admission_queue_depth Heavy inspections currently waiting for a permit.\n\
             # TYPE waf_admission_queue_depth gauge\n\
             waf_admission_queue_depth {}\n\
             # HELP waf_admission_admitted_total Heavy inspections admitted after waiting.\n\
             # TYPE waf_admission_admitted_total counter\n\
             waf_admission_admitted_total {}\n\
             # HELP waf_admission_rejected_total Heavy inspections rejected by admission control, by reason.\n\
             # TYPE waf_admission_rejected_total counter\n\
             waf_admission_rejected_total{{reason=\"queue_full\"}} {}\n\
             waf_admission_rejected_total{{reason=\"timeout\"}} {}\n\
             # HELP waf_admission_inflight In-flight evaluations by inspection class.\n\
             # TYPE waf_admission_inflight gauge\n\
             waf_admission_inflight{{class=\"cheap\"}} {}\n\
             waf_admission_inflight{{class=\"heavy\"}} {}\n",
            self.admission_queued_total.load(Ordering::Relaxed),
            self.admission_queue_depth.load(Ordering::Relaxed),
            self.admission_admitted_total.load(Ordering::Relaxed),
            self.admission_rejected_queue_full_total.load(Ordering::Relaxed),
            self.admission_rejected_timeout_total.load(Ordering::Relaxed),
            self.admission_cheap_inflight.load(Ordering::Relaxed),
            self.admission_heavy_inflight.load(Ordering::Relaxed),
        ));

        out.push_str(&format!(
            "# HELP waf_grpc_decisions_total gRPC protocol pre-check decisions by outcome.\n\
             # TYPE waf_grpc_decisions_total counter\n\
             waf_grpc_decisions_total{{decision=\"allow\"}} {}\n\
             waf_grpc_decisions_total{{decision=\"block\"}} {}\n\
             waf_grpc_decisions_total{{decision=\"error\"}} {}\n\
             # HELP waf_grpc_content_scans_total gRPC field-content scans sent to Coraza.\n\
             # TYPE waf_grpc_content_scans_total counter\n\
             waf_grpc_content_scans_total {}\n\
             # HELP waf_grpc_content_blocks_total gRPC requests blocked by field-content scanning.\n\
             # TYPE waf_grpc_content_blocks_total counter\n\
             waf_grpc_content_blocks_total {}\n\
             # HELP waf_graphql_decisions_total GraphQL protocol pre-check decisions by outcome.\n\
             # TYPE waf_graphql_decisions_total counter\n\
             waf_graphql_decisions_total{{decision=\"allow\"}} {}\n\
             waf_graphql_decisions_total{{decision=\"block\"}} {}\n\
             waf_graphql_decisions_total{{decision=\"error\"}} {}\n",
            self.grpc_allow_total.load(Ordering::Relaxed),
            self.grpc_block_total.load(Ordering::Relaxed),
            self.grpc_error_total.load(Ordering::Relaxed),
            self.grpc_content_scan_total.load(Ordering::Relaxed),
            self.grpc_content_block_total.load(Ordering::Relaxed),
            self.graphql_allow_total.load(Ordering::Relaxed),
            self.graphql_block_total.load(Ordering::Relaxed),
            self.graphql_error_total.load(Ordering::Relaxed),
        ));

        out.push_str(&format!(
            "# HELP waf_fast_allow_hits_total Bodyless requests decided by the compiled allowlist.\n\
             # TYPE waf_fast_allow_hits_total counter\n\
             waf_fast_allow_hits_total {}\n\
             # HELP waf_fast_allow_blocks_total Fast-allow requests rejected by an always-on gate.\n\
             # TYPE waf_fast_allow_blocks_total counter\n\
             waf_fast_allow_blocks_total {}\n\
             # HELP waf_fast_allow_fallthrough_total Matched fast-allow routes that fell through to full evaluation.\n\
             # TYPE waf_fast_allow_fallthrough_total counter\n\
             waf_fast_allow_fallthrough_total {}\n",
            self.fast_allow_hits_total.load(Ordering::Relaxed),
            self.fast_allow_blocks_total.load(Ordering::Relaxed),
            self.fast_allow_fallthrough_total.load(Ordering::Relaxed),
        ));

        out.push_str(
            "# HELP waf_admission_wait_duration_seconds Time heavy inspections waited for a permit.\n\
             # TYPE waf_admission_wait_duration_seconds histogram\n",
        );
        let mut admission_cumulative = 0u64;
        for (index, bound) in DURATION_BUCKETS.iter().enumerate() {
            admission_cumulative = admission_cumulative
                .saturating_add(self.admission_wait_buckets[index].load(Ordering::Relaxed));
            out.push_str(&format!(
                "waf_admission_wait_duration_seconds_bucket{{le=\"{}\"}} {}\n",
                format_bucket(*bound),
                admission_cumulative
            ));
        }
        let admission_total =
            admission_cumulative.saturating_add(self.admission_wait_inf.load(Ordering::Relaxed));
        out.push_str(&format!(
            "waf_admission_wait_duration_seconds_bucket{{le=\"+Inf\"}} {}\n",
            admission_total
        ));
        out.push_str(&format!(
            "waf_admission_wait_duration_seconds_sum {}\n",
            self.admission_wait_sum_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
        ));
        out.push_str(&format!(
            "waf_admission_wait_duration_seconds_count {}\n",
            self.admission_wait_count.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP waf_coraza_evaluation_duration_seconds Coraza reactor evaluation duration in seconds.\n\
             # TYPE waf_coraza_evaluation_duration_seconds histogram\n",
        );
        let mut coraza_cumulative = 0u64;
        for (index, bound) in CORAZA_DURATION_BUCKETS.iter().enumerate() {
            coraza_cumulative = coraza_cumulative
                .saturating_add(self.coraza_duration_buckets[index].load(Ordering::Relaxed));
            out.push_str(&format!(
                "waf_coraza_evaluation_duration_seconds_bucket{{le=\"{}\"}} {}\n",
                format_bucket(*bound),
                coraza_cumulative
            ));
        }
        let coraza_total =
            coraza_cumulative.saturating_add(self.coraza_duration_inf.load(Ordering::Relaxed));
        out.push_str(&format!(
            "waf_coraza_evaluation_duration_seconds_bucket{{le=\"+Inf\"}} {}\n",
            coraza_total
        ));
        out.push_str(&format!(
            "waf_coraza_evaluation_duration_seconds_sum {}\n",
            self.coraza_duration_sum_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
        ));
        out.push_str(&format!(
            "waf_coraza_evaluation_duration_seconds_count {}\n",
            self.coraza_duration_count.load(Ordering::Relaxed)
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
            "# HELP waf_allow_cache_hits_total Allow-verdict cache lookups that hit a live entry.\n\
             # TYPE waf_allow_cache_hits_total counter\n\
             waf_allow_cache_hits_total {}\n\
             # HELP waf_allow_cache_misses_total Allow-verdict cache lookups that missed.\n\
             # TYPE waf_allow_cache_misses_total counter\n\
             waf_allow_cache_misses_total {}\n\
             # HELP waf_allow_cache_evictions_total Allow-verdict cache entries evicted at capacity.\n\
             # TYPE waf_allow_cache_evictions_total counter\n\
             waf_allow_cache_evictions_total {}\n\
             # HELP waf_allow_cache_expired_total Allow-verdict cache entries dropped after their TTL.\n\
             # TYPE waf_allow_cache_expired_total counter\n\
             waf_allow_cache_expired_total {}\n\
             # HELP waf_allow_cache_skipped_total Requests the allow-verdict cache declined to key.\n\
             # TYPE waf_allow_cache_skipped_total counter\n\
             waf_allow_cache_skipped_total {}\n\
             # HELP waf_allow_cache_invalidations_total Allow-verdict cache invalidations.\n\
             # TYPE waf_allow_cache_invalidations_total counter\n\
             waf_allow_cache_invalidations_total {}\n\
             # HELP waf_allow_cache_entries Live allow-verdict cache entries.\n\
             # TYPE waf_allow_cache_entries gauge\n\
             waf_allow_cache_entries {}\n",
            self.allow_cache_hits_total.load(Ordering::Relaxed),
            self.allow_cache_misses_total.load(Ordering::Relaxed),
            self.allow_cache_evictions_total.load(Ordering::Relaxed),
            self.allow_cache_expired_total.load(Ordering::Relaxed),
            self.allow_cache_skipped_total.load(Ordering::Relaxed),
            self.allow_cache_invalidations_total.load(Ordering::Relaxed),
            self.allow_cache_entries.load(Ordering::Relaxed),
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
    fn render_includes_fast_allow_counters() {
        let metrics = Metrics::new();
        metrics.record_fast_allow_hit();
        metrics.record_fast_allow_hit();
        metrics.record_fast_allow_block();
        metrics.record_fast_allow_fallthrough();

        let rendered = metrics.render_prometheus();
        assert_eq!(
            find_line(&rendered, "waf_fast_allow_hits_total "),
            "waf_fast_allow_hits_total 2"
        );
        assert_eq!(
            find_line(&rendered, "waf_fast_allow_blocks_total "),
            "waf_fast_allow_blocks_total 1"
        );
        assert_eq!(
            find_line(&rendered, "waf_fast_allow_fallthrough_total "),
            "waf_fast_allow_fallthrough_total 1"
        );
    }

    #[test]
    fn render_includes_coraza_counters() {
        let metrics = Metrics::new();
        metrics.record_coraza_evaluation(Duration::from_micros(500));
        metrics.record_coraza_evaluation(Duration::from_millis(7));
        metrics.record_coraza_block();
        metrics.record_coraza_error();

        let rendered = metrics.render_prometheus();
        assert_eq!(
            find_line(&rendered, "waf_coraza_evaluations_total "),
            "waf_coraza_evaluations_total 2"
        );
        assert_eq!(
            find_line(&rendered, "waf_coraza_blocks_total "),
            "waf_coraza_blocks_total 1"
        );
        assert_eq!(
            find_line(&rendered, "waf_coraza_errors_total "),
            "waf_coraza_errors_total 1"
        );
    }

    #[test]
    fn render_includes_protocol_decision_counters() {
        let metrics = Metrics::new();
        metrics.record_grpc_allow();
        metrics.record_grpc_block();
        metrics.record_grpc_error();
        metrics.record_graphql_allow();
        metrics.record_graphql_block();
        metrics.record_graphql_error();

        let rendered = metrics.render_prometheus();
        for (prefix, expected) in [
            (
                "waf_grpc_decisions_total{decision=\"allow\"} ",
                "waf_grpc_decisions_total{decision=\"allow\"} 1",
            ),
            (
                "waf_grpc_decisions_total{decision=\"block\"} ",
                "waf_grpc_decisions_total{decision=\"block\"} 1",
            ),
            (
                "waf_grpc_decisions_total{decision=\"error\"} ",
                "waf_grpc_decisions_total{decision=\"error\"} 1",
            ),
            (
                "waf_graphql_decisions_total{decision=\"allow\"} ",
                "waf_graphql_decisions_total{decision=\"allow\"} 1",
            ),
            (
                "waf_graphql_decisions_total{decision=\"block\"} ",
                "waf_graphql_decisions_total{decision=\"block\"} 1",
            ),
            (
                "waf_graphql_decisions_total{decision=\"error\"} ",
                "waf_graphql_decisions_total{decision=\"error\"} 1",
            ),
        ] {
            assert_eq!(find_line(&rendered, prefix), expected);
        }
    }

    #[test]
    fn render_coraza_histogram_is_cumulative_and_valid() {
        let metrics = Metrics::new();
        metrics.record_coraza_evaluation(Duration::from_micros(500));
        metrics.record_coraza_evaluation(Duration::from_millis(7));
        metrics.record_coraza_evaluation(Duration::from_millis(80));
        metrics.record_coraza_evaluation(Duration::from_secs(10));

        let rendered = metrics.render_prometheus();

        assert_eq!(
            find_line(
                &rendered,
                "waf_coraza_evaluation_duration_seconds_bucket{le=\"0.001\"}"
            ),
            "waf_coraza_evaluation_duration_seconds_bucket{le=\"0.001\"} 1"
        );
        assert_eq!(
            find_line(
                &rendered,
                "waf_coraza_evaluation_duration_seconds_bucket{le=\"0.01\"}"
            ),
            "waf_coraza_evaluation_duration_seconds_bucket{le=\"0.01\"} 2"
        );
        assert_eq!(
            find_line(
                &rendered,
                "waf_coraza_evaluation_duration_seconds_bucket{le=\"0.1\"}"
            ),
            "waf_coraza_evaluation_duration_seconds_bucket{le=\"0.1\"} 3"
        );
        assert_eq!(
            find_line(
                &rendered,
                "waf_coraza_evaluation_duration_seconds_bucket{le=\"+Inf\"}"
            ),
            "waf_coraza_evaluation_duration_seconds_bucket{le=\"+Inf\"} 4"
        );
        assert_eq!(
            find_line(&rendered, "waf_coraza_evaluation_duration_seconds_count "),
            "waf_coraza_evaluation_duration_seconds_count 4"
        );

        let sum = find_line(&rendered, "waf_coraza_evaluation_duration_seconds_sum ");
        let sum: f64 = sum.rsplit(' ').next().unwrap().parse().unwrap();
        assert!((sum - 10.0875).abs() < 0.001, "unexpected sum {sum}");

        for prefix in [
            "# HELP waf_coraza_evaluations_total",
            "# TYPE waf_coraza_evaluations_total counter",
            "# HELP waf_coraza_blocks_total",
            "# TYPE waf_coraza_blocks_total counter",
            "# HELP waf_coraza_errors_total",
            "# TYPE waf_coraza_errors_total counter",
            "# TYPE waf_coraza_evaluation_duration_seconds histogram",
        ] {
            assert!(rendered.contains(prefix), "missing {prefix}");
        }
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
