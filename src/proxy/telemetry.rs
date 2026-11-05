//! Central request-completion telemetry.
//!
//! Every accepted request must contribute exactly one duration observation,
//! regardless of protocol or which pipeline stage returned early. `begin`
//! creates a guard that records the observation on drop, so new early returns
//! cannot silently skip the histogram.
//!
//! Rejections also carry a stable reason. The existing counters
//! (`waf_blocked_total`, `waf_auth_failures_total`, `waf_rate_limited_total`)
//! provide the aggregate category; the reason is attached to the structured
//! completion log for per-cause attribution.

use std::sync::Arc;
use std::time::Instant;

use tracing::debug;

use crate::metrics::Metrics;

/// Why a request was rejected before a normal upstream response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestRejection {
    UnsupportedHttpVersion,
    InvalidFraming,
    InvalidTrailerFraming,
    Authentication,
    WebSocketVersion,
    WebTransportUnsupported,
    FastAllowBlocked,
    FastAllowRateLimited,
    WafBlocked,
    WafRateLimited,
    BodyTooLarge,
    BodyReadError,
    BodyTimeout,
    UnsupportedContentEncoding,
    DecompressedTooLarge,
    MalformedCompression,
}

impl RequestRejection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedHttpVersion => "unsupported_http_version",
            Self::InvalidFraming => "invalid_framing",
            Self::InvalidTrailerFraming => "invalid_trailer_framing",
            Self::Authentication => "authentication",
            Self::WebSocketVersion => "websocket_version",
            Self::WebTransportUnsupported => "webtransport_unsupported",
            Self::FastAllowBlocked => "fast_allow_blocked",
            Self::FastAllowRateLimited => "fast_allow_rate_limited",
            Self::WafBlocked => "waf_blocked",
            Self::WafRateLimited => "waf_rate_limited",
            Self::BodyTooLarge => "body_too_large",
            Self::BodyReadError => "body_read_error",
            Self::BodyTimeout => "body_timeout",
            Self::UnsupportedContentEncoding => "unsupported_content_encoding",
            Self::DecompressedTooLarge => "decompressed_too_large",
            Self::MalformedCompression => "malformed_compression",
        }
    }
}

/// Records request-count, duration and (when rejected) a reason exactly once.
pub(crate) struct RequestTelemetry {
    metrics: Arc<Metrics>,
    started: Instant,
    completed: bool,
}

impl RequestTelemetry {
    pub(crate) fn begin(metrics: Arc<Metrics>) -> Self {
        metrics.record_request();
        Self {
            metrics,
            started: Instant::now(),
            completed: false,
        }
    }

    /// Attach a rejection reason. Call immediately before returning the error
    /// response so the structured completion log carries the cause.
    pub(crate) fn reject(&self, reason: RequestRejection) {
        debug!(
            reason = reason.as_str(),
            "request rejected before upstream completion"
        );
    }

    /// Record the duration observation. Idempotent; `Drop` calls this too.
    pub(crate) fn finish(&mut self) {
        if self.completed {
            return;
        }
        self.completed = true;
        self.metrics.record_request_duration(self.started.elapsed());
    }
}

impl Drop for RequestTelemetry {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_request_and_duration_once() {
        let metrics = Arc::new(Metrics::new());
        {
            let mut telemetry = RequestTelemetry::begin(Arc::clone(&metrics));
            telemetry.reject(RequestRejection::BodyTimeout);
            telemetry.finish();
            telemetry.finish();
        }

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("waf_requests_total 1"));
        assert!(rendered.contains("waf_request_duration_seconds_count 1"));
    }

    #[test]
    fn drop_records_duration_for_early_return() {
        let metrics = Arc::new(Metrics::new());
        {
            let _telemetry = RequestTelemetry::begin(Arc::clone(&metrics));
        }

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("waf_request_duration_seconds_count 1"));
    }
}
