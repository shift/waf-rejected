//! Admission control for expensive (CRS body) WAF inspections.
//!
//! A request that scans a body occupies a reactor worker for milliseconds to
//! seconds. Without admission control, a handful of large bodies can occupy
//! every worker and starve cheap requests. This module classifies each
//! evaluation as [`InspectionCost::Cheap`] or [`InspectionCost::Heavy`] and
//! bounds concurrent heavy evaluations so at least one reactor worker stays
//! available for cheap traffic.
//!
//! Classification runs before the protocol pre-checks, on signals available on
//! the original request. A gRPC field-content scan withholds the protobuf body
//! from CRS but performs its own Coraza evaluation, so it is heavy.
//!
//! Waiting is asynchronous (`tokio::sync::Semaphore` + `tokio::time::timeout`)
//! so a queued request does not block a Tokio worker. Saturation and timeout
//! both fail closed: the engine maps them to `503` with `Retry-After`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::WafAdmissionConfig;
use crate::metrics::Metrics;

/// Cost class of a request's WAF inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionCost {
    /// No body, or a body withheld from CRS by a protocol pre-check.
    Cheap,
    /// A body that CRS body rules will scan, or a protocol pre-check that runs
    /// its own Coraza evaluation (gRPC field-content scanning).
    Heavy,
}

impl InspectionCost {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cheap => "cheap",
            Self::Heavy => "heavy",
        }
    }
}

/// Why a heavy request was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRejection {
    /// The bounded wait queue is full.
    QueueFull { max_queued: usize },
    /// The request waited for `queue_timeout_ms` without obtaining a permit.
    Timeout { waited_ms: u64 },
}

impl std::fmt::Display for AdmissionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull { max_queued } => write!(
                f,
                "heavy-inspection queue is full (max_queued = {max_queued})"
            ),
            Self::Timeout { waited_ms } => {
                write!(f, "heavy-inspection permit wait exceeded {waited_ms} ms")
            }
        }
    }
}

/// Inputs to classification that are known before any pre-check runs.
///
/// Classification must not look at the post-pre-check context: the gRPC
/// pre-check withholds the protobuf body from CRS *and* may run its own Coraza
/// evaluation of decoded field values. A stripped body therefore does not
/// imply a cheap evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InspectionSignals {
    /// The request carries a non-empty body.
    pub body_present: bool,
    /// A protocol pre-check will run a Coraza evaluation of decoded content.
    pub protocol_content_scan: bool,
    /// A protocol pre-check withholds the body from CRS body rules.
    pub body_withheld: bool,
}

/// Classify an evaluation from signals available on the original request.
///
/// A protocol content scan is heavy even though the raw body is withheld: it
/// triggers a full Coraza evaluation of the decoded payload. Otherwise a body
/// that reaches CRS body rules is heavy, and a body withheld by a pre-check is
/// cheap.
pub fn classify(signals: InspectionSignals) -> InspectionCost {
    if signals.protocol_content_scan {
        return InspectionCost::Heavy;
    }
    if !signals.body_present || signals.body_withheld {
        InspectionCost::Cheap
    } else {
        InspectionCost::Heavy
    }
}

struct Inner {
    enabled: bool,
    semaphore: Arc<Semaphore>,
    timeout: Duration,
    max_queued: usize,
    queued: AtomicUsize,
    metrics: Option<Arc<Metrics>>,
}

/// Heavy-inspection admission controller. Cloning shares counters and permits.
#[derive(Clone)]
pub struct AdmissionController {
    inner: Arc<Inner>,
}

/// RAII guard for one admitted evaluation. Dropping it releases the heavy
/// permit and updates the per-class in-flight gauge.
pub struct AdmissionGuard {
    _permit: Option<OwnedSemaphorePermit>,
    cost: InspectionCost,
    metrics: Option<Arc<Metrics>>,
}

impl AdmissionGuard {
    fn new(
        permit: Option<OwnedSemaphorePermit>,
        cost: InspectionCost,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        if let Some(metrics) = &metrics {
            match cost {
                InspectionCost::Cheap => metrics.admission_cheap_started(),
                InspectionCost::Heavy => metrics.admission_heavy_started(),
            }
        }
        Self {
            _permit: permit,
            cost,
            metrics,
        }
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if let Some(metrics) = &self.metrics {
            match self.cost {
                InspectionCost::Cheap => metrics.admission_cheap_finished(),
                InspectionCost::Heavy => metrics.admission_heavy_finished(),
            }
        }
    }
}

impl AdmissionController {
    /// Build a controller from configuration. `pool_size` is the resolved
    /// reactor pool size and is used for `heavy_permits = 0` (auto).
    pub fn from_config(
        config: &WafAdmissionConfig,
        pool_size: usize,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self::with_permits(
            config.enabled,
            config.resolved_heavy_permits(pool_size),
            Duration::from_millis(config.queue_timeout_ms.max(1)),
            config.max_queued,
            metrics,
        )
    }

    /// Build a controller with explicit values. Used by configuration and
    /// tests; `permits` is always at least one.
    pub fn with_permits(
        enabled: bool,
        permits: usize,
        timeout: Duration,
        max_queued: usize,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                enabled,
                semaphore: Arc::new(Semaphore::new(permits.max(1))),
                timeout,
                max_queued,
                queued: AtomicUsize::new(0),
                metrics,
            }),
        }
    }

    /// A disabled controller admits everything with no waiting.
    pub fn disabled() -> Self {
        Self::with_permits(false, 1, Duration::from_millis(1), 0, None)
    }

    pub fn enabled(&self) -> bool {
        self.inner.enabled
    }

    /// Number of heavy permits currently available.
    pub fn available_permits(&self) -> usize {
        self.inner.semaphore.available_permits()
    }

    /// Admit an evaluation. Cheap requests and disabled admission return
    /// immediately. Heavy requests acquire a permit or wait asynchronously
    /// up to the configured timeout.
    pub async fn admit(&self, cost: InspectionCost) -> Result<AdmissionGuard, AdmissionRejection> {
        let metrics = self.inner.metrics.as_ref();
        if cost == InspectionCost::Cheap || !self.inner.enabled {
            return Ok(AdmissionGuard::new(None, cost, self.inner.metrics.clone()));
        }

        // Fast path: a permit is free.
        if let Ok(permit) = self.inner.semaphore.clone().try_acquire_owned() {
            if let Some(metrics) = metrics {
                metrics.admission_admitted();
            }
            return Ok(AdmissionGuard::new(
                Some(permit),
                cost,
                self.inner.metrics.clone(),
            ));
        }

        // Bound the queue before waiting. fetch_add returns the previous
        // depth; if it is already max_queued, this request is rejected.
        let previous = self.inner.queued.fetch_add(1, Ordering::AcqRel);
        if previous >= self.inner.max_queued {
            self.inner.queued.fetch_sub(1, Ordering::AcqRel);
            if let Some(metrics) = metrics {
                metrics.admission_rejected_queue_full();
            }
            return Err(AdmissionRejection::QueueFull {
                max_queued: self.inner.max_queued,
            });
        }

        if let Some(metrics) = metrics {
            metrics.admission_queued();
        }
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(
            self.inner.timeout,
            self.inner.semaphore.clone().acquire_owned(),
        )
        .await;
        self.inner.queued.fetch_sub(1, Ordering::AcqRel);
        if let Some(metrics) = metrics {
            metrics.admission_dequeued();
            metrics.record_admission_wait(started.elapsed());
        }

        match result {
            Ok(Ok(permit)) => {
                if let Some(metrics) = metrics {
                    metrics.admission_admitted();
                }
                Ok(AdmissionGuard::new(
                    Some(permit),
                    cost,
                    self.inner.metrics.clone(),
                ))
            }
            Ok(Err(_)) | Err(_) => {
                if let Some(metrics) = metrics {
                    metrics.admission_rejected_timeout();
                }
                Err(AdmissionRejection::Timeout {
                    waited_ms: self.inner.timeout.as_millis().min(u64::MAX as u128) as u64,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(
        body_present: bool,
        protocol_content_scan: bool,
        body_withheld: bool,
    ) -> InspectionSignals {
        InspectionSignals {
            body_present,
            protocol_content_scan,
            body_withheld,
        }
    }

    #[test]
    fn classifies_bodies_as_heavy_and_empty_or_absent_as_cheap() {
        assert_eq!(
            classify(signals(false, false, false)),
            InspectionCost::Cheap
        );
        assert_eq!(classify(signals(true, false, false)), InspectionCost::Heavy);
        assert_eq!(classify(signals(true, false, true)), InspectionCost::Cheap);
    }

    #[test]
    fn protocol_content_scans_are_heavy_even_when_the_body_is_withheld() {
        assert_eq!(classify(signals(true, true, true)), InspectionCost::Heavy);
        assert_eq!(classify(signals(false, true, true)), InspectionCost::Heavy);
    }

    #[test]
    fn auto_permits_reserve_a_worker() {
        let config = WafAdmissionConfig {
            heavy_permits: 0,
            ..WafAdmissionConfig::default()
        };
        assert_eq!(config.resolved_heavy_permits(6), 3);
        assert_eq!(config.resolved_heavy_permits(2), 1);
        assert_eq!(config.resolved_heavy_permits(1), 1);
        let config = WafAdmissionConfig {
            heavy_permits: 12,
            ..WafAdmissionConfig::default()
        };
        assert_eq!(config.resolved_heavy_permits(6), 6);
    }

    #[tokio::test]
    async fn cheap_requests_bypass_a_saturated_heavy_pool() {
        let controller =
            AdmissionController::with_permits(true, 1, Duration::from_millis(50), 4, None);
        let _held = controller.admit(InspectionCost::Heavy).await.unwrap();
        assert_eq!(controller.available_permits(), 0);

        let cheap = controller.admit(InspectionCost::Cheap).await;
        assert!(
            cheap.is_ok(),
            "cheap request must not wait for heavy permits"
        );
    }

    #[tokio::test]
    async fn full_queue_rejects_heavy_requests() {
        let controller =
            AdmissionController::with_permits(true, 1, Duration::from_millis(200), 0, None);
        let _held = controller.admit(InspectionCost::Heavy).await.unwrap();
        let rejected = controller.admit(InspectionCost::Heavy).await;
        assert!(matches!(
            rejected,
            Err(AdmissionRejection::QueueFull { max_queued: 0 })
        ));
    }

    #[tokio::test]
    async fn heavy_wait_times_out_then_recovers() {
        let controller =
            AdmissionController::with_permits(true, 1, Duration::from_millis(20), 1, None);
        let held = controller.admit(InspectionCost::Heavy).await.unwrap();
        let rejected = controller.admit(InspectionCost::Heavy).await;
        assert!(matches!(rejected, Err(AdmissionRejection::Timeout { .. })));
        drop(held);
        assert!(controller.admit(InspectionCost::Heavy).await.is_ok());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn classification_follows_body_and_protocol_signals(
            body_present in any::<bool>(),
            protocol_content_scan in any::<bool>(),
            body_withheld in any::<bool>(),
        ) {
            let cost = classify(InspectionSignals {
                body_present,
                protocol_content_scan,
                body_withheld,
            });
            let expected = if protocol_content_scan || (body_present && !body_withheld) {
                InspectionCost::Heavy
            } else {
                InspectionCost::Cheap
            };
            prop_assert_eq!(cost, expected);
        }
    }
}
