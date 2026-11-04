use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::Request;

use crate::config::AiConfig;
use crate::error::WafError;
use crate::waf::RequestContext;

/// Result of AI threat analysis
#[derive(Debug, Clone)]
pub struct AiAnalysisResult {
    /// Raw threat analysis from AI service
    pub analysis: crate::ai_threat_detection::ThreatAnalysis,

    /// Whether the request should be blocked based on AI analysis
    pub should_block: bool,

    /// Processing time in milliseconds
    pub processing_time_ms: f32,

    /// Model version used for analysis
    pub model_version: String,
}

impl Default for AiAnalysisResult {
    fn default() -> Self {
        Self {
            analysis: crate::ai_threat_detection::ThreatAnalysis::default(),
            should_block: false,
            processing_time_ms: 0.0,
            model_version: "disabled".to_string(),
        }
    }
}

/// AI threat detector that integrates with the WAF engine
pub struct AiThreatDetector {
    /// Core AI threat detection service
    threat_detector: Arc<crate::ai_threat_detection::ThreatDetectionService>,

    /// AI WAF middleware for advanced analysis
    ai_middleware: Arc<crate::ai_waf_integration::AiWafMiddleware>,

    /// Configuration for AI analysis
    config: AiConfig,
}

impl AiThreatDetector {
    /// Create a new AI threat detector
    pub fn new(config: AiConfig) -> Result<Self, WafError> {
        // Initialize the core threat detection service
        let threat_detector = Arc::new(crate::ai_threat_detection::ThreatDetectionService::new());

        // Initialize the AI WAF middleware
        let ai_middleware = Arc::new(crate::ai_waf_integration::AiWafMiddleware::new()?);

        Ok(Self {
            threat_detector,
            ai_middleware,
            config,
        })
    }

    /// Analyze a request for threats using AI
    pub async fn analyze_request(
        &self,
        ctx: &RequestContext,
    ) -> Result<AiAnalysisResult, WafError> {
        if !self.config.enabled {
            return Ok(AiAnalysisResult::default());
        }

        let start_time = Instant::now();

        // Construct HTTP request from context
        let mut req_builder = Request::builder()
            .method(ctx.method.clone())
            .uri(ctx.uri.clone());

        for (key, value) in &ctx.headers {
            req_builder = req_builder.header(key, value);
        }

        let body_bytes = ctx.body.as_ref().map(|b| b.as_ref()).unwrap_or(&[]);
        let req = req_builder.body(body_bytes.to_vec()).unwrap();

        // Perform AI analysis with timeout
        let analysis_result = tokio::time::timeout(
            Duration::from_millis(self.config.timeout_ms),
            self.ai_middleware.analyze_request(&req, body_bytes),
        )
        .await
        .map_err(|_| WafError::internal("AI analysis timeout".to_string()))?
        .map_err(|e| WafError::internal(format!("AI analysis error: {}", e)))?;

        let processing_time = start_time.elapsed().as_millis();

        // Determine if request should be blocked based on threat threshold
        let should_block = analysis_result.should_block
            && analysis_result.analysis.overall_risk_score >= self.config.threat_threshold as f32;

        Ok(AiAnalysisResult {
            analysis: analysis_result.analysis,
            should_block,
            processing_time_ms: processing_time as f32,
            model_version: analysis_result.model_version,
        })
    }

    /// Get current configuration
    pub fn config(&self) -> &AiConfig {
        &self.config
    }

    /// Check if AI analysis is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{HeaderMap, Method};
    use std::net::IpAddr;
    use std::str::FromStr;

    fn create_test_context() -> RequestContext {
        RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            hyper::Uri::from_str("/test").unwrap(),
            HeaderMap::new(),
            None,
        )
    }

    #[test]
    fn test_ai_detector_disabled() {
        let config = AiConfig {
            enabled: false,
            ..Default::default()
        };

        let detector = AiThreatDetector::new(config).unwrap();
        assert!(!detector.is_enabled());
    }

    #[tokio::test]
    async fn test_ai_detector_analyze_disabled() {
        let config = AiConfig {
            enabled: false,
            ..Default::default()
        };

        let detector = AiThreatDetector::new(config).unwrap();
        let ctx = create_test_context();

        let result = detector.analyze_request(&ctx).await.unwrap();
        assert!(!result.should_block);
        assert_eq!(result.model_version, "disabled");
    }

    #[test]
    fn test_config_access() {
        let config = AiConfig {
            enabled: true,
            threat_threshold: 0.9,
            timeout_ms: 3000,
            model: crate::config::AiModelConfig {
                model_path: Some("/path/to/model".to_string()),
                anomaly_detection: true,
                advanced_classification: true,
            },
        };

        let detector = AiThreatDetector::new(config.clone()).unwrap();
        assert_eq!(detector.config().threat_threshold, 0.9);
        assert_eq!(detector.config().timeout_ms, 3000);
    }
}
