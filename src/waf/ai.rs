use std::sync::Arc;
use std::time::{Duration, Instant};

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
    pub processing_time_ms: u128,

    /// Model version used for analysis
    pub model_version: String,
}

impl Default for AiAnalysisResult {
    fn default() -> Self {
        Self {
            analysis: crate::ai_threat_detection::ThreatAnalysis {
                threat_score: 0.0,
                threat_categories: vec![],
                confidence: 0.0,
                processing_time_ms: 0,
                model_version: "disabled".to_string(),
            },
            should_block: false,
            processing_time_ms: 0,
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
        let ai_middleware = Arc::new(crate::ai_waf_integration::AiWafMiddleware::new(
            Arc::clone(&threat_detector),
            Arc::new(crate::advanced_ml_models::AdvancedThreatClassifier::new()),
            Arc::new(crate::threat_intelligence::ThreatIntelligenceEngine::new()),
            crate::ai_waf_integration::AIConfig {
                enabled: config.enabled,
                threat_threshold: config.threat_threshold,
                timeout_ms: config.timeout_ms,
                model_path: config.model.model_path.clone(),
            },
        ));

        Ok(Self {
            threat_detector,
            ai_middleware,
            config,
        })
    }

    /// Analyze a request for threats using AI
    pub async fn analyze_request(&self, ctx: &RequestContext) -> Result<AiAnalysisResult, WafError> {
        if !self.config.enabled {
            return Ok(AiAnalysisResult::default());
        }

        let start_time = Instant::now();

        // Convert WAF RequestContext to AI analysis format
        let ai_request = self.convert_to_ai_request(ctx);

        // Perform AI analysis with timeout
        let analysis_result = tokio::time::timeout(
            Duration::from_millis(self.config.timeout_ms),
            self.ai_middleware.analyze_request(&ai_request)
        ).await
        .map_err(|_| WafError::Internal("AI analysis timeout".to_string()))?
        .map_err(|e| WafError::Internal(format!("AI analysis error: {}", e)))?;

        let processing_time = start_time.elapsed().as_millis();

        // Determine if request should be blocked based on threat threshold
        let should_block = analysis_result.should_block
            && analysis_result.analysis.threat_score >= self.config.threat_threshold;

        Ok(AiAnalysisResult {
            analysis: analysis_result.analysis,
            should_block,
            processing_time_ms: processing_time,
            model_version: analysis_result.model_version,
        })
    }

    /// Convert WAF RequestContext to AI analysis format
    fn convert_to_ai_request(&self, ctx: &RequestContext) -> crate::ai_threat_detection::RequestContext {
        // Convert headers to the format expected by AI analysis
        let headers = ctx.headers.iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        crate::ai_threat_detection::RequestContext {
            client_ip: ctx.client_ip,
            method: ctx.method.as_str().to_string(),
            uri: ctx.uri.to_string(),
            headers,
            body: ctx.body.clone(),
            timestamp: ctx.timestamp,
            http_version: ctx.http_version.clone(),
        }
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
    use std::net::IpAddr;
    use hyper::{HeaderMap, Method};
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