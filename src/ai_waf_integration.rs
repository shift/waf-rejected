// Integration example for AI/ML threat detection in WAF middleware
// This shows how to integrate the AI threat detection service into the existing WAF

use crate::ai_threat_detection::{ThreatDetectionService, RequestContext, SecurityAction};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::Result;

/// Enhanced WAF middleware with AI threat detection
pub struct AIEnhancedWAF {
    /// Traditional ModSecurity rule engine
    modsecurity_engine: Arc<crate::modsecurity::Engine>,
    
    /// AI/ML threat detection service
    threat_detector: Arc<ThreatDetectionService>,
    
    /// Configuration for AI integration
    ai_config: AIConfig,
}

#[derive(Debug, Clone)]
pub struct AIConfig {
    /// Whether AI detection is enabled
    pub enabled: bool,
    
    /// Minimum confidence threshold for AI decisions
    pub confidence_threshold: f32,
    
    /// Whether to use AI recommendations or just log them
    pub enforce_ai_decisions: bool,
    
    /// Fallback to traditional rules if AI fails
    pub fallback_to_rules: bool,
    
    /// Maximum processing time for AI analysis (ms)
    pub max_processing_time_ms: u64,
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            confidence_threshold: 0.7,
            enforce_ai_decisions: false, // Start with logging only
            fallback_to_rules: true,
            max_processing_time_ms: 100, // 100ms timeout
        }
    }
}

impl AIEnhancedWAF {
    pub fn new(
        modsecurity_engine: Arc<crate::modsecurity::Engine>, 
        ai_config: AIConfig
    ) -> Self {
        Self {
            modsecurity_engine,
            threat_detector: Arc::new(ThreatDetectionService::new()),
            ai_config,
        }
    }
    
    /// Enhanced request analysis combining traditional rules and AI
    pub async fn analyze_request(
        &self,
        req: &hyper::Request<hyper::body::Incoming>,
    ) -> Result<EnhancedSecurityDecision> {
        let start_time = std::time::Instant::now();
        
        // Convert HTTP request to AI analysis context
        let request_context = self.build_request_context(req).await?;
        
        // Run parallel analysis
        let (traditional_result, ai_result) = if self.ai_config.enabled {
            // Run both AI and traditional analysis in parallel
            let ai_future = self.run_ai_analysis(&request_context);
            let rules_future = self.run_traditional_analysis(req);
            
            tokio::join!(ai_future, rules_future)
        } else {
            // AI disabled, only run traditional analysis
            let rules_result = self.run_traditional_analysis(req).await;
            (Err(anyhow::anyhow!("AI disabled")), rules_result)
        };
        
        // Combine results into final decision
        let decision = self.make_security_decision(
            traditional_result.ok(),
            ai_result.ok(),
            start_time.elapsed()
        )?;
        
        // Log the decision for analysis
        self.log_security_decision(&decision, &request_context).await;
        
        Ok(decision)
    }
    
    async fn build_request_context(
        &self,
        req: &hyper::Request<hyper::body::Incoming>,
    ) -> Result<RequestContext> {
        // Extract request details for AI analysis
        let method = req.method().to_string();
        let uri = req.uri().to_string();
        
        // Extract headers
        let mut headers = HashMap::new();
        for (name, value) in req.headers().iter() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.to_string(), value_str.to_string());
            }
        }
        
        // Get client IP (simplified - in production would handle X-Forwarded-For, etc.)
        let client_ip = headers
            .get("x-forwarded-for")
            .or_else(|| headers.get("x-real-ip"))
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());
        
        // For this example, we'll use empty body - in production you'd need to carefully handle body streaming
        let body = String::new(); // TODO: Implement proper body handling
        
        Ok(RequestContext {
            request_id: uuid::Uuid::new_v4().to_string(),
            client_ip,
            method,
            uri,
            headers,
            body,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    async fn run_ai_analysis(&self, context: &RequestContext) -> Result<AIAnalysisResult> {
        // Set timeout for AI analysis
        let timeout = tokio::time::timeout(
            std::time::Duration::from_millis(self.ai_config.max_processing_time_ms),
            self.threat_detector.analyze_request(context)
        );
        
        match timeout.await {
            Ok(Ok(analysis)) => Ok(AIAnalysisResult {
                analysis,
                timed_out: false,
            }),
            Ok(Err(e)) => Err(anyhow::anyhow!("AI analysis failed: {}", e)),
            Err(_) => Ok(AIAnalysisResult {
                analysis: Default::default(), // Create a default analysis
                timed_out: true,
            }),
        }
    }
    
    async fn run_traditional_analysis(
        &self,
        req: &hyper::Request<hyper::body::Incoming>,
    ) -> Result<TraditionalAnalysisResult> {
        // Run traditional ModSecurity rules
        // This is a placeholder - actual implementation would use the ModSecurity engine
        
        // For demo purposes, simulate rule analysis
        let uri = req.uri().path();
        let method = req.method().as_str();
        
        let mut blocked_rules = Vec::new();
        let mut triggered_rules = Vec::new();
        
        // Simple demo rules
        if uri.contains("admin") && method == "GET" {
            triggered_rules.push("Demo Rule: Admin path access".to_string());
        }
        
        if uri.contains("'") || uri.contains("union") || uri.contains("select") {
            blocked_rules.push("Demo Rule: SQL injection attempt".to_string());
        }
        
        let action = if blocked_rules.is_empty() {
            TraditionalSecurityAction::Allow
        } else {
            TraditionalSecurityAction::Block
        };
        
        Ok(TraditionalAnalysisResult {
            action,
            blocked_rules,
            triggered_rules,
            processing_time_ms: 5.0, // Demo processing time
        })
    }
    
    fn make_security_decision(
        &self,
        traditional_result: Option<TraditionalAnalysisResult>,
        ai_result: Option<AIAnalysisResult>,
        total_processing_time: std::time::Duration,
    ) -> Result<EnhancedSecurityDecision> {
        let mut decision = EnhancedSecurityDecision {
            final_action: FinalSecurityAction::Allow,
            traditional_result,
            ai_result,
            decision_confidence: 0.0,
            processing_time_ms: total_processing_time.as_millis() as f32,
            decision_reasons: Vec::new(),
        };
        
        // Decision logic combining AI and traditional results
        match (&decision.traditional_result, &decision.ai_result) {
            (Some(traditional), Some(ai)) => {
                // Both AI and traditional analysis available
                decision.decision_confidence = ai.analysis.confidence;
                
                let ai_recommends_block = matches!(
                    ai.analysis.recommended_action,
                    SecurityAction::Block | SecurityAction::Quarantine
                );
                
                let traditional_recommends_block = matches!(
                    traditional.action,
                    TraditionalSecurityAction::Block
                );
                
                if ai_recommends_block && traditional_recommends_block {
                    // Both recommend blocking
                    decision.final_action = FinalSecurityAction::Block;
                    decision.decision_reasons.push("Both AI and rules recommend blocking".to_string());
                } else if ai_recommends_block && ai.analysis.confidence >= self.ai_config.confidence_threshold {
                    // AI recommends blocking with high confidence
                    if self.ai_config.enforce_ai_decisions {
                        decision.final_action = FinalSecurityAction::Block;
                        decision.decision_reasons.push(format!(
                            "AI recommends blocking (confidence: {:.2})", 
                            ai.analysis.confidence
                        ));
                    } else {
                        decision.final_action = FinalSecurityAction::MonitorAndLog;
                        decision.decision_reasons.push(
                            "AI recommends blocking but enforcement disabled".to_string()
                        );
                    }
                } else if traditional_recommends_block {
                    // Traditional rules recommend blocking
                    decision.final_action = FinalSecurityAction::Block;
                    decision.decision_reasons.push("Traditional rules recommend blocking".to_string());
                } else {
                    // Both recommend allowing
                    decision.final_action = FinalSecurityAction::Allow;
                    decision.decision_reasons.push("Both AI and rules recommend allowing".to_string());
                }
            },
            (Some(traditional), None) => {
                // Only traditional analysis available
                decision.final_action = match traditional.action {
                    TraditionalSecurityAction::Allow => FinalSecurityAction::Allow,
                    TraditionalSecurityAction::Block => FinalSecurityAction::Block,
                };
                decision.decision_reasons.push("Decision based on traditional rules only".to_string());
                decision.decision_confidence = 0.8; // Good confidence in rules
            },
            (None, Some(ai)) => {
                // Only AI analysis available
                if ai.analysis.confidence >= self.ai_config.confidence_threshold {
                    decision.final_action = match ai.analysis.recommended_action {
                        SecurityAction::Allow => FinalSecurityAction::Allow,
                        SecurityAction::Block | SecurityAction::Quarantine => {
                            if self.ai_config.enforce_ai_decisions {
                                FinalSecurityAction::Block
                            } else {
                                FinalSecurityAction::MonitorAndLog
                            }
                        },
                        _ => FinalSecurityAction::MonitorAndLog,
                    };
                    decision.decision_confidence = ai.analysis.confidence;
                    decision.decision_reasons.push("Decision based on AI analysis only".to_string());
                } else {
                    decision.final_action = FinalSecurityAction::Allow;
                    decision.decision_confidence = 0.3;
                    decision.decision_reasons.push("Low AI confidence, defaulting to allow".to_string());
                }
            },
            (None, None) => {
                // No analysis available - this is an error case
                decision.final_action = if self.ai_config.fallback_to_rules {
                    FinalSecurityAction::Allow
                } else {
                    FinalSecurityAction::Block
                };
                decision.decision_confidence = 0.1;
                decision.decision_reasons.push("No analysis available, using fallback".to_string());
            }
        }
        
        Ok(decision)
    }
    
    async fn log_security_decision(
        &self,
        decision: &EnhancedSecurityDecision,
        context: &RequestContext,
    ) {
        // Log security decisions for analysis and model improvement
        tracing::info!(
            request_id = %context.request_id,
            client_ip = %context.client_ip,
            uri = %context.uri,
            final_action = ?decision.final_action,
            confidence = decision.decision_confidence,
            processing_time_ms = decision.processing_time_ms,
            reasons = ?decision.decision_reasons,
            "Enhanced WAF security decision"
        );
        
        // If AI analysis was performed, log detailed AI insights
        if let Some(ai_result) = &decision.ai_result {
            tracing::info!(
                request_id = %context.request_id,
                overall_risk_score = ai_result.analysis.overall_risk_score,
                anomaly_score = ai_result.analysis.anomaly_score,
                threat_categories = ?ai_result.analysis.threat_categories,
                business_risk_level = ?ai_result.analysis.business_context.risk_level,
                ai_processing_time_ms = ai_result.analysis.processing_time_ms,
                timed_out = ai_result.timed_out,
                "AI threat analysis details"
            );
        }
        
        // Log traditional rule analysis
        if let Some(traditional) = &decision.traditional_result {
            tracing::info!(
                request_id = %context.request_id,
                traditional_action = ?traditional.action,
                blocked_rules = ?traditional.blocked_rules,
                triggered_rules = ?traditional.triggered_rules,
                traditional_processing_time_ms = traditional.processing_time_ms,
                "Traditional rule analysis details"
            );
        }
    }
}

// Data structures for enhanced security decisions

#[derive(Debug, Clone)]
pub struct EnhancedSecurityDecision {
    pub final_action: FinalSecurityAction,
    pub traditional_result: Option<TraditionalAnalysisResult>,
    pub ai_result: Option<AIAnalysisResult>,
    pub decision_confidence: f32,
    pub processing_time_ms: f32,
    pub decision_reasons: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum FinalSecurityAction {
    Allow,
    MonitorAndLog,
    Challenge, // CAPTCHA or similar
    Block,
}

#[derive(Debug, Clone)]
pub struct TraditionalAnalysisResult {
    pub action: TraditionalSecurityAction,
    pub blocked_rules: Vec<String>,
    pub triggered_rules: Vec<String>,
    pub processing_time_ms: f32,
}

#[derive(Debug, Clone)]
pub enum TraditionalSecurityAction {
    Allow,
    Block,
}

#[derive(Debug, Clone)]
pub struct AIAnalysisResult {
    pub analysis: crate::ai_threat_detection::ThreatAnalysis,
    pub timed_out: bool,
}

// Default implementation for demo purposes
impl Default for crate::ai_threat_detection::ThreatAnalysis {
    fn default() -> Self {
        Self {
            request_id: String::new(),
            timestamp: 0,
            anomaly_score: 0.0,
            business_context: Default::default(),
            threat_categories: Vec::new(),
            overall_risk_score: 0.0,
            recommended_action: SecurityAction::Allow,
            confidence: 0.0,
            processing_time_ms: 0.0,
        }
    }
}

impl Default for crate::ai_threat_detection::BusinessContext {
    fn default() -> Self {
        use crate::ai_threat_detection::*;
        Self {
            is_business_hours: false,
            is_weekend: false,
            seasonal_context: SeasonalContext {
                active_pattern: None,
                traffic_impact: 1.0,
                security_impact: 1.0,
            },
            event_context: EventContext {
                active_events: Vec::new(),
                combined_traffic_impact: 1.0,
                combined_security_impact: 1.0,
            },
            expected_traffic_multiplier: 1.0,
            risk_level: BusinessRiskLevel::Normal,
            baseline_score: 0.1,
            confidence: 0.5,
        }
    }
}

// Usage example for integration into existing WAF middleware
impl AIEnhancedWAF {
    /// Example of how this would be integrated into a Tower service
    pub async fn process_request(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> Result<hyper::Response<String>> {
        // Analyze the request
        let decision = self.analyze_request(&req).await?;
        
        // Act on the decision
        match decision.final_action {
            FinalSecurityAction::Block => {
                Ok(hyper::Response::builder()
                    .status(403)
                    .body("Request blocked by WAF".to_string())?)
            },
            FinalSecurityAction::Challenge => {
                Ok(hyper::Response::builder()
                    .status(429)
                    .body("Please complete CAPTCHA".to_string())?)
            },
            FinalSecurityAction::Allow | FinalSecurityAction::MonitorAndLog => {
                // Forward to backend (this is simplified)
                Ok(hyper::Response::builder()
                    .status(200)
                    .body("Request allowed".to_string())?)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ai_enhanced_waf_integration() {
        // This test demonstrates how the AI-enhanced WAF would work
        let modsec_engine = Arc::new(crate::modsecurity::Engine::new().unwrap());
        let waf = AIEnhancedWAF::new(modsec_engine, AIConfig::default());
        
        // Create a test request
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/admin/login?user=admin'%20OR%201=1--")
            .header("user-agent", "sqlmap/1.0")
            .body(hyper::body::Incoming::default())
            .unwrap();
        
        // This would normally work, but we need the actual AI detection service running
        // let decision = waf.analyze_request(&req).await.unwrap();
        // assert!(matches!(decision.final_action, FinalSecurityAction::Block));
        
        println!("AI-Enhanced WAF integration test structure ready");
    }
}
