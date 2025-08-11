// AI/ML threat detection integration for WAF middleware
// Exports AI analysis types and middleware for main WAF application

use crate::ai_threat_detection::{ThreatDetectionService, RequestContext, SecurityAction};
use crate::advanced_ml_models::{AdvancedThreatClassifier, ComprehensiveThreatAnalysis, ThreatFeedback};
use crate::threat_intelligence::{ThreatIntelligenceEngine, EnrichedThreatAnalysis};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::Result;
use hyper::{Request};
use serde_json::Value;

/// Main AI WAF middleware integrating threat detection
#[derive(Debug, Clone)]
pub struct AiWafMiddleware {
    /// AI/ML threat detection service (Phase 1)
    threat_detector: Arc<ThreatDetectionService>,
    
    /// Advanced ML models for Phase 2
    advanced_classifier: Arc<AdvancedThreatClassifier>,
    
    /// Phase 3: Threat intelligence and zero-day detection
    threat_intelligence: Arc<ThreatIntelligenceEngine>,
    
    /// Configuration for AI integration
    ai_config: AIConfig,
    
    /// Last analysis result for debugging/monitoring
    last_analysis: Arc<Mutex<Option<crate::ai_threat_detection::ThreatAnalysis>>>,
    
    /// Last comprehensive analysis (Phase 2)
    last_comprehensive_analysis: Arc<Mutex<Option<ComprehensiveThreatAnalysis>>>,
    
    /// Feedback collection for model improvement
    feedback_buffer: Arc<Mutex<Vec<ThreatFeedback>>>,
}

/// Result of AI analysis with blocking decision
#[derive(Debug, Clone)]
pub struct AiAnalysisResult {
    pub analysis: crate::ai_threat_detection::ThreatAnalysis,
    pub comprehensive_analysis: Option<ComprehensiveThreatAnalysis>,
    pub enriched_analysis: Option<EnrichedThreatAnalysis>,
    pub should_block: bool,
    pub processing_time_ms: u128,
    pub model_version: String,
}

/// Configuration for AI threat detection
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
    
    /// Whether to use advanced ML models (Phase 2)
    pub use_advanced_models: bool,
    
    /// Model update frequency (hours)
    pub model_update_frequency_hours: u64,
    
    /// Feedback collection enabled
    pub collect_feedback: bool,
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            confidence_threshold: 0.7,
            enforce_ai_decisions: false, // Start with logging only
            fallback_to_rules: true,
            max_processing_time_ms: 100, // 100ms timeout
            use_advanced_models: true,   // Enable Phase 2 models
            model_update_frequency_hours: 24,
            collect_feedback: true,
        }
    }
}

impl AiWafMiddleware {
    pub async fn new() -> Result<Self> {
        let mut threat_intelligence = ThreatIntelligenceEngine::new();
        threat_intelligence.initialize().await?;
        
        Ok(Self {
            threat_detector: Arc::new(ThreatDetectionService::new()),
            advanced_classifier: Arc::new(AdvancedThreatClassifier::new()),
            threat_intelligence: Arc::new(threat_intelligence),
            ai_config: AIConfig::default(),
            last_analysis: Arc::new(Mutex::new(None)),
            last_comprehensive_analysis: Arc::new(Mutex::new(None)),
            feedback_buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }
    
    /// Analyze a request using AI threat detection (Phase 1 + Phase 2)
    pub async fn analyze_request<T>(
        &self,
        req: &Request<T>,
        body_bytes: &[u8],
    ) -> Result<AiAnalysisResult> {
        let start_time = std::time::Instant::now();
        
        // Convert HTTP request to AI analysis context
        let request_context = self.build_request_context(req, body_bytes)?;
        
        // Phase 1: Run basic statistical AI analysis with timeout
        let phase1_result = tokio::time::timeout(
            std::time::Duration::from_millis(self.ai_config.max_processing_time_ms / 2),
            self.threat_detector.analyze_request(&request_context)
        ).await??;
        
        // Store Phase 1 analysis
        {
            let mut last = self.last_analysis.lock().unwrap();
            *last = Some(phase1_result.clone());
        }
        
        // Phase 2: Run advanced ML models if enabled and time permits
        let comprehensive_analysis = if self.ai_config.use_advanced_models {
            let remaining_time = self.ai_config.max_processing_time_ms / 2;
            match tokio::time::timeout(
                std::time::Duration::from_millis(remaining_time),
                self.run_advanced_analysis(&request_context)
            ).await {
                Ok(Ok(analysis)) => {
                    // Store Phase 2 analysis
                    {
                        let mut last = self.last_comprehensive_analysis.lock().unwrap();
                        *last = Some(analysis.clone());
                    }
                    Some(analysis)
                },
                Ok(Err(e)) => {
                    eprintln!("Advanced ML analysis failed: {}", e);
                    None
                },
                Err(_) => {
                    eprintln!("Advanced ML analysis timed out");
                    None
                },
            }
        } else {
            None
        };
        
        // Phase 3: Threat intelligence enrichment
        let enriched_analysis = if self.ai_config.enabled {
            let remaining_time = self.ai_config.max_processing_time_ms / 4;
            match tokio::time::timeout(
                std::time::Duration::from_millis(remaining_time),
                self.enrich_with_threat_intelligence(&request_context, &phase1_result)
            ).await {
                Ok(Ok(analysis)) => Some(analysis),
                Ok(Err(e)) => {
                    eprintln!("Threat intelligence enrichment failed: {}", e);
                    None
                },
                Err(_) => {
                    eprintln!("Threat intelligence enrichment timed out");
                    None
                },
            }
        } else {
            None
        };
        
        // Determine if we should block based on combined analysis
        let should_block = self.should_block_request_combined(&phase1_result, &comprehensive_analysis, &enriched_analysis);
        
        Ok(AiAnalysisResult {
            analysis: phase1_result,
            comprehensive_analysis,
            enriched_analysis,
            should_block,
            processing_time_ms: start_time.elapsed().as_millis(),
            model_version: "v3.0-phase3".to_string(),
        })
    }
    
    /// Get health status of AI system (Phase 1 + Phase 2)
    pub async fn get_health_status(&self) -> Result<Value> {
        let phase1_metrics = self.threat_detector.get_performance_metrics().unwrap_or_default();
        let phase2_metrics = self.advanced_classifier.get_performance_metrics();
        
        let status = serde_json::json!({
            "status": "healthy",
            "ai_config": {
                "enabled": self.ai_config.enabled,
                "confidence_threshold": self.ai_config.confidence_threshold,
                "enforce_decisions": self.ai_config.enforce_ai_decisions,
                "max_processing_time_ms": self.ai_config.max_processing_time_ms,
                "use_advanced_models": self.ai_config.use_advanced_models,
                "model_update_frequency_hours": self.ai_config.model_update_frequency_hours
            },
            "phase1_metrics": {
                "requests_analyzed": phase1_metrics.requests_analyzed,
                "threats_detected": phase1_metrics.threats_detected,
                "false_positive_rate": phase1_metrics.false_positive_rate,
                "average_processing_time_ms": phase1_metrics.average_processing_time_ms
            },
            "phase2_metrics": {
                "accuracy": phase2_metrics.accuracy,
                "precision": phase2_metrics.precision,
                "recall": phase2_metrics.recall,
                "f1_score": phase2_metrics.f1_score,
                "false_positive_rate": phase2_metrics.false_positive_rate,
                "false_negative_rate": phase2_metrics.false_negative_rate
            },
            "model_version": "v2.0-phase2",
            "last_check": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        });
        
        Ok(status)
    }
    
    /// Get last analysis for debugging (Phase 1)
    pub async fn get_last_analysis(&self) -> Option<crate::ai_threat_detection::ThreatAnalysis> {
        let last = self.last_analysis.lock().unwrap();
        last.clone()
    }
    
    /// Get last comprehensive analysis for debugging (Phase 2)
    pub async fn get_last_comprehensive_analysis(&self) -> Option<ComprehensiveThreatAnalysis> {
        let last = self.last_comprehensive_analysis.lock().unwrap();
        last.clone()
    }
    
    /// Run advanced ML analysis (Phase 2)
    async fn run_advanced_analysis(&self, request_context: &RequestContext) -> Result<ComprehensiveThreatAnalysis> {
        // Convert RequestContext to RequestFeatures for advanced models
        let features = self.convert_to_features(request_context)?;
        
        // Run comprehensive threat analysis
        self.advanced_classifier.analyze_threat_comprehensive(&features).await
    }
    
    /// Convert RequestContext to RequestFeatures for advanced models
    fn convert_to_features(&self, context: &RequestContext) -> Result<crate::ai_threat_detection::RequestFeatures> {
        // Extract features from the request context
        use crate::ai_threat_detection::*;
        
        // This converts our Phase 1 RequestContext to the more detailed RequestFeatures needed for Phase 2
        Ok(RequestFeatures {
            // HTTP Protocol Features
            method: context.method.clone(),
            uri_length: context.uri.len() as u32,
            header_count: context.headers.len() as u32,
            body_size: context.body.len() as u32,
            
            // Content Analysis Features
            entropy_score: calculate_entropy(&context.body),
            base64_ratio: calculate_base64_ratio(&context.body),
            sql_keywords_count: count_sql_keywords(&context.body),
            xss_keywords_count: count_xss_keywords(&context.body),
            shell_keywords_count: count_shell_keywords(&context.body),
            
            // User Agent Analysis
            user_agent_entropy: calculate_entropy(&context.headers.get("user-agent").cloned().unwrap_or_default()),
            is_known_scanner: false, // Would be implemented
            browser_automation_score: 0.0, // Would be calculated
            
            // PII/PHI Detection
            contains_credit_cards: detect_credit_cards(&context.body),
            contains_ssn: detect_ssn(&context.body),
            contains_email: detect_email(&context.body),
            contains_phone: detect_phone(&context.body),
            
            // Rate Limiting Features
            requests_per_minute: 1.0, // Would be calculated from request history
            requests_per_hour: 1.0, // Would be calculated from request history
            
            // Phase 2 Additional Fields
            client_ip: context.client_ip.clone(),
            user_agent: context.headers.get("user-agent").cloned().unwrap_or_default(),
            path: context.uri.clone(),
            query_string: context.headers.get("query-string").cloned().unwrap_or_default(),
            referer: context.headers.get("referer").cloned().unwrap_or_default(),
            content_type: context.headers.get("content-type").cloned().unwrap_or_default(),
            accept: context.headers.get("accept").cloned().unwrap_or_default(),
            is_business_hours: self.is_business_hours(context.timestamp),
            contains_pii: detect_pii(&context.body),
            geographic_score: self.estimate_geolocation_risk(&context.client_ip),
            reputation_score: 0.1, // Would be looked up from reputation database
            behavioral_score: 0.5, // Would be calculated from behavioral analysis
            seasonal_score: 0.5, // Would be calculated from seasonal patterns
            
            // Phase 3 fields
            request_id: context.request_id.clone(),
            client_ip_parsed: context.client_ip.parse().ok(),
            timestamp: context.timestamp,
            session_id: context.session_id.clone(),
            is_encrypted: context.is_https,
            contains_financial_data: detect_financial_data(&context.body),
            contains_healthcare_data: detect_healthcare_data(&context.body),
            regulatory_zone: self.determine_regulatory_zone(&context.client_ip),
            headers: context.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            request_body: context.body.clone(),
        })
    }
    
    /// Enrich analysis with threat intelligence (Phase 3)
    async fn enrich_with_threat_intelligence(
        &self,
        request_context: &RequestContext,
        base_analysis: &crate::ai_threat_detection::ThreatAnalysis,
    ) -> Result<EnrichedThreatAnalysis> {
        // Convert RequestContext to RequestFeatures for threat intelligence
        let features = self.convert_to_features(request_context)?;
        
                // Enrich the base analysis with threat intelligence
        self.threat_intelligence.enrich_threat_analysis(&features, base_analysis).await
    }
    
    /// Determine regulatory zone based on client IP
    fn determine_regulatory_zone(&self, client_ip: &str) -> String {
        // In a real implementation, this would use GeoIP databases
        // For now, return a default zone
        if client_ip.starts_with("192.168.") || client_ip.starts_with("10.") || client_ip.starts_with("127.") {
            "internal".to_string()
        } else {
            "external".to_string()
        }
    }
    
    /// Combined blocking decision using both Phase 1, Phase 2, and Phase 3 results
    fn should_block_request_combined(
        &self, 
        phase1_result: &crate::ai_threat_detection::ThreatAnalysis,
        phase2_result: &Option<ComprehensiveThreatAnalysis>,
        phase3_result: &Option<EnrichedThreatAnalysis>,
    ) -> bool {
        if !self.ai_config.enforce_ai_decisions {
            return false; // Only logging mode
        }
        
        // Phase 1 decision
        let phase1_block = self.should_block_request(phase1_result);
        
        // Phase 3 intelligence takes highest precedence for critical threats
        if let Some(phase3) = phase3_result {
            // Immediate block for active threat campaign matches
            if !phase3.threat_campaigns.is_empty() {
                for campaign in &phase3.threat_campaigns {
                    if campaign.severity >= 8 && campaign.confidence > 0.8 {
                        return true; // Block high-severity campaign matches
                    }
                }
            }
            
            // Immediate block for high-confidence IoC matches
            for ioc_match in &phase3.ioc_matches {
                if ioc_match.threat_score.score > 0.9 && ioc_match.threat_score.confidence > 0.85 {
                    return true; // Block high-confidence malicious indicators
                }
            }
            
            // Immediate block for zero-day detections
            for zero_day in &phase3.zero_day_indicators {
                if zero_day.severity >= 8 && zero_day.confidence > 0.8 {
                    return true; // Block high-confidence zero-day patterns
                }
            }
            
            // Block for critical compliance violations
            for violation in &phase3.compliance_violations {
                if matches!(violation.severity, crate::threat_intelligence::ViolationSeverity::Critical) {
                    return true; // Block critical compliance violations
                }
            }
        }
        
        // If Phase 2 is available, use its decision with higher precedence
        if let Some(phase2) = phase2_result {
            let phase2_confidence = phase2.overall_assessment.confidence;
            let phase2_score = phase2.overall_assessment.combined_threat_score;
            
            // Phase 2 decision based on advanced models
            if phase2_confidence > 0.8 && phase2_score > self.ai_config.confidence_threshold {
                match phase2.overall_assessment.recommended_action {
                    SecurityAction::Block | SecurityAction::Quarantine => return true,
                    SecurityAction::Challenge => return phase2_score > 0.8,
                    SecurityAction::Alert => return phase2_score > 0.9,
                    _ => {}
                }
            }
        }
        
        // Fallback to Phase 1 decision
        phase1_block
    }
    
    /// Estimate geolocation risk (simplified)
    fn estimate_geolocation_risk(&self, ip: &str) -> f32 {
        // Simplified geolocation risk - in practice would use GeoIP database
        if ip.starts_with("127.") || ip.starts_with("192.168.") || ip.starts_with("10.") {
            0.0 // Local/private IPs are low risk
        } else {
            0.3 // Default moderate risk for public IPs
        }
    }
    
    /// Check if current time is business hours
    fn is_business_hours(&self, timestamp: u64) -> bool {
        use std::time::{UNIX_EPOCH, Duration};
        let _datetime = UNIX_EPOCH + Duration::from_secs(timestamp);
        // Simplified: assume business hours are 9 AM to 6 PM UTC
        // In practice, would use proper timezone handling
        let hour = (timestamp % 86400) / 3600; // Hours since midnight UTC
        hour >= 9 && hour < 18
    }
    
    /// Check if current time is weekend
    fn is_weekend(&self, timestamp: u64) -> bool {
        // Simplified weekend detection - in practice would use proper date libraries
        let days_since_epoch = timestamp / 86400;
        let day_of_week = (days_since_epoch + 4) % 7; // Jan 1, 1970 was a Thursday (4)
        day_of_week == 5 || day_of_week == 6 // Saturday or Sunday
    }
    
    /// Submit feedback for model improvement
    pub async fn submit_feedback(&self, feedback: ThreatFeedback) -> Result<()> {
        if self.ai_config.collect_feedback {
            let mut buffer = self.feedback_buffer.lock().unwrap();
            buffer.push(feedback);
            
            // Process feedback when buffer is full
            if buffer.len() >= 100 {
                let feedback_batch = buffer.drain(..).collect::<Vec<_>>();
                drop(buffer); // Release lock before async operation
                
                // Update models with feedback (async)
                if let Err(e) = self.process_feedback_batch(feedback_batch).await {
                    eprintln!("Failed to process feedback batch: {}", e);
                }
            }
        }
        Ok(())
    }
    
    /// Process a batch of feedback to update models
    async fn process_feedback_batch(&self, feedback: Vec<ThreatFeedback>) -> Result<()> {
        // Update Phase 2 advanced models
        let mut classifier = Arc::try_unwrap(Arc::clone(&self.advanced_classifier))
            .map_err(|_| anyhow::anyhow!("Could not get exclusive access to classifier"))?;
        
        classifier.update_models_with_feedback(&feedback).await?;
        
        Ok(())
    }
    
    /// Build request context from HTTP request
    fn build_request_context<T>(&self, req: &Request<T>, body_bytes: &[u8]) -> Result<crate::ai_threat_detection::RequestContext> {
        let headers = req.headers().iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
            .collect();
        
        Ok(crate::ai_threat_detection::RequestContext {
            request_id: format!("req_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()),
            client_ip: "127.0.0.1".to_string(), // Would extract from headers/connection
            method: req.method().to_string(),
            uri: req.uri().to_string(),
            headers,
            body: String::from_utf8_lossy(body_bytes).to_string(),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            session_id: None, // Would extract from cookies/headers
            is_https: req.uri().scheme_str() == Some("https"),
        })
    }
    
    /// Simple blocking decision based on Phase 1 analysis
    fn should_block_request(&self, analysis: &crate::ai_threat_detection::ThreatAnalysis) -> bool {
        analysis.overall_risk_score > self.ai_config.confidence_threshold &&
        matches!(analysis.recommended_action, SecurityAction::Block)
    }
}

// Helper functions for content analysis
// Helper functions for content analysis
fn count_shell_commands(text: &str) -> u32 {
    let shell_patterns = ["sh", "bash", "cmd", "powershell", "&", "|", ";"];
    let text_lower = text.to_lowercase();
    
    shell_patterns.iter()
        .map(|&pattern| text_lower.matches(pattern).count() as u32)
        .sum()
}

fn calculate_special_chars_ratio(text: &str) -> f32 {
    let special_chars = text.chars().filter(|c| !c.is_alphanumeric() && !c.is_whitespace()).count();
    if text.is_empty() {
        0.0
    } else {
        special_chars as f32 / text.len() as f32
    }
}

fn detect_pii(text: &str) -> bool {
    let pii_patterns = [
        // Credit card patterns (simplified)
        "credit", "card", "visa", "mastercard",
        // SSN patterns (simplified) 
        "ssn", "social",
        // Email patterns
        "@",
    ];
    
    let text_lower = text.to_lowercase();
    for &pattern in &pii_patterns {
        if text_lower.contains(pattern) {
            return true;
        }
    }
    false
}

fn detect_financial_data(text: &str) -> bool {
    let financial_keywords = [
        "credit", "debit", "card", "account", "routing", "swift",
        "iban", "payment", "transaction", "balance", "withdraw"
    ];
    
    let text_lower = text.to_lowercase();
    financial_keywords.iter().any(|&keyword| text_lower.contains(keyword))
}

fn detect_healthcare_data(text: &str) -> bool {
    let healthcare_keywords = [
        "patient", "medical", "diagnosis", "prescription", "doctor",
        "hospital", "clinic", "insurance", "medicare", "medicaid"
    ];
    
    let text_lower = text.to_lowercase();
    healthcare_keywords.iter().any(|&keyword| text_lower.contains(keyword))
}

// Default implementation for performance metrics
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    pub requests_analyzed: u64,
    pub threats_detected: u64,
    pub false_positive_rate: f32,
    pub average_processing_time_ms: f32,
}

// Extension trait for ThreatDetectionService to provide performance metrics
pub trait ThreatDetectionServiceExt {
    fn get_performance_metrics(&self) -> Option<PerformanceMetrics>;
}

impl ThreatDetectionServiceExt for crate::ai_threat_detection::ThreatDetectionService {
    fn get_performance_metrics(&self) -> Option<PerformanceMetrics> {
        // In a real implementation, this would return actual metrics
        Some(PerformanceMetrics {
            requests_analyzed: 10000,
            threats_detected: 150,
            false_positive_rate: 0.02,
            average_processing_time_ms: 45.0,
        })
    }
}
