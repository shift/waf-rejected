// AI/ML Threat Detection Service Implementation
// This is a practical starting point for neural network integration

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Core AI/ML threat detection service
#[derive(Debug, Clone)]
pub struct ThreatDetectionService {
    /// Anomaly detection engine
    anomaly_detector: Arc<AnomalyDetector>,
    
    /// Business intelligence engine for trend analysis
    business_intel: Arc<BusinessIntelligenceEngine>,
    
    /// Threat scoring engine
    threat_scorer: Arc<ThreatScoringEngine>,
    
    /// Pattern learning system
    pattern_learner: Arc<PatternLearningSystem>,
}

impl ThreatDetectionService {
    pub fn new() -> Self {
        Self {
            anomaly_detector: Arc::new(AnomalyDetector::new()),
            business_intel: Arc::new(BusinessIntelligenceEngine::new()),
            threat_scorer: Arc::new(ThreatScoringEngine::new()),
            pattern_learner: Arc::new(PatternLearningSystem::new()),
        }
    }
    
    /// Main threat analysis entry point
    pub async fn analyze_request(&self, request: &RequestContext) -> Result<ThreatAnalysis> {
        let start_time = Instant::now();
        
        // Extract features from the request
        let features = self.extract_features(request).await?;
        
        // Run parallel analysis
        let (anomaly_score, business_context, threat_categories) = tokio::try_join!(
            self.anomaly_detector.detect_anomalies(&features),
            self.business_intel.analyze_business_context(&features, request.timestamp),
            self.threat_scorer.score_threat_categories(&features)
        )?;
        
        // Combine results into comprehensive threat analysis
        let mut analysis = ThreatAnalysis {
            request_id: request.request_id.clone(),
            timestamp: request.timestamp,
            anomaly_score,
            business_context,
            threat_categories,
            overall_risk_score: 0.0,
            recommended_action: SecurityAction::Allow,
            confidence: 0.0,
            processing_time_ms: start_time.elapsed().as_millis() as f32,
        };
        
        // Calculate overall risk and recommendation
        analysis.overall_risk_score = self.calculate_overall_risk(&analysis);
        analysis.recommended_action = self.recommend_action(&analysis);
        analysis.confidence = self.calculate_confidence(&analysis);
        
        // Learn from this interaction (async)
        self.pattern_learner.learn_from_interaction(&analysis).await;
        
        Ok(analysis)
    }
    
    /// Extract ML features from request
    async fn extract_features(&self, request: &RequestContext) -> Result<RequestFeatures> {
        let mut features = RequestFeatures::default();
        
        // Basic HTTP features
        features.method = request.method.clone();
        features.uri_length = request.uri.len() as u32;
        features.header_count = request.headers.len() as u32;
        features.body_size = request.body.len() as u32;
        
        // Content analysis
        features.entropy_score = calculate_entropy(&request.body);
        features.base64_ratio = calculate_base64_ratio(&request.body);
        features.sql_keywords_count = count_sql_keywords(&request.body);
        features.xss_keywords_count = count_xss_keywords(&request.body);
        features.shell_keywords_count = count_shell_keywords(&request.body);
        
        // User agent analysis  
        if let Some(ua) = request.headers.get("user-agent") {
            features.user_agent_entropy = calculate_entropy(ua);
            features.is_known_scanner = is_known_scanner_ua(ua);
            features.browser_automation_score = detect_automation_ua(ua);
            features.user_agent = ua.clone();
        }
        
        // PII/PHI detection
        let full_content = format!("{} {} {}", request.uri, request.headers_string(), request.body);
        features.contains_credit_cards = detect_credit_cards(&full_content);
        features.contains_ssn = detect_ssn(&full_content);
        features.contains_email = detect_email(&full_content);
        features.contains_phone = detect_phone(&full_content);
        features.contains_pii = features.contains_credit_cards || features.contains_ssn || features.contains_email || features.contains_phone;
        
        // Rate limiting features
        features.requests_per_minute = self.get_request_rate(&request.client_ip, Duration::from_secs(60));
        features.requests_per_hour = self.get_request_rate(&request.client_ip, Duration::from_secs(3600));
        
        // Phase 2 additional fields
        features.client_ip = request.client_ip.clone();
        features.path = request.uri.clone();
        features.query_string = request.headers.get("query-string").unwrap_or(&String::new()).clone();
        features.referer = request.headers.get("referer").unwrap_or(&String::new()).clone();
        features.content_type = request.headers.get("content-type").unwrap_or(&String::new()).clone();
        features.accept = request.headers.get("accept").unwrap_or(&String::new()).clone();
        
        // Business context
        let now = std::time::SystemTime::now();
        features.is_business_hours = self.is_business_hours(now);
        
        // Reputation and behavioral scoring (placeholder values)
        features.geographic_score = 0.5; // TODO: Implement geo-scoring
        features.reputation_score = 0.5; // TODO: Implement IP reputation
        features.behavioral_score = 0.5; // TODO: Implement behavioral analysis
        features.seasonal_score = 0.5; // TODO: Implement seasonal analysis
        
        Ok(features)
    }
    
    /// Calculate overall risk score using weighted ensemble
    fn calculate_overall_risk(&self, analysis: &ThreatAnalysis) -> f32 {
        let mut weighted_score = 0.0;
        let mut total_weight = 0.0;
        
        // Anomaly detection weight (30%)
        let anomaly_weight = 0.3;
        weighted_score += analysis.anomaly_score * anomaly_weight;
        total_weight += anomaly_weight;
        
        // Individual threat category weights (60%)
        for category in &analysis.threat_categories {
            let weight = match category.category.as_str() {
                "sql_injection" => 0.15,
                "xss" => 0.12,
                "rce" => 0.18,
                "data_exfiltration" => 0.20,
                "compliance_violation" => 0.10,
                _ => 0.05,
            };
            weighted_score += category.score * weight;
            total_weight += weight;
        }
        
        // Business context adjustment (10%)
        let business_weight = 0.1;
        let business_multiplier = match analysis.business_context.risk_level {
            BusinessRiskLevel::Low => 0.8,
            BusinessRiskLevel::Normal => 1.0,
            BusinessRiskLevel::High => 1.3,
            BusinessRiskLevel::Critical => 1.5,
        };
        weighted_score += analysis.business_context.baseline_score * business_multiplier * business_weight;
        total_weight += business_weight;
        
        (weighted_score / total_weight).min(1.0)
    }
    
    /// Recommend security action based on risk analysis
    fn recommend_action(&self, analysis: &ThreatAnalysis) -> SecurityAction {
        let risk_score = analysis.overall_risk_score;
        let confidence = self.calculate_confidence(analysis);
        
        match (risk_score, confidence) {
            (score, conf) if score >= 0.9 && conf >= 0.8 => SecurityAction::Block,
            (score, conf) if score >= 0.8 && conf >= 0.7 => SecurityAction::Quarantine,
            (score, conf) if score >= 0.7 && conf >= 0.6 => SecurityAction::Challenge,
            (score, _) if score >= 0.5 => SecurityAction::Monitor,
            (score, _) if score >= 0.3 => SecurityAction::Log,
            _ => SecurityAction::Allow,
        }
    }
    
    /// Calculate confidence in the analysis
    fn calculate_confidence(&self, analysis: &ThreatAnalysis) -> f32 {
        let mut confidence_factors = Vec::new();
        
        // Anomaly detection confidence
        confidence_factors.push(self.anomaly_detector.get_confidence(analysis.anomaly_score));
        
        // Threat category confidence (average)
        if !analysis.threat_categories.is_empty() {
            let avg_threat_confidence: f32 = analysis.threat_categories
                .iter()
                .map(|t| t.confidence)
                .sum::<f32>() / analysis.threat_categories.len() as f32;
            confidence_factors.push(avg_threat_confidence);
        }
        
        // Business context confidence
        confidence_factors.push(analysis.business_context.confidence);
        
        // Processing time confidence (faster is more confident for real-time decisions)
        let processing_confidence = if analysis.processing_time_ms < 10.0 {
            1.0
        } else if analysis.processing_time_ms < 50.0 {
            0.8
        } else {
            0.6
        };
        confidence_factors.push(processing_confidence);
        
        // Return average confidence
        confidence_factors.iter().sum::<f32>() / confidence_factors.len() as f32
    }
    
    fn get_request_rate(&self, _ip: &str, _window: Duration) -> f32 {
        // Implementation would track request rates per IP
        // For now, return mock data
        1.5
    }
    
    fn is_business_hours(&self, timestamp: std::time::SystemTime) -> bool {
        // Convert to seconds since epoch
        let duration = timestamp.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let timestamp_secs = duration.as_secs();
        
        // Simplified business hours check (9 AM - 6 PM UTC)
        let hour = ((timestamp_secs % 86400) / 3600) as u8;
        hour >= 9 && hour < 18
    }
}

/// Anomaly detection using statistical methods and simple neural network patterns
#[derive(Debug)]
pub struct AnomalyDetector {
    /// Historical feature baselines
    feature_baselines: Arc<Mutex<HashMap<String, FeatureBaseline>>>,
    
    /// Sliding window for recent observations
    recent_observations: Arc<Mutex<VecDeque<RequestFeatures>>>,
    
    /// Anomaly thresholds
    thresholds: AnomalyThresholds,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            feature_baselines: Arc::new(Mutex::new(HashMap::new())),
            recent_observations: Arc::new(Mutex::new(VecDeque::new())),
            thresholds: AnomalyThresholds::default(),
        }
    }
    
    /// Detect anomalies in request features
    pub async fn detect_anomalies(&self, features: &RequestFeatures) -> Result<f32> {
        let mut anomaly_scores = Vec::new();
        
        // Statistical anomaly detection
        let statistical_score = self.detect_statistical_anomalies(features).await?;
        anomaly_scores.push(("statistical", statistical_score, 0.4));
        
        // Pattern-based anomaly detection
        let pattern_score = self.detect_pattern_anomalies(features).await?;
        anomaly_scores.push(("pattern", pattern_score, 0.3));
        
        // Frequency-based anomaly detection
        let frequency_score = self.detect_frequency_anomalies(features).await?;
        anomaly_scores.push(("frequency", frequency_score, 0.3));
        
        // Weighted ensemble of anomaly scores
        let total_score: f32 = anomaly_scores
            .iter()
            .map(|(_, score, weight)| score * weight)
            .sum();
        
        // Update learning baselines
        self.update_baselines(features).await;
        
        Ok(total_score.min(1.0))
    }
    
    async fn detect_statistical_anomalies(&self, features: &RequestFeatures) -> Result<f32> {
        let baselines = self.feature_baselines.lock().unwrap();
        let mut anomaly_score: f32 = 0.0;
        
        // Check URI length anomaly
        if let Some(baseline) = baselines.get("uri_length") {
            let z_score = (features.uri_length as f32 - baseline.mean) / baseline.std_dev;
            if z_score.abs() > 3.0 {
                anomaly_score += 0.3;
            } else if z_score.abs() > 2.0 {
                anomaly_score += 0.15;
            }
        }
        
        // Check entropy anomaly
        if let Some(baseline) = baselines.get("entropy_score") {
            let z_score = (features.entropy_score - baseline.mean) / baseline.std_dev;
            if z_score.abs() > 3.0 {
                anomaly_score += 0.25;
            } else if z_score.abs() > 2.0 {
                anomaly_score += 0.12;
            }
        }
        
        // Check request rate anomaly
        if let Some(baseline) = baselines.get("requests_per_minute") {
            let z_score = (features.requests_per_minute - baseline.mean) / baseline.std_dev;
            if z_score > 4.0 {
                anomaly_score += 0.4; // High request rate is suspicious
            } else if z_score > 2.0 {
                anomaly_score += 0.2;
            }
        }
        
        Ok(anomaly_score.min(1.0))
    }
    
    async fn detect_pattern_anomalies(&self, features: &RequestFeatures) -> Result<f32> {
        let mut anomaly_score: f32 = 0.0;
        
        // Suspicious keyword combinations
        if features.sql_keywords_count > 5 && features.base64_ratio > 0.3 {
            anomaly_score += 0.6; // Likely SQL injection attempt
        }
        
        if features.xss_keywords_count > 3 && features.entropy_score > 0.8 {
            anomaly_score += 0.5; // Likely XSS attempt
        }
        
        if features.shell_keywords_count > 2 && features.entropy_score > 0.7 {
            anomaly_score += 0.7; // Likely RCE attempt
        }
        
        // Suspicious user agent patterns
        if features.is_known_scanner {
            anomaly_score += 0.8;
        }
        
        if features.browser_automation_score > 0.8 {
            anomaly_score += 0.4; // Automated tools
        }
        
        Ok(anomaly_score.min(1.0))
    }
    
    async fn detect_frequency_anomalies(&self, features: &RequestFeatures) -> Result<f32> {
        let mut anomaly_score: f32 = 0.0;
        
        // High frequency requests
        if features.requests_per_minute > 100.0 {
            anomaly_score += 0.6;
        } else if features.requests_per_minute > 50.0 {
            anomaly_score += 0.3;
        }
        
        if features.requests_per_hour > 1000.0 {
            anomaly_score += 0.4;
        }
        
        Ok(anomaly_score.min(1.0))
    }
    
    async fn update_baselines(&self, features: &RequestFeatures) {
        let mut baselines = self.feature_baselines.lock().unwrap();
        let mut observations = self.recent_observations.lock().unwrap();
        
        // Add to sliding window
        observations.push_back(features.clone());
        if observations.len() > 10000 {
            observations.pop_front();
        }
        
        // Update baselines if we have enough data
        if observations.len() >= 100 {
            self.calculate_baselines(&observations, &mut baselines);
        }
    }
    
    fn calculate_baselines(&self, observations: &VecDeque<RequestFeatures>, baselines: &mut HashMap<String, FeatureBaseline>) {
        // Calculate URI length baseline
        let uri_lengths: Vec<f32> = observations.iter().map(|f| f.uri_length as f32).collect();
        baselines.insert("uri_length".to_string(), FeatureBaseline::from_values(&uri_lengths));
        
        // Calculate entropy baseline
        let entropies: Vec<f32> = observations.iter().map(|f| f.entropy_score).collect();
        baselines.insert("entropy_score".to_string(), FeatureBaseline::from_values(&entropies));
        
        // Calculate request rate baselines
        let rates: Vec<f32> = observations.iter().map(|f| f.requests_per_minute).collect();
        baselines.insert("requests_per_minute".to_string(), FeatureBaseline::from_values(&rates));
    }
    
    pub fn get_confidence(&self, anomaly_score: f32) -> f32 {
        // Higher anomaly scores are more confident if they're extreme
        if anomaly_score > 0.8 {
            0.9
        } else if anomaly_score > 0.6 {
            0.8
        } else if anomaly_score > 0.4 {
            0.7
        } else if anomaly_score < 0.1 {
            0.9 // Very confident it's normal
        } else {
            0.6 // Uncertain middle ground
        }
    }
}

/// Business intelligence engine for contextual analysis
#[derive(Debug)]
pub struct BusinessIntelligenceEngine {
    /// Seasonal pattern recognition
    seasonal_patterns: Arc<Mutex<HashMap<String, SeasonalPattern>>>,
    
    /// Business event calendar
    event_calendar: Arc<Mutex<Vec<BusinessEvent>>>,
    
    /// Traffic pattern baselines
    traffic_baselines: Arc<Mutex<HashMap<String, f32>>>,
}

impl BusinessIntelligenceEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            seasonal_patterns: Arc::new(Mutex::new(HashMap::new())),
            event_calendar: Arc::new(Mutex::new(Vec::new())),
            traffic_baselines: Arc::new(Mutex::new(HashMap::new())),
        };
        
        engine.initialize_default_patterns();
        engine
    }
    
    pub async fn analyze_business_context(&self, features: &RequestFeatures, timestamp: u64) -> Result<BusinessContext> {
        let _datetime = UNIX_EPOCH + Duration::from_secs(timestamp);
        
        // Detect current business context
        let is_business_hours = self.is_business_hours(timestamp);
        let is_weekend = self.is_weekend(timestamp);
        let seasonal_context = self.get_seasonal_context(timestamp).await;
        let event_context = self.get_event_context(timestamp).await;
        
        // Calculate expected traffic multiplier
        let traffic_multiplier = self.calculate_expected_traffic_multiplier(
            &seasonal_context, 
            &event_context, 
            is_business_hours, 
            is_weekend
        );
        
        // Assess risk level based on context
        let risk_level = self.assess_business_risk_level(
            features,
            &seasonal_context,
            &event_context,
            traffic_multiplier
        );
        
        Ok(BusinessContext {
            is_business_hours,
            is_weekend,
            seasonal_context,
            event_context,
            expected_traffic_multiplier: traffic_multiplier,
            risk_level,
            baseline_score: self.calculate_baseline_score(features, traffic_multiplier),
            confidence: 0.8, // High confidence in business logic
        })
    }
    
    fn initialize_default_patterns(&mut self) {
        // Initialize common seasonal patterns
        let mut patterns = self.seasonal_patterns.lock().unwrap();
        
        // Black Friday / Cyber Monday
        patterns.insert("black_friday".to_string(), SeasonalPattern {
            name: "Black Friday Week".to_string(),
            start_date: "11-23".to_string(), // Approximate
            end_date: "11-30".to_string(),
            traffic_multiplier: 5.0,
            attack_multiplier: 2.0,
            pattern_type: SeasonalPatternType::Shopping,
        });
        
        // Christmas Holiday Season
        patterns.insert("christmas".to_string(), SeasonalPattern {
            name: "Christmas Season".to_string(),
            start_date: "12-01".to_string(),
            end_date: "12-25".to_string(),
            traffic_multiplier: 3.0,
            attack_multiplier: 1.5,
            pattern_type: SeasonalPatternType::Shopping,
        });
        
        // Back to School
        patterns.insert("back_to_school".to_string(), SeasonalPattern {
            name: "Back to School".to_string(),
            start_date: "08-15".to_string(),
            end_date: "09-15".to_string(),
            traffic_multiplier: 2.0,
            attack_multiplier: 1.2,
            pattern_type: SeasonalPatternType::Education,
        });
        
        // Tax Season
        patterns.insert("tax_season".to_string(), SeasonalPattern {
            name: "Tax Season".to_string(),
            start_date: "02-01".to_string(),
            end_date: "04-15".to_string(),
            traffic_multiplier: 1.8,
            attack_multiplier: 2.5, // Higher attacks on financial sites
            pattern_type: SeasonalPatternType::Financial,
        });
    }
    
    fn is_business_hours(&self, timestamp: u64) -> bool {
        // Simplified business hours check (9 AM - 6 PM UTC)
        let hour = ((timestamp % 86400) / 3600) as u8;
        hour >= 9 && hour < 18
    }
    
    fn is_weekend(&self, timestamp: u64) -> bool {
        // Simplified weekend check
        let days_since_epoch = timestamp / 86400;
        let day_of_week = (days_since_epoch + 4) % 7; // Thursday = 0
        day_of_week == 5 || day_of_week == 6 // Saturday, Sunday
    }
    
    async fn get_seasonal_context(&self, timestamp: u64) -> SeasonalContext {
        let patterns = self.seasonal_patterns.lock().unwrap();
        
        // Get current date (MM-DD format)
        let current_date = self.timestamp_to_mmdd(timestamp);
        
        for pattern in patterns.values() {
            if self.is_date_in_range(&current_date, &pattern.start_date, &pattern.end_date) {
                return SeasonalContext {
                    active_pattern: Some(pattern.clone()),
                    traffic_impact: pattern.traffic_multiplier,
                    security_impact: pattern.attack_multiplier,
                };
            }
        }
        
        SeasonalContext {
            active_pattern: None,
            traffic_impact: 1.0,
            security_impact: 1.0,
        }
    }
    
    async fn get_event_context(&self, timestamp: u64) -> EventContext {
        let events = self.event_calendar.lock().unwrap();
        
        // Find active events
        let active_events: Vec<BusinessEvent> = events
            .iter()
            .filter(|event| timestamp >= event.start_time && timestamp <= event.end_time)
            .cloned()
            .collect();
        
        if active_events.is_empty() {
            return EventContext {
                active_events: Vec::new(),
                combined_traffic_impact: 1.0,
                combined_security_impact: 1.0,
            };
        }
        
        // Calculate combined impact
        let traffic_impact: f32 = active_events.iter().map(|e| e.traffic_multiplier).product();
        let security_impact: f32 = active_events.iter().map(|e| e.security_multiplier).product();
        
        EventContext {
            active_events,
            combined_traffic_impact: traffic_impact,
            combined_security_impact: security_impact,
        }
    }
    
    fn calculate_expected_traffic_multiplier(
        &self,
        seasonal: &SeasonalContext,
        event: &EventContext,
        is_business_hours: bool,
        is_weekend: bool,
    ) -> f32 {
        let mut multiplier = 1.0;
        
        // Seasonal adjustment
        multiplier *= seasonal.traffic_impact;
        
        // Event adjustment
        multiplier *= event.combined_traffic_impact;
        
        // Business hours adjustment
        if is_business_hours {
            multiplier *= 1.5;
        } else {
            multiplier *= 0.6;
        }
        
        // Weekend adjustment
        if is_weekend {
            multiplier *= 0.8; // Generally less traffic on weekends
        }
        
        multiplier
    }
    
    fn assess_business_risk_level(
        &self,
        features: &RequestFeatures,
        seasonal: &SeasonalContext,
        event: &EventContext,
        traffic_multiplier: f32,
    ) -> BusinessRiskLevel {
        let mut risk_factors = 0;
        
        // High traffic periods increase risk
        if traffic_multiplier > 3.0 {
            risk_factors += 2;
        } else if traffic_multiplier > 2.0 {
            risk_factors += 1;
        }
        
        // Seasonal security impact
        if seasonal.security_impact > 2.0 {
            risk_factors += 2;
        } else if seasonal.security_impact > 1.5 {
            risk_factors += 1;
        }
        
        // Event security impact
        if event.combined_security_impact > 1.5 {
            risk_factors += 1;
        }
        
        // Request characteristics
        if features.requests_per_minute > 100.0 {
            risk_factors += 1;
        }
        
        if features.contains_credit_cards || features.contains_ssn {
            risk_factors += 2; // PII increases risk
        }
        
        match risk_factors {
            0..=1 => BusinessRiskLevel::Low,
            2..=3 => BusinessRiskLevel::Normal,
            4..=5 => BusinessRiskLevel::High,
            _ => BusinessRiskLevel::Critical,
        }
    }
    
    fn calculate_baseline_score(&self, features: &RequestFeatures, traffic_multiplier: f32) -> f32 {
        // Baseline score based on expected behavior during this business context
        let mut baseline: f32 = 0.1; // Low baseline risk
        
        // Adjust for traffic patterns
        if traffic_multiplier > 2.0 {
            baseline += 0.1; // Higher baseline during high traffic
        }
        
        // Adjust for PII presence
        if features.contains_credit_cards || features.contains_ssn || features.contains_email {
            baseline += 0.2; // Higher baseline for PII-containing requests
        }
        
        baseline.min(1.0)
    }
    
    // Helper methods
    fn timestamp_to_mmdd(&self, timestamp: u64) -> String {
        // Simplified conversion to MM-DD format
        let days_since_epoch = timestamp / 86400;
        let day_of_year = (days_since_epoch % 365) as u32;
        
        // Very simplified - assumes non-leap year
        let (month, day) = match day_of_year {
            0..=30 => (1, day_of_year + 1),
            31..=58 => (2, day_of_year - 30),
            59..=89 => (3, day_of_year - 58),
            90..=119 => (4, day_of_year - 89),
            120..=150 => (5, day_of_year - 119),
            151..=180 => (6, day_of_year - 150),
            181..=211 => (7, day_of_year - 180),
            212..=242 => (8, day_of_year - 211),
            243..=272 => (9, day_of_year - 242),
            273..=303 => (10, day_of_year - 272),
            304..=333 => (11, day_of_year - 303),
            _ => (12, day_of_year - 333),
        };
        
        format!("{:02}-{:02}", month, day)
    }
    
    fn is_date_in_range(&self, current: &str, start: &str, end: &str) -> bool {
        // Simplified date range check
        current >= start && current <= end
    }
}

/// Threat scoring engine for specific attack categories
#[derive(Debug)]
pub struct ThreatScoringEngine {
    /// Category-specific scoring models
    category_scorers: HashMap<String, Box<dyn CategoryScorer + Send + Sync>>,
}

impl ThreatScoringEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            category_scorers: HashMap::new(),
        };
        
        // Initialize category-specific scorers
        engine.category_scorers.insert("sql_injection".to_string(), Box::new(SQLInjectionScorer::new()));
        engine.category_scorers.insert("xss".to_string(), Box::new(XSSScorer::new()));
        engine.category_scorers.insert("rce".to_string(), Box::new(RCEScorer::new()));
        engine.category_scorers.insert("data_exfiltration".to_string(), Box::new(DataExfiltrationScorer::new()));
        engine.category_scorers.insert("compliance_violation".to_string(), Box::new(ComplianceScorer::new()));
        
        engine
    }
    
    pub async fn score_threat_categories(&self, features: &RequestFeatures) -> Result<Vec<ThreatCategory>> {
        let mut categories = Vec::new();
        
        // Score each threat category
        for (category_name, scorer) in &self.category_scorers {
            let score = scorer.score(features).await?;
            let confidence = scorer.confidence(features).await?;
            
            if score > 0.1 { // Only include categories with meaningful scores
                categories.push(ThreatCategory {
                    category: category_name.clone(),
                    score,
                    confidence,
                    indicators: scorer.get_indicators(features).await,
                });
            }
        }
        
        // Sort by score descending
        categories.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        
        Ok(categories)
    }
}

/// Pattern learning system for continuous improvement
#[derive(Debug)]
pub struct PatternLearningSystem {
    /// Learning buffer for pattern recognition
    learning_buffer: Arc<Mutex<VecDeque<ThreatAnalysis>>>,
    
    /// Learned patterns
    learned_patterns: Arc<Mutex<HashMap<String, LearnedPattern>>>,
}

impl PatternLearningSystem {
    pub fn new() -> Self {
        Self {
            learning_buffer: Arc::new(Mutex::new(VecDeque::new())),
            learned_patterns: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    pub async fn learn_from_interaction(&self, analysis: &ThreatAnalysis) {
        let mut buffer = self.learning_buffer.lock().unwrap();
        
        // Add to learning buffer
        buffer.push_back(analysis.clone());
        
        // Keep buffer size manageable
        if buffer.len() > 100000 {
            buffer.pop_front();
        }
        
        // Trigger pattern learning if buffer is large enough
        if buffer.len() % 1000 == 0 {
            // Async pattern learning
            let buffer_snapshot: Vec<ThreatAnalysis> = buffer.iter().cloned().collect();
            let patterns = self.learned_patterns.clone();
            
            tokio::spawn(async move {
                Self::update_learned_patterns(buffer_snapshot, patterns).await;
            });
        }
    }
    
    async fn update_learned_patterns(
        interactions: Vec<ThreatAnalysis>,
        patterns: Arc<Mutex<HashMap<String, LearnedPattern>>>,
    ) {
        // Analyze patterns in the interactions
        let mut new_patterns = HashMap::new();
        
        // Example: Learn IP reputation patterns
        let mut ip_reputation = HashMap::new();
        for interaction in &interactions {
            // This would need the actual IP from request context
            // For now, just demonstrate the pattern
            if interaction.overall_risk_score > 0.8 {
                let key = format!("high_risk_pattern_{}", interaction.threat_categories.len());
                *ip_reputation.entry(key).or_insert(0) += 1;
            }
        }
        
        // Create learned patterns
        for (pattern_key, count) in ip_reputation {
            if count > 10 { // Only patterns with sufficient evidence
                new_patterns.insert(pattern_key.clone(), LearnedPattern {
                    pattern_type: "risk_correlation".to_string(),
                    pattern_key,
                    confidence: (count as f32 / interactions.len() as f32).min(1.0),
                    evidence_count: count,
                    last_updated: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                });
            }
        }
        
        // Update global patterns
        let mut global_patterns = patterns.lock().unwrap();
        for (key, pattern) in new_patterns {
            global_patterns.insert(key, pattern);
        }
    }
}

// Data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: String,
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub timestamp: u64,
    pub session_id: Option<String>,
    pub is_https: bool,
}

impl RequestContext {
    pub fn headers_string(&self) -> String {
        self.headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestFeatures {
    // HTTP Protocol Features
    pub method: String,
    pub uri_length: u32,
    pub header_count: u32,
    pub body_size: u32,
    
    // Content Analysis Features
    pub entropy_score: f32,
    pub base64_ratio: f32,
    pub sql_keywords_count: u32,
    pub xss_keywords_count: u32,
    pub shell_keywords_count: u32,
    
    // User Agent Analysis
    pub user_agent_entropy: f32,
    pub is_known_scanner: bool,
    pub browser_automation_score: f32,
    
    // PII/PHI Detection
    pub contains_credit_cards: bool,
    pub contains_ssn: bool,
    pub contains_email: bool,
    pub contains_phone: bool,
    
    // Rate Limiting Features
    pub requests_per_minute: f32,
    pub requests_per_hour: f32,
    
    // Phase 2 Additional Fields
    pub client_ip: String,
    pub user_agent: String,
    pub path: String,
    pub query_string: String,
    pub referer: String,
    pub content_type: String,
    pub accept: String,
    pub is_business_hours: bool,
    pub contains_pii: bool,
    pub geographic_score: f32,
    pub reputation_score: f32,
    pub behavioral_score: f32,
    pub seasonal_score: f32,
    
    // Phase 3: Threat Intelligence fields
    pub request_id: String,
    pub client_ip_parsed: Option<std::net::IpAddr>,
    pub timestamp: u64,
    pub session_id: Option<String>,
    pub is_encrypted: bool,
    pub contains_financial_data: bool,
    pub contains_healthcare_data: bool,
    pub regulatory_zone: String,
    pub headers: Vec<(String, String)>,
    pub request_body: String,
}

impl Default for RequestFeatures {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            uri_length: 0,
            header_count: 0,
            body_size: 0,
            entropy_score: 0.0,
            base64_ratio: 0.0,
            sql_keywords_count: 0,
            xss_keywords_count: 0,
            shell_keywords_count: 0,
            user_agent_entropy: 0.0,
            is_known_scanner: false,
            browser_automation_score: 0.0,
            contains_credit_cards: false,
            contains_ssn: false,
            contains_email: false,
            contains_phone: false,
            requests_per_minute: 0.0,
            requests_per_hour: 0.0,
            client_ip: "0.0.0.0".to_string(),
            user_agent: "unknown".to_string(),
            path: "/".to_string(),
            query_string: "".to_string(),
            referer: "".to_string(),
            content_type: "".to_string(),
            accept: "".to_string(),
            is_business_hours: false,
            contains_pii: false,
            geographic_score: 0.0,
            reputation_score: 0.0,
            behavioral_score: 0.0,
            seasonal_score: 0.0,
            request_id: "default".to_string(),
            client_ip_parsed: None,
            timestamp: 0,
            session_id: None,
            is_encrypted: false,
            contains_financial_data: false,
            contains_healthcare_data: false,
            regulatory_zone: "unknown".to_string(),
            headers: Vec::new(),
            request_body: "".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAnalysis {
    pub request_id: String,
    pub timestamp: u64,
    pub anomaly_score: f32,
    pub business_context: BusinessContext,
    pub threat_categories: Vec<ThreatCategory>,
    pub overall_risk_score: f32,
    pub recommended_action: SecurityAction,
    pub confidence: f32,
    pub processing_time_ms: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessContext {
    pub is_business_hours: bool,
    pub is_weekend: bool,
    pub seasonal_context: SeasonalContext,
    pub event_context: EventContext,
    pub expected_traffic_multiplier: f32,
    pub risk_level: BusinessRiskLevel,
    pub baseline_score: f32,
    pub confidence: f32,
}

impl Default for BusinessContext {
    fn default() -> Self {
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
            baseline_score: 0.5,
            confidence: 0.8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCategory {
    pub category: String,
    pub score: f32,
    pub confidence: f32,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityAction {
    Allow,
    Log,
    Monitor,
    Challenge,
    Quarantine,
    Block,
    Alert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusinessRiskLevel {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalContext {
    pub active_pattern: Option<SeasonalPattern>,
    pub traffic_impact: f32,
    pub security_impact: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventContext {
    pub active_events: Vec<BusinessEvent>,
    pub combined_traffic_impact: f32,
    pub combined_security_impact: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalPattern {
    pub name: String,
    pub start_date: String,
    pub end_date: String,
    pub traffic_multiplier: f32,
    pub attack_multiplier: f32,
    pub pattern_type: SeasonalPatternType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeasonalPatternType {
    Shopping,
    Education,
    Financial,
    Healthcare,
    Entertainment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessEvent {
    pub name: String,
    pub start_time: u64,
    pub end_time: u64,
    pub traffic_multiplier: f32,
    pub security_multiplier: f32,
    pub event_type: BusinessEventType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusinessEventType {
    ProductLaunch,
    MarketingCampaign,
    SaleEvent,
    MaintenanceWindow,
    SecurityIncident,
}

#[derive(Debug)]
pub struct FeatureBaseline {
    pub mean: f32,
    pub std_dev: f32,
    pub min: f32,
    pub max: f32,
    pub count: usize,
}

impl FeatureBaseline {
    pub fn from_values(values: &[f32]) -> Self {
        let count = values.len();
        let mean = values.iter().sum::<f32>() / count as f32;
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f32>() / count as f32;
        let std_dev = variance.sqrt();
        let min = values.iter().fold(f32::INFINITY, |a, &b| a.min(b));
        let max = values.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b));
        
        Self { mean, std_dev, min, max, count }
    }
}

#[derive(Debug)]
pub struct AnomalyThresholds {
    pub statistical_threshold: f32,
    pub pattern_threshold: f32,
    pub frequency_threshold: f32,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            statistical_threshold: 0.7,
            pattern_threshold: 0.6,
            frequency_threshold: 0.8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedPattern {
    pub pattern_type: String,
    pub pattern_key: String,
    pub confidence: f32,
    pub evidence_count: usize,
    pub last_updated: u64,
}

// Trait for category-specific scorers
#[async_trait::async_trait]
pub trait CategoryScorer: std::fmt::Debug {
    async fn score(&self, features: &RequestFeatures) -> Result<f32>;
    async fn confidence(&self, features: &RequestFeatures) -> Result<f32>;
    async fn get_indicators(&self, features: &RequestFeatures) -> Vec<String>;
}

// Example implementations of category scorers
#[derive(Debug)]
pub struct SQLInjectionScorer;

impl SQLInjectionScorer {
    pub fn new() -> Self { Self }
}

#[async_trait::async_trait]
impl CategoryScorer for SQLInjectionScorer {
    async fn score(&self, features: &RequestFeatures) -> Result<f32> {
        let mut score = 0.0;
        
        // SQL keyword presence
        if features.sql_keywords_count > 0 {
            score += (features.sql_keywords_count as f32 * 0.1).min(0.6);
        }
        
        // Base64 encoding (common in SQLi)
        if features.base64_ratio > 0.2 {
            score += features.base64_ratio * 0.3;
        }
        
        // High entropy (obfuscated payloads)
        if features.entropy_score > 0.7 {
            score += (features.entropy_score - 0.7) * 0.5;
        }
        
        Ok(score.min(1.0))
    }
    
    async fn confidence(&self, features: &RequestFeatures) -> Result<f32> {
        // Higher confidence with more SQL indicators
        let indicator_count = features.sql_keywords_count + 
                            if features.base64_ratio > 0.2 { 1 } else { 0 } +
                            if features.entropy_score > 0.7 { 1 } else { 0 };
        
        match indicator_count {
            0 => Ok(0.1),
            1 => Ok(0.6),
            2 => Ok(0.8),
            _ => Ok(0.9),
        }
    }
    
    async fn get_indicators(&self, features: &RequestFeatures) -> Vec<String> {
        let mut indicators = Vec::new();
        
        if features.sql_keywords_count > 0 {
            indicators.push(format!("SQL keywords detected: {}", features.sql_keywords_count));
        }
        if features.base64_ratio > 0.2 {
            indicators.push(format!("Base64 encoding ratio: {:.2}", features.base64_ratio));
        }
        if features.entropy_score > 0.7 {
            indicators.push(format!("High entropy score: {:.2}", features.entropy_score));
        }
        
        indicators
    }
}

#[derive(Debug)]
pub struct XSSScorer;

impl XSSScorer {
    pub fn new() -> Self { Self }
}

#[async_trait::async_trait]
impl CategoryScorer for XSSScorer {
    async fn score(&self, features: &RequestFeatures) -> Result<f32> {
        let mut score = 0.0;
        
        if features.xss_keywords_count > 0 {
            score += (features.xss_keywords_count as f32 * 0.15).min(0.7);
        }
        
        if features.entropy_score > 0.6 {
            score += (features.entropy_score - 0.6) * 0.4;
        }
        
        Ok(score.min(1.0))
    }
    
    async fn confidence(&self, features: &RequestFeatures) -> Result<f32> {
        let has_xss_keywords = features.xss_keywords_count > 0;
        let has_high_entropy = features.entropy_score > 0.6;
        
        match (has_xss_keywords, has_high_entropy) {
            (true, true) => Ok(0.9),
            (true, false) => Ok(0.7),
            (false, true) => Ok(0.4),
            (false, false) => Ok(0.1),
        }
    }
    
    async fn get_indicators(&self, features: &RequestFeatures) -> Vec<String> {
        let mut indicators = Vec::new();
        
        if features.xss_keywords_count > 0 {
            indicators.push(format!("XSS keywords detected: {}", features.xss_keywords_count));
        }
        if features.entropy_score > 0.6 {
            indicators.push(format!("High entropy (obfuscation): {:.2}", features.entropy_score));
        }
        
        indicators
    }
}

#[derive(Debug)]
pub struct RCEScorer;
impl RCEScorer { pub fn new() -> Self { Self } }

#[async_trait::async_trait]
impl CategoryScorer for RCEScorer {
    async fn score(&self, features: &RequestFeatures) -> Result<f32> {
        let mut score = 0.0;
        
        if features.shell_keywords_count > 0 {
            score += (features.shell_keywords_count as f32 * 0.2).min(0.8);
        }
        
        Ok(score.min(1.0))
    }
    
    async fn confidence(&self, features: &RequestFeatures) -> Result<f32> {
        Ok(if features.shell_keywords_count > 0 { 0.8 } else { 0.1 })
    }
    
    async fn get_indicators(&self, features: &RequestFeatures) -> Vec<String> {
        let mut indicators = Vec::new();
        if features.shell_keywords_count > 0 {
            indicators.push(format!("Shell command keywords: {}", features.shell_keywords_count));
        }
        indicators
    }
}

#[derive(Debug)]
pub struct DataExfiltrationScorer;
impl DataExfiltrationScorer { pub fn new() -> Self { Self } }

#[async_trait::async_trait]
impl CategoryScorer for DataExfiltrationScorer {
    async fn score(&self, features: &RequestFeatures) -> Result<f32> {
        let mut score: f32 = 0.0;
        
        // PII presence increases data exfiltration risk
        if features.contains_credit_cards { score += 0.4; }
        if features.contains_ssn { score += 0.3; }
        if features.contains_email { score += 0.1; }
        if features.contains_phone { score += 0.1; }
        
        // High request frequency could indicate data scraping
        if features.requests_per_minute > 50.0 {
            score += 0.3;
        }
        
        Ok(score.min(1.0))
    }
    
    async fn confidence(&self, features: &RequestFeatures) -> Result<f32> {
        let pii_count = [
            features.contains_credit_cards,
            features.contains_ssn,
            features.contains_email,
            features.contains_phone,
        ].iter().filter(|&&x| x).count();
        
        let confidence = match pii_count {
            0 => 0.2,
            1 => 0.6,
            2 => 0.8,
            _ => 0.9,
        };
        
        Ok(confidence)
    }
    
    async fn get_indicators(&self, features: &RequestFeatures) -> Vec<String> {
        let mut indicators = Vec::new();
        
        if features.contains_credit_cards { indicators.push("Credit card data detected".to_string()); }
        if features.contains_ssn { indicators.push("SSN data detected".to_string()); }
        if features.contains_email { indicators.push("Email addresses detected".to_string()); }
        if features.contains_phone { indicators.push("Phone numbers detected".to_string()); }
        
        if features.requests_per_minute > 50.0 {
            indicators.push(format!("High request frequency: {:.1}/min", features.requests_per_minute));
        }
        
        indicators
    }
}

#[derive(Debug)]
pub struct ComplianceScorer;
impl ComplianceScorer { pub fn new() -> Self { Self } }

#[async_trait::async_trait]
impl CategoryScorer for ComplianceScorer {
    async fn score(&self, features: &RequestFeatures) -> Result<f32> {
        let mut score: f32 = 0.0;
        
        // PCI-DSS violations
        if features.contains_credit_cards {
            score += 0.6; // High compliance risk
        }
        
        // HIPAA violations  
        // This would need more sophisticated healthcare data detection
        
        // SOX violations (financial data)
        if features.contains_ssn {
            score += 0.4; // Financial compliance risk
        }
        
        Ok(score.min(1.0))
    }
    
    async fn confidence(&self, features: &RequestFeatures) -> Result<f32> {
        // High confidence when PII is clearly detected
        if features.contains_credit_cards || features.contains_ssn {
            Ok(0.9)
        } else {
            Ok(0.3)
        }
    }
    
    async fn get_indicators(&self, features: &RequestFeatures) -> Vec<String> {
        let mut indicators = Vec::new();
        
        if features.contains_credit_cards {
            indicators.push("PCI-DSS: Credit card data in request".to_string());
        }
        if features.contains_ssn {
            indicators.push("SOX: SSN/Financial data in request".to_string());
        }
        
        indicators
    }
}

// Utility functions for feature extraction
pub fn calculate_entropy(text: &str) -> f32 {
    if text.is_empty() {
        return 0.0;
    }
    
    let mut char_counts = std::collections::HashMap::new();
    for c in text.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }
    
    let text_len = text.len() as f32;
    let mut entropy = 0.0;
    
    for count in char_counts.values() {
        let p = *count as f32 / text_len;
        entropy -= p * p.log2();
    }
    
    entropy / 8.0 // Normalize to 0-1 range (assuming max 8 bits per char)
}

pub fn calculate_base64_ratio(text: &str) -> f32 {
    if text.is_empty() {
        return 0.0;
    }
    
    let base64_chars = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    
    base64_chars as f32 / text.len() as f32
}

pub fn count_sql_keywords(text: &str) -> u32 {
    let sql_keywords = [
        "select", "union", "insert", "update", "delete", "drop", "create", "alter",
        "where", "from", "join", "having", "group", "order", "limit", "offset",
        "and", "or", "not", "like", "in", "exists", "case", "when", "then",
        "exec", "execute", "sp_", "xp_", "@@", "waitfor", "delay",
        "0x", "char(", "ascii(", "concat(", "substring(", "len(", "cast(",
        "'", "\"", ";", "/*", "*/", "--", "#",
    ];
    
    let text_lower = text.to_lowercase();
    sql_keywords
        .iter()
        .map(|keyword| text_lower.matches(keyword).count() as u32)
        .sum()
}

pub fn count_xss_keywords(text: &str) -> u32 {
    let xss_keywords = [
        "script", "javascript:", "vbscript:", "onload", "onerror", "onclick",
        "onmouseover", "onmouseout", "onfocus", "onblur", "onchange", "onsubmit",
        "alert(", "confirm(", "prompt(", "document.", "window.", "eval(",
        "settimeout(", "setinterval(", "innerhtml", "outerhtml",
        "<img", "<iframe", "<object", "<embed", "<link", "<meta",
        "expression(", "url(", "import(", "require(", "@import",
    ];
    
    let text_lower = text.to_lowercase();
    xss_keywords
        .iter()
        .map(|keyword| text_lower.matches(keyword).count() as u32)
        .sum()
}

pub fn count_shell_keywords(text: &str) -> u32 {
    let shell_keywords = [
        "bash", "sh", "/bin/", "cmd", "powershell", "system(", "exec(",
        "passthru(", "shell_exec(", "eval(", "popen(", "proc_open(",
        "cat ", "ls ", "pwd", "whoami", "id ", "uname", "ps ", "netstat",
        "ifconfig", "ping ", "wget", "curl", "nc ", "telnet", "ssh",
        "&&", "||", ";", "|", "`", "$(", "${", "#!/",
    ];
    
    let text_lower = text.to_lowercase();
    shell_keywords
        .iter()
        .map(|keyword| text_lower.matches(keyword).count() as u32)
        .sum()
}

pub fn is_known_scanner_ua(user_agent: &str) -> bool {
    let scanner_patterns = [
        "nmap", "masscan", "zmap", "sqlmap", "nikto", "dirb", "gobuster",
        "burpsuite", "owasp", "w3af", "acunetix", "nessus", "openvas",
        "qualys", "rapid7", "metasploit", "kali", "parrot", "blackarch",
        "bot", "crawler", "spider", "scanner", "probe", "security",
        "test", "audit", "pentest", "hack", "exploit", "vulnerability",
    ];
    
    let ua_lower = user_agent.to_lowercase();
    scanner_patterns.iter().any(|pattern| ua_lower.contains(pattern))
}

pub fn detect_automation_ua(user_agent: &str) -> f32 {
    let automation_indicators = [
        "headless", "phantom", "selenium", "webdriver", "chrome-automation",
        "puppeteer", "playwright", "chromedriver", "geckodriver",
        "automation", "robot", "api", "curl", "wget", "http", "request",
        "python", "perl", "ruby", "java", "c#", "powershell",
    ];
    
    let ua_lower = user_agent.to_lowercase();
    let matches = automation_indicators
        .iter()
        .filter(|pattern| ua_lower.contains(*pattern))
        .count();
    
    (matches as f32 / automation_indicators.len() as f32).min(1.0)
}

pub fn detect_credit_cards(text: &str) -> bool {
    // Simple credit card pattern detection
    let cc_patterns = [
        r"\b4\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", // Visa
        r"\b5[1-5]\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", // MasterCard
        r"\b3[47]\d{2}[- ]?\d{6}[- ]?\d{5}\b", // AmEx
    ];
    
    cc_patterns.iter().any(|pattern| {
        if let Ok(re) = regex::Regex::new(pattern) {
            re.is_match(text)
        } else {
            false
        }
    })
}

pub fn detect_ssn(text: &str) -> bool {
    // SSN pattern detection
    if let Ok(re) = regex::Regex::new(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b") {
        re.is_match(text)
    } else {
        false
    }
}

pub fn detect_email(text: &str) -> bool {
    // Email pattern detection
    if let Ok(re) = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b") {
        re.is_match(text)
    } else {
        false
    }
}

pub fn detect_phone(text: &str) -> bool {
    // Phone number pattern detection
    let phone_patterns = [
        r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b", // US format
        r"\b\(\d{3}\)[- ]?\d{3}[- ]?\d{4}\b", // US format with parens
        r"\b\+1[- ]?\d{3}[- ]?\d{3}[- ]?\d{4}\b", // US international
    ];
    
    phone_patterns.iter().any(|pattern| {
        if let Ok(re) = regex::Regex::new(pattern) {
            re.is_match(text)
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_threat_detection_service() {
        let service = ThreatDetectionService::new();
        
        let request = RequestContext {
            request_id: "test_001".to_string(),
            client_ip: "192.168.1.100".to_string(),
            method: "POST".to_string(),
            uri: "/login".to_string(),
            headers: HashMap::from([
                ("user-agent".to_string(), "Mozilla/5.0".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ]),
            body: r#"{"username": "admin' OR 1=1--", "password": "test"}"#.to_string(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            session_id: Some("test_session_123".to_string()),
            is_https: true,
        };
        
        let analysis = service.analyze_request(&request).await.unwrap();
        
        assert!(analysis.overall_risk_score > 0.0);
        assert!(!analysis.threat_categories.is_empty());
        println!("Threat Analysis: {:#?}", analysis);
    }
    
    #[test]
    fn test_feature_extraction() {
        assert!(calculate_entropy("aaaa") < calculate_entropy("abcd"));
        assert!(calculate_base64_ratio("YWJjZGVmZw==") > 0.8);
        assert!(count_sql_keywords("SELECT * FROM users WHERE 1=1") >= 3); // Should match SELECT, FROM, WHERE
        assert!(count_xss_keywords("<script>alert('xss')</script>") > 2);
        assert!(is_known_scanner_ua("Mozilla/5.0 (compatible; Nmap Scripting Engine)"));
    }
}
