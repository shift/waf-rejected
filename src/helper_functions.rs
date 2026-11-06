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
