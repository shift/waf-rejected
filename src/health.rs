use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime: u64,
    pub components: HashMap<String, ComponentHealth>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: String,
    pub last_check: u64,
    pub details: Option<String>,
}

impl HealthStatus {
    pub fn new() -> Self {
        let mut components = HashMap::new();
        
        components.insert("waf_engine".to_string(), ComponentHealth {
            status: "healthy".to_string(),
            last_check: chrono::Utc::now().timestamp() as u64,
            details: None,
        });
        
        components.insert("ai_models".to_string(), ComponentHealth {
            status: "healthy".to_string(),
            last_check: chrono::Utc::now().timestamp() as u64,
            details: None,
        });
        
        Self {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: 0,
            components,
        }
    }
    
    pub fn is_healthy(&self) -> bool {
        self.status == "healthy" && 
        self.components.values().all(|c| c.status == "healthy")
    }
}
