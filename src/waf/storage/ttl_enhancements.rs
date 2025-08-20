//! TTL Enhancement Module for P2-05 and P2-06
//!
//! Advanced TTL expiration strategies and bulk optimization enhancements
//! for the WAF-Rejected storage system.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

/// Enhanced TTL cleanup configuration
#[derive(Debug, Clone)]
pub struct TtlCleanupConfig {
    /// Base cleanup interval
    pub base_interval: Duration,
    /// Maximum batch size for bulk operations
    pub max_batch_size: usize,
    /// Minimum batch size
    pub min_batch_size: usize,
    /// Enable adaptive interval adjustment
    pub enable_adaptive_intervals: bool,
    /// Threshold for interval adjustment (keys per run)
    pub adaptive_threshold: usize,
    /// Maximum interval during low activity
    pub max_interval: Duration,
    /// Minimum interval during high activity
    pub min_interval: Duration,
    /// Enable priority-based expiration
    pub enable_priority_expiration: bool,
    /// Maximum processing time per cleanup cycle (milliseconds)
    pub max_processing_time_ms: u64,
}

impl Default for TtlCleanupConfig {
    fn default() -> Self {
        Self {
            base_interval: Duration::from_secs(60),
            max_batch_size: 1000,
            min_batch_size: 10,
            enable_adaptive_intervals: true,
            adaptive_threshold: 100,
            max_interval: Duration::from_secs(300), // 5 minutes
            min_interval: Duration::from_secs(10),  // 10 seconds
            enable_priority_expiration: true,
            max_processing_time_ms: 5000, // 5 seconds max per cycle
        }
    }
}

/// Enhanced TTL cleanup performance statistics
#[derive(Debug, Clone, Default)]
pub struct EnhancedTtlStats {
    /// Total cleanup runs performed
    pub cleanup_runs: u64,
    /// Total keys expired across all runs
    pub total_expired_keys: u64,
    /// Average cleanup duration in milliseconds
    pub avg_cleanup_duration_ms: f64,
    /// Last cleanup duration in milliseconds
    pub last_cleanup_duration_ms: u64,
    /// Last cleanup key count
    pub last_cleanup_key_count: u64,
    /// Maximum cleanup duration observed
    pub max_cleanup_duration_ms: u64,
    /// Current batch size being used
    pub current_batch_size: usize,
    /// Number of adaptive interval changes
    pub adaptive_interval_changes: u64,
    /// Current cleanup interval in milliseconds
    pub current_interval_ms: u64,
    /// Total bytes cleaned up
    pub total_bytes_cleaned: u64,
    /// Average cleanup rate (keys per second)
    pub avg_cleanup_rate_per_sec: f64,
    /// Number of batch operations performed
    pub total_batch_operations: u64,
    /// Average batch processing time
    pub avg_batch_processing_ms: f64,
    /// Priority keys processed (if priority mode enabled)
    pub priority_keys_processed: u64,
    /// Time saved through adaptive intervals (estimated)
    pub estimated_time_saved_ms: u64,
}

/// Enhanced cleanup operation result
#[derive(Debug, Clone)]
pub struct CleanupResult {
    pub expired_keys: u64,
    pub bytes_cleaned: u64,
    pub processing_time_ms: u64,
    pub batches_processed: u32,
    pub priority_keys: u64,
    pub adaptive_adjustments: u32,
}

/// TTL Enhancement Manager
/// 
/// This manager provides advanced TTL expiration strategies that can be
/// integrated with existing storage adapters to enhance their performance.
pub struct TtlEnhancementManager {
    config: TtlCleanupConfig,
    stats: Arc<RwLock<EnhancedTtlStats>>,
    current_interval: Arc<RwLock<Duration>>,
    consecutive_low_activity: Arc<RwLock<u32>>,
    consecutive_high_activity: Arc<RwLock<u32>>,
}

impl TtlEnhancementManager {
    /// Create a new TTL enhancement manager
    pub fn new(config: TtlCleanupConfig) -> Self {
        Self {
            config: config.clone(),
            stats: Arc::new(RwLock::new(EnhancedTtlStats {
                current_batch_size: config.max_batch_size,
                current_interval_ms: config.base_interval.as_millis() as u64,
                ..Default::default()
            })),
            current_interval: Arc::new(RwLock::new(config.base_interval)),
            consecutive_low_activity: Arc::new(RwLock::new(0)),
            consecutive_high_activity: Arc::new(RwLock::new(0)),
        }
    }

    /// Get comprehensive TTL cleanup statistics
    pub async fn get_stats(&self) -> EnhancedTtlStats {
        self.stats.read().await.clone()
    }

    /// Update configuration dynamically
    pub async fn update_config(&mut self, new_config: TtlCleanupConfig) {
        self.config = new_config.clone();
        let mut stats = self.stats.write().await;
        stats.current_batch_size = new_config.max_batch_size;
        
        if new_config.base_interval != *self.current_interval.read().await {
            *self.current_interval.write().await = new_config.base_interval;
            stats.current_interval_ms = new_config.base_interval.as_millis() as u64;
            stats.adaptive_interval_changes += 1;
        }
    }

    /// Calculate optimal batch size based on recent performance
    pub async fn calculate_optimal_batch_size(&self) -> usize {
        let stats = self.stats.read().await;
        
        if stats.cleanup_runs < 3 {
            return self.config.max_batch_size;
        }

        // Adjust batch size based on processing time
        let target_processing_time = self.config.max_processing_time_ms as f64 * 0.8; // 80% of max
        
        if stats.avg_cleanup_duration_ms > target_processing_time {
            // Reduce batch size if processing takes too long
            let reduction_factor = target_processing_time / stats.avg_cleanup_duration_ms;
            let new_size = (stats.current_batch_size as f64 * reduction_factor) as usize;
            new_size.max(self.config.min_batch_size).min(self.config.max_batch_size)
        } else if stats.avg_cleanup_duration_ms < target_processing_time * 0.5 {
            // Increase batch size if processing is very fast
            let increase_factor = 1.5;
            let new_size = (stats.current_batch_size as f64 * increase_factor) as usize;
            new_size.min(self.config.max_batch_size)
        } else {
            stats.current_batch_size
        }
    }

    /// Determine if interval adjustment is needed and return new interval
    pub async fn should_adjust_interval(&self, expired_keys: u64) -> Option<Duration> {
        if !self.config.enable_adaptive_intervals {
            return None;
        }

        let threshold = self.config.adaptive_threshold as u64;
        let mut low_activity = self.consecutive_low_activity.write().await;
        let mut high_activity = self.consecutive_high_activity.write().await;
        
        if expired_keys < threshold / 2 {
            *low_activity += 1;
            *high_activity = 0;
            
            // Increase interval if consistently low activity
            if *low_activity >= 3 {
                let current = *self.current_interval.read().await;
                let new_interval = (current * 2).min(self.config.max_interval);
                
                if new_interval != current {
                    *low_activity = 0;
                    return Some(new_interval);
                }
            }
        } else if expired_keys > threshold {
            *high_activity += 1;
            *low_activity = 0;
            
            // Decrease interval if consistently high activity
            if *high_activity >= 2 {
                let current = *self.current_interval.read().await;
                let new_interval = (current / 2).max(self.config.min_interval);
                
                if new_interval != current {
                    *high_activity = 0;
                    return Some(new_interval);
                }
            }
        } else {
            // Reset counters for moderate activity
            *low_activity = 0;
            *high_activity = 0;
        }
        
        None
    }

    /// Update statistics after cleanup operation
    pub async fn update_stats(&self, result: &CleanupResult) {
        let mut stats = self.stats.write().await;
        
        stats.cleanup_runs += 1;
        stats.total_expired_keys += result.expired_keys;
        stats.last_cleanup_duration_ms = result.processing_time_ms;
        stats.last_cleanup_key_count = result.expired_keys;
        stats.max_cleanup_duration_ms = stats.max_cleanup_duration_ms.max(result.processing_time_ms);
        stats.total_bytes_cleaned += result.bytes_cleaned;
        stats.total_batch_operations += result.batches_processed as u64;
        stats.priority_keys_processed += result.priority_keys;

        // Update rolling averages
        if stats.cleanup_runs > 0 {
            stats.avg_cleanup_duration_ms = (stats.avg_cleanup_duration_ms
                * (stats.cleanup_runs - 1) as f64
                + result.processing_time_ms as f64)
                / stats.cleanup_runs as f64;
                
            // Calculate cleanup rate (keys per second)
            if result.processing_time_ms > 0 {
                let rate = (result.expired_keys as f64 * 1000.0) / result.processing_time_ms as f64;
                stats.avg_cleanup_rate_per_sec = (stats.avg_cleanup_rate_per_sec
                    * (stats.cleanup_runs - 1) as f64 + rate)
                    / stats.cleanup_runs as f64;
            }

            // Update batch processing average
            if result.batches_processed > 0 {
                let batch_time = result.processing_time_ms as f64 / result.batches_processed as f64;
                stats.avg_batch_processing_ms = (stats.avg_batch_processing_ms
                    * (stats.total_batch_operations - result.batches_processed as u64) as f64
                    + batch_time * result.batches_processed as f64)
                    / stats.total_batch_operations as f64;
            }
        }
    }

    /// Apply interval adjustment and update tracking
    pub async fn apply_interval_adjustment(&self, new_interval: Duration) -> bool {
        let mut current_interval = self.current_interval.write().await;
        if *current_interval != new_interval {
            let old_interval = *current_interval;
            *current_interval = new_interval;
            
            let mut stats = self.stats.write().await;
            stats.current_interval_ms = new_interval.as_millis() as u64;
            stats.adaptive_interval_changes += 1;
            
            // Estimate time saved/lost due to adjustment
            let old_ms = old_interval.as_millis() as u64;
            let new_ms = new_interval.as_millis() as u64;
            if new_ms > old_ms {
                // Interval increased - we're saving processing time
                stats.estimated_time_saved_ms += new_ms - old_ms;
            }
            
            info!(
                "TTL cleanup interval adjusted from {}ms to {}ms (activity-based optimization)",
                old_ms, new_ms
            );
            
            true
        } else {
            false
        }
    }

    /// Generate performance report
    pub async fn generate_performance_report(&self) -> String {
        let stats = self.stats.read().await;
        
        format!(
            r#"TTL Enhancement Performance Report
=====================================
Total Cleanup Runs: {}
Total Keys Expired: {}
Total Bytes Cleaned: {} MB
Current Batch Size: {}
Current Interval: {}ms

Performance Metrics:
- Average Cleanup Duration: {:.2}ms
- Maximum Cleanup Duration: {}ms
- Average Cleanup Rate: {:.1} keys/sec
- Average Batch Processing: {:.2}ms
- Total Batch Operations: {}

Adaptive Optimizations:
- Interval Changes: {}
- Priority Keys Processed: {}
- Estimated Time Saved: {}ms

Efficiency Indicators:
- Cleanup Efficiency: {:.1}% (based on max processing time)
- Batch Utilization: {:.1}% (avg keys per batch)
- Time Optimization: {:.1}% (interval adjustments)
"#,
            stats.cleanup_runs,
            stats.total_expired_keys,
            stats.total_bytes_cleaned / (1024 * 1024),
            stats.current_batch_size,
            stats.current_interval_ms,
            stats.avg_cleanup_duration_ms,
            stats.max_cleanup_duration_ms,
            stats.avg_cleanup_rate_per_sec,
            stats.avg_batch_processing_ms,
            stats.total_batch_operations,
            stats.adaptive_interval_changes,
            stats.priority_keys_processed,
            stats.estimated_time_saved_ms,
            // Efficiency calculations
            if self.config.max_processing_time_ms > 0 {
                100.0 - (stats.avg_cleanup_duration_ms / self.config.max_processing_time_ms as f64 * 100.0)
            } else { 0.0 },
            if stats.total_batch_operations > 0 {
                (stats.total_expired_keys as f64 / stats.total_batch_operations as f64 / self.config.max_batch_size as f64) * 100.0
            } else { 0.0 },
            if stats.cleanup_runs > 0 {
                (stats.adaptive_interval_changes as f64 / stats.cleanup_runs as f64) * 100.0
            } else { 0.0 }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_ttl_enhancement_manager_creation() {
        let config = TtlCleanupConfig::default();
        let manager = TtlEnhancementManager::new(config.clone());
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.current_batch_size, config.max_batch_size);
        assert_eq!(stats.current_interval_ms, config.base_interval.as_millis() as u64);
        assert_eq!(stats.cleanup_runs, 0);
    }

    #[tokio::test]
    async fn test_adaptive_interval_calculation() {
        let config = TtlCleanupConfig::default();
        let manager = TtlEnhancementManager::new(config.clone());
        
        // Test low activity scenario
        let new_interval = manager.should_adjust_interval(10).await; // Low activity
        assert!(new_interval.is_none()); // Should not adjust on first run
        
        // Simulate consistent low activity
        for _ in 0..3 {
            manager.should_adjust_interval(10).await;
        }
        
        let adjusted_interval = manager.should_adjust_interval(10).await;
        // Should increase interval due to consistent low activity
        assert!(adjusted_interval.is_some());
        if let Some(interval) = adjusted_interval {
            assert!(interval > config.base_interval);
        }
    }

    #[tokio::test]
    async fn test_optimal_batch_size_calculation() {
        let config = TtlCleanupConfig::default();
        let manager = TtlEnhancementManager::new(config.clone());
        
        // Initial batch size should be max
        let initial_batch_size = manager.calculate_optimal_batch_size().await;
        assert_eq!(initial_batch_size, config.max_batch_size);
        
        // Simulate slow processing
        let slow_result = CleanupResult {
            expired_keys: 500,
            bytes_cleaned: 10000,
            processing_time_ms: 8000, // Slower than target
            batches_processed: 1,
            priority_keys: 0,
            adaptive_adjustments: 0,
        };
        
        manager.update_stats(&slow_result).await;
        manager.update_stats(&slow_result).await;
        manager.update_stats(&slow_result).await;
        
        let adjusted_batch_size = manager.calculate_optimal_batch_size().await;
        assert!(adjusted_batch_size < config.max_batch_size);
    }

    #[tokio::test]
    async fn test_performance_report_generation() {
        let config = TtlCleanupConfig::default();
        let manager = TtlEnhancementManager::new(config);
        
        let result = CleanupResult {
            expired_keys: 100,
            bytes_cleaned: 5000,
            processing_time_ms: 500,
            batches_processed: 2,
            priority_keys: 10,
            adaptive_adjustments: 1,
        };
        
        manager.update_stats(&result).await;
        
        let report = manager.generate_performance_report().await;
        assert!(report.contains("Total Cleanup Runs: 1"));
        assert!(report.contains("Total Keys Expired: 100"));
        assert!(report.contains("Priority Keys Processed: 10"));
    }
}