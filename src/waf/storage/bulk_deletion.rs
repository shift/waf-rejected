//! Bulk Deletion Optimization Module for P2-06
//!
//! Advanced bulk deletion strategies and optimizations for TTL cleanup
//! operations in the WAF-Rejected storage system.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Bulk deletion optimization configuration
#[derive(Debug, Clone)]
pub struct BulkDeletionConfig {
    /// Maximum keys to delete in a single transaction
    pub max_transaction_size: usize,
    /// Minimum keys before triggering bulk deletion
    pub min_bulk_threshold: usize,
    /// Enable parallel deletion workers
    pub enable_parallel_deletion: bool,
    /// Number of parallel deletion workers
    pub parallel_workers: usize,
    /// Transaction timeout in milliseconds
    pub transaction_timeout_ms: u64,
    /// Enable deletion result caching
    pub enable_result_caching: bool,
    /// Cache TTL for deletion results
    pub cache_ttl_seconds: u64,
    /// Enable deletion statistics tracking
    pub enable_statistics: bool,
}

impl Default for BulkDeletionConfig {
    fn default() -> Self {
        Self {
            max_transaction_size: 500,
            min_bulk_threshold: 10,
            enable_parallel_deletion: true,
            parallel_workers: 4,
            transaction_timeout_ms: 1000,
            enable_result_caching: false,
            cache_ttl_seconds: 300,
            enable_statistics: true,
        }
    }
}

/// Bulk deletion performance statistics
#[derive(Debug, Clone, Default)]
pub struct BulkDeletionStats {
    /// Total bulk operations performed
    pub total_bulk_operations: u64,
    /// Total keys deleted across all operations
    pub total_keys_deleted: u64,
    /// Total bytes reclaimed
    pub total_bytes_reclaimed: u64,
    /// Average deletion rate (keys per second)
    pub avg_deletion_rate_per_sec: f64,
    /// Average transaction size
    pub avg_transaction_size: f64,
    /// Maximum transaction size observed
    pub max_transaction_size: usize,
    /// Total transaction time in milliseconds
    pub total_transaction_time_ms: u64,
    /// Average transaction time
    pub avg_transaction_time_ms: f64,
    /// Number of failed transactions
    pub failed_transactions: u64,
    /// Number of timeout errors
    pub timeout_errors: u64,
    /// Number of parallel operations
    pub parallel_operations: u64,
    /// Efficiency ratio (successful / total operations)
    pub efficiency_ratio: f64,
}

/// Bulk deletion operation result
#[derive(Debug, Clone)]
pub struct BulkDeletionResult {
    /// Number of keys successfully deleted
    pub keys_deleted: u64,
    /// Number of bytes reclaimed
    pub bytes_reclaimed: u64,
    /// Transaction time in milliseconds
    pub transaction_time_ms: u64,
    /// Number of failed deletions
    pub failed_deletions: u64,
    /// Whether operation used parallel processing
    pub used_parallel_processing: bool,
    /// Individual transaction results
    pub transaction_results: Vec<TransactionResult>,
}

/// Individual transaction result
#[derive(Debug, Clone)]
pub struct TransactionResult {
    /// Keys in this transaction
    pub keys_count: usize,
    /// Bytes reclaimed in this transaction
    pub bytes_reclaimed: u64,
    /// Transaction duration
    pub duration_ms: u64,
    /// Success status
    pub success: bool,
    /// Error message if failed
    pub error_message: Option<String>,
}

/// Deletion key with metadata
#[derive(Debug, Clone)]
pub struct DeletionKey {
    /// The key to delete
    pub key: Vec<u8>,
    /// Estimated size in bytes
    pub estimated_size: u64,
    /// Priority level (higher = delete first)
    pub priority: u8,
    /// Expiration timestamp
    pub expiration_time: u64,
}

/// Bulk deletion optimizer
///
/// This optimizer provides advanced bulk deletion strategies that can be
/// integrated with storage adapters to enhance TTL cleanup performance.
pub struct BulkDeletionOptimizer {
    config: BulkDeletionConfig,
    stats: Arc<RwLock<BulkDeletionStats>>,
    deletion_cache: Arc<RwLock<HashMap<Vec<u8>, SystemTime>>>,
    current_workers: Arc<RwLock<usize>>,
}

impl BulkDeletionOptimizer {
    /// Create a new bulk deletion optimizer
    pub fn new(config: BulkDeletionConfig) -> Self {
        Self {
            config,
            stats: Arc::new(RwLock::new(BulkDeletionStats::default())),
            deletion_cache: Arc::new(RwLock::new(HashMap::new())),
            current_workers: Arc::new(RwLock::new(0)),
        }
    }

    /// Get comprehensive deletion statistics
    pub async fn get_stats(&self) -> BulkDeletionStats {
        self.stats.read().await.clone()
    }

    /// Update configuration dynamically
    pub async fn update_config(&mut self, new_config: BulkDeletionConfig) {
        self.config = new_config;
        info!("Bulk deletion configuration updated");
    }

    /// Optimize key grouping for bulk deletion
    pub async fn optimize_key_grouping(&self, keys: Vec<DeletionKey>) -> Vec<Vec<DeletionKey>> {
        if keys.len() < self.config.min_bulk_threshold {
            return vec![keys];
        }

        let keys_len = keys.len(); // Store length before moving
        let mut sorted_keys = keys;

        // Sort by priority (highest first), then by size (largest first)
        sorted_keys.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(b.estimated_size.cmp(&a.estimated_size))
        });

        // Group keys into optimal transaction sizes
        let mut groups = Vec::new();
        let mut current_group = Vec::new();
        let mut _current_group_size = 0;

        for key in sorted_keys {
            // Start new group if current would exceed max transaction size
            if current_group.len() >= self.config.max_transaction_size {
                if !current_group.is_empty() {
                    groups.push(current_group);
                    current_group = Vec::new();
                    _current_group_size = 0;
                }
            }

            _current_group_size += key.estimated_size;
            current_group.push(key);
        }

        // Add final group
        if !current_group.is_empty() {
            groups.push(current_group);
        }

        debug!(
            "Organized {} keys into {} transaction groups",
            keys_len,
            groups.len()
        );
        groups
    }

    /// Execute bulk deletion with optimization strategies
    pub async fn execute_bulk_deletion<F, Fut>(
        &self,
        key_groups: Vec<Vec<DeletionKey>>,
        deletion_fn: F,
    ) -> Result<BulkDeletionResult, String>
    where
        F: Fn(Vec<DeletionKey>) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<TransactionResult, String>> + Send,
    {
        let start_time = SystemTime::now();
        let mut total_result = BulkDeletionResult {
            keys_deleted: 0,
            bytes_reclaimed: 0,
            transaction_time_ms: 0,
            failed_deletions: 0,
            used_parallel_processing: false,
            transaction_results: Vec::new(),
        };

        if key_groups.is_empty() {
            return Ok(total_result);
        }

        // Decide on execution strategy
        let use_parallel = self.config.enable_parallel_deletion
            && key_groups.len() > 1
            && key_groups.len() >= self.config.parallel_workers;

        if use_parallel {
            total_result.used_parallel_processing = true;
            total_result = self
                .execute_parallel_deletion(key_groups, deletion_fn)
                .await?;
        } else {
            total_result = self
                .execute_sequential_deletion(key_groups, deletion_fn)
                .await?;
        }

        total_result.transaction_time_ms =
            start_time.elapsed().unwrap_or_default().as_millis() as u64;

        // Update statistics
        self.update_deletion_stats(&total_result).await;

        Ok(total_result)
    }

    /// Execute deletions in parallel
    async fn execute_parallel_deletion<F, Fut>(
        &self,
        key_groups: Vec<Vec<DeletionKey>>,
        deletion_fn: F,
    ) -> Result<BulkDeletionResult, String>
    where
        F: Fn(Vec<DeletionKey>) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<TransactionResult, String>> + Send,
    {
        let mut total_result = BulkDeletionResult {
            keys_deleted: 0,
            bytes_reclaimed: 0,
            transaction_time_ms: 0,
            failed_deletions: 0,
            used_parallel_processing: true,
            transaction_results: Vec::new(),
        };

        // Limit concurrent operations
        let max_concurrent = self.config.parallel_workers.min(key_groups.len());
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));

        let mut handles = Vec::new();

        for group in key_groups {
            let deletion_fn_clone = deletion_fn.clone();
            let semaphore_clone = semaphore.clone();
            let timeout_duration = Duration::from_millis(self.config.transaction_timeout_ms);

            let handle = tokio::spawn(async move {
                let _permit = semaphore_clone.acquire().await.unwrap();

                // Apply timeout to each transaction
                match tokio::time::timeout(timeout_duration, deletion_fn_clone(group)).await {
                    Ok(result) => result,
                    Err(_) => Err("Transaction timeout".to_string()),
                }
            });

            handles.push(handle);
        }

        // Collect results
        for handle in handles {
            match handle.await {
                Ok(Ok(transaction_result)) => {
                    total_result.keys_deleted += transaction_result.keys_count as u64;
                    total_result.bytes_reclaimed += transaction_result.bytes_reclaimed;
                    total_result.transaction_results.push(transaction_result);
                }
                Ok(Err(e)) => {
                    error!("Parallel deletion transaction failed: {}", e);
                    total_result.failed_deletions += 1;
                    total_result.transaction_results.push(TransactionResult {
                        keys_count: 0,
                        bytes_reclaimed: 0,
                        duration_ms: 0,
                        success: false,
                        error_message: Some(e),
                    });
                }
                Err(e) => {
                    error!("Parallel deletion task panicked: {}", e);
                    total_result.failed_deletions += 1;
                }
            }
        }

        debug!(
            "Parallel deletion completed: {} keys deleted, {} failures",
            total_result.keys_deleted, total_result.failed_deletions
        );

        Ok(total_result)
    }

    /// Execute deletions sequentially
    async fn execute_sequential_deletion<F, Fut>(
        &self,
        key_groups: Vec<Vec<DeletionKey>>,
        deletion_fn: F,
    ) -> Result<BulkDeletionResult, String>
    where
        F: Fn(Vec<DeletionKey>) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<TransactionResult, String>> + Send,
    {
        let mut total_result = BulkDeletionResult {
            keys_deleted: 0,
            bytes_reclaimed: 0,
            transaction_time_ms: 0,
            failed_deletions: 0,
            used_parallel_processing: false,
            transaction_results: Vec::new(),
        };

        for group in key_groups {
            let timeout_duration = Duration::from_millis(self.config.transaction_timeout_ms);

            match tokio::time::timeout(timeout_duration, deletion_fn(group)).await {
                Ok(Ok(transaction_result)) => {
                    total_result.keys_deleted += transaction_result.keys_count as u64;
                    total_result.bytes_reclaimed += transaction_result.bytes_reclaimed;
                    total_result.transaction_results.push(transaction_result);
                }
                Ok(Err(e)) => {
                    error!("Sequential deletion transaction failed: {}", e);
                    total_result.failed_deletions += 1;
                    total_result.transaction_results.push(TransactionResult {
                        keys_count: 0,
                        bytes_reclaimed: 0,
                        duration_ms: 0,
                        success: false,
                        error_message: Some(e),
                    });
                }
                Err(_) => {
                    warn!("Sequential deletion transaction timed out");
                    total_result.failed_deletions += 1;
                    total_result.transaction_results.push(TransactionResult {
                        keys_count: 0,
                        bytes_reclaimed: 0,
                        duration_ms: self.config.transaction_timeout_ms,
                        success: false,
                        error_message: Some("Transaction timeout".to_string()),
                    });
                }
            }
        }

        debug!(
            "Sequential deletion completed: {} keys deleted, {} failures",
            total_result.keys_deleted, total_result.failed_deletions
        );

        Ok(total_result)
    }

    /// Update deletion statistics
    async fn update_deletion_stats(&self, result: &BulkDeletionResult) {
        let mut stats = self.stats.write().await;

        stats.total_bulk_operations += 1;
        stats.total_keys_deleted += result.keys_deleted;
        stats.total_bytes_reclaimed += result.bytes_reclaimed;
        stats.total_transaction_time_ms += result.transaction_time_ms;

        if result.used_parallel_processing {
            stats.parallel_operations += 1;
        }

        // Update rolling averages
        if stats.total_bulk_operations > 0 {
            stats.avg_transaction_time_ms =
                stats.total_transaction_time_ms as f64 / stats.total_bulk_operations as f64;

            if result.transaction_time_ms > 0 {
                let rate =
                    (result.keys_deleted as f64 * 1000.0) / result.transaction_time_ms as f64;
                stats.avg_deletion_rate_per_sec = (stats.avg_deletion_rate_per_sec
                    * (stats.total_bulk_operations - 1) as f64
                    + rate)
                    / stats.total_bulk_operations as f64;
            }

            stats.avg_transaction_size =
                stats.total_keys_deleted as f64 / stats.total_bulk_operations as f64;
        }

        // Update max transaction size
        for tx_result in &result.transaction_results {
            if tx_result.keys_count > stats.max_transaction_size {
                stats.max_transaction_size = tx_result.keys_count;
            }

            if !tx_result.success {
                stats.failed_transactions += 1;
                if tx_result
                    .error_message
                    .as_ref()
                    .map_or(false, |e| e.contains("timeout"))
                {
                    stats.timeout_errors += 1;
                }
            }
        }

        // Calculate efficiency ratio
        let total_operations = stats.total_bulk_operations;
        let successful_operations = total_operations - stats.failed_transactions;
        stats.efficiency_ratio = if total_operations > 0 {
            successful_operations as f64 / total_operations as f64
        } else {
            0.0
        };
    }

    /// Check deletion cache for recently deleted keys
    pub async fn is_recently_deleted(&self, key: &[u8]) -> bool {
        if !self.config.enable_result_caching {
            return false;
        }

        let cache = self.deletion_cache.read().await;
        if let Some(deletion_time) = cache.get(key) {
            let cache_ttl = Duration::from_secs(self.config.cache_ttl_seconds);
            SystemTime::now()
                .duration_since(*deletion_time)
                .unwrap_or_default()
                < cache_ttl
        } else {
            false
        }
    }

    /// Mark key as recently deleted in cache
    pub async fn mark_deleted(&self, key: Vec<u8>) {
        if !self.config.enable_result_caching {
            return;
        }

        let mut cache = self.deletion_cache.write().await;
        cache.insert(key, SystemTime::now());

        // Cleanup old cache entries if cache is too large
        if cache.len() > 10000 {
            let cutoff_time =
                SystemTime::now() - Duration::from_secs(self.config.cache_ttl_seconds);
            cache.retain(|_, deletion_time| *deletion_time > cutoff_time);
        }
    }

    /// Generate performance report
    pub async fn generate_performance_report(&self) -> String {
        let stats = self.stats.read().await;

        format!(
            r#"Bulk Deletion Optimization Performance Report
==============================================
Total Bulk Operations: {}
Total Keys Deleted: {}
Total Bytes Reclaimed: {} MB
Average Transaction Size: {:.1} keys

Performance Metrics:
- Average Deletion Rate: {:.1} keys/sec
- Average Transaction Time: {:.2}ms
- Maximum Transaction Size: {} keys
- Parallel Operations: {}

Reliability Metrics:
- Failed Transactions: {}
- Timeout Errors: {}
- Efficiency Ratio: {:.1}%

Configuration:
- Max Transaction Size: {}
- Parallel Workers: {}
- Transaction Timeout: {}ms
- Result Caching: {}

Optimization Indicators:
- Parallel Processing Usage: {:.1}%
- Transaction Success Rate: {:.1}%
- Average Throughput: {:.1} MB/sec
"#,
            stats.total_bulk_operations,
            stats.total_keys_deleted,
            stats.total_bytes_reclaimed / (1024 * 1024),
            stats.avg_transaction_size,
            stats.avg_deletion_rate_per_sec,
            stats.avg_transaction_time_ms,
            stats.max_transaction_size,
            stats.parallel_operations,
            stats.failed_transactions,
            stats.timeout_errors,
            stats.efficiency_ratio * 100.0,
            self.config.max_transaction_size,
            self.config.parallel_workers,
            self.config.transaction_timeout_ms,
            if self.config.enable_result_caching {
                "Enabled"
            } else {
                "Disabled"
            },
            // Optimization indicators
            if stats.total_bulk_operations > 0 {
                (stats.parallel_operations as f64 / stats.total_bulk_operations as f64) * 100.0
            } else {
                0.0
            },
            stats.efficiency_ratio * 100.0,
            if stats.avg_transaction_time_ms > 0.0 {
                (stats.total_bytes_reclaimed as f64 / (1024.0 * 1024.0))
                    / (stats.total_transaction_time_ms as f64 / 1000.0)
            } else {
                0.0
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_bulk_deletion_optimizer_creation() {
        let config = BulkDeletionConfig::default();
        let optimizer = BulkDeletionOptimizer::new(config.clone());

        let stats = optimizer.get_stats().await;
        assert_eq!(stats.total_bulk_operations, 0);
        assert_eq!(stats.total_keys_deleted, 0);
    }

    #[tokio::test]
    async fn test_key_grouping_optimization() {
        let config = BulkDeletionConfig {
            max_transaction_size: 3,
            min_bulk_threshold: 2,
            ..Default::default()
        };
        let optimizer = BulkDeletionOptimizer::new(config);

        let keys = vec![
            DeletionKey {
                key: b"key1".to_vec(),
                estimated_size: 100,
                priority: 1,
                expiration_time: 1000,
            },
            DeletionKey {
                key: b"key2".to_vec(),
                estimated_size: 200,
                priority: 2,
                expiration_time: 2000,
            },
            DeletionKey {
                key: b"key3".to_vec(),
                estimated_size: 150,
                priority: 1,
                expiration_time: 1500,
            },
            DeletionKey {
                key: b"key4".to_vec(),
                estimated_size: 50,
                priority: 3,
                expiration_time: 500,
            },
        ];

        let groups = optimizer.optimize_key_grouping(keys).await;

        // Should create groups based on max transaction size
        assert!(groups.len() >= 1);

        // Verify priority ordering (key4 should be first due to highest priority)
        assert_eq!(groups[0][0].key, b"key4");
    }

    #[tokio::test]
    async fn test_deletion_cache() {
        let config = BulkDeletionConfig {
            enable_result_caching: true,
            cache_ttl_seconds: 1,
            ..Default::default()
        };
        let optimizer = BulkDeletionOptimizer::new(config);

        let key = b"test_key".to_vec();

        // Key should not be in cache initially
        assert!(!optimizer.is_recently_deleted(&key).await);

        // Mark key as deleted
        optimizer.mark_deleted(key.clone()).await;

        // Key should now be in cache
        assert!(optimizer.is_recently_deleted(&key).await);

        // Wait for cache TTL to expire
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Key should no longer be in cache
        assert!(!optimizer.is_recently_deleted(&key).await);
    }

    #[tokio::test]
    async fn test_bulk_deletion_execution() {
        let config = BulkDeletionConfig {
            max_transaction_size: 2,
            enable_parallel_deletion: false, // Use sequential for predictable testing
            ..Default::default()
        };
        let optimizer = BulkDeletionOptimizer::new(config);

        let key_groups = vec![vec![
            DeletionKey {
                key: b"key1".to_vec(),
                estimated_size: 100,
                priority: 1,
                expiration_time: 1000,
            },
            DeletionKey {
                key: b"key2".to_vec(),
                estimated_size: 200,
                priority: 1,
                expiration_time: 1000,
            },
        ]];

        // Mock deletion function that always succeeds
        let deletion_fn = |keys: Vec<DeletionKey>| async move {
            let total_size: u64 = keys.iter().map(|k| k.estimated_size).sum();
            Ok(TransactionResult {
                keys_count: keys.len(),
                bytes_reclaimed: total_size,
                duration_ms: 10,
                success: true,
                error_message: None,
            })
        };

        let result = optimizer
            .execute_bulk_deletion(key_groups, deletion_fn)
            .await;
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.keys_deleted, 2);
        assert_eq!(result.bytes_reclaimed, 300);
        assert_eq!(result.failed_deletions, 0);
        assert!(!result.used_parallel_processing);
    }
}
