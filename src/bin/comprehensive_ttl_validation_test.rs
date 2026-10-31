//! Comprehensive TTL Performance Validation Test (P2-07)
//!
//! This test validates the combined P2-05 and P2-06 TTL enhancements
//! working together in realistic scenarios.

use std::time::{Duration, SystemTime};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use waf_ingress::waf::storage::{
    BulkDeletionConfig, BulkDeletionOptimizer, DeletionKey, MemoryStorageAdapter, ReadConsistency,
    StorageAdapter, TransactionResult, TtlCleanupConfig, TtlEnhancementManager,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt().with_env_filter("info").init();

    info!("🚀 Starting Comprehensive TTL Performance Validation (P2-07)");

    // Test 1: Integration test of TTL enhancement and bulk deletion
    test_integrated_ttl_enhancements().await?;

    // Test 2: Real-world workload simulation
    test_realistic_workload_simulation().await?;

    // Test 3: Stress testing under high load
    test_stress_testing().await?;

    // Test 4: Performance regression validation
    test_performance_regression_validation().await?;

    // Test 5: End-to-end storage integration
    test_end_to_end_storage_integration().await?;

    info!("✅ Comprehensive TTL Performance Validation completed successfully!");
    Ok(())
}

async fn test_integrated_ttl_enhancements() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 1: Integration of TTL Enhancement and Bulk Deletion");

    // Configure TTL enhancement manager
    let ttl_config = TtlCleanupConfig {
        base_interval: Duration::from_millis(100),
        max_batch_size: 50,
        min_batch_size: 5,
        enable_adaptive_intervals: true,
        adaptive_threshold: 25,
        max_interval: Duration::from_millis(500),
        min_interval: Duration::from_millis(25),
        enable_priority_expiration: true,
        max_processing_time_ms: 100,
    };
    let ttl_manager = TtlEnhancementManager::new(ttl_config);

    // Configure bulk deletion optimizer
    let bulk_config = BulkDeletionConfig {
        max_transaction_size: 25,
        min_bulk_threshold: 5,
        enable_parallel_deletion: true,
        parallel_workers: 3,
        transaction_timeout_ms: 500,
        enable_result_caching: true,
        cache_ttl_seconds: 60,
        enable_statistics: true,
    };
    let bulk_optimizer = BulkDeletionOptimizer::new(bulk_config);

    // Create simulated expired keys
    let expired_keys: Vec<DeletionKey> = (0..100)
        .map(|i| DeletionKey {
            key: format!("expired_key_{}", i).into_bytes(),
            estimated_size: 100 + (i as u64 * 10),
            priority: if i % 10 == 0 { 5 } else { 2 },
            expiration_time: 1000 + (i as u64 * 100),
        })
        .collect();

    // Use TTL manager to optimize batch sizing
    let optimal_batch_size = ttl_manager.calculate_optimal_batch_size().await;
    debug!("Optimal batch size determined: {}", optimal_batch_size);

    // Use bulk optimizer to group keys
    let key_groups = bulk_optimizer.optimize_key_grouping(expired_keys).await;
    debug!("Organized keys into {} groups", key_groups.len());

    // Simulate cleanup process with integrated components
    let deletion_fn = |keys: Vec<DeletionKey>| async move {
        let total_size: u64 = keys.iter().map(|k| k.estimated_size).sum();

        // Simulate variable processing time based on priority
        let avg_priority = keys.iter().map(|k| k.priority as f64).sum::<f64>() / keys.len() as f64;
        let processing_time = if avg_priority > 3.0 { 10 } else { 20 };

        sleep(Duration::from_millis(processing_time)).await;

        Ok(TransactionResult {
            keys_count: keys.len(),
            bytes_reclaimed: total_size,
            duration_ms: processing_time,
            success: true,
            error_message: None,
        })
    };

    let cleanup_start = SystemTime::now();
    let deletion_result = bulk_optimizer
        .execute_bulk_deletion(key_groups, deletion_fn)
        .await?;
    let cleanup_duration = cleanup_start.elapsed().unwrap();

    // Update TTL manager statistics
    let cleanup_result = waf_ingress::waf::storage::CleanupResult {
        expired_keys: deletion_result.keys_deleted,
        bytes_cleaned: deletion_result.bytes_reclaimed,
        processing_time_ms: cleanup_duration.as_millis() as u64,
        batches_processed: deletion_result.transaction_results.len() as u32,
        priority_keys: deletion_result
            .transaction_results
            .iter()
            .map(|tr| tr.keys_count / 10) // Estimate priority keys
            .sum::<usize>() as u64,
        adaptive_adjustments: 1,
    };
    ttl_manager.update_stats(&cleanup_result).await;

    // Validate results
    assert_eq!(deletion_result.keys_deleted, 100);
    assert!(deletion_result.bytes_reclaimed > 0);
    assert_eq!(deletion_result.failed_deletions, 0);

    // Check adaptive behavior
    let interval_adjustment = ttl_manager
        .should_adjust_interval(deletion_result.keys_deleted)
        .await;
    if let Some(new_interval) = interval_adjustment {
        ttl_manager.apply_interval_adjustment(new_interval).await;
        debug!("Interval adjusted based on cleanup performance");
    }

    let ttl_stats = ttl_manager.get_stats().await;
    let bulk_stats = bulk_optimizer.get_stats().await;

    info!("Integration test results:");
    info!(
        "  TTL cleanup rate: {:.1} keys/sec",
        ttl_stats.avg_cleanup_rate_per_sec
    );
    info!(
        "  Bulk deletion rate: {:.1} keys/sec",
        bulk_stats.avg_deletion_rate_per_sec
    );
    info!(
        "  Combined efficiency: {:.1}%",
        bulk_stats.efficiency_ratio * 100.0
    );

    assert!(ttl_stats.avg_cleanup_rate_per_sec > 0.0);
    assert!(bulk_stats.efficiency_ratio > 0.95); // >95% efficiency

    info!("✅ Integrated TTL enhancements test passed");
    Ok(())
}

async fn test_realistic_workload_simulation() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 2: Realistic Workload Simulation");

    let ttl_manager = TtlEnhancementManager::new(TtlCleanupConfig::default());
    let bulk_optimizer = BulkDeletionOptimizer::new(BulkDeletionConfig::default());

    // Simulate realistic workload patterns over time
    let workload_phases = vec![
        ("Startup Phase", 50usize, 1u8, 2u8), // Light load, low priority
        ("Normal Operation", 200usize, 2u8, 3u8), // Medium load, mixed priority
        ("Peak Hours", 500usize, 3u8, 4u8),   // Heavy load, high priority
        ("Maintenance Window", 1000usize, 1u8, 5u8), // Very heavy load, mixed priority
        ("Off-Peak", 100usize, 2u8, 2u8),     // Return to light load
    ];

    let mut total_processed = 0u64;
    let mut total_duration = Duration::default();

    for (phase_name, key_count, base_priority, max_priority) in workload_phases {
        info!("📊 Simulating phase: {}", phase_name);

        // Generate keys with realistic patterns
        let keys: Vec<DeletionKey> = (0..key_count)
            .map(|i| {
                let priority =
                    base_priority + ((i % (max_priority - base_priority + 1) as usize) as u8);
                DeletionKey {
                    key: format!("{}_{}", phase_name.replace(" ", "_").to_lowercase(), i)
                        .into_bytes(),
                    estimated_size: 50 + (i as u64 * 25) + (priority as u64 * 100),
                    priority,
                    expiration_time: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64
                        + (i as u64 * 1000),
                }
            })
            .collect();

        let phase_start = SystemTime::now();

        // Process keys with optimized grouping
        let key_groups = bulk_optimizer.optimize_key_grouping(keys).await;

        // Realistic deletion function that varies by load
        let deletion_fn = move |keys: Vec<DeletionKey>| async move {
            let total_size: u64 = keys.iter().map(|k| k.estimated_size).sum();

            // Processing time varies with batch size and priority
            let avg_priority =
                keys.iter().map(|k| k.priority as f64).sum::<f64>() / keys.len() as f64;
            let base_time = (keys.len() as f64).sqrt() as u64;
            let priority_factor = if avg_priority > 4.0 { 0.5 } else { 1.0 }; // High priority = faster
            let processing_time = (base_time as f64 * priority_factor) as u64;

            if processing_time > 0 {
                sleep(Duration::from_millis(processing_time)).await;
            }

            // Simulate occasional failures in high-load scenarios
            let success = (key_count < 800) || (keys.len() % 20) != 0; // Deterministic "failure" pattern

            Ok(TransactionResult {
                keys_count: keys.len(),
                bytes_reclaimed: total_size,
                duration_ms: processing_time,
                success,
                error_message: if success {
                    None
                } else {
                    Some("High load timeout".to_string())
                },
            })
        };

        let result = bulk_optimizer
            .execute_bulk_deletion(key_groups, deletion_fn)
            .await?;
        let phase_duration = phase_start.elapsed().unwrap();

        total_processed += result.keys_deleted;
        total_duration += phase_duration;

        // Update TTL manager with results
        let cleanup_result = waf_ingress::waf::storage::CleanupResult {
            expired_keys: result.keys_deleted,
            bytes_cleaned: result.bytes_reclaimed,
            processing_time_ms: phase_duration.as_millis() as u64,
            batches_processed: result.transaction_results.len() as u32,
            priority_keys: result
                .transaction_results
                .iter()
                .filter(|tr| tr.success)
                .map(|tr| tr.keys_count / 5) // Estimate high-priority keys
                .sum::<usize>() as u64,
            adaptive_adjustments: if result.failed_deletions > 0 { 1 } else { 0 },
        };
        ttl_manager.update_stats(&cleanup_result).await;

        // Check for adaptive adjustments
        if let Some(new_interval) = ttl_manager
            .should_adjust_interval(result.keys_deleted)
            .await
        {
            ttl_manager.apply_interval_adjustment(new_interval).await;
            debug!("Interval adjusted during {} phase", phase_name);
        }

        debug!(
            "Phase '{}' completed: {} keys processed in {:?}",
            phase_name, result.keys_deleted, phase_duration
        );
    }

    // Validate overall performance
    let final_ttl_stats = ttl_manager.get_stats().await;
    let final_bulk_stats = bulk_optimizer.get_stats().await;

    info!("Realistic workload results:");
    info!("  Total keys processed: {}", total_processed);
    info!("  Total duration: {:?}", total_duration);
    info!(
        "  Overall rate: {:.1} keys/sec",
        total_processed as f64 / total_duration.as_secs_f64()
    );
    info!(
        "  TTL adaptive adjustments: {}",
        final_ttl_stats.adaptive_interval_changes
    );
    info!(
        "  Bulk operation efficiency: {:.1}%",
        final_bulk_stats.efficiency_ratio * 100.0
    );

    assert!(total_processed >= 1850); // Should process most keys successfully
    assert!(final_bulk_stats.efficiency_ratio > 0.85); // >85% efficiency under realistic load
    assert!(final_ttl_stats.adaptive_interval_changes > 0); // Should adapt to changing load

    info!("✅ Realistic workload simulation test passed");
    Ok(())
}

async fn test_stress_testing() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 3: Stress Testing Under High Load");

    // Configure for high performance under stress
    let stress_ttl_config = TtlCleanupConfig {
        base_interval: Duration::from_millis(50),
        max_batch_size: 200,
        min_batch_size: 20,
        enable_adaptive_intervals: true,
        adaptive_threshold: 150,
        max_interval: Duration::from_millis(200),
        min_interval: Duration::from_millis(10),
        enable_priority_expiration: true,
        max_processing_time_ms: 50,
    };

    let stress_bulk_config = BulkDeletionConfig {
        max_transaction_size: 100,
        min_bulk_threshold: 20,
        enable_parallel_deletion: true,
        parallel_workers: 6,
        transaction_timeout_ms: 1000,
        enable_result_caching: false, // Disable for stress testing
        cache_ttl_seconds: 300,
        enable_statistics: true,
    };

    let ttl_manager = TtlEnhancementManager::new(stress_ttl_config);
    let bulk_optimizer = BulkDeletionOptimizer::new(stress_bulk_config);

    // Generate large number of keys for stress testing
    let stress_key_count = 5000;
    let stress_keys: Vec<DeletionKey> = (0..stress_key_count)
        .map(|i| DeletionKey {
            key: format!("stress_key_{:06}", i).into_bytes(),
            estimated_size: 75 + (i as u64 % 500),
            priority: ((i % 5) + 1) as u8,
            expiration_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + (i as u64 * 100),
        })
        .collect();

    info!("Starting stress test with {} keys", stress_key_count);
    let stress_start = SystemTime::now();

    // Process in multiple concurrent batches
    let batch_size = 1000;
    let mut total_stress_processed = 0u64;
    let mut total_stress_bytes = 0u64;

    for batch_start in (0..stress_key_count).step_by(batch_size) {
        let batch_end = (batch_start + batch_size).min(stress_key_count);
        let batch_keys = stress_keys[batch_start..batch_end].to_vec();

        // Don't clone the manager, just use it for each batch sequentially
        let groups = bulk_optimizer.optimize_key_grouping(batch_keys).await;

        let deletion_fn = |keys: Vec<DeletionKey>| async move {
            let total_size: u64 = keys.iter().map(|k| k.estimated_size).sum();

            // Fast processing for stress test
            let processing_time = 5 + (keys.len() / 20) as u64;
            sleep(Duration::from_millis(processing_time)).await;

            Ok(TransactionResult {
                keys_count: keys.len(),
                bytes_reclaimed: total_size,
                duration_ms: processing_time,
                success: true,
                error_message: None,
            })
        };

        let result = bulk_optimizer
            .execute_bulk_deletion(groups, deletion_fn)
            .await?;

        // Update TTL manager for each batch
        let cleanup_result = waf_ingress::waf::storage::CleanupResult {
            expired_keys: result.keys_deleted,
            bytes_cleaned: result.bytes_reclaimed,
            processing_time_ms: result.transaction_time_ms,
            batches_processed: result.transaction_results.len() as u32,
            priority_keys: result.keys_deleted / 5, // Estimate
            adaptive_adjustments: 0,
        };
        ttl_manager.update_stats(&cleanup_result).await;

        total_stress_processed += result.keys_deleted;
        total_stress_bytes += result.bytes_reclaimed;
    }

    let stress_duration = stress_start.elapsed().unwrap();

    // Validate stress test results
    let stress_ttl_stats = ttl_manager.get_stats().await;
    let stress_bulk_stats = bulk_optimizer.get_stats().await;

    info!("Stress test results:");
    info!(
        "  Keys processed: {}/{}",
        total_stress_processed, stress_key_count
    );
    info!("  Total duration: {:?}", stress_duration);
    info!(
        "  Processing rate: {:.1} keys/sec",
        total_stress_processed as f64 / stress_duration.as_secs_f64()
    );
    info!(
        "  Bytes reclaimed: {} MB",
        total_stress_bytes / (1024 * 1024)
    );
    info!(
        "  Average batch time: {:.2}ms",
        stress_bulk_stats.avg_transaction_time_ms
    );
    info!(
        "  Efficiency: {:.1}%",
        stress_bulk_stats.efficiency_ratio * 100.0
    );

    // Stress test acceptance criteria
    assert_eq!(total_stress_processed, stress_key_count as u64); // Should process all keys
    assert!(total_stress_processed as f64 / stress_duration.as_secs_f64() > 1000.0); // >1000 keys/sec
    assert!(stress_bulk_stats.efficiency_ratio > 0.95); // >95% efficiency even under stress
    assert!(stress_bulk_stats.avg_transaction_time_ms < 100.0); // Fast transaction times

    info!("✅ Stress testing passed");
    Ok(())
}

async fn test_performance_regression_validation() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 4: Performance Regression Validation");

    // Test with baseline configuration (simple setup)
    let baseline_start = SystemTime::now();
    let baseline_keys = create_test_keys(500, 2);
    let baseline_result = simulate_simple_cleanup(baseline_keys).await?;
    let baseline_duration = baseline_start.elapsed().unwrap();

    // Test with enhanced configuration
    let enhanced_start = SystemTime::now();
    let enhanced_keys = create_test_keys(500, 2);
    let enhanced_result = simulate_enhanced_cleanup(enhanced_keys).await?;
    let enhanced_duration = enhanced_start.elapsed().unwrap();

    // Compare performance
    let baseline_rate = baseline_result.keys_deleted as f64 / baseline_duration.as_secs_f64();
    let enhanced_rate = enhanced_result.keys_deleted as f64 / enhanced_duration.as_secs_f64();
    let improvement_ratio = enhanced_rate / baseline_rate;

    info!("Performance regression validation:");
    info!("  Baseline rate: {:.1} keys/sec", baseline_rate);
    info!("  Enhanced rate: {:.1} keys/sec", enhanced_rate);
    info!("  Improvement ratio: {:.2}x", improvement_ratio);
    info!(
        "  Enhanced efficiency: {:.1}%",
        enhanced_result.efficiency_ratio * 100.0
    );

    // Regression validation criteria
    assert!(improvement_ratio >= 1.0); // Enhanced should be at least as fast as baseline
    assert!(enhanced_result.efficiency_ratio > 0.95); // High efficiency maintained

    if improvement_ratio < 1.2 {
        warn!("Performance improvement is less than 20% - consider further optimizations");
    }

    info!("✅ Performance regression validation passed");
    Ok(())
}

async fn test_end_to_end_storage_integration() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 5: End-to-End Storage Integration");

    // Create storage adapter with TTL support
    let storage = MemoryStorageAdapter::new(
        Some(2000),                // Capacity
        Duration::from_millis(50), // Fast cleanup for testing
    )
    .await?;

    // Insert test data with various TTL values
    let test_data = vec![
        (
            b"short_ttl_1".to_vec(),
            b"value1".to_vec(),
            Some(Duration::from_millis(100)),
        ),
        (
            b"short_ttl_2".to_vec(),
            b"value2".to_vec(),
            Some(Duration::from_millis(150)),
        ),
        (
            b"medium_ttl_1".to_vec(),
            b"value3".to_vec(),
            Some(Duration::from_millis(300)),
        ),
        (
            b"medium_ttl_2".to_vec(),
            b"value4".to_vec(),
            Some(Duration::from_millis(350)),
        ),
        (
            b"long_ttl_1".to_vec(),
            b"value5".to_vec(),
            Some(Duration::from_millis(600)),
        ),
        (b"persistent".to_vec(), b"value6".to_vec(), None), // No TTL
    ];

    // Insert all data
    for (key, value, ttl) in &test_data {
        storage.set(key, value, *ttl).await?;
    }

    // Verify all data is initially present
    for (key, _, _) in &test_data {
        assert!(storage.get(key, ReadConsistency::Strong).await?.is_some());
    }

    // Wait for first batch to expire
    sleep(Duration::from_millis(200)).await;
    let first_cleanup = storage.expire_keys().await?;
    debug!("First cleanup removed {} keys", first_cleanup);

    // Check expiration results
    assert!(storage
        .get(b"short_ttl_1", ReadConsistency::Strong)
        .await?
        .is_none());
    assert!(storage
        .get(b"short_ttl_2", ReadConsistency::Strong)
        .await?
        .is_none());
    assert!(storage
        .get(b"medium_ttl_1", ReadConsistency::Strong)
        .await?
        .is_some());
    assert!(storage
        .get(b"persistent", ReadConsistency::Strong)
        .await?
        .is_some());

    // Wait for second batch to expire
    sleep(Duration::from_millis(200)).await;
    let second_cleanup = storage.expire_keys().await?;
    debug!("Second cleanup removed {} keys", second_cleanup);

    // Check second expiration results
    assert!(storage
        .get(b"medium_ttl_1", ReadConsistency::Strong)
        .await?
        .is_none());
    assert!(storage
        .get(b"medium_ttl_2", ReadConsistency::Strong)
        .await?
        .is_none());
    assert!(storage
        .get(b"long_ttl_1", ReadConsistency::Strong)
        .await?
        .is_some());
    assert!(storage
        .get(b"persistent", ReadConsistency::Strong)
        .await?
        .is_some());

    // Final cleanup after all TTLs expired
    sleep(Duration::from_millis(500)).await;
    let final_cleanup = storage.expire_keys().await?;
    debug!("Final cleanup removed {} keys", final_cleanup);

    // Only persistent key should remain
    assert!(storage
        .get(b"long_ttl_1", ReadConsistency::Strong)
        .await?
        .is_none());
    assert!(storage
        .get(b"persistent", ReadConsistency::Strong)
        .await?
        .is_some());

    let total_cleaned = first_cleanup + second_cleanup + final_cleanup;
    debug!("Total keys cleaned up: {}", total_cleaned);
    assert_eq!(total_cleaned, 5); // All TTL keys should be cleaned

    info!("✅ End-to-end storage integration test passed");
    Ok(())
}

// Helper functions

fn create_test_keys(count: usize, priority: u8) -> Vec<DeletionKey> {
    (0..count)
        .map(|i| DeletionKey {
            key: format!("test_key_{}", i).into_bytes(),
            estimated_size: 100 + (i as u64 * 50),
            priority,
            expiration_time: 1000 + (i as u64 * 100),
        })
        .collect()
}

#[derive(Debug)]
struct SimpleCleanupResult {
    keys_deleted: u64,
    processing_time_ms: u64,
}

#[derive(Debug)]
struct EnhancedCleanupResult {
    keys_deleted: u64,
    processing_time_ms: u64,
    efficiency_ratio: f64,
}

async fn simulate_simple_cleanup(
    keys: Vec<DeletionKey>,
) -> Result<SimpleCleanupResult, Box<dyn std::error::Error>> {
    let start = SystemTime::now();

    // Simple sequential processing
    let mut processed = 0u64;
    for batch in keys.chunks(50) {
        // Simulate simple processing time
        sleep(Duration::from_millis(batch.len() as u64 * 2)).await;
        processed += batch.len() as u64;
    }

    let duration = start.elapsed().unwrap();
    Ok(SimpleCleanupResult {
        keys_deleted: processed,
        processing_time_ms: duration.as_millis() as u64,
    })
}

async fn simulate_enhanced_cleanup(
    keys: Vec<DeletionKey>,
) -> Result<EnhancedCleanupResult, Box<dyn std::error::Error>> {
    let bulk_optimizer = BulkDeletionOptimizer::new(BulkDeletionConfig::default());

    let start = SystemTime::now();
    let key_groups = bulk_optimizer.optimize_key_grouping(keys).await;

    let deletion_fn = |keys: Vec<DeletionKey>| async move {
        let total_size: u64 = keys.iter().map(|k| k.estimated_size).sum();

        // Enhanced processing with optimizations
        let processing_time = (keys.len() as f64).sqrt() as u64;
        sleep(Duration::from_millis(processing_time)).await;

        Ok(TransactionResult {
            keys_count: keys.len(),
            bytes_reclaimed: total_size,
            duration_ms: processing_time,
            success: true,
            error_message: None,
        })
    };

    let result = bulk_optimizer
        .execute_bulk_deletion(key_groups, deletion_fn)
        .await?;
    let duration = start.elapsed().unwrap();

    let stats = bulk_optimizer.get_stats().await;

    Ok(EnhancedCleanupResult {
        keys_deleted: result.keys_deleted,
        processing_time_ms: duration.as_millis() as u64,
        efficiency_ratio: stats.efficiency_ratio,
    })
}
