//! Enhanced TTL Performance Test
//!
//! This test validates the P2-05 and P2-06 TTL enhancements for
//! adaptive cleanup strategies and bulk optimization.

use std::time::{Duration, SystemTime};
use tokio::time::sleep;
use tracing::{debug, info};

use waf_ingress::waf::storage::{
    CleanupResult, MemoryStorageAdapter, ReadConsistency, StorageAdapter, TtlCleanupConfig,
    TtlEnhancementManager,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt().with_env_filter("debug").init();

    info!("🚀 Starting Enhanced TTL Performance Test (P2-05/P2-06)");

    // Test 1: Basic TTL Enhancement Manager functionality
    test_ttl_enhancement_manager().await?;

    // Test 2: Adaptive interval adjustment
    test_adaptive_intervals().await?;

    // Test 3: Optimal batch size calculation
    test_optimal_batch_sizing().await?;

    // Test 4: Integration with storage adapter
    test_storage_integration().await?;

    // Test 5: Performance benchmarking
    test_performance_characteristics().await?;

    info!("✅ Enhanced TTL Performance Test completed successfully!");
    Ok(())
}

async fn test_ttl_enhancement_manager() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 1: TTL Enhancement Manager Basic Functionality");

    let config = TtlCleanupConfig {
        base_interval: Duration::from_millis(100),
        max_batch_size: 50,
        min_batch_size: 5,
        enable_adaptive_intervals: true,
        adaptive_threshold: 20,
        max_interval: Duration::from_millis(500),
        min_interval: Duration::from_millis(50),
        enable_priority_expiration: true,
        max_processing_time_ms: 200,
    };

    let manager = TtlEnhancementManager::new(config.clone());

    // Test initial state
    let initial_stats = manager.get_stats().await;
    assert_eq!(initial_stats.cleanup_runs, 0);
    assert_eq!(initial_stats.current_batch_size, config.max_batch_size);

    // Simulate cleanup operations
    let results = vec![
        CleanupResult {
            expired_keys: 25,
            bytes_cleaned: 1000,
            processing_time_ms: 50,
            batches_processed: 1,
            priority_keys: 5,
            adaptive_adjustments: 0,
        },
        CleanupResult {
            expired_keys: 15,
            bytes_cleaned: 600,
            processing_time_ms: 30,
            batches_processed: 1,
            priority_keys: 2,
            adaptive_adjustments: 0,
        },
        CleanupResult {
            expired_keys: 45,
            bytes_cleaned: 1800,
            processing_time_ms: 90,
            batches_processed: 2,
            priority_keys: 8,
            adaptive_adjustments: 1,
        },
    ];

    for result in &results {
        manager.update_stats(result).await;
    }

    let final_stats = manager.get_stats().await;
    assert_eq!(final_stats.cleanup_runs, 3);
    assert_eq!(final_stats.total_expired_keys, 85);
    assert_eq!(final_stats.total_bytes_cleaned, 3400);
    assert_eq!(final_stats.priority_keys_processed, 15);

    // Test performance report generation
    let report = manager.generate_performance_report().await;
    assert!(report.contains("Total Cleanup Runs: 3"));
    assert!(report.contains("Total Keys Expired: 85"));

    info!("✅ TTL Enhancement Manager basic functionality test passed");
    Ok(())
}

async fn test_adaptive_intervals() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 2: Adaptive Interval Adjustment");

    let config = TtlCleanupConfig {
        base_interval: Duration::from_millis(100),
        max_batch_size: 100,
        min_batch_size: 10,
        enable_adaptive_intervals: true,
        adaptive_threshold: 50,
        max_interval: Duration::from_millis(400),
        min_interval: Duration::from_millis(25),
        enable_priority_expiration: true,
        max_processing_time_ms: 200,
    };

    let manager = TtlEnhancementManager::new(config);

    // Test low activity scenario (should increase interval)
    debug!("Testing low activity scenario");
    for i in 0..4 {
        let adjustment = manager.should_adjust_interval(10).await; // Low activity
        debug!(
            "Low activity iteration {}: adjustment = {:?}",
            i, adjustment
        );

        if i >= 2 {
            // Should suggest interval increase after 3 consecutive low activity runs
            if let Some(new_interval) = adjustment {
                assert!(new_interval > Duration::from_millis(100));
                manager.apply_interval_adjustment(new_interval).await;
                break;
            }
        }
    }

    // Reset and test high activity scenario (should decrease interval)
    debug!("Testing high activity scenario");
    for i in 0..3 {
        let adjustment = manager.should_adjust_interval(100).await; // High activity
        debug!(
            "High activity iteration {}: adjustment = {:?}",
            i, adjustment
        );

        if i >= 1 {
            // Should suggest interval decrease after 2 consecutive high activity runs
            if let Some(new_interval) = adjustment {
                assert!(new_interval < Duration::from_millis(400)); // Less than previous increased interval
                manager.apply_interval_adjustment(new_interval).await;
                break;
            }
        }
    }

    let final_stats = manager.get_stats().await;
    assert!(final_stats.adaptive_interval_changes > 0);

    info!("✅ Adaptive interval adjustment test passed");
    Ok(())
}

async fn test_optimal_batch_sizing() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 3: Optimal Batch Size Calculation");

    let config = TtlCleanupConfig {
        base_interval: Duration::from_millis(100),
        max_batch_size: 1000,
        min_batch_size: 10,
        enable_adaptive_intervals: true,
        adaptive_threshold: 50,
        max_interval: Duration::from_millis(400),
        min_interval: Duration::from_millis(25),
        enable_priority_expiration: true,
        max_processing_time_ms: 200, // Target processing time
    };

    let manager = TtlEnhancementManager::new(config.clone());

    // Initial batch size should be max
    let initial_batch_size = manager.calculate_optimal_batch_size().await;
    assert_eq!(initial_batch_size, config.max_batch_size);

    // Simulate processing that's too slow (should reduce batch size)
    let slow_results = vec![
        CleanupResult {
            expired_keys: 500,
            bytes_cleaned: 10000,
            processing_time_ms: 300, // Exceeds target
            batches_processed: 1,
            priority_keys: 0,
            adaptive_adjustments: 0,
        },
        CleanupResult {
            expired_keys: 500,
            bytes_cleaned: 10000,
            processing_time_ms: 320,
            batches_processed: 1,
            priority_keys: 0,
            adaptive_adjustments: 0,
        },
        CleanupResult {
            expired_keys: 500,
            bytes_cleaned: 10000,
            processing_time_ms: 310,
            batches_processed: 1,
            priority_keys: 0,
            adaptive_adjustments: 0,
        },
    ];

    for result in &slow_results {
        manager.update_stats(result).await;
    }

    let reduced_batch_size = manager.calculate_optimal_batch_size().await;
    assert!(reduced_batch_size < config.max_batch_size);
    debug!(
        "Batch size reduced from {} to {} due to slow processing",
        config.max_batch_size, reduced_batch_size
    );

    info!("✅ Optimal batch size calculation test passed");
    Ok(())
}

async fn test_storage_integration() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 4: Storage Integration with TTL Enhancements");

    // Create a memory storage adapter for testing
    let storage = MemoryStorageAdapter::new(
        Some(1000),                 // Capacity
        Duration::from_millis(100), // TTL cleanup interval
    )
    .await?;

    // Insert test data with TTL
    let test_data = vec![
        (
            b"key1".to_vec(),
            b"value1".to_vec(),
            Some(Duration::from_millis(200)),
        ),
        (
            b"key2".to_vec(),
            b"value2".to_vec(),
            Some(Duration::from_millis(400)),
        ),
        (
            b"key3".to_vec(),
            b"value3".to_vec(),
            Some(Duration::from_millis(600)),
        ),
        (b"key4".to_vec(), b"value4".to_vec(), None), // No TTL
    ];

    for (key, value, ttl) in &test_data {
        storage.set(key, value, *ttl).await?;
    }

    // Verify initial data
    assert!(storage
        .get(b"key1", ReadConsistency::Strong)
        .await?
        .is_some());
    assert!(storage
        .get(b"key2", ReadConsistency::Strong)
        .await?
        .is_some());
    assert!(storage
        .get(b"key3", ReadConsistency::Strong)
        .await?
        .is_some());
    assert!(storage
        .get(b"key4", ReadConsistency::Strong)
        .await?
        .is_some());

    // Wait for some keys to expire
    sleep(Duration::from_millis(250)).await;

    // key1 should be expired, others should still exist
    // Note: Due to cleanup intervals, we might need to trigger cleanup manually
    let expired_count = storage.expire_keys().await?;
    debug!(
        "Manually triggered expiration, removed {} keys",
        expired_count
    );

    // Verify expiration
    assert!(storage
        .get(b"key1", ReadConsistency::Strong)
        .await?
        .is_none());
    assert!(storage
        .get(b"key2", ReadConsistency::Strong)
        .await?
        .is_some());
    assert!(storage
        .get(b"key3", ReadConsistency::Strong)
        .await?
        .is_some());
    assert!(storage
        .get(b"key4", ReadConsistency::Strong)
        .await?
        .is_some());

    // Wait for more keys to expire
    sleep(Duration::from_millis(200)).await;
    let expired_count2 = storage.expire_keys().await?;
    debug!("Second expiration cycle, removed {} keys", expired_count2);

    // key2 should now also be expired
    assert!(storage
        .get(b"key2", ReadConsistency::Strong)
        .await?
        .is_none());
    assert!(storage
        .get(b"key3", ReadConsistency::Strong)
        .await?
        .is_some());
    assert!(storage
        .get(b"key4", ReadConsistency::Strong)
        .await?
        .is_some());

    info!("✅ Storage integration test passed");
    Ok(())
}

async fn test_performance_characteristics() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 5: Performance Characteristics Validation");

    let config = TtlCleanupConfig {
        base_interval: Duration::from_millis(50),
        max_batch_size: 500,
        min_batch_size: 10,
        enable_adaptive_intervals: true,
        adaptive_threshold: 100,
        max_interval: Duration::from_millis(200),
        min_interval: Duration::from_millis(10),
        enable_priority_expiration: true,
        max_processing_time_ms: 100,
    };

    let manager = TtlEnhancementManager::new(config);

    // Simulate a realistic workload over time
    let workload_scenarios = vec![
        // High load period
        (vec![150, 200, 180, 220, 190], "High Load"),
        // Medium load period
        (vec![80, 90, 85, 95, 88], "Medium Load"),
        // Low load period
        (vec![20, 15, 25, 18, 22], "Low Load"),
        // Mixed load period
        (vec![200, 30, 150, 40, 180], "Mixed Load"),
    ];

    for (load_pattern, scenario_name) in workload_scenarios {
        info!("📊 Testing scenario: {}", scenario_name);

        let scenario_start = SystemTime::now();

        for (i, expired_keys) in load_pattern.iter().enumerate() {
            let processing_time = if *expired_keys > 150 {
                80 // High load = longer processing
            } else if *expired_keys > 50 {
                40 // Medium load
            } else {
                20 // Low load = fast processing
            };

            let result = CleanupResult {
                expired_keys: *expired_keys as u64,
                bytes_cleaned: (*expired_keys as u64) * 50, // 50 bytes per key
                processing_time_ms: processing_time,
                batches_processed: (*expired_keys / 100 + 1) as u32,
                priority_keys: (*expired_keys / 10) as u64,
                adaptive_adjustments: if i % 3 == 0 { 1 } else { 0 },
            };

            manager.update_stats(&result).await;

            // Check for adaptive adjustments
            if let Some(new_interval) = manager.should_adjust_interval(*expired_keys as u64).await {
                manager.apply_interval_adjustment(new_interval).await;
                debug!("Interval adjusted during {} scenario", scenario_name);
            }

            // Simulate realistic timing between cleanups
            sleep(Duration::from_millis(10)).await;
        }

        let scenario_duration = scenario_start.elapsed().unwrap();
        debug!(
            "Scenario '{}' completed in {:?}",
            scenario_name, scenario_duration
        );
    }

    // Generate final performance report
    let final_stats = manager.get_stats().await;
    let performance_report = manager.generate_performance_report().await;

    info!("📈 Final Performance Statistics:");
    info!("Total cleanup runs: {}", final_stats.cleanup_runs);
    info!("Total keys processed: {}", final_stats.total_expired_keys);
    info!(
        "Average processing time: {:.2}ms",
        final_stats.avg_cleanup_duration_ms
    );
    info!(
        "Average cleanup rate: {:.1} keys/sec",
        final_stats.avg_cleanup_rate_per_sec
    );
    info!(
        "Adaptive adjustments: {}",
        final_stats.adaptive_interval_changes
    );

    // Performance assertions
    assert!(final_stats.cleanup_runs >= 20); // Should have multiple runs
    assert!(final_stats.avg_cleanup_duration_ms > 0.0);
    assert!(final_stats.avg_cleanup_rate_per_sec > 0.0);
    assert!(final_stats.adaptive_interval_changes > 0); // Should have adapted

    debug!("📄 Full Performance Report:\n{}", performance_report);

    info!("✅ Performance characteristics validation passed");
    Ok(())
}
