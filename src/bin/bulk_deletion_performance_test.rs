//! Bulk Deletion Performance Test
//!
//! This test validates the P2-06 bulk deletion optimizations for
//! TTL cleanup operations.

use std::time::{Duration, SystemTime};
use tokio::time::sleep;
use tracing::{info, debug};

use waf_ingress::waf::storage::{
    BulkDeletionOptimizer, BulkDeletionConfig, DeletionKey, TransactionResult,
    BulkDeletionStats, BulkDeletionResult,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .init();

    info!("🚀 Starting Bulk Deletion Performance Test (P2-06)");

    // Test 1: Basic bulk deletion optimizer functionality
    test_bulk_deletion_optimizer().await?;

    // Test 2: Key grouping optimization
    test_key_grouping_optimization().await?;

    // Test 3: Parallel vs sequential execution
    test_parallel_vs_sequential().await?;

    // Test 4: Deletion caching
    test_deletion_caching().await?;

    // Test 5: Performance characteristics under load
    test_performance_under_load().await?;

    // Test 6: Transaction timeout handling
    test_timeout_handling().await?;

    info!("✅ Bulk Deletion Performance Test completed successfully!");
    Ok(())
}

async fn test_bulk_deletion_optimizer() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 1: Bulk Deletion Optimizer Basic Functionality");

    let config = BulkDeletionConfig {
        max_transaction_size: 10,
        min_bulk_threshold: 3,
        enable_parallel_deletion: false,
        parallel_workers: 2,
        transaction_timeout_ms: 1000,
        enable_result_caching: true,
        cache_ttl_seconds: 300,
        enable_statistics: true,
    };

    let optimizer = BulkDeletionOptimizer::new(config.clone());

    // Test initial state
    let initial_stats = optimizer.get_stats().await;
    assert_eq!(initial_stats.total_bulk_operations, 0);
    assert_eq!(initial_stats.total_keys_deleted, 0);

    // Create test keys
    let test_keys = create_test_keys(5, 1);
    let key_groups = optimizer.optimize_key_grouping(test_keys).await;

    // Mock deletion function that simulates successful deletions
    let deletion_fn = |keys: Vec<DeletionKey>| async move {
        let total_size: u64 = keys.iter().map(|k| k.estimated_size).sum();
        // Simulate some processing time
        sleep(Duration::from_millis(10)).await;
        Ok(TransactionResult {
            keys_count: keys.len(),
            bytes_reclaimed: total_size,
            duration_ms: 10,
            success: true,
            error_message: None,
        })
    };

    // Execute bulk deletion
    let result = optimizer.execute_bulk_deletion(key_groups, deletion_fn).await?;

    assert_eq!(result.keys_deleted, 5);
    assert!(result.bytes_reclaimed > 0);
    assert_eq!(result.failed_deletions, 0);

    let final_stats = optimizer.get_stats().await;
    assert_eq!(final_stats.total_bulk_operations, 1);
    assert_eq!(final_stats.total_keys_deleted, 5);

    info!("✅ Bulk deletion optimizer basic functionality test passed");
    Ok(())
}

async fn test_key_grouping_optimization() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 2: Key Grouping Optimization");

    let config = BulkDeletionConfig {
        max_transaction_size: 3,
        min_bulk_threshold: 2,
        ..Default::default()
    };
    let optimizer = BulkDeletionOptimizer::new(config);

    // Create keys with different priorities and sizes
    let keys = vec![
        DeletionKey {
            key: b"low_priority_large".to_vec(),
            estimated_size: 1000,
            priority: 1,
            expiration_time: 1000,
        },
        DeletionKey {
            key: b"high_priority_small".to_vec(),
            estimated_size: 100,
            priority: 5,
            expiration_time: 500,
        },
        DeletionKey {
            key: b"medium_priority_medium".to_vec(),
            estimated_size: 500,
            priority: 3,
            expiration_time: 750,
        },
        DeletionKey {
            key: b"high_priority_large".to_vec(),
            estimated_size: 800,
            priority: 5,
            expiration_time: 400,
        },
        DeletionKey {
            key: b"low_priority_small".to_vec(),
            estimated_size: 200,
            priority: 1,
            expiration_time: 1200,
        },
    ];

    let groups = optimizer.optimize_key_grouping(keys).await;

    // Verify grouping
    assert!(groups.len() >= 1);
    debug!("Created {} groups from 5 keys", groups.len());

    // Verify priority ordering (highest priority should come first)
    let first_group = &groups[0];
    assert!(first_group[0].priority >= first_group.last().unwrap().priority);

    // Verify group size constraints
    for group in &groups {
        assert!(group.len() <= 3); // max_transaction_size
    }

    info!("✅ Key grouping optimization test passed");
    Ok(())
}

async fn test_parallel_vs_sequential() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 3: Parallel vs Sequential Execution");

    // Test sequential execution
    let sequential_config = BulkDeletionConfig {
        max_transaction_size: 5,
        enable_parallel_deletion: false,
        parallel_workers: 1,
        transaction_timeout_ms: 1000,
        ..Default::default()
    };
    let sequential_optimizer = BulkDeletionOptimizer::new(sequential_config);

    // Test parallel execution
    let parallel_config = BulkDeletionConfig {
        max_transaction_size: 5,
        enable_parallel_deletion: true,
        parallel_workers: 3,
        transaction_timeout_ms: 1000,
        ..Default::default()
    };
    let parallel_optimizer = BulkDeletionOptimizer::new(parallel_config);

    // Create multiple groups for testing
    let test_keys = create_test_keys(20, 5); // 20 keys, priority 5
    let key_groups_sequential = sequential_optimizer.optimize_key_grouping(test_keys.clone()).await;
    let key_groups_parallel = parallel_optimizer.optimize_key_grouping(test_keys).await;

    // Mock deletion function with simulated processing time
    let deletion_fn = |keys: Vec<DeletionKey>| async move {
        let total_size: u64 = keys.iter().map(|k| k.estimated_size).sum();
        // Simulate processing time proportional to number of keys
        sleep(Duration::from_millis(keys.len() as u64 * 5)).await;
        Ok(TransactionResult {
            keys_count: keys.len(),
            bytes_reclaimed: total_size,
            duration_ms: keys.len() as u64 * 5,
            success: true,
            error_message: None,
        })
    };

    // Time sequential execution
    let sequential_start = SystemTime::now();
    let sequential_result = sequential_optimizer
        .execute_bulk_deletion(key_groups_sequential, deletion_fn.clone())
        .await?;
    let sequential_duration = sequential_start.elapsed().unwrap();

    // Time parallel execution
    let parallel_start = SystemTime::now();
    let parallel_result = parallel_optimizer
        .execute_bulk_deletion(key_groups_parallel, deletion_fn)
        .await?;
    let parallel_duration = parallel_start.elapsed().unwrap();

    // Verify results
    assert_eq!(sequential_result.keys_deleted, 20);
    assert_eq!(parallel_result.keys_deleted, 20);
    assert!(!sequential_result.used_parallel_processing);
    assert!(parallel_result.used_parallel_processing);

    debug!(
        "Sequential execution: {:?}, Parallel execution: {:?}",
        sequential_duration, parallel_duration
    );

    // Parallel should be faster for multiple groups (though not guaranteed in all environments)
    info!(
        "Sequential: {}ms, Parallel: {}ms",
        sequential_duration.as_millis(),
        parallel_duration.as_millis()
    );

    info!("✅ Parallel vs sequential execution test passed");
    Ok(())
}

async fn test_deletion_caching() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 4: Deletion Caching");

    let config = BulkDeletionConfig {
        enable_result_caching: true,
        cache_ttl_seconds: 1, // Short TTL for testing
        ..Default::default()
    };
    let optimizer = BulkDeletionOptimizer::new(config);

    let test_key = b"cached_key".to_vec();

    // Key should not be in cache initially
    assert!(!optimizer.is_recently_deleted(&test_key).await);

    // Mark key as deleted
    optimizer.mark_deleted(test_key.clone()).await;

    // Key should now be in cache
    assert!(optimizer.is_recently_deleted(&test_key).await);

    // Wait for cache to expire
    sleep(Duration::from_millis(1100)).await;

    // Key should no longer be in cache
    assert!(!optimizer.is_recently_deleted(&test_key).await);

    info!("✅ Deletion caching test passed");
    Ok(())
}

async fn test_performance_under_load() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 5: Performance Characteristics Under Load");

    let config = BulkDeletionConfig {
        max_transaction_size: 50,
        min_bulk_threshold: 10,
        enable_parallel_deletion: true,
        parallel_workers: 4,
        transaction_timeout_ms: 2000,
        enable_result_caching: false, // Disable for performance testing
        cache_ttl_seconds: 300, // Default value
        enable_statistics: true,
    };
    let optimizer = BulkDeletionOptimizer::new(config);

    // Test scenarios with increasing load
    let load_scenarios = vec![
        (100, "Light Load"),
        (500, "Medium Load"),
        (1000, "Heavy Load"),
        (2000, "Extreme Load"),
    ];

    for (key_count, scenario_name) in load_scenarios {
        info!("📊 Testing scenario: {} ({} keys)", scenario_name, key_count);

        let test_keys = create_test_keys(key_count, 2);
        let key_groups = optimizer.optimize_key_grouping(test_keys).await;

        // Mock deletion function with variable processing time
        let deletion_fn = |keys: Vec<DeletionKey>| async move {
            let total_size: u64 = keys.iter().map(|k| k.estimated_size).sum();
            
            // Simulate processing time that scales with batch size
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

        let scenario_start = SystemTime::now();
        let result = optimizer.execute_bulk_deletion(key_groups, deletion_fn).await?;
        let scenario_duration = scenario_start.elapsed().unwrap();

        debug!(
            "Scenario '{}': {} keys deleted in {:?} (rate: {:.1} keys/sec)",
            scenario_name,
            result.keys_deleted,
            scenario_duration,
            result.keys_deleted as f64 / scenario_duration.as_secs_f64()
        );

        assert_eq!(result.keys_deleted, key_count as u64);
        assert_eq!(result.failed_deletions, 0);
    }

    // Generate performance report
    let final_stats = optimizer.get_stats().await;
    let performance_report = optimizer.generate_performance_report().await;
    
    info!("📈 Final Performance Statistics:");
    info!("Total bulk operations: {}", final_stats.total_bulk_operations);
    info!("Total keys deleted: {}", final_stats.total_keys_deleted);
    info!("Average deletion rate: {:.1} keys/sec", final_stats.avg_deletion_rate_per_sec);
    info!("Efficiency ratio: {:.1}%", final_stats.efficiency_ratio * 100.0);

    debug!("📄 Full Performance Report:\n{}", performance_report);

    assert!(final_stats.total_bulk_operations >= 4); // Should have multiple operations
    assert!(final_stats.avg_deletion_rate_per_sec > 0.0);
    assert!(final_stats.efficiency_ratio > 0.9); // Should be >90% efficient

    info!("✅ Performance under load test passed");
    Ok(())
}

async fn test_timeout_handling() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Test 6: Transaction Timeout Handling");

    let config = BulkDeletionConfig {
        max_transaction_size: 5,
        transaction_timeout_ms: 100, // Very short timeout for testing
        enable_parallel_deletion: false,
        ..Default::default()
    };
    let optimizer = BulkDeletionOptimizer::new(config);

    let test_keys = create_test_keys(3, 1);
    let key_groups = optimizer.optimize_key_grouping(test_keys).await;

    // Mock deletion function that takes longer than timeout
    let slow_deletion_fn = |keys: Vec<DeletionKey>| async move {
        // Sleep longer than the timeout
        sleep(Duration::from_millis(200)).await;
        let total_size: u64 = keys.iter().map(|k| k.estimated_size).sum();
        Ok(TransactionResult {
            keys_count: keys.len(),
            bytes_reclaimed: total_size,
            duration_ms: 200,
            success: true,
            error_message: None,
        })
    };

    let result = optimizer.execute_bulk_deletion(key_groups, slow_deletion_fn).await?;

    // Should have timeout failures
    assert!(result.failed_deletions > 0);
    
    // Check that timeout was properly recorded
    let stats = optimizer.get_stats().await;
    assert!(stats.timeout_errors > 0 || stats.failed_transactions > 0);

    info!("✅ Timeout handling test passed");
    Ok(())
}

/// Helper function to create test keys
fn create_test_keys(count: usize, priority: u8) -> Vec<DeletionKey> {
    (0..count)
        .map(|i| DeletionKey {
            key: format!("test_key_{}", i).into_bytes(),
            estimated_size: 100 + (i as u64 * 50), // Variable sizes
            priority,
            expiration_time: 1000 + (i as u64 * 100),
        })
        .collect()
}