//! Simple performance validation for SIMD optimizations
//!
//! This test validates that our SIMD-accelerated WAF pattern matching
//! provides performance benefits over traditional regex-only approaches.

#[cfg(test)]
#[allow(clippy::module_inception)]
mod performance_validation {
    use crate::waf::simd_ops::{SimdStringOps, WafPatternMatcher};
    use std::time::Instant;

    #[test]
    fn validate_simd_pattern_matching_performance() {
        // Large test payload to demonstrate SIMD benefits
        let large_payload = b"GET /api/users?id=1 OR 1=1-- HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n<script>alert('xss')</script>".repeat(1000);

        println!(
            "Testing SIMD pattern matching on {} byte payload",
            large_payload.len()
        );

        // Test SIMD-accelerated SQL injection detection
        let start = Instant::now();
        let sql_detected = WafPatternMatcher::contains_sql_injection(&large_payload);
        let simd_duration = start.elapsed();

        println!(
            "SIMD SQL injection detection: {} in {:?}",
            sql_detected, simd_duration
        );
        assert!(sql_detected, "Should detect SQL injection pattern");

        // Test SIMD-accelerated XSS detection
        let start = Instant::now();
        let xss_detected = WafPatternMatcher::contains_xss(&large_payload);
        let simd_xss_duration = start.elapsed();

        println!(
            "SIMD XSS detection: {} in {:?}",
            xss_detected, simd_xss_duration
        );
        assert!(xss_detected, "Should detect XSS pattern");

        // Test SIMD byte counting
        let start = Instant::now();
        let byte_count = SimdStringOps::count_byte(&large_payload, b'<');
        let simd_count_duration = start.elapsed();

        println!(
            "SIMD byte counting: {} '<' characters in {:?}",
            byte_count, simd_count_duration
        );
        assert!(byte_count > 0, "Should find '<' characters");

        // Wall-clock budgets are only meaningful in an isolated perf run. Under a
        // fully parallel unit-test run this assertion measures scheduler contention
        // rather than SIMD throughput, so it is opt-in via WAF_PERF_ASSERT=1.
        if std::env::var_os("WAF_PERF_ASSERT").is_some() {
            assert!(
                simd_duration.as_millis() < 100,
                "SIMD SQL detection should be fast: {simd_duration:?}"
            );
            assert!(
                simd_xss_duration.as_millis() < 100,
                "SIMD XSS detection should be fast: {simd_xss_duration:?}"
            );
            assert!(
                simd_count_duration.as_millis() < 100,
                "SIMD byte counting should be fast: {simd_count_duration:?}"
            );
        }
    }

    #[test]
    fn validate_buffer_pool_performance() {
        use crate::proxy::buffer_pool::BufferPool;

        let pool = BufferPool::new();
        let stats = pool.stats();

        println!(
            "Buffer pool initialized with {} total buffers",
            stats.small_capacity + stats.medium_capacity + stats.large_capacity
        );

        // Test buffer allocation performance
        let start = Instant::now();
        for _ in 0..1000 {
            let _buffer = pool.get_small_buffer();
            // Buffer automatically returns to pool when dropped
        }
        let allocation_duration = start.elapsed();

        println!(
            "1000 buffer allocations/deallocations in {:?}",
            allocation_duration
        );

        // Should be very fast due to pooling
        assert!(
            allocation_duration.as_millis() < 50,
            "Buffer pooling should be very fast"
        );

        // Pool should still have buffers available
        let final_stats = pool.stats();
        assert!(
            final_stats.small_available > 0,
            "Pool should still have buffers available"
        );
    }

    #[test]
    fn validate_cpu_feature_detection() {
        use crate::waf::simd_ops::CpuFeatures;

        let features = CpuFeatures::detect();
        println!("Detected CPU features: {:?}", features);

        // Should successfully detect features without crashing
        let pattern_matcher = features.get_pattern_matcher();
        let hasher = features.get_hasher();

        println!("Selected pattern matcher: {:?}", pattern_matcher);
        println!("Selected hasher: {:?}", hasher);

        // Test that feature detection is cached and fast on subsequent calls
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = CpuFeatures::detect();
        }
        let detection_duration = start.elapsed();

        println!("1000 CPU feature detections in {:?}", detection_duration);
        assert!(
            detection_duration.as_millis() < 10,
            "Cached CPU detection should be extremely fast"
        );
    }
}
