use crate::waf::{Decision, RequestContext, WafRule};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u32,
    tokens: u32,
    refill_rate: u32, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, tokens: u32) -> bool {
        self.refill();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let new_tokens = (elapsed.as_secs_f64() * self.refill_rate as f64) as u32;

        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }

    pub fn available_tokens(&mut self) -> u32 {
        self.refill();
        self.tokens
    }
}

/// Per-IP rate limiter
pub struct RateLimiter {
    name: String,
    buckets: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
    capacity: u32,
    refill_rate: u32,
    window_size: Duration,
    enabled: bool,
}

impl RateLimiter {
    pub fn new(name: &str, capacity: u32, refill_rate: u32, window_size: Duration) -> Self {
        Self {
            name: name.to_string(),
            buckets: Arc::new(RwLock::new(HashMap::new())),
            capacity,
            refill_rate,
            window_size,
            enabled: true,
        }
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    fn cleanup_expired_buckets(&self) {
        let mut buckets = self.buckets.write().unwrap();
        let now = Instant::now();

        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < self.window_size * 2);
    }
}

impl WafRule for RateLimiter {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        // Periodically clean up expired buckets
        if rand::random::<f32>() < 0.01 {
            // 1% chance
            self.cleanup_expired_buckets();
        }

        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets
            .entry(ctx.client_ip)
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_rate));

        if bucket.try_consume(1) {
            debug!(
                "Rate limit check passed for {}, {} tokens remaining",
                ctx.client_ip,
                bucket.available_tokens()
            );
            Decision::Allow
        } else {
            warn!("Rate limit exceeded for {}", ctx.client_ip);
            Decision::RateLimit {
                reason: format!(
                    "Rate limit exceeded: {} requests per {} seconds",
                    self.capacity,
                    self.window_size.as_secs()
                ),
            }
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Global rate limiter across all IPs
pub struct GlobalRateLimiter {
    name: String,
    bucket: Arc<RwLock<TokenBucket>>,
    enabled: bool,
}

impl GlobalRateLimiter {
    pub fn new(name: &str, capacity: u32, refill_rate: u32) -> Self {
        Self {
            name: name.to_string(),
            bucket: Arc::new(RwLock::new(TokenBucket::new(capacity, refill_rate))),
            enabled: true,
        }
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

impl WafRule for GlobalRateLimiter {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _ctx: &RequestContext) -> Decision {
        let mut bucket = self.bucket.write().unwrap();

        if bucket.try_consume(1) {
            debug!(
                "Global rate limit check passed, {} tokens remaining",
                bucket.available_tokens()
            );
            Decision::Allow
        } else {
            warn!("Global rate limit exceeded");
            Decision::RateLimit {
                reason: "Global rate limit exceeded".to_string(),
            }
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Adaptive rate limiter that adjusts based on threat levels
pub struct AdaptiveRateLimiter {
    name: String,
    buckets: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
    base_capacity: u32,
    base_refill_rate: u32,
    threat_multiplier: f32,
    enabled: bool,
}

impl AdaptiveRateLimiter {
    pub fn new(name: &str, base_capacity: u32, base_refill_rate: u32) -> Self {
        Self {
            name: name.to_string(),
            buckets: Arc::new(RwLock::new(HashMap::new())),
            base_capacity,
            base_refill_rate,
            threat_multiplier: 1.0,
            enabled: true,
        }
    }

    pub fn set_threat_multiplier(&mut self, multiplier: f32) {
        self.threat_multiplier = multiplier.max(0.1).min(10.0);
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    fn get_adjusted_limits(&self) -> (u32, u32) {
        let capacity = ((self.base_capacity as f32) / self.threat_multiplier) as u32;
        let refill_rate = ((self.base_refill_rate as f32) / self.threat_multiplier) as u32;
        (capacity.max(1), refill_rate.max(1))
    }
}

impl WafRule for AdaptiveRateLimiter {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        let (capacity, refill_rate) = self.get_adjusted_limits();
        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets
            .entry(ctx.client_ip)
            .or_insert_with(|| TokenBucket::new(capacity, refill_rate));

        // Update existing bucket parameters if they've changed
        if bucket.capacity != capacity || bucket.refill_rate != refill_rate {
            bucket.capacity = capacity;
            bucket.refill_rate = refill_rate;
            // Don't reduce tokens below the new capacity
            bucket.tokens = bucket.tokens.min(capacity);
        }

        if bucket.try_consume(1) {
            debug!(
                "Adaptive rate limit check passed for {}, {} tokens remaining",
                ctx.client_ip,
                bucket.available_tokens()
            );
            Decision::Allow
        } else {
            warn!(
                "Adaptive rate limit exceeded for {} (multiplier: {})",
                ctx.client_ip, self.threat_multiplier
            );
            Decision::RateLimit {
                reason: format!(
                    "Adaptive rate limit exceeded: {} requests per second (threat level: {:.2})",
                    refill_rate, self.threat_multiplier
                ),
            }
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Burst rate limiter for handling traffic spikes
pub struct BurstRateLimiter {
    name: String,
    buckets: Arc<RwLock<HashMap<IpAddr, (TokenBucket, TokenBucket)>>>,
    normal_capacity: u32,
    normal_refill: u32,
    burst_capacity: u32,
    burst_refill: u32,
    enabled: bool,
}

impl BurstRateLimiter {
    pub fn new(
        name: &str,
        normal_capacity: u32,
        normal_refill: u32,
        burst_capacity: u32,
        burst_refill: u32,
    ) -> Self {
        Self {
            name: name.to_string(),
            buckets: Arc::new(RwLock::new(HashMap::new())),
            normal_capacity,
            normal_refill,
            burst_capacity,
            burst_refill,
            enabled: true,
        }
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

impl WafRule for BurstRateLimiter {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        let mut buckets = self.buckets.write().unwrap();
        let (normal_bucket, burst_bucket) = buckets.entry(ctx.client_ip).or_insert_with(|| {
            (
                TokenBucket::new(self.normal_capacity, self.normal_refill),
                TokenBucket::new(self.burst_capacity, self.burst_refill),
            )
        });

        // Try normal bucket first
        if normal_bucket.try_consume(1) {
            debug!("Normal rate limit check passed for {}", ctx.client_ip);
            Decision::Allow
        }
        // Fall back to burst bucket
        else if burst_bucket.try_consume(1) {
            debug!("Burst rate limit check passed for {}", ctx.client_ip);
            Decision::Allow
        }
        // Both buckets exhausted
        else {
            warn!("Burst rate limit exceeded for {}", ctx.client_ip);
            Decision::RateLimit {
                reason: "Burst rate limit exceeded".to_string(),
            }
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Rate limiter factory for creating common rate limiting configurations
pub struct RateLimiterFactory;

impl RateLimiterFactory {
    /// Creates a basic per-IP rate limiter (100 req/min)
    pub fn create_basic_rate_limiter() -> RateLimiter {
        RateLimiter::new(
            "basic_rate_limit",
            100, // capacity
            2,   // ~100 requests per minute
            Duration::from_secs(60),
        )
    }

    /// Creates a strict per-IP rate limiter (20 req/min)
    pub fn create_strict_rate_limiter() -> RateLimiter {
        RateLimiter::new(
            "strict_rate_limit",
            20, // capacity
            1,  // ~20 requests per minute
            Duration::from_secs(60),
        )
    }

    /// Creates a global rate limiter (1000 req/sec)
    pub fn create_global_rate_limiter() -> GlobalRateLimiter {
        GlobalRateLimiter::new(
            "global_rate_limit",
            1000, // capacity
            1000, // refill rate
        )
    }

    /// Creates an adaptive rate limiter
    pub fn create_adaptive_rate_limiter() -> AdaptiveRateLimiter {
        AdaptiveRateLimiter::new(
            "adaptive_rate_limit",
            50, // base capacity
            1,  // base refill rate
        )
    }

    /// Creates a burst rate limiter
    pub fn create_burst_rate_limiter() -> BurstRateLimiter {
        BurstRateLimiter::new(
            "burst_rate_limit",
            10, // normal capacity
            1,  // normal refill
            50, // burst capacity
            1,  // burst refill
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Method, Uri};
    use std::str::FromStr;

    fn create_test_context(ip: &str) -> RequestContext {
        RequestContext::new(
            IpAddr::from_str(ip).unwrap(),
            Method::GET,
            Uri::from_str("/test").unwrap(),
            hyper::HeaderMap::new(),
            None,
        )
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 5);

        // Should be able to consume initial capacity
        assert!(bucket.try_consume(10));
        assert_eq!(bucket.available_tokens(), 0);

        // Should not be able to consume more
        assert!(!bucket.try_consume(1));
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new("test", 2, 1, Duration::from_secs(1));
        let ctx = create_test_context("192.168.1.1");

        // First two requests should pass
        assert_eq!(limiter.evaluate(&ctx), Decision::Allow);
        assert_eq!(limiter.evaluate(&ctx), Decision::Allow);

        // Third request should be rate limited
        match limiter.evaluate(&ctx) {
            Decision::RateLimit { .. } => {}
            _ => panic!("Expected RateLimit decision"),
        }
    }

    #[test]
    fn test_global_rate_limiter() {
        let limiter = GlobalRateLimiter::new("test", 1, 1);
        let ctx1 = create_test_context("192.168.1.1");
        let ctx2 = create_test_context("192.168.1.2");

        // First request should pass
        assert_eq!(limiter.evaluate(&ctx1), Decision::Allow);

        // Second request from different IP should be rate limited
        match limiter.evaluate(&ctx2) {
            Decision::RateLimit { .. } => {}
            _ => panic!("Expected RateLimit decision"),
        }
    }

    #[test]
    fn test_adaptive_rate_limiter() {
        let mut limiter = AdaptiveRateLimiter::new("test", 4, 1);
        let ctx = create_test_context("192.168.1.1");

        // With normal threat level, should allow 4 requests
        for _ in 0..4 {
            assert_eq!(limiter.evaluate(&ctx), Decision::Allow);
        }

        // Fifth should be limited
        match limiter.evaluate(&ctx) {
            Decision::RateLimit { .. } => {}
            _ => panic!("Expected RateLimit decision"),
        }

        // Increase threat level and test with same limiter
        limiter.set_threat_multiplier(2.0);
        let mut limiter2 = AdaptiveRateLimiter::new("test2", 4, 1);
        limiter2.set_threat_multiplier(2.0); // Apply threat multiplier to new instance
        let ctx2 = create_test_context("192.168.1.3");

        // Should now allow only 2 requests (4/2)
        assert_eq!(limiter2.evaluate(&ctx2), Decision::Allow);
        assert_eq!(limiter2.evaluate(&ctx2), Decision::Allow);

        match limiter2.evaluate(&ctx2) {
            Decision::RateLimit { .. } => {}
            _ => panic!("Expected RateLimit decision"),
        }
    }
}
