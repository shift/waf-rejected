use crate::waf::{Decision, RequestContext, WafRule};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::IpAddr;

/// Geographic information for an IP address
#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country_code: String,
    pub country_name: String,
    pub region: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub is_tor_exit: bool,
    pub is_vpn: bool,
    pub is_datacenter: bool,
    pub asn: u32,
    pub asn_org: String,
}

/// Simple GeoIP lookup service (placeholder for MaxMind/IP2Location integration)
pub struct GeoIpService {
    // For now, use a simple in-memory cache
    // TODO: Integrate with MaxMind GeoLite2 database before K/V integration
    cache: HashMap<IpAddr, GeoInfo>,
}

impl GeoIpService {
    pub fn new() -> Self {
        Self {
            cache: Self::init_test_data(),
        }
    }

    /// Initialize with some test data for development
    /// TODO: Replace with actual MaxMind database loading
    fn init_test_data() -> HashMap<IpAddr, GeoInfo> {
        let mut cache = HashMap::new();

        // Add some test data for common IP ranges
        if let Ok(ip) = "8.8.8.8".parse() {
            cache.insert(
                ip,
                GeoInfo {
                    country_code: "US".to_string(),
                    country_name: "United States".to_string(),
                    region: "California".to_string(),
                    city: "Mountain View".to_string(),
                    latitude: 37.4056,
                    longitude: -122.0775,
                    is_tor_exit: false,
                    is_vpn: false,
                    is_datacenter: true,
                    asn: 15169,
                    asn_org: "Google LLC".to_string(),
                },
            );
        }

        // Add a known bad IP for testing
        if let Ok(ip) = "192.0.2.1".parse() {
            cache.insert(
                ip,
                GeoInfo {
                    country_code: "XX".to_string(),
                    country_name: "Unknown".to_string(),
                    region: "Unknown".to_string(),
                    city: "Unknown".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    is_tor_exit: true, // Mark as Tor for testing
                    is_vpn: false,
                    is_datacenter: false,
                    asn: 0,
                    asn_org: "Unknown".to_string(),
                },
            );
        }

        cache
    }

    /// Look up geographic information for an IP address
    pub fn lookup(&self, ip: &IpAddr) -> Option<&GeoInfo> {
        // First check cache
        if let Some(geo_info) = self.cache.get(ip) {
            return Some(geo_info);
        }

        // TODO: Implement actual MaxMind database lookup
        // For now, return default info for unknown IPs
        None
    }

    /// Update cache with new geo information
    /// TODO: This will be replaced by K/V store integration
    pub fn update_cache(&mut self, ip: IpAddr, info: GeoInfo) {
        self.cache.insert(ip, info);
    }

    /// Get default geo info for unknown IPs
    pub fn default_geo_info(&self) -> GeoInfo {
        GeoInfo {
            country_code: "XX".to_string(),
            country_name: "Unknown".to_string(),
            region: "Unknown".to_string(),
            city: "Unknown".to_string(),
            latitude: 0.0,
            longitude: 0.0,
            is_tor_exit: false,
            is_vpn: false,
            is_datacenter: false,
            asn: 0,
            asn_org: "Unknown".to_string(),
        }
    }
}

impl Default for GeoIpService {
    fn default() -> Self {
        Self::new()
    }
}

/// Global GeoIP service instance
static GEOIP_SERVICE: Lazy<std::sync::Mutex<GeoIpService>> =
    Lazy::new(|| std::sync::Mutex::new(GeoIpService::new()));

/// Get the global GeoIP service instance
pub fn geoip_service() -> &'static std::sync::Mutex<GeoIpService> {
    &GEOIP_SERVICE
}

/// Geographic blocking rule based on country, region, or specific characteristics
pub struct GeoBlockingRule {
    name: String,
    enabled: bool,
    blocked_countries: Vec<String>,
    blocked_regions: Vec<String>,
    block_tor: bool,
    block_vpn: bool,
    block_datacenter: bool,
    allowed_countries: Option<Vec<String>>, // If set, only allow these countries
}

impl GeoBlockingRule {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            enabled: true,
            blocked_countries: Vec::new(),
            blocked_regions: Vec::new(),
            block_tor: false,
            block_vpn: false,
            block_datacenter: false,
            allowed_countries: None,
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn block_country(mut self, country_code: &str) -> Self {
        self.blocked_countries.push(country_code.to_uppercase());
        self
    }

    pub fn block_countries(mut self, country_codes: Vec<&str>) -> Self {
        for country in country_codes {
            self.blocked_countries.push(country.to_uppercase());
        }
        self
    }

    pub fn allow_only_countries(mut self, country_codes: Vec<&str>) -> Self {
        self.allowed_countries = Some(
            country_codes
                .into_iter()
                .map(|c| c.to_uppercase())
                .collect(),
        );
        self
    }

    pub fn block_tor(mut self, block: bool) -> Self {
        self.block_tor = block;
        self
    }

    pub fn block_vpn(mut self, block: bool) -> Self {
        self.block_vpn = block;
        self
    }

    pub fn block_datacenter(mut self, block: bool) -> Self {
        self.block_datacenter = block;
        self
    }

    pub fn block_region(mut self, region: &str) -> Self {
        self.blocked_regions.push(region.to_string());
        self
    }
}

impl WafRule for GeoBlockingRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }

        let geo_service = geoip_service().lock().unwrap();
        let geo_info = geo_service
            .lookup(&ctx.client_ip)
            .cloned()
            .unwrap_or_else(|| geo_service.default_geo_info());

        // Check if country is in allowed list (if specified)
        if let Some(ref allowed) = self.allowed_countries {
            if !allowed.contains(&geo_info.country_code) {
                return Decision::Block {
                    status: 403,
                    reason: format!(
                        "Geographic blocking: Country {} not in allowed list",
                        geo_info.country_code
                    ),
                };
            }
        }

        // Check blocked countries
        if self.blocked_countries.contains(&geo_info.country_code) {
            return Decision::Block {
                status: 403,
                reason: format!(
                    "Geographic blocking: Country {} is blocked",
                    geo_info.country_code
                ),
            };
        }

        // Check blocked regions
        if self.blocked_regions.contains(&geo_info.region) {
            return Decision::Block {
                status: 403,
                reason: format!("Geographic blocking: Region {} is blocked", geo_info.region),
            };
        }

        // Check Tor exit nodes
        if self.block_tor && geo_info.is_tor_exit {
            return Decision::Block {
                status: 403,
                reason: "Geographic blocking: Tor exit nodes are blocked".to_string(),
            };
        }

        // Check VPN
        if self.block_vpn && geo_info.is_vpn {
            return Decision::Block {
                status: 403,
                reason: "Geographic blocking: VPN traffic is blocked".to_string(),
            };
        }

        // Check datacenter IPs
        if self.block_datacenter && geo_info.is_datacenter {
            return Decision::Block {
                status: 403,
                reason: format!(
                    "Geographic blocking: Datacenter IP from {} blocked",
                    geo_info.asn_org
                ),
            };
        }

        Decision::Allow
    }
}

/// Factory for creating common geographic blocking rules
pub struct GeoBlockingRuleFactory;

impl GeoBlockingRuleFactory {
    /// Create a country blocking rule
    pub fn create_country_rule(
        country_code: &str,
        _geoip_service: std::sync::Arc<GeoIpService>,
    ) -> GeoBlockingRule {
        GeoBlockingRule::new(&format!("Block Country {}", country_code))
            .block_countries(vec![country_code])
    }

    /// Create a Tor blocking rule
    pub fn create_tor_blocking_rule(
        _geoip_service: std::sync::Arc<GeoIpService>,
    ) -> GeoBlockingRule {
        GeoBlockingRule::new("Block Tor Traffic").block_tor(true)
    }

    /// Block high-risk countries commonly associated with malicious traffic
    pub fn high_risk_countries_rule() -> GeoBlockingRule {
        GeoBlockingRule::new("High Risk Countries").block_countries(vec![
            // Note: These are examples - adjust based on your actual risk assessment
            "CN", "RU", "KP", "IR", // Common high-risk countries
        ])
    }

    /// Block Tor and VPN traffic
    pub fn anonymization_blocking_rule() -> GeoBlockingRule {
        GeoBlockingRule::new("Block Anonymization Services")
            .block_tor(true)
            .block_vpn(true)
    }

    /// Block datacenter traffic to prevent bot attacks
    pub fn datacenter_blocking_rule() -> GeoBlockingRule {
        GeoBlockingRule::new("Block Datacenter Traffic").block_datacenter(true)
    }

    /// Allow only specific countries (for region-specific applications)
    pub fn country_allowlist_rule(allowed_countries: Vec<&str>) -> GeoBlockingRule {
        GeoBlockingRule::new("Country Allowlist").allow_only_countries(allowed_countries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{HeaderMap, Method, Uri};
    use std::str::FromStr;

    fn create_test_context(ip: &str) -> RequestContext {
        RequestContext::new(
            IpAddr::from_str(ip).unwrap(),
            Method::GET,
            Uri::from_str("/").unwrap(),
            HeaderMap::new(),
            None,
        )
    }

    #[test]
    fn test_geoip_service_lookup() {
        let service = GeoIpService::new();

        // Test known IP
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        if let Some(info) = service.lookup(&ip) {
            assert_eq!(info.country_code, "US");
            assert_eq!(info.asn, 15169);
            assert_eq!(info.asn_org, "Google LLC");
        } else {
            panic!("Expected to find geo info for 8.8.8.8");
        }

        // Test unknown IP
        let ip: IpAddr = "203.0.113.100".parse().unwrap();
        assert!(service.lookup(&ip).is_none());
    }

    #[test]
    fn test_country_blocking() {
        let rule = GeoBlockingRule::new("Country Block Test")
            .block_country("CN")
            .block_country("RU");

        // Test US IP (should be allowed)
        let ctx = create_test_context("8.8.8.8");
        assert_eq!(rule.evaluate(&ctx), Decision::Allow);

        // Since we don't have CN/RU IPs in test data, this tests the default case
        let ctx = create_test_context("203.0.113.100");
        assert_eq!(rule.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn test_tor_blocking() {
        let rule = GeoBlockingRule::new("Tor Block Test").block_tor(true);

        // Test Tor exit node (using our test data)
        let ctx = create_test_context("192.0.2.1");
        match rule.evaluate(&ctx) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("Tor exit nodes"));
            }
            _ => panic!("Expected Tor IP to be blocked"),
        }

        // Test regular IP
        let ctx = create_test_context("8.8.8.8");
        assert_eq!(rule.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn test_datacenter_blocking() {
        let rule = GeoBlockingRule::new("Datacenter Block Test").block_datacenter(true);

        // Test datacenter IP (Google)
        let ctx = create_test_context("8.8.8.8");
        match rule.evaluate(&ctx) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("Datacenter IP"));
            }
            _ => panic!("Expected datacenter IP to be blocked"),
        }
    }

    #[test]
    fn test_country_allowlist() {
        let rule =
            GeoBlockingRule::new("Allowlist Test").allow_only_countries(vec!["US", "CA", "GB"]);

        // Test allowed country
        let ctx = create_test_context("8.8.8.8");
        assert_eq!(rule.evaluate(&ctx), Decision::Allow);

        // Test unknown country (should be blocked)
        let ctx = create_test_context("203.0.113.100");
        match rule.evaluate(&ctx) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("not in allowed list"));
            }
            _ => panic!("Expected non-allowed country to be blocked"),
        }
    }

    #[test]
    fn test_disabled_rule() {
        let rule = GeoBlockingRule::new("Disabled Test")
            .block_tor(true)
            .enabled(false);

        // Even Tor IP should be allowed when rule is disabled
        let ctx = create_test_context("192.0.2.1");
        assert_eq!(rule.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn test_geoip_cache_update() {
        let mut service = GeoIpService::new();

        let test_ip: IpAddr = "203.0.113.200".parse().unwrap();
        let test_info = GeoInfo {
            country_code: "FR".to_string(),
            country_name: "France".to_string(),
            region: "Île-de-France".to_string(),
            city: "Paris".to_string(),
            latitude: 48.8566,
            longitude: 2.3522,
            is_tor_exit: false,
            is_vpn: false,
            is_datacenter: false,
            asn: 12345,
            asn_org: "Test ISP".to_string(),
        };

        service.update_cache(test_ip, test_info);

        if let Some(cached_info) = service.lookup(&test_ip) {
            assert_eq!(cached_info.country_code, "FR");
            assert_eq!(cached_info.city, "Paris");
        } else {
            panic!("Expected cached geo info");
        }
    }

    #[test]
    fn test_factory_rules() {
        let high_risk_rule = GeoBlockingRuleFactory::high_risk_countries_rule();
        assert_eq!(high_risk_rule.name(), "High Risk Countries");
        assert!(high_risk_rule.is_enabled());

        let tor_rule = GeoBlockingRuleFactory::anonymization_blocking_rule();
        assert_eq!(tor_rule.name(), "Block Anonymization Services");

        let datacenter_rule = GeoBlockingRuleFactory::datacenter_blocking_rule();
        assert_eq!(datacenter_rule.name(), "Block Datacenter Traffic");

        let allowlist_rule = GeoBlockingRuleFactory::country_allowlist_rule(vec!["US", "CA"]);
        assert_eq!(allowlist_rule.name(), "Country Allowlist");
    }

    #[test]
    fn test_default_geo_info() {
        let service = GeoIpService::new();
        let default_info = service.default_geo_info();

        assert_eq!(default_info.country_code, "XX");
        assert_eq!(default_info.country_name, "Unknown");
        assert!(!default_info.is_tor_exit);
        assert!(!default_info.is_vpn);
        assert!(!default_info.is_datacenter);
    }
}
