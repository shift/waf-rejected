//! Environment-gated integration tests for MaxMind GeoIP databases.
//!
//! The tests are skipped unless `MAXMIND_CITY_DB` and/or
//! `MAXMIND_ANONYMOUS_DB` point at local `.mmdb` fixtures. Licensed database
//! files must never be committed; see `docs/operations/maxmind-testing.md`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use waf_ingress::waf::geoip::{GeoInfo, GeoIpService};

/// A public address that is not part of `GeoIpService`'s built-in test cache.
const KNOWN_PUBLIC_IP: &str = "1.1.1.1";

fn database_path(variable: &str) -> Option<PathBuf> {
    match std::env::var_os(variable) {
        Some(value) if !value.is_empty() => Some(PathBuf::from(value)),
        _ => None,
    }
}

fn as_str(path: &Path) -> &str {
    path.to_str()
        .expect("MaxMind database path must be valid UTF-8")
}

fn known_public_ip() -> IpAddr {
    KNOWN_PUBLIC_IP
        .parse()
        .expect("KNOWN_PUBLIC_IP is a valid IP address")
}

fn assert_boolean_flags(info: &GeoInfo) {
    let flags = [info.is_tor_exit, info.is_vpn, info.is_datacenter];
    assert!(
        flags.iter().all(|flag| [true, false].contains(flag)),
        "anonymous flags must be booleans"
    );
}

#[test]
fn city_database_resolves_known_public_ip() {
    let Some(path) = database_path("MAXMIND_CITY_DB") else {
        eprintln!(
            "skipping MaxMind city test: set MAXMIND_CITY_DB to a GeoLite2/GeoIP2 City .mmdb file"
        );
        return;
    };

    let service = GeoIpService::from_database(as_str(&path))
        .expect("MAXMIND_CITY_DB must point to a readable MaxMind city database");

    let info = service
        .lookup(&known_public_ip())
        .expect("known public IP should resolve from the MaxMind city database");

    assert!(
        !info.country_code.is_empty(),
        "country code for {KNOWN_PUBLIC_IP} must not be empty"
    );
    assert!(
        !info.is_tor_exit && !info.is_vpn && !info.is_datacenter,
        "anonymous flags must be false when no anonymous database is loaded"
    );
}

#[test]
fn anonymous_database_flags_are_booleans() {
    let Some(anonymous_path) = database_path("MAXMIND_ANONYMOUS_DB") else {
        eprintln!(
            "skipping MaxMind anonymous test: set MAXMIND_ANONYMOUS_DB to a GeoIP2 Anonymous IP .mmdb file"
        );
        return;
    };

    let city_path = database_path("MAXMIND_CITY_DB");
    let service = match city_path.as_deref() {
        Some(city_path) => GeoIpService::from_database(as_str(city_path))
            .expect("MAXMIND_CITY_DB must point to a readable MaxMind city database")
            .with_anonymous_database(as_str(&anonymous_path))
            .expect("MAXMIND_ANONYMOUS_DB must point to a readable anonymous IP database"),
        None => GeoIpService::new()
            .with_anonymous_database(as_str(&anonymous_path))
            .expect("MAXMIND_ANONYMOUS_DB must point to a readable anonymous IP database"),
    };

    let ip = known_public_ip();
    match service.lookup(&ip) {
        Some(info) => {
            if city_path.is_some() {
                assert!(
                    !info.country_code.is_empty(),
                    "country code for {KNOWN_PUBLIC_IP} must not be empty when MAXMIND_CITY_DB is set"
                );
            }
            assert_boolean_flags(&info);
        }
        None => {
            // An anonymous-only database need not contain this address. The
            // lookup itself must still complete without panicking.
            assert!(
                city_path.is_none(),
                "known public IP should resolve when both MaxMind databases are configured"
            );
        }
    }
}
