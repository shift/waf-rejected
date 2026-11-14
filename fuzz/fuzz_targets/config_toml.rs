#![no_main]

use libfuzzer_sys::fuzz_target;
use waf_ingress::config::Config;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Deserialization is allowed to fail; it must never panic.
    if let Ok(config) = toml::from_str::<Config>(text) {
        let _ = config.validate();
    }
});
