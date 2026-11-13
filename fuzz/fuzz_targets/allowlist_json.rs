#![no_main]

use libfuzzer_sys::fuzz_target;
use waf_ingress::waf::grpc_allowlist::{
    build_allowlist, parse_allowlist, parse_descriptor_set, AllowlistOptions, DescriptorFormat,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_allowlist(data);
    let _ = parse_descriptor_set(data, DescriptorFormat::Auto);
    let _ = build_allowlist(data, DescriptorFormat::Auto, &AllowlistOptions::default());
});
