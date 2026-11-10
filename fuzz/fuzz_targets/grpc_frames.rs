#![no_main]

use libfuzzer_sys::fuzz_target;
use waf_ingress::waf::grpc::{parse_method_path, validate_frames, FrameLimits};

fuzz_target!(|data: &[u8]| {
    let limits = FrameLimits {
        max_message_bytes: 1024 * 1024,
        max_frames: 64,
    };
    let _ = validate_frames(data, limits);

    // The same bytes are also exercised as a method path so the path parser
    // sees arbitrary UTF-8 (and lossy non-UTF-8) input.
    let _ = parse_method_path(&String::from_utf8_lossy(data));
});
