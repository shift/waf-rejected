//! CPU feature detection and SIMD-accelerated operations
//!
//! This module provides runtime CPU feature detection optimized for GKE/K8s
//! environments, with SIMD-accelerated pattern matching for WAF rules.
//! Compatible across different deployment environments with graceful fallback.

use std::sync::atomic::{AtomicBool, Ordering};

/// CPU features available for optimization
#[derive(Debug, Clone)]
pub struct CpuFeatures {
    pub sse2: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub avx512bw: bool,
    pub bmi1: bool,
    pub bmi2: bool,
    pub popcnt: bool,
    pub aes: bool,
}

/// Global CPU feature detection result (cached)
static CPU_FEATURES_DETECTED: AtomicBool = AtomicBool::new(false);
static mut CPU_FEATURES: Option<CpuFeatures> = None;

impl CpuFeatures {
    /// Detect CPU features once and cache the result
    pub fn detect() -> &'static CpuFeatures {
        if !CPU_FEATURES_DETECTED.load(Ordering::Acquire) {
            let features = Self::detect_features();
            unsafe {
                CPU_FEATURES = Some(features);
            }
            CPU_FEATURES_DETECTED.store(true, Ordering::Release);
        }

        unsafe { CPU_FEATURES.as_ref().unwrap() }
    }

    /// Perform actual CPU feature detection
    fn detect_features() -> CpuFeatures {
        // Use target_feature attributes for compile-time detection when possible
        CpuFeatures {
            sse2: is_x86_feature_detected!("sse2"),
            sse3: is_x86_feature_detected!("sse3"),
            ssse3: is_x86_feature_detected!("ssse3"),
            sse4_1: is_x86_feature_detected!("sse4.1"),
            sse4_2: is_x86_feature_detected!("sse4.2"),
            avx: is_x86_feature_detected!("avx"),
            avx2: is_x86_feature_detected!("avx2"),
            avx512f: is_x86_feature_detected!("avx512f"),
            avx512bw: is_x86_feature_detected!("avx512bw"),
            bmi1: is_x86_feature_detected!("bmi1"),
            bmi2: is_x86_feature_detected!("bmi2"),
            popcnt: is_x86_feature_detected!("popcnt"),
            aes: is_x86_feature_detected!("aes"),
        }
    }

    /// Get the best pattern matching implementation for available CPU features
    pub fn get_pattern_matcher(&self) -> PatternMatcher {
        if self.avx512bw && self.avx512f {
            PatternMatcher::Avx512
        } else if self.avx2 {
            PatternMatcher::Avx2
        } else if self.sse4_2 {
            PatternMatcher::Sse42
        } else {
            PatternMatcher::Scalar
        }
    }

    /// Get the best hash implementation for available CPU features
    pub fn get_hasher(&self) -> HasherType {
        if self.aes && self.sse4_2 {
            HasherType::AesNi
        } else if self.sse4_2 {
            HasherType::Crc32
        } else {
            HasherType::Scalar
        }
    }
}

/// SIMD-optimized pattern matcher implementations
#[derive(Debug, Clone, Copy)]
pub enum PatternMatcher {
    Scalar,
    Sse42,
    Avx2,
    Avx512,
}

/// Hardware-accelerated hasher types
#[derive(Debug, Clone, Copy)]
pub enum HasherType {
    Scalar,
    Crc32,
    AesNi,
}

/// SIMD-accelerated string operations for WAF pattern matching
pub struct SimdStringOps;

impl SimdStringOps {
    /// Find byte pattern in haystack using best available SIMD instructions
    pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        let cpu_features = CpuFeatures::detect();
        match cpu_features.get_pattern_matcher() {
            PatternMatcher::Avx512 => unsafe { Self::find_pattern_avx512(haystack, needle) },
            PatternMatcher::Avx2 => unsafe { Self::find_pattern_avx2(haystack, needle) },
            PatternMatcher::Sse42 => unsafe { Self::find_pattern_sse42(haystack, needle) },
            PatternMatcher::Scalar => Self::find_pattern_scalar(haystack, needle),
        }
    }

    /// Count byte occurrences using SIMD acceleration
    pub fn count_byte(haystack: &[u8], byte: u8) -> usize {
        let cpu_features = CpuFeatures::detect();
        match cpu_features.get_pattern_matcher() {
            PatternMatcher::Avx2 => unsafe { Self::count_byte_avx2(haystack, byte) },
            PatternMatcher::Sse42 => unsafe { Self::count_byte_sse42(haystack, byte) },
            _ => Self::count_byte_scalar(haystack, byte),
        }
    }

    /// Case-insensitive string comparison with SIMD
    pub fn compare_case_insensitive(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let cpu_features = CpuFeatures::detect();
        match cpu_features.get_pattern_matcher() {
            PatternMatcher::Avx2 => unsafe { Self::compare_case_insensitive_avx2(a, b) },
            PatternMatcher::Sse42 => unsafe { Self::compare_case_insensitive_sse42(a, b) },
            _ => Self::compare_case_insensitive_scalar(a, b),
        }
    }

    /// Fast hash computation for IP addresses and patterns
    pub fn fast_hash(data: &[u8]) -> u64 {
        let cpu_features = CpuFeatures::detect();
        match cpu_features.get_hasher() {
            HasherType::AesNi => unsafe { Self::hash_aes_ni(data) },
            HasherType::Crc32 => unsafe { Self::hash_crc32(data) },
            HasherType::Scalar => Self::hash_scalar(data),
        }
    }
}

// AVX-512 optimized implementations (GKE Tier-1 instances)
impl SimdStringOps {
    #[target_feature(enable = "avx512f,avx512bw")]
    unsafe fn find_pattern_avx512(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        if needle.len() > haystack.len() {
            return None;
        }

        // For small patterns, use scalar - AVX-512 overhead not worth it
        if needle.len() < 8 || haystack.len() < 64 {
            return Self::find_pattern_scalar(haystack, needle);
        }

        // AVX-512 implementation for large patterns
        // This is a simplified version - production would use optimized SIMD algorithms
        Self::find_pattern_avx2(haystack, needle)
    }
}

// AVX2 optimized implementations (Standard GKE instances)
impl SimdStringOps {
    #[target_feature(enable = "avx2")]
    unsafe fn find_pattern_avx2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        if needle.len() > haystack.len() {
            return None;
        }

        // For very small patterns, scalar is faster due to setup overhead
        if needle.len() == 1 {
            return haystack.iter().position(|&b| b == needle[0]);
        }

        if needle.len() < 4 || haystack.len() < 32 {
            return Self::find_pattern_scalar(haystack, needle);
        }

        // Use optimized AVX2 string search for medium/large patterns
        // This is a placeholder - production would use optimized algorithms like:
        // - AVX2 vectorized Boyer-Moore
        // - AVX2 SIMD string comparison with shuffles
        // - Parallel character matching with bit operations

        Self::find_pattern_scalar(haystack, needle) // Fallback for now
    }

    #[target_feature(enable = "avx2")]
    unsafe fn count_byte_avx2(haystack: &[u8], target: u8) -> usize {
        use std::arch::x86_64::*;

        let mut count = 0;
        let mut ptr = haystack.as_ptr();
        let mut remaining = haystack.len();

        // Process 32 bytes at a time with AVX2
        while remaining >= 32 {
            let chunk = _mm256_loadu_si256(ptr as *const __m256i);
            let target_vec = _mm256_set1_epi8(target as i8);
            let compare = _mm256_cmpeq_epi8(chunk, target_vec);
            let mask = _mm256_movemask_epi8(compare) as u32;
            count += mask.count_ones() as usize;

            ptr = ptr.add(32);
            remaining -= 32;
        }

        // Handle remaining bytes with scalar
        let remainder = std::slice::from_raw_parts(ptr, remaining);
        count + remainder.iter().filter(|&&b| b == target).count()
    }

    #[target_feature(enable = "avx2")]
    unsafe fn compare_case_insensitive_avx2(a: &[u8], b: &[u8]) -> bool {
        use std::arch::x86_64::*;

        if a.len() != b.len() {
            return false;
        }

        let mut a_ptr = a.as_ptr();
        let mut b_ptr = b.as_ptr();
        let mut remaining = a.len();

        // Process 32 bytes at a time
        while remaining >= 32 {
            let a_chunk = _mm256_loadu_si256(a_ptr as *const __m256i);
            let b_chunk = _mm256_loadu_si256(b_ptr as *const __m256i);

            // Convert to lowercase using SIMD bit manipulation
            let a_lower = Self::to_lowercase_avx2(a_chunk);
            let b_lower = Self::to_lowercase_avx2(b_chunk);

            // Compare the lowercase versions
            let equal = _mm256_cmpeq_epi8(a_lower, b_lower);
            let mask = _mm256_movemask_epi8(equal);

            if mask != 0xffffffff_u32 as i32 {
                return false; // Found difference
            }

            a_ptr = a_ptr.add(32);
            b_ptr = b_ptr.add(32);
            remaining -= 32;
        }

        // Handle remaining bytes
        let a_remainder = std::slice::from_raw_parts(a_ptr, remaining);
        let b_remainder = std::slice::from_raw_parts(b_ptr, remaining);
        Self::compare_case_insensitive_scalar(a_remainder, b_remainder)
    }

    #[target_feature(enable = "avx2")]
    unsafe fn to_lowercase_avx2(input: std::arch::x86_64::__m256i) -> std::arch::x86_64::__m256i {
        use std::arch::x86_64::*;

        // Check if byte is uppercase (A-Z: 0x41-0x5A)
        let upper_a = _mm256_set1_epi8(b'A' as i8);
        let upper_z = _mm256_set1_epi8(b'Z' as i8);

        let ge_a = _mm256_cmpgt_epi8(input, _mm256_sub_epi8(upper_a, _mm256_set1_epi8(1)));
        let le_z = _mm256_cmpgt_epi8(_mm256_add_epi8(upper_z, _mm256_set1_epi8(1)), input);
        let is_upper = _mm256_and_si256(ge_a, le_z);

        // Add 32 to convert to lowercase (difference between 'A' and 'a')
        let to_lower = _mm256_and_si256(is_upper, _mm256_set1_epi8(32));
        _mm256_add_epi8(input, to_lower)
    }
}

// SSE4.2 optimized implementations (Minimum GKE support)
impl SimdStringOps {
    #[target_feature(enable = "sse4.2")]
    unsafe fn find_pattern_sse42(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        // Use hardware string comparison instructions where beneficial
        if needle.len() == 1 {
            return haystack.iter().position(|&b| b == needle[0]);
        }

        // For small patterns on SSE4.2, scalar might be better
        if needle.len() < 8 || haystack.len() < 16 {
            return Self::find_pattern_scalar(haystack, needle);
        }

        // Simplified SSE4.2 implementation - production would use _mm_cmpistri
        Self::find_pattern_scalar(haystack, needle)
    }

    #[target_feature(enable = "sse4.2")]
    unsafe fn count_byte_sse42(haystack: &[u8], target: u8) -> usize {
        use std::arch::x86_64::*;

        let mut count = 0;
        let mut ptr = haystack.as_ptr();
        let mut remaining = haystack.len();

        // Process 16 bytes at a time with SSE
        while remaining >= 16 {
            let chunk = _mm_loadu_si128(ptr as *const __m128i);
            let target_vec = _mm_set1_epi8(target as i8);
            let compare = _mm_cmpeq_epi8(chunk, target_vec);
            let mask = _mm_movemask_epi8(compare) as u16;
            count += mask.count_ones() as usize;

            ptr = ptr.add(16);
            remaining -= 16;
        }

        // Handle remaining bytes
        let remainder = std::slice::from_raw_parts(ptr, remaining);
        count + remainder.iter().filter(|&&b| b == target).count()
    }

    #[target_feature(enable = "sse4.2")]
    unsafe fn compare_case_insensitive_sse42(a: &[u8], b: &[u8]) -> bool {
        // Similar to AVX2 but using 128-bit registers
        Self::compare_case_insensitive_scalar(a, b) // Fallback for now
    }
}

// Hardware-accelerated hashing
impl SimdStringOps {
    #[target_feature(enable = "aes,sse4.2")]
    unsafe fn hash_aes_ni(data: &[u8]) -> u64 {
        use std::arch::x86_64::*;

        // Use AES-NI for fast, high-quality hashing
        let mut hasher = _mm_set1_epi64x(0x517cc1b727220a95); // Random constant

        let mut ptr = data.as_ptr();
        let mut remaining = data.len();

        while remaining >= 16 {
            let chunk = _mm_loadu_si128(ptr as *const __m128i);
            hasher = _mm_aesenc_si128(hasher, chunk);
            ptr = ptr.add(16);
            remaining -= 16;
        }

        // Handle remaining bytes
        if remaining > 0 {
            let mut last_chunk = [0u8; 16];
            std::ptr::copy_nonoverlapping(ptr, last_chunk.as_mut_ptr(), remaining);
            let chunk = _mm_loadu_si128(last_chunk.as_ptr() as *const __m128i);
            hasher = _mm_aesenc_si128(hasher, chunk);
        }

        // Final mix
        hasher = _mm_aesenc_si128(hasher, _mm_set1_epi64x(data.len() as i64));

        // Extract 64-bit result
        _mm_extract_epi64(hasher, 0) as u64
    }

    #[target_feature(enable = "sse4.2")]
    unsafe fn hash_crc32(data: &[u8]) -> u64 {
        use std::arch::x86_64::*;

        let mut crc = 0xffffffff_u32;
        let mut ptr = data.as_ptr();
        let mut remaining = data.len();

        // Process 8 bytes at a time
        while remaining >= 8 {
            let chunk = std::ptr::read_unaligned(ptr as *const u64);
            crc = _mm_crc32_u64(crc as u64, chunk) as u32;
            ptr = ptr.add(8);
            remaining -= 8;
        }

        // Process remaining bytes
        while remaining > 0 {
            crc = _mm_crc32_u8(crc, *ptr);
            ptr = ptr.add(1);
            remaining -= 1;
        }

        (crc ^ 0xffffffff) as u64
    }
}

// Scalar fallback implementations
impl SimdStringOps {
    fn find_pattern_scalar(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn count_byte_scalar(haystack: &[u8], byte: u8) -> usize {
        haystack.iter().filter(|&&b| b == byte).count()
    }

    fn compare_case_insensitive_scalar(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        a.iter()
            .zip(b.iter())
            .all(|(a_byte, b_byte)| a_byte.to_ascii_lowercase() == b_byte.to_ascii_lowercase())
    }

    fn hash_scalar(data: &[u8]) -> u64 {
        // Simple FNV-1a hash as fallback
        let mut hash = 0xcbf29ce484222325_u64;
        for &byte in data {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
}

/// WAF-specific optimized pattern matching functions
pub struct WafPatternMatcher;

impl WafPatternMatcher {
    /// Search for SQL injection patterns with SIMD acceleration
    pub fn contains_sql_injection(payload: &[u8]) -> bool {
        // Common SQL injection patterns
        const SQL_PATTERNS: &[&[u8]] = &[
            b"' OR '1'='1",
            b"' OR 1=1--",
            b"UNION SELECT",
            b"DROP TABLE",
            b"DELETE FROM",
            b"INSERT INTO",
            b"UPDATE SET",
        ];

        // Convert to lowercase once using SIMD
        let lowercase_payload = Self::to_lowercase_simd(payload);

        // Check all patterns using optimized SIMD search
        SQL_PATTERNS
            .iter()
            .any(|pattern| SimdStringOps::find_pattern(&lowercase_payload, pattern).is_some())
    }

    /// Search for XSS patterns with SIMD acceleration
    pub fn contains_xss(payload: &[u8]) -> bool {
        const XSS_PATTERNS: &[&[u8]] = &[
            b"<script",
            b"javascript:",
            b"onload=",
            b"onerror=",
            b"onclick=",
            b"<iframe",
            b"<object",
        ];

        let lowercase_payload = Self::to_lowercase_simd(payload);

        XSS_PATTERNS
            .iter()
            .any(|pattern| SimdStringOps::find_pattern(&lowercase_payload, pattern).is_some())
    }

    /// Convert string to lowercase using best available SIMD instructions
    fn to_lowercase_simd(input: &[u8]) -> Vec<u8> {
        let cpu_features = CpuFeatures::detect();

        match cpu_features.get_pattern_matcher() {
            PatternMatcher::Avx2 => unsafe { Self::to_lowercase_avx2_wrapper(input) },
            _ => input.iter().map(|b| b.to_ascii_lowercase()).collect(),
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn to_lowercase_avx2_wrapper(input: &[u8]) -> Vec<u8> {
        use std::arch::x86_64::*;

        let mut result = Vec::with_capacity(input.len());
        let mut ptr = input.as_ptr();
        let mut remaining = input.len();

        while remaining >= 32 {
            let chunk = _mm256_loadu_si256(ptr as *const __m256i);
            let lowercase = SimdStringOps::to_lowercase_avx2(chunk);

            // Store result
            let mut temp = [0u8; 32];
            _mm256_storeu_si256(temp.as_mut_ptr() as *mut __m256i, lowercase);
            result.extend_from_slice(&temp);

            ptr = ptr.add(32);
            remaining -= 32;
        }

        // Handle remaining bytes
        while remaining > 0 {
            result.push((*ptr).to_ascii_lowercase());
            ptr = ptr.add(1);
            remaining -= 1;
        }

        result
    }
}

/// Public API functions for WAF pattern matching
/// These provide the interface expected by the WAF module

/// Fast pattern search using SIMD acceleration
pub fn fast_pattern_search(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    SimdStringOps::find_pattern(haystack, needle)
}

/// Check for SQL injection patterns using SIMD-accelerated matching
pub fn contains_sql_injection_patterns(payload: &[u8]) -> bool {
    WafPatternMatcher::contains_sql_injection(payload)
}

/// Check for XSS patterns using SIMD-accelerated matching
pub fn contains_xss_patterns(payload: &[u8]) -> bool {
    WafPatternMatcher::contains_xss(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_detection() {
        let features = CpuFeatures::detect();
        println!("CPU Features: {:?}", features);

        // Should at least have SSE2 on x86_64
        #[cfg(target_arch = "x86_64")]
        assert!(features.sse2);
    }

    #[test]
    fn test_pattern_search() {
        let haystack = b"Hello world, this is a test string";
        let needle = b"world";

        let pos = SimdStringOps::find_pattern(haystack, needle);
        assert_eq!(pos, Some(6));

        let not_found = SimdStringOps::find_pattern(haystack, b"xyz");
        assert_eq!(not_found, None);
    }

    #[test]
    fn test_byte_counting() {
        let data = b"hello world";
        let count = SimdStringOps::count_byte(data, b'l');
        assert_eq!(count, 3);
    }

    #[test]
    fn test_case_insensitive_compare() {
        assert!(SimdStringOps::compare_case_insensitive(b"Hello", b"HELLO"));
        assert!(SimdStringOps::compare_case_insensitive(b"Test", b"test"));
        assert!(!SimdStringOps::compare_case_insensitive(b"Hello", b"World"));
    }

    #[test]
    fn test_waf_patterns() {
        let sql_payload = b"admin' OR '1'='1'--";
        assert!(WafPatternMatcher::contains_sql_injection(sql_payload));

        let xss_payload = b"<script>alert('xss')</script>";
        assert!(WafPatternMatcher::contains_xss(xss_payload));

        let clean_payload = b"normal user input";
        assert!(!WafPatternMatcher::contains_sql_injection(clean_payload));
        assert!(!WafPatternMatcher::contains_xss(clean_payload));
    }
}
