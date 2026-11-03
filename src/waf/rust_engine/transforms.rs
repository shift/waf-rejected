//! Engine transform surface.
//!
//! The byte implementations live in the shared, Coraza-parity pipeline
//! ([`crate::waf::transforms`]). This module keeps the engine's `Transform`
//! enum (the parser and IR use it) and maps each variant onto one shared step,
//! so the engine and the CRS prefilter can never drift apart again.
//!
//! The request path does not implement its own cache any more: the engine
//! registers each value in a shared [`TransformCache`](crate::waf::transforms::TransformCache)
//! and resolves an interned prefix plan, which shares prefixes across rules,
//! aliases identity steps and performs no steady-state allocation. See
//! `docs/suggestions_from_agents/engine-transforms.md`.

use super::budget::Budget;
use super::error::EngineError;
use crate::waf::transforms as shared;

/// A SecLang transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transform {
    None,
    Lowercase,
    Uppercase,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    JsDecode,
    CssDecode,
    CmdLine,
    ReplaceComments,
    EscapeSeqDecode,
    RemoveWhitespace,
    NormalizePath,
    NormalizePathWin,
    CompressWhitespace,
    RemoveNulls,
    Base64Decode,
    Sha1,
    HexEncode,
    RemoveCommentsChar,
    Length,
    Utf8ToUnicode,
    Trim,
    TrimLeft,
    TrimRight,
}

impl Transform {
    /// Parses a `t:` argument. Returns `None` for unknown transforms so the
    /// caller can report an unsupported construct.
    pub fn parse(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        Some(match lower.as_str() {
            "none" => Self::None,
            "lowercase" => Self::Lowercase,
            "uppercase" => Self::Uppercase,
            "urldecode" => Self::UrlDecode,
            "urldecodeuni" => Self::UrlDecodeUni,
            "htmlentitydecode" => Self::HtmlEntityDecode,
            "jsdecode" => Self::JsDecode,
            "cssdecode" => Self::CssDecode,
            "cmdline" => Self::CmdLine,
            "replacecomments" => Self::ReplaceComments,
            "escapeseqdecode" => Self::EscapeSeqDecode,
            "removewhitespace" => Self::RemoveWhitespace,
            "normalizepath" | "normalisepath" => Self::NormalizePath,
            "normalizepathwin" | "normalisepathwin" => Self::NormalizePathWin,
            "compresswhitespace" => Self::CompressWhitespace,
            "removenulls" => Self::RemoveNulls,
            "base64decode" => Self::Base64Decode,
            "sha1" => Self::Sha1,
            "hexencode" => Self::HexEncode,
            "removecommentschar" => Self::RemoveCommentsChar,
            "length" => Self::Length,
            "utf8tounicode" => Self::Utf8ToUnicode,
            "trim" => Self::Trim,
            "trimleft" => Self::TrimLeft,
            "trimright" => Self::TrimRight,
            _ => return None,
        })
    }

    /// The shared pipeline step with identical Coraza semantics.
    #[inline]
    pub(crate) fn shared(self) -> shared::Transform {
        match self {
            Self::None => shared::Transform::Identity,
            Self::Lowercase => shared::Transform::Lowercase,
            Self::Uppercase => shared::Transform::Uppercase,
            Self::UrlDecode => shared::Transform::UrlDecode,
            Self::UrlDecodeUni => shared::Transform::UrlDecodeUni,
            Self::HtmlEntityDecode => shared::Transform::HtmlEntityDecode,
            Self::JsDecode => shared::Transform::JsDecode,
            Self::CssDecode => shared::Transform::CssDecode,
            Self::CmdLine => shared::Transform::CmdLine,
            Self::ReplaceComments => shared::Transform::ReplaceComments,
            Self::EscapeSeqDecode => shared::Transform::EscapeSeqDecode,
            Self::RemoveWhitespace => shared::Transform::RemoveWhitespace,
            Self::NormalizePath => shared::Transform::NormalizePath,
            Self::NormalizePathWin => shared::Transform::NormalizePathWin,
            Self::CompressWhitespace => shared::Transform::CompressWhitespace,
            Self::RemoveNulls => shared::Transform::RemoveNulls,
            Self::Base64Decode => shared::Transform::Base64Decode,
            Self::Sha1 => shared::Transform::Sha1,
            Self::HexEncode => shared::Transform::HexEncode,
            Self::RemoveCommentsChar => shared::Transform::RemoveCommentsChar,
            Self::Length => shared::Transform::Length,
            Self::Utf8ToUnicode => shared::Transform::Utf8ToUnicode,
            Self::Trim => shared::Transform::Trim,
            Self::TrimLeft => shared::Transform::TrimLeft,
            Self::TrimRight => shared::Transform::TrimRight,
        }
    }

    /// Applies the transform without budget accounting.
    #[inline]
    fn apply_bytes_into(self, input: &[u8], out: &mut Vec<u8>) {
        self.shared().apply_into(input, out);
    }

    /// Applies the transform, charging the request budget.
    ///
    /// Allocating convenience wrapper. The request path uses
    /// [`Self::apply_into`] with reused buffers.
    pub fn apply(self, input: &[u8], budget: &mut Budget) -> Result<Vec<u8>, EngineError> {
        let mut out = Vec::new();
        self.apply_into(input, &mut out, budget)?;
        Ok(out)
    }

    /// Applies the transform into `out`. `out` is cleared first and keeps its
    /// capacity across calls.
    pub fn apply_into(
        self,
        input: &[u8],
        out: &mut Vec<u8>,
        budget: &mut Budget,
    ) -> Result<(), EngineError> {
        self.apply_bytes_into(input, out);
        budget.bytes(out.len())?;
        Ok(())
    }
}

impl shared::Step for Transform {
    #[inline]
    fn apply_into(self, input: &[u8], output: &mut Vec<u8>) {
        self.apply_bytes_into(input, output);
    }

    #[inline]
    fn is_identity(self, input: &[u8]) -> bool {
        self.shared().is_identity_on(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(transform: Transform, input: &[u8]) -> Vec<u8> {
        let mut budget = Budget::new(crate::waf::rust_engine::budget::Limits::default());
        transform.apply(input, &mut budget).expect("transform")
    }

    #[test]
    fn url_decode_uni_handles_iis_encoding() {
        assert_eq!(apply(Transform::UrlDecodeUni, b"a%u0041b"), b"aAb");
        assert_eq!(apply(Transform::UrlDecodeUni, b"a%41b"), b"aAb");
        assert_eq!(apply(Transform::UrlDecodeUni, b"a+b"), b"a b");
    }

    #[test]
    fn js_decode_handles_unicode_and_hex() {
        assert_eq!(apply(Transform::JsDecode, b"\\u0041\\x42"), b"AB");
        assert_eq!(apply(Transform::JsDecode, b"\\n"), b"\n");
    }

    #[test]
    fn html_entities_decode() {
        assert_eq!(
            apply(Transform::HtmlEntityDecode, b"&lt;script&gt;&#x41;"),
            b"<script>A"
        );
    }

    #[test]
    fn base64_decode_stops_at_padding() {
        assert_eq!(apply(Transform::Base64Decode, b"YWJjZA=="), b"abcd");
    }

    #[test]
    fn normalize_path_collapses_segments() {
        assert_eq!(apply(Transform::NormalizePath, b"/a/./b/../c/"), b"/a/c/");
        assert_eq!(apply(Transform::NormalizePathWin, b"\\a\\..\\b"), b"/b");
        assert_eq!(apply(Transform::NormalizePath, b".."), b"..");
        assert_eq!(apply(Transform::NormalizePath, b"a/../../b"), b"../b");
    }

    #[test]
    fn cmd_line_matches_modsecurity() {
        assert_eq!(apply(Transform::CmdLine, b"a ; b/c"), b"a b/c");
    }

    #[test]
    fn uppercase_and_lowercase_are_unicode_aware() {
        assert_eq!(
            apply(Transform::Lowercase, "ÄÖÜ".as_bytes()),
            "äöü".as_bytes()
        );
        assert_eq!(
            apply(Transform::Uppercase, "äöü".as_bytes()),
            "ÄÖÜ".as_bytes()
        );
    }

    #[test]
    fn engine_only_transforms_match_coraza() {
        assert_eq!(apply(Transform::Length, b"abcd"), b"4");
        assert_eq!(apply(Transform::HexEncode, b"a\xff"), b"61ff");
        assert_eq!(
            apply(Transform::Sha1, b"abc"),
            hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d").expect("sha1")
        );
        assert_eq!(
            apply(Transform::RemoveCommentsChar, b"a/*x*/b<!--c-->#d"),
            b"axbcd"
        );
        assert_eq!(
            apply(Transform::Utf8ToUnicode, "aäb".as_bytes()),
            b"a%u00e4b"
        );
        assert_eq!(apply(Transform::Utf8ToUnicode, b"a\xffb"), b"a%ufffdb");
    }
}
