//! Reverse proxy implementation for the WAF
//!
//! This module handles the core proxy functionality, forwarding legitimate
//! requests to upstream servers while applying WAF rules for security filtering.
//! Includes support for HTTP/1.0-3, WebSocket, and WebTransport protocols.

pub mod buffer_pool;
pub(crate) mod decompression;
pub mod framing;
#[cfg(feature = "http3")]
pub(crate) mod http3;
pub mod service;
pub mod websocket;
#[cfg(feature = "webtransport")]
pub(crate) mod webtransport;

pub use buffer_pool::BufferPool;
pub use service::WafProxyService;
pub use websocket::WebSocketHandler;
