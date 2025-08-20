//! Reverse proxy implementation for the WAF
//!
//! This module handles the core proxy functionality, forwarding legitimate
//! requests to upstream servers while applying WAF rules for security filtering.
//! Includes support for HTTP/1.0-3, WebSocket, and WebTransport protocols.

pub mod service;
pub mod websocket;

pub use service::WafProxyService;
pub use websocket::WebSocketHandler;

#[cfg(feature = "webtransport")]
pub use websocket::WebTransportHandler;
