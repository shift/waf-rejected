//! Reverse proxy implementation for the WAF
//! 
//! This module handles the core proxy functionality, forwarding legitimate 
//! requests to upstream servers while applying WAF rules for security filtering.

pub mod service;

pub use service::WafProxyService;
