//! Minimal banner-only honeypot. Embed `network::serve` with a custom
//! `telemetry::EventSink` to forward events into a future HoneyForge agent.
pub mod config;
pub mod network;
pub mod telemetry;
