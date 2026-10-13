//! Low-interaction SSH honeypot. Embed `network::serve` with a custom
//! `telemetry::EventSink` to forward connection events into HoneyForge.
pub mod config;
pub mod network;
pub mod telemetry;
