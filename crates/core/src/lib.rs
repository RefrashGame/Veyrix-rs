//! Логика Veyrix-rs без драйвера: разбор IP/TCP/UDP и распознавание TLS, HTTP, QUIC, голоса Discord.

pub mod packet;
pub mod proto;

pub use packet::{Packet, TcpHeader, Transport, UdpHeader, parse};
pub use proto::{Proto, classify};
