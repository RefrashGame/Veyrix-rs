//! Логика Veyrix-rs без драйвера: разбор IP/TCP/UDP и распознавание TLS, HTTP, QUIC, голоса Discord.

pub mod desync;
pub mod dns;
pub mod packet;
pub mod proto;
pub mod tuner;

pub use desync::{Action, Fooling, QuicMode, SplitPos, Strategy, apply};
pub use packet::{Packet, TcpHeader, Transport, UdpHeader, parse};
pub use proto::{Proto, classify};
