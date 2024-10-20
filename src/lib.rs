extern crate mini_rust_desk_proto;
pub use protobuf;
pub use mini_rust_desk_proto::message_proto as message_proto;
pub use mini_rust_desk_proto::rendezvous_proto as rendezvous_proto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
pub mod compress;
pub use log;
pub use tokio;
pub use tokio_util;
pub mod bytes_codec;
pub mod tcp;
pub mod udp;
pub use anyhow::{self, bail};
pub mod fs;
pub use lazy_static;
// pub mod keyboard;
pub type ResultType<F, E = anyhow::Error> = anyhow::Result<F, E>;
pub type Stream = tcp::FramedStream;

pub fn is_ipv4_str(id: &str) -> bool {
    regex::Regex::new(r"^\d+\.\d+\.\d+\.\d+(:\d+)?$")
        .unwrap()
        .is_match(id)
}

pub fn is_ip_str(id: &str) -> bool {
    is_ipv4_str(id) || is_ipv6_str(id)
}


pub fn timeout<T: std::future::Future>(ms: u64, future: T) -> tokio::time::Timeout<T> {
    tokio::time::timeout(std::time::Duration::from_millis(ms), future)
}

pub fn get_version_number(v: &str) -> i64 {
    let mut n = 0;
    for x in v.split('.') {
        n = n * 1000 + x.parse::<i64>().unwrap_or(0);
    }
    n
}

pub fn get_any_listen_addr(is_ipv4: bool) -> SocketAddr {
    if is_ipv4 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    }
}

pub fn is_ipv6_str(id: &str) -> bool {
    regex::Regex::new(r"^((([a-fA-F0-9]{1,4}:{1,2})+[a-fA-F0-9]{1,4})|(\[([a-fA-F0-9]{1,4}:{1,2})+[a-fA-F0-9]{1,4}\]:\d+))$")
        .unwrap()
        .is_match(id)
}