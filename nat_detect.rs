//! NAT behavior discovery per RFC 4787 / RFC 5780 (UDP, IPv4, standard library only).
//!
//! Build: rustc -O nat_detect.rs        (needs Rust 1.65 or newer)
//! Usage: ./nat_detect [host[:port]]
//!
//! The STUN server must support RFC 5780 (OTHER-ADDRESS and CHANGE-REQUEST).

use std::collections::hash_map::RandomState;
use std::env;
use std::hash::{BuildHasher, Hasher};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::process;
use std::time::{Duration, Instant};

const MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED: u16 = 0x0001;
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
const ATTR_CHANGED_ADDRESS: u16 = 0x0005; // RFC 3489 name for OTHER-ADDRESS
const ATTR_XOR_MAPPED: u16 = 0x0020;
const ATTR_OTHER_ADDRESS: u16 = 0x802C;
const FLAG_CHANGE_IP: u32 = 0x04;
const FLAG_CHANGE_PORT: u32 = 0x02;

const EI: &str = "Endpoint-Independent";
const AD: &str = "Address-Dependent";
const APD: &str = "Address and Port-Dependent";

const DEFAULT_SERVER: &str = "stunserver2025.stunprotocol.org:3478";

struct Reply {
    mapped: SocketAddrV4,
    other: Option<SocketAddrV4>,
}

/// Random transaction ID built from std's randomly keyed hasher (no external crates).
fn random_txid() -> [u8; 12] {
    let mut id = [0u8; 12];
    for chunk in id.chunks_mut(8) {
        let v = RandomState::new().build_hasher().finish().to_be_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
    id
}

fn build_request(flags: u32) -> (Vec<u8>, [u8; 12]) {
    let txid = random_txid();
    let attr_len: u16 = if flags != 0 { 8 } else { 0 };
    let mut buf = Vec::with_capacity(28);
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&attr_len.to_be_bytes());
    buf.extend_from_slice(&MAGIC.to_be_bytes());
    buf.extend_from_slice(&txid);
    if flags != 0 {
        buf.extend_from_slice(&ATTR_CHANGE_REQUEST.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&flags.to_be_bytes());
    }
    (buf, txid)
}

fn parse_addr(v: &[u8], xor: bool) -> Option<SocketAddrV4> {
    if v.len() < 8 || v[1] != 1 {
        return None;
    }
    let mut port = u16::from_be_bytes([v[2], v[3]]);
    let mut ip = u32::from_be_bytes([v[4], v[5], v[6], v[7]]);
    if xor {
        port ^= (MAGIC >> 16) as u16;
        ip ^= MAGIC;
    }
    Some(SocketAddrV4::new(Ipv4Addr::from(ip), port))
}

fn parse_reply(data: &[u8], txid: &[u8; 12]) -> Option<Reply> {
    if data.len() < 20
        || u16::from_be_bytes([data[0], data[1]]) != BINDING_SUCCESS
        || u32::from_be_bytes([data[4], data[5], data[6], data[7]]) != MAGIC
        || data[8..20] != txid[..]
    {
        return None;
    }
    let end = (20 + u16::from_be_bytes([data[2], data[3]]) as usize).min(data.len());
    let (mut xor_mapped, mut plain_mapped, mut other) = (None, None, None);
    let mut pos = 20;
    while pos + 4 <= end {
        let t = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let l = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if pos + 4 + l > end {
            break;
        }
        let v = &data[pos + 4..pos + 4 + l];
        match t {
            ATTR_XOR_MAPPED => xor_mapped = parse_addr(v, true),
            ATTR_MAPPED => plain_mapped = parse_addr(v, false),
            ATTR_OTHER_ADDRESS | ATTR_CHANGED_ADDRESS => other = parse_addr(v, false),
            _ => {}
        }
        pos += 4 + ((l + 3) & !3); // attributes are padded to 4 bytes
    }
    Some(Reply { mapped: xor_mapped.or(plain_mapped)?, other })
}

/// Send a Binding Request and wait for a matching reply (1 s per try).
/// The socket is unconnected, so replies from another IP/port are accepted.
fn transact(sock: &UdpSocket, dst: SocketAddrV4, flags: u32, tries: u32) -> Option<Reply> {
    let (req, txid) = build_request(flags);
    let mut buf = [0u8; 2048];
    for _ in 0..tries {
        if sock.send_to(&req, dst).is_err() {
            return None;
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            sock.set_read_timeout(Some(left)).ok()?;
            match sock.recv_from(&mut buf) {
                Ok((n, _)) => {
                    if let Some(r) = parse_reply(&buf[..n], &txid) {
                        return Some(r);
                    }
                }
                Err(_) => break,
            }
        }
    }
    None
}

fn local_ip(server: SocketAddrV4) -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect(server).ok()?;
    match s.local_addr().ok()? {
        SocketAddr::V4(a) => Some(*a.ip()),
        _ => None,
    }
}

/// RFC 5780 section 4.3. Every probe uses the same socket.
fn detect_mapping(
    sock: &UdpSocket,
    server: SocketAddrV4,
    mapped1: SocketAddrV4,
    other: SocketAddrV4,
) -> Option<&'static str> {
    let alt_ip = SocketAddrV4::new(*other.ip(), server.port()); // other IP, primary port
    let r2 = transact(sock, alt_ip, 0, 3)?;
    if r2.mapped == mapped1 {
        return Some(EI);
    }
    let r3 = transact(sock, other, 0, 3)?; // other IP, other port
    Some(if r3.mapped == r2.mapped { AD } else { APD })
}

/// RFC 5780 section 4.4. Uses a fresh socket so earlier probes cannot have
/// opened the filter toward the server's alternate address.
fn detect_filtering(server: SocketAddrV4) -> Option<&'static str> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    transact(&sock, server, 0, 3)?;
    if transact(&sock, server, FLAG_CHANGE_IP | FLAG_CHANGE_PORT, 2).is_some() {
        return Some(EI);
    }
    if transact(&sock, server, FLAG_CHANGE_PORT, 2).is_some() {
        return Some(AD);
    }
    Some(APD)
}

fn legacy_name(mapping: Option<&str>, filtering: Option<&str>) -> &'static str {
    match (mapping, filtering) {
        (Some(m), Some(f)) => {
            if m != EI {
                "symmetric"
            } else if f == EI {
                "full cone"
            } else if f == AD {
                "restricted cone"
            } else {
                "port-restricted cone"
            }
        }
        _ => "unknown",
    }
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    process::exit(1);
}

fn main() {
    let arg = env::args().nth(1).unwrap_or_else(|| DEFAULT_SERVER.to_string());
    let arg = if arg.contains(':') { arg } else { format!("{arg}:3478") };
    let server = arg
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| {
            it.find_map(|a| match a {
                SocketAddr::V4(v4) => Some(v4),
                _ => None,
            })
        })
        .unwrap_or_else(|| die(&format!("cannot resolve {arg} to an IPv4 address")));

    let sock = UdpSocket::bind("0.0.0.0:0").unwrap_or_else(|e| die(&format!("cannot open socket: {e}")));
    let first = transact(&sock, server, 0, 3).unwrap_or_else(|| die(&format!("no STUN reply from {server}")));
    println!("Server:  {server}\nMapped:  {}", first.mapped);

    let local_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
    if local_ip(server) == Some(*first.mapped.ip()) && local_port == first.mapped.port() {
        println!("Note:    mapped address equals local address, so no NAT was detected.");
    }
    let other = first.other.unwrap_or_else(|| {
        die("The server did not send OTHER-ADDRESS, so it does not support RFC 5780. \
             Use a server that does (for example coturn or stunserver2025.stunprotocol.org).")
    });

    let mapping = detect_mapping(&sock, server, first.mapped, other);
    let filtering = detect_filtering(server);
    println!("Mapping behavior:   {}", mapping.unwrap_or("unknown (no reply from alternate address)"));
    println!("Filtering behavior: {}", filtering.unwrap_or("unknown (no reply)"));
    println!("Legacy name (approximate): {}", legacy_name(mapping, filtering));
}
