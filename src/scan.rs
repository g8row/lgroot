//! LAN discovery.
//!
//! Three probes run together, because no single one is reliable in a home
//! network:
//!
//!   1. SSDP `M-SEARCH` for the webOS second-screen service (instant, but
//!      multicast is blocked on some access points and by VPNs),
//!   2. a TCP sweep of ports 3001/3000 (works whenever unicast works),
//!   3. a look at the TLS certificate (every LG TV ships the same one) and the
//!      DIAL description on port 1925, which carries the TV's display name.

use crate::events::{Event, TvInfo};
use crate::ssap;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_HOSTS: usize = 1024;
const SWEEP_THREADS: usize = 128;

fn log(tx: &Sender<Event>, msg: impl Into<String>) {
    let _ = tx.send(Event::Log(msg.into()));
}

/// IPv4 interfaces worth scanning, as (address, prefix length).
pub fn lan_interfaces() -> Vec<(Ipv4Addr, u8)> {
    let mut out = Vec::new();
    let ifaces = match if_addrs::get_if_addrs() {
        Ok(v) => v,
        Err(_) => return out,
    };
    for iface in ifaces {
        let name = iface.name.as_str();
        // VPN tunnels, container bridges, AirDrop and VM adapters all have
        // addresses that the TV cannot reach back on.
        const SKIP: &[&str] = &[
            "utun", "awdl", "llw", "docker", "veth", "br-", "virbr", "vmnet", "vboxnet",
            "vEthernet", "bridge", "tun", "tap", "zt", "wg",
        ];
        if SKIP.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = &iface.addr {
            if v4.ip.is_loopback() || v4.ip.is_link_local() || v4.ip.is_unspecified() {
                continue;
            }
            let prefix = if v4.prefixlen == 0 {
                mask_prefix(v4.netmask)
            } else {
                v4.prefixlen
            };
            out.push((v4.ip, prefix.clamp(8, 32)));
        }
    }
    out
}

fn mask_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// Hosts to sweep. Very large subnets are narrowed to the local /24, which is
/// where a TV on the same Wi-Fi will be.
fn hosts_for(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let prefix = prefix.clamp(24, 30);
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let net = u32::from(ip) & mask;
    let last = net | !mask;
    let mut out = Vec::new();
    let mut n = net.wrapping_add(1);
    while n < last && out.len() < MAX_HOSTS {
        out.push(Ipv4Addr::from(n));
        n = n.wrapping_add(1);
    }
    out
}

pub fn local_ip_for(ip: &str) -> Option<String> {
    let target: Ipv4Addr = ip.parse().ok()?;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(SocketAddr::from((target, 80))).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4.to_string()),
        _ => None,
    }
}

/// The address most likely to be reachable from the LAN.
pub fn default_local_ip() -> Option<String> {
    default_route_ip().map(|ip| ip.to_string())
}

fn default_route_ip() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    // No packet is sent; this only asks the routing table for a source address.
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// SSDP
// ---------------------------------------------------------------------------

fn ssdp_probe(ifaces: &[(Ipv4Addr, u8)], cancel: &AtomicBool) -> HashSet<Ipv4Addr> {
    let search = "M-SEARCH * HTTP/1.1\r\n\
                  HOST: 239.255.255.250:1900\r\n\
                  MAN: \"ssdp:discover\"\r\n\
                  MX: 2\r\n\
                  ST: urn:lge-com:service:webos-second-screen:1\r\n\r\n";

    let mut sockets = Vec::new();
    for &(ip, _) in ifaces.iter().take(4) {
        let sock = UdpSocket::bind(SocketAddr::from((ip, 0)))
            .or_else(|_| UdpSocket::bind("0.0.0.0:0"));
        if let Ok(sock) = sock {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
            let _ = sock.send_to(search.as_bytes(), "239.255.255.250:1900");
            sockets.push(sock);
        }
    }
    if sockets.is_empty() {
        return HashSet::new();
    }

    let mut hits = HashSet::new();
    let deadline = Instant::now() + Duration::from_millis(2200);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        for sock in &sockets {
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                let text = String::from_utf8_lossy(&buf[..n]);
                if let Some(ip) = location_ip(&text) {
                    hits.insert(ip);
                }
            }
        }
    }
    hits
}

fn location_ip(response: &str) -> Option<Ipv4Addr> {
    for line in response.lines() {
        if line.len() > 9 && line[..9].eq_ignore_ascii_case("location:") {
            let value = line[9..].trim();
            let rest = value
                .strip_prefix("http://")
                .or_else(|| value.strip_prefix("HTTP://"))
                .unwrap_or(value);
            let host = rest.split([':', '/', '?']).next()?;
            if let Ok(ip) = host.parse() {
                return Some(ip);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// HTTP (used for DIAL names and as the payload server's client-side twin)
// ---------------------------------------------------------------------------

fn http_get(ip: &str, port: u16, path: &str, timeout: Duration) -> Option<String> {
    let addr: Ipv4Addr = ip.parse().ok()?;
    let mut sock = TcpStream::connect_timeout(&SocketAddr::from((addr, port)), timeout).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    sock.set_write_timeout(Some(timeout)).ok()?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: LGroot\r\nConnection: close\r\n\r\n"
    );
    sock.write_all(request.as_bytes()).ok()?;
    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                body.extend_from_slice(&chunk[..n]);
                if body.len() > 256 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    Some(String::from_utf8_lossy(&body).into_owned())
}

fn xml_tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let value = xml[start..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Display name and model from the TV's DIAL description, if it answers.
fn dial_info(ip: &str) -> (Option<String>, Option<String>) {
    let candidates = [
        (1925u16, "/ssdp/device-desc.xml"),
        (3000u16, "/"),
    ];
    for (port, path) in candidates {
        if let Some(body) = http_get(ip, port, path, Duration::from_millis(700)) {
            let name = xml_tag(&body, "friendlyName");
            let model = xml_tag(&body, "modelName").or_else(|| xml_tag(&body, "modelNumber"));
            let is_lg = body.contains("LG Electronics") || body.contains("LGE");
            if name.is_some() || model.is_some() || is_lg {
                return (name, model);
            }
        }
    }
    (None, None)
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

pub fn run(tx: &Sender<Event>, cancel: &Arc<AtomicBool>) {
    let _ = tx.send(Event::ScanStarted);

    let ifaces = lan_interfaces();
    for (ip, prefix) in &ifaces {
        log(tx, format!("local interface {ip}/{prefix}"));
    }

    let mut hosts: Vec<Ipv4Addr> = Vec::new();
    let mut seen = HashSet::new();
    for (ip, prefix) in &ifaces {
        for host in hosts_for(*ip, *prefix) {
            if seen.insert(host) {
                hosts.push(host);
            }
        }
    }
    if hosts.is_empty() {
        if let Some(ip) = default_route_ip() {
            log(tx, format!("falling back to {ip}/24"));
            for host in hosts_for(ip, 24) {
                if seen.insert(host) {
                    hosts.push(host);
                }
            }
        }
    }
    if hosts.is_empty() {
        let _ = tx.send(Event::Failed {
            title: "No network to scan".into(),
            body: "This computer does not appear to have an IPv4 network connection.".into(),
            hint: "Connect to the same Wi-Fi as the TV, then scan again.".into(),
        });
        let _ = tx.send(Event::ScanFinished);
        return;
    }

    let total = hosts.len();
    log(tx, format!("sweeping {total} addresses"));

    // SSDP in the background while the unicast sweep runs.
    let ssdp_hits = Arc::new(Mutex::new(HashSet::new()));
    let ssdp = {
        let ifaces = ifaces.clone();
        let cancel = cancel.clone();
        let hits = ssdp_hits.clone();
        thread::spawn(move || {
            let found = ssdp_probe(&ifaces, &cancel);
            if let Ok(mut hits) = hits.lock() {
                hits.extend(found);
            }
        })
    };

    let hosts = Arc::new(hosts);
    let index = Arc::new(AtomicUsize::new(0));
    let open = Arc::new(Mutex::new(HashSet::<Ipv4Addr>::new()));
    let done = Arc::new(AtomicUsize::new(0));

    let mut workers = Vec::new();
    for _ in 0..SWEEP_THREADS {
        let hosts = hosts.clone();
        let index = index.clone();
        let open = open.clone();
        let done = done.clone();
        let tx = tx.clone();
        let cancel = cancel.clone();
        workers.push(thread::spawn(move || loop {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            let i = index.fetch_add(1, Ordering::Relaxed);
            if i >= hosts.len() {
                return;
            }
            let ip = hosts[i];
            let timeout = Duration::from_millis(450);
            let reachable = TcpStream::connect_timeout(
                &SocketAddr::from((ip, ssap::PORT_TLS)),
                timeout,
            )
            .is_ok()
                || TcpStream::connect_timeout(&SocketAddr::from((ip, ssap::PORT_PLAIN)), timeout)
                    .is_ok();
            if reachable {
                if let Ok(mut open) = open.lock() {
                    open.insert(ip);
                }
            }
            let finished = done.fetch_add(1, Ordering::Relaxed) + 1;
            if finished % 16 == 0 || finished == total {
                let _ = tx.send(Event::ScanProgress {
                    done: finished,
                    total,
                });
            }
        }));
    }
    for worker in workers {
        let _ = worker.join();
    }
    let _ = ssdp.join();

    if cancel.load(Ordering::Relaxed) {
        let _ = tx.send(Event::ScanFinished);
        return;
    }

    let mut candidates: Vec<Ipv4Addr> = Vec::new();
    if let Ok(open) = open.lock() {
        candidates.extend(open.iter().copied());
    }
    if let Ok(hits) = ssdp_hits.lock() {
        for ip in hits.iter() {
            if !candidates.contains(ip) {
                candidates.push(*ip);
            }
        }
    }
    candidates.sort();
    let ssdp_only: HashSet<Ipv4Addr> = ssdp_hits.lock().map(|h| h.clone()).unwrap_or_default();

    log(tx, format!("{} candidate(s) answered", candidates.len()));

    for ip in candidates {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let addr = ip.to_string();
        let (name, model) = dial_info(&addr);
        let cert = ssap::probe_cert(&addr, Duration::from_millis(1200));
        let is_lg = cert.as_ref().map(|c| c.is_lg).unwrap_or(false);
        if let Some(cert) = cert.as_ref() {
            log(
                tx,
                format!(
                    "{addr}: certificate {}sha256:{}",
                    if cert.is_lg { "matches LG · " } else { "" },
                    &cert.fingerprint[..16.min(cert.fingerprint.len())]
                ),
            );
        }

        let badge = if is_lg {
            "LG TV"
        } else if name.is_some() || ssdp_only.contains(&ip) {
            "webOS"
        } else {
            "?"
        };
        let display = name.unwrap_or_else(|| {
            if is_lg {
                "LG TV".to_string()
            } else {
                "Unknown device".to_string()
            }
        });
        let detail = match model {
            Some(m) => format!("{addr}  ·  {m}"),
            None => addr.clone(),
        };

        let _ = tx.send(Event::TvFound(TvInfo {
            ip: addr,
            name: display,
            detail,
            badge: badge.to_string(),
        }));
    }

    let _ = tx.send(Event::ScanFinished);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_ssdp_location_header() {
        let response = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\n\
                        LOCATION: http://192.168.1.44:3000/\r\nST: urn:lge-com:service:webos-second-screen:1\r\n\r\n";
        assert_eq!(location_ip(response), Some(Ipv4Addr::new(192, 168, 1, 44)));
    }

    #[test]
    fn ignores_responses_without_a_location() {
        assert_eq!(location_ip("HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n"), None);
        assert_eq!(location_ip("LOCATION: http://[::1]:3000/"), None);
    }

    #[test]
    fn pulls_tags_out_of_the_dial_description() {
        let xml = "<root><device><friendlyName>[LG] webOS TV OLED55C1</friendlyName>\
                   <modelName>OLED55C1PUB</modelName></device></root>";
        assert_eq!(
            xml_tag(xml, "friendlyName").as_deref(),
            Some("[LG] webOS TV OLED55C1")
        );
        assert_eq!(xml_tag(xml, "modelName").as_deref(), Some("OLED55C1PUB"));
        assert_eq!(xml_tag(xml, "modelNumber"), None);
    }

    #[test]
    fn sweeps_a_whole_slash_24() {
        let hosts = hosts_for(Ipv4Addr::new(192, 168, 1, 23), 24);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn narrows_absurdly_large_subnets() {
        // A /16 is 65k addresses; scanning that would take forever and is never
        // where a TV on the same Wi-Fi lives.
        let hosts = hosts_for(Ipv4Addr::new(10, 4, 9, 8), 16);
        assert!(hosts.len() <= 254, "got {}", hosts.len());
        assert!(hosts.contains(&Ipv4Addr::new(10, 4, 9, 1)));
    }

    #[test]
    fn prefix_from_netmask() {
        assert_eq!(mask_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(mask_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
    }
}
