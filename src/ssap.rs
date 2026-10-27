//! Minimal SSAP client.
//!
//! SSAP is LG's JSON-RPC-over-WebSocket control protocol, served by the TV on
//! port 3001 (TLS) and 3000 (plain). We speak it directly so the app needs no
//! external dependencies:
//!
//!   * a hand-rolled RFC 6455 client (text frames only, client masking),
//!   * rustls with a deliberately permissive verifier, because every webOS TV
//!     presents a self-signed certificate that no CA will ever vouch for.
//!
//! The handshake deliberately omits the `Origin` header, which is what stops a
//! web page from talking to the TV and is what allows a native client to.

use crate::events::Event;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const PORT_TLS: u16 = 3001;
pub const PORT_PLAIN: u16 = 3000;

/// SHA-256 of the certificate LG ships on every TV (leaf "LGE TV SSG") and of
/// its issuer. Matching either is a strong "this really is an LG TV" signal.
const LG_LEAF_FP: &str = "11c5b1c5907750abb9da2a6665ccce2bb288a583f45a3339e71f87bf2f808552";
const LG_CA_FP: &str = "e2bd6464d3f51c1b95b7697d9d6773c33d9412eba0299c568c34937d3fe68aa0";

/// Launcher apps that can host a privileged page, with the query parameter each
/// one forwards to the page it opens, and the webOS majors they exist on.
pub const TARGET_APPS: &[(&str, &str, &[u32])] = &[
    ("com.webos.app.voiceweb", "URL", &[11]),
    ("com.webos.app.adoverlayex", "interactiveUrl", &[3, 4, 5, 6, 7, 8, 9, 10]),
    ("com.webos.app.adoverlay", "interactiveUrl", &[3, 4, 5, 6, 7, 8, 9, 10]),
    ("com.webos.app.acroverlay", "contentTarget", &[3, 4, 5, 6, 7, 8, 9, 10]),
    ("com.webos.app.tinybrowser", "contentTarget", &[3, 4, 5, 6, 7, 8, 9, 10]),
    ("com.webos.app.dangbei-overlay", "target", &[3, 4, 6, 7, 8, 9, 10]),
];

pub const HB_CHANNEL: &str = "org.webosbrew.hbchannel";

fn manifest() -> Value {
    // Same identity the reference client uses, so a key saved by slopbro is
    // reused here and the TV prompt says "SlopBro".
    json!({
        "manifestVersion": 1,
        "appVersion": "1.0",
        "appId": "lol.slopbro",
        "vendorId": "throwaway96",
        "localizedAppNames": { "": "SlopBro" },
        "localizedVendorNames": { "": "throwaway96" },
        "permissions": [
            "LAUNCH",
            "CLOSE",
            "READ_APP_STATUS",
            "READ_INSTALLED_APPS",
            "READ_RUNNING_APPS"
        ]
    })
}

fn log(tx: &Sender<Event>, msg: impl Into<String>) {
    let _ = tx.send(Event::Log(msg.into()));
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct AnyCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AnyCert {
    fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn tls_connect(ip: &str, timeout: Duration) -> io::Result<TlsStream> {
    let addr: Ipv4Addr = ip
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not an IPv4 address"))?;
    let sock = TcpStream::connect_timeout(&SocketAddr::from((addr, PORT_TLS)), timeout)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    sock.set_nodelay(true).ok();

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert::new()))
        .with_no_client_auth();
    let name = ServerName::try_from(ip.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad server name"))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(rustls::StreamOwned::new(conn, sock))
}

pub struct CertInfo {
    pub is_lg: bool,
    pub fingerprint: String,
}

/// Peek at the certificate a TV presents, without speaking SSAP.
pub fn probe_cert(ip: &str, timeout: Duration) -> Option<CertInfo> {
    let mut stream = tls_connect(ip, timeout).ok()?;
    let deadline = Instant::now() + Duration::from_secs(4);
    while stream.conn.is_handshaking() {
        if Instant::now() > deadline {
            return None;
        }
        if stream.conn.complete_io(&mut stream.sock).is_err() {
            return None;
        }
    }
    let cert = stream.conn.peer_certificates()?.first()?.to_vec();
    let fingerprint = hex(&Sha256::digest(&cert));
    let is_lg = fingerprint == LG_LEAF_FP
        || fingerprint == LG_CA_FP
        || cert.windows(10).any(|w| w == b"LGE TV SSG");
    Some(CertInfo {
        is_lg,
        fingerprint,
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Stream (plain or TLS)
// ---------------------------------------------------------------------------

pub enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
}

impl Stream {
    fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.set_read_timeout(timeout),
            Stream::Tls(s) => s.sock.set_read_timeout(timeout),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

fn open_stream(ip: &str) -> io::Result<(Stream, u16)> {
    let addr: Ipv4Addr = ip
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not an IPv4 address"))?;

    if let Ok(tls) = tls_connect(ip, Duration::from_secs(6)) {
        return Ok((Stream::Tls(Box::new(tls)), PORT_TLS));
    }
    let plain = TcpStream::connect_timeout(
        &SocketAddr::from((addr, PORT_PLAIN)),
        Duration::from_secs(4),
    )?;
    plain.set_read_timeout(Some(Duration::from_secs(10)))?;
    plain.set_write_timeout(Some(Duration::from_secs(10)))?;
    plain.set_nodelay(true).ok();
    Ok((Stream::Plain(plain), PORT_PLAIN))
}

// ---------------------------------------------------------------------------
// WebSocket client
// ---------------------------------------------------------------------------

pub enum Recv {
    Text(String),
    Closed,
    Timeout,
}

pub struct Ws {
    stream: Stream,
    buf: Vec<u8>,
    closed: bool,
}

impl Ws {
    pub fn connect(ip: &str, tx: &Sender<Event>) -> Result<Ws, String> {
        let (mut stream, port) = open_stream(ip)
            .map_err(|e| format!("nothing answered on {ip}: {e}"))?;
        log(tx, format!("connected to {ip}:{port}"));

        let key = ws_key();
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("handshake write failed: {e}"))?;

        let mut head = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(pos) = find(&head, b"\r\n\r\n") {
                let rest = head.split_off(pos + 4);
                let status = String::from_utf8_lossy(&head);
                let status_line = status.lines().next().unwrap_or("");
                if !status_line.contains(" 101 ") {
                    return Err(format!("unexpected handshake: {status_line}"));
                }
                return Ok(Ws {
                    stream,
                    buf: rest,
                    closed: false,
                });
            }
            match stream.read(&mut chunk) {
                Ok(0) => return Err("TV closed the connection during handshake".into()),
                Ok(n) => head.extend_from_slice(&chunk[..n]),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    if Instant::now() > deadline {
                        return Err("handshake timed out".into());
                    }
                }
                Err(e) => return Err(format!("handshake read failed: {e}")),
            }
        }
    }

    fn fill(&mut self, n: usize, deadline: Option<Instant>) -> Result<(), Recv> {
        while self.buf.len() < n {
            let mut chunk = [0u8; 8192];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(Recv::Closed),
                Ok(k) => self.buf.extend_from_slice(&chunk[..k]),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    match deadline {
                        Some(d) if Instant::now() >= d => return Err(Recv::Timeout),
                        _ => continue,
                    }
                }
                Err(_) => return Err(Recv::Closed),
            }
        }
        Ok(())
    }

    fn read_frame(&mut self, deadline: Option<Instant>) -> Result<(u8, Vec<u8>), Recv> {
        self.fill(2, deadline)?;
        let b0 = self.buf[0];
        let b1 = self.buf[1];
        let opcode = b0 & 0x0f;
        let masked = (b1 & 0x80) != 0;

        let mut len = (b1 & 0x7f) as usize;
        let mut header = 2usize;
        if len == 126 {
            self.fill(4, deadline)?;
            len = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;
            header = 4;
        } else if len == 127 {
            self.fill(10, deadline)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(&self.buf[2..10]);
            len = u64::from_be_bytes(a) as usize;
            header = 10;
        }
        if len > 8 * 1024 * 1024 {
            return Err(Recv::Closed);
        }

        let mask_len = if masked { 4 } else { 0 };
        let total = header + mask_len + len;
        self.fill(total, deadline)?;

        let mut payload = self.buf[header + mask_len..total].to_vec();
        if masked {
            let m = [
                self.buf[header],
                self.buf[header + 1],
                self.buf[header + 2],
                self.buf[header + 3],
            ];
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }
        self.buf.drain(..total);
        Ok((opcode, payload))
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        }
        let mut out = Vec::with_capacity(payload.len() + 14);
        out.push(0x80 | opcode);
        let len = payload.len();
        if len < 126 {
            out.push(0x80 | len as u8);
        } else if len < 65536 {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0x80 | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mask = mask_key();
        out.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 4]);
        }
        self.stream.write_all(&out)?;
        self.stream.flush()
    }

    pub fn send_text(&mut self, text: &str) -> Result<(), String> {
        self.send_frame(0x1, text.as_bytes())
            .map_err(|e| format!("send failed: {e}"))
    }

    pub fn recv(&mut self, timeout: Option<Duration>) -> Recv {
        let deadline = timeout.map(|t| Instant::now() + t);
        let _ = self.stream.set_timeout(Some(Duration::from_millis(200)));
        loop {
            match self.read_frame(deadline) {
                Ok((0x1, payload)) => return Recv::Text(String::from_utf8_lossy(&payload).into()),
                Ok((0x8, _)) => {
                    self.closed = true;
                    return Recv::Closed;
                }
                Ok((0x9, payload)) => {
                    let _ = self.send_frame(0xA, &payload);
                }
                Ok(_) => continue,
                Err(e) => return e,
            }
        }
    }

    pub fn close(&mut self) {
        if !self.closed {
            let _ = self.send_frame(0x8, b"");
            self.closed = true;
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Two rounds of SipHash over the clock is plenty for a WebSocket nonce; it is
/// not a secret and we do not verify the server's Accept value.
fn pseudo_random() -> [u64; 2] {
    use std::hash::{BuildHasher, Hasher};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut a = std::collections::hash_map::RandomState::new().build_hasher();
    a.write_u128(nanos);
    a.write_u32(std::process::id());
    a.write_usize(&a as *const _ as usize);
    let x = a.finish();
    let mut b = std::collections::hash_map::RandomState::new().build_hasher();
    b.write_u64(x);
    b.write_u128(nanos.rotate_left(31));
    [x, b.finish()]
}

fn ws_key() -> String {
    let mut bytes = [0u8; 16];
    let r = pseudo_random();
    bytes[..8].copy_from_slice(&r[0].to_le_bytes());
    bytes[8..].copy_from_slice(&r[1].to_le_bytes());
    b64(&bytes)
}

fn mask_key() -> [u8; 4] {
    let r = pseudo_random();
    r[1].to_le_bytes()[..4].try_into().unwrap()
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        out.push(T[(b[0] >> 2) as usize] as char);
        out.push(T[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(b[2] & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

// ---------------------------------------------------------------------------
// SSAP
// ---------------------------------------------------------------------------

pub struct Ssap {
    ws: Ws,
    counter: u64,
}

impl Ssap {
    pub fn connect(ip: &str, tx: &Sender<Event>) -> Result<Ssap, String> {
        Ok(Ssap {
            ws: Ws::connect(ip, tx)?,
            counter: 0,
        })
    }

    /// Pair. Returns the client key. `tick(left, total)` is called four times a
    /// second so the UI can show a countdown, because the TV is waiting for a
    /// human. `cancelled` is polled at the same cadence: when the user gives up
    /// we stop waiting instead of tying up the worker for a whole minute.
    pub fn register(
        &mut self,
        client_key: &str,
        timeout: Duration,
        mut tick: impl FnMut(u32, u32),
        cancelled: impl Fn() -> bool,
    ) -> Result<String, String> {
        let mut payload = json!({
            "forcePairing": false,
            "pairingType": "PROMPT",
            "manifest": manifest(),
        });
        if !client_key.is_empty() {
            payload["client-key"] = json!(client_key);
        }
        self.ws.send_text(
            &json!({ "id": "register_0", "type": "register", "payload": payload }).to_string(),
        )?;

        let deadline = Instant::now() + timeout;
        let total = timeout.as_secs() as u32;
        let mut prompted = false;

        loop {
            if cancelled() {
                return Err("cancelled".into());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("timed out waiting for the TV".into());
            }
            tick(left.as_secs() as u32, total);

            match self.ws.recv(Some(Duration::from_millis(250))) {
                Recv::Text(text) => {
                    let msg: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    match msg.get("type").and_then(|t| t.as_str()).unwrap_or("") {
                        "registered" => {
                            let key = msg
                                .get("payload")
                                .and_then(|p| p.get("client-key"))
                                .and_then(|k| k.as_str())
                                .unwrap_or(client_key)
                                .to_string();
                            return Ok(key);
                        }
                        "error" => {
                            let err = msg
                                .get("error")
                                .and_then(|e| e.as_str())
                                .unwrap_or("the TV rejected the pairing")
                                .to_string();
                            return Err(err);
                        }
                        "response" => {
                            prompted = true;
                            continue;
                        }
                        _ => continue,
                    }
                }
                Recv::Timeout => {
                    let _ = prompted;
                    continue;
                }
                Recv::Closed => return Err("the TV closed the connection".into()),
            }
        }
    }

    pub fn request(
        &mut self,
        uri: &str,
        payload: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        self.counter += 1;
        let id = format!("req_{}", self.counter);
        self.ws.send_text(
            &json!({ "id": id, "type": "request", "uri": uri, "payload": payload }).to_string(),
        )?;

        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!("no reply to {uri}"));
            }
            match self.ws.recv(Some(left)) {
                Recv::Text(text) => {
                    let msg: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if msg.get("id").and_then(|i| i.as_str()) != Some(id.as_str()) {
                        continue;
                    }
                    if msg.get("type").and_then(|t| t.as_str()) == Some("error") {
                        return Err(msg
                            .get("error")
                            .and_then(|e| e.as_str())
                            .unwrap_or("request failed")
                            .to_string());
                    }
                    let body = msg.get("payload").cloned().unwrap_or(Value::Null);
                    if body.get("returnValue").and_then(|v| v.as_bool()) == Some(false) {
                        return Err(body
                            .get("errorText")
                            .and_then(|e| e.as_str())
                            .unwrap_or("the TV refused the request")
                            .to_string());
                    }
                    return Ok(body);
                }
                Recv::Timeout => return Err(format!("no reply to {uri}")),
                Recv::Closed => return Err("the TV closed the connection".into()),
            }
        }
    }

    /// Ids of installed apps, or empty if the TV will not tell us.
    pub fn installed_apps(&mut self) -> Vec<String> {
        let payload = match self.request(
            "ssap://com.webos.applicationManager/listApps",
            json!({}),
            Duration::from_secs(10),
        ) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };
        payload
            .get("apps")
            .and_then(|a| a.as_array())
            .map(|apps| {
                apps.iter()
                    .filter_map(|a| a.get("id").and_then(|i| i.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn launch(&mut self, app_id: &str, param: &str, url: &str) -> Result<(), String> {
        let mut params = Map::new();
        params.insert(param.to_string(), json!(url));
        self.request(
            "ssap://system.launcher/launch",
            json!({ "id": app_id, "params": Value::Object(params) }),
            Duration::from_secs(20),
        )
        .map(|_| ())
    }

    /// Launch an app with no extra parameters.
    pub fn launch_app(&mut self, app_id: &str) -> Result<(), String> {
        self.request(
            "ssap://system.launcher/launch",
            json!({ "id": app_id }),
            Duration::from_secs(15),
        )
        .map(|_| ())
    }

    pub fn app_installed(&mut self, app_id: &str) -> bool {
        match self.request(
            "ssap://com.webos.applicationManager/getAppInfo",
            json!({ "id": app_id }),
            Duration::from_secs(12),
        ) {
            Ok(p) => p
                .get("returnValue")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    /// Ask the TV to reboot. Not every firmware exposes this over SSAP, so a
    /// failure here is not fatal — the TV shows its own reboot prompt anyway.
    pub fn reboot(&mut self) -> Result<(), String> {
        self.request(
            "ssap://com.webos.service.sleep/shutdown/machineReboot",
            json!({ "reason": "remoteKey" }),
            Duration::from_secs(8),
        )
        .map(|_| ())
    }

    pub fn close(&mut self) {
        self.ws.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"hello world"), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn websocket_keys_are_sixteen_bytes_of_base64() {
        let key = ws_key();
        assert_eq!(key.len(), 24);
        assert!(key.ends_with("=="));
        assert_ne!(key, ws_key(), "keys must not repeat");
    }

    #[test]
    fn fingerprints_are_compact_lowercase_hex() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}
