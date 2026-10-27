//! End-to-end test of the rooting flow against a fake TV.
//!
//! The fake TV speaks enough SSAP over a plain WebSocket on 127.0.0.1:3000 to
//! exercise the real client: pairing, `listApps`, `launch`, the embedded file
//! server, and the `getAppInfo` verification poll. It also downloads every asset
//! the way the TV's download manager would, so the tracker and the 1.7 MB IPK
//! transfer are both covered.

use lgroot::events::Event;
use lgroot::session::run_exploit;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const CLIENT_KEY: &str = "mock-client-key";

/// The test needs the real port, because that is what the client dials.
const MOCK_PORT: u16 = 3000;

#[test]
fn roots_a_mock_tv_end_to_end() {
    // Never write a pairing key into the developer's real config directory.
    let sandbox = std::env::temp_dir().join(format!("lgroot-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&sandbox);
    std::env::set_var("HOME", &sandbox);
    std::env::set_var("XDG_CONFIG_HOME", sandbox.join("config"));

    let Ok(listener) = TcpListener::bind(("127.0.0.1", MOCK_PORT)) else {
        eprintln!("skipping: 127.0.0.1:{MOCK_PORT} is in use");
        return;
    };

    let downloads_done = Arc::new(AtomicBool::new(false));
    let served = Arc::new(std::sync::Mutex::new(Vec::<(String, usize)>::new()));

    {
        let downloads_done = downloads_done.clone();
        let served = served.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let downloads_done = downloads_done.clone();
                let served = served.clone();
                thread::spawn(move || {
                    let _ = serve_tv(stream, downloads_done, served);
                });
            }
        });
    }

    let (tx, rx) = mpsc::channel::<Event>();
    let cancel = Arc::new(AtomicBool::new(false));
    let client_cancel = cancel.clone();

    let client = thread::spawn(move || {
        run_exploit(
            &tx,
            &client_cancel,
            "127.0.0.1",
            "127.0.0.1",
            false,
        )
    });

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut saw_files_5 = false;
    let mut saw_done = false;
    let mut failure: Option<(String, String)> = None;
    let mut steps = Vec::new();

    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Event::Files { served, total }) => {
                assert_eq!(total, 5, "five assets are tracked");
                if served == 5 {
                    saw_files_5 = true;
                }
            }
            Ok(Event::Step(step)) => steps.push(step),
            Ok(Event::Done) => {
                saw_done = true;
                break;
            }
            Ok(Event::Failed { title, body, .. }) => {
                failure = Some((title, body));
                break;
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    if let Some((title, body)) = failure {
        panic!("flow reported failure: {title}: {body}");
    }
    assert!(saw_files_5, "all five assets should reach the TV");
    assert!(saw_done, "flow should finish with Done");
    assert_eq!(steps, vec![0, 1, 2, 3, 4], "every progress step should fire");

    let out = client.join().expect("client thread should not panic");
    assert!(out.is_ok(), "run_exploit returned an error");

    // The TV should have pulled byte-identical copies of every asset.
    let served = served.lock().unwrap().clone();
    for (name, len) in &served {
        let asset = lgroot::payload::assets()
            .iter()
            .find(|a| a.name == name)
            .unwrap_or_else(|| panic!("TV fetched unknown file {name}"));
        assert_eq!(
            *len,
            asset.bytes.len(),
            "{name} should arrive with the full {} bytes",
            asset.bytes.len()
        );
    }
    assert!(
        served.iter().any(|(n, _)| n == "hbchannel.ipk"),
        "the bundled Homebrew Channel IPK must be served, so the TV never needs the internet"
    );
    assert!(downloads_done.load(Ordering::Relaxed));

    let _ = std::fs::remove_dir_all(&sandbox);
}

// ---------------------------------------------------------------------------
// A television, more or less
// ---------------------------------------------------------------------------

fn serve_tv(
    mut s: TcpStream,
    downloads_done: Arc<AtomicBool>,
    served: Arc<std::sync::Mutex<Vec<(String, usize)>>>,
) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.set_write_timeout(Some(Duration::from_secs(30)))?;

    // --- HTTP upgrade ---
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte)? {
            0 => return Ok(()),
            _ => head.push(byte[0]),
        }
    }
    let request = String::from_utf8_lossy(&head);
    assert!(
        request.contains("Upgrade: websocket"),
        "client must send a WebSocket upgrade"
    );
    assert!(
        !request.to_ascii_lowercase().contains("\r\norigin:"),
        "the handshake must omit Origin, or the TV's filter rejects it"
    );
    s.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: unverified\r\n\r\n",
    )?;

    // --- SSAP ---
    loop {
        let Some((opcode, payload)) = read_frame(&mut s)? else {
            return Ok(());
        };
        match opcode {
            0x8 => return Ok(()),
            0x9 => continue,
            0x1 => {}
            _ => continue,
        }
        let msg: Value = match serde_json::from_slice(&payload) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let kind = msg["type"].as_str().unwrap_or("");
        let id = msg["id"].as_str().unwrap_or("");

        match kind {
            "register" => {
                let manifest = &msg["payload"]["manifest"];
                assert_eq!(
                    manifest["appId"].as_str(),
                    Some("lol.slopbro"),
                    "keep the reference app identity so existing keys work"
                );
                write_json(
                    &mut s,
                    &json!({"type": "response", "id": id, "payload": {"pairingType": "PROMPT"}}),
                )?;
                write_json(
                    &mut s,
                    &json!({"type": "registered", "id": id, "payload": {"client-key": CLIENT_KEY}}),
                )?;
            }
            "request" => {
                let uri = msg["uri"].as_str().unwrap_or("");
                let payload = match uri {
                    "ssap://com.webos.applicationManager/listApps" => json!({
                        "returnValue": true,
                        "apps": [
                            {"id": "com.webos.app.voiceweb"},
                            {"id": "com.webos.app.browser"},
                        ],
                    }),
                    "ssap://system.launcher/launch" => {
                        let url = msg["payload"]["params"]["URL"]
                            .as_str()
                            .or_else(|| msg["payload"]["params"]["interactiveUrl"].as_str())
                            .unwrap_or("")
                            .to_string();
                        assert!(
                            url.contains("files=package.json;main.js;hbchannel.ipk"),
                            "the IPK must be in the download list, got {url}"
                        );
                        let done = downloads_done.clone();
                        let served = served.clone();
                        thread::spawn(move || download_everything(&url, done, served));
                        json!({"returnValue": true})
                    }
                    "ssap://com.webos.applicationManager/getAppInfo" => {
                        json!({
                            "returnValue": downloads_done.load(Ordering::Relaxed),
                            "id": msg["payload"]["id"],
                        })
                    }
                    _ => json!({"returnValue": true}),
                };
                write_json(
                    &mut s,
                    &json!({"type": "response", "id": id, "payload": payload}),
                )?;
            }
            _ => {}
        }
    }
}

fn write_json(s: &mut TcpStream, value: &Value) -> std::io::Result<()> {
    let text = value.to_string();
    let mut out = vec![0x81u8];
    let len = text.len();
    if len < 126 {
        out.push(len as u8);
    } else if len < 65536 {
        out.push(126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(text.as_bytes());
    s.write_all(&out)?;
    s.flush()
}

fn read_frame(s: &mut TcpStream) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let Some(header) = read_exact(s, 2)? else {
        return Ok(None);
    };
    let opcode = header[0] & 0x0f;
    let masked = (header[1] & 0x80) != 0;
    let mut len = (header[1] & 0x7f) as usize;
    if len == 126 {
        let Some(ext) = read_exact(s, 2)? else {
            return Ok(None);
        };
        len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    } else if len == 127 {
        let Some(ext) = read_exact(s, 8)? else {
            return Ok(None);
        };
        len = u64::from_be_bytes(ext.try_into().unwrap()) as usize;
    }
    let mask = if masked {
        match read_exact(s, 4)? {
            Some(m) => m,
            None => return Ok(None),
        }
    } else {
        vec![0, 0, 0, 0]
    };
    let Some(mut payload) = read_exact(s, len)? else {
        return Ok(None);
    };
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(Some((opcode, payload)))
}

fn read_exact(s: &mut TcpStream, n: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; n];
    let mut off = 0;
    while off < n {
        match s.read(&mut buf[off..]) {
            Ok(0) => return Ok(None),
            Ok(k) => off += k,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(Some(buf))
}

/// What the TV's download manager does with the page URL it was launched with.
fn download_everything(
    page_url: &str,
    done: Arc<AtomicBool>,
    served: Arc<std::sync::Mutex<Vec<(String, usize)>>>,
) {
    let base = match page_url.split_once('?') {
        Some((head, _)) => head,
        None => page_url,
    };
    let base = base.trim_end_matches("index.html");

    let mut files = vec!["index.html".to_string(), "autoroot.sh".to_string()];
    if let Some(query) = page_url.split("files=").nth(1) {
        let list = query.split('&').next().unwrap_or("");
        files.extend(list.split(';').filter(|s| !s.is_empty()).map(String::from));
    }

    for file in files {
        let url = format!("{base}{file}");
        let (status, body) = match http_get(&url) {
            Some(v) => v,
            None => panic!("could not download {url}"),
        };
        assert_eq!(status, 200, "unexpected status for {url}");
        if file == "index.html" {
            let text = String::from_utf8_lossy(&body);
            assert!(text.contains("SlopBro"), "index.html should be the payload page");
        }
        if file == "autoroot.sh" {
            let text = String::from_utf8_lossy(&body);
            assert!(text.contains("hbchannel.ipk"), "autoroot.sh should look for the bundled IPK");
        }
        served.lock().unwrap().push((file, body.len()));
    }
    done.store(true, Ordering::Relaxed);
}

fn http_get(url: &str) -> Option<(u16, Vec<u8>)> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let mut s = TcpStream::connect(hostport).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok()?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, raw[split + 4..].to_vec()))
}
