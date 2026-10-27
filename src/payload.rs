//! Static file server for the exploit payload.
//!
//! `wwwroot/index.html` runs on the TV and pulls the rest of the files over
//! plain HTTP; `autoroot.sh` is then executed as root. Everything is embedded in
//! the binary, including the Homebrew Channel IPK, so `autoroot.sh` never has to
//! reach GitHub from the TV (which fails on TVs whose clock or TLS is broken).

use crate::events::Event;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct Asset {
    pub name: &'static str,
    pub bytes: &'static [u8],
    pub ctype: &'static str,
}

pub fn assets() -> &'static [Asset] {
    &[
        Asset {
            name: "index.html",
            bytes: include_bytes!("../vendor/slopbro/wwwroot/index.html"),
            ctype: "text/html; charset=utf-8",
        },
        Asset {
            name: "autoroot.sh",
            bytes: include_bytes!("../vendor/slopbro/wwwroot/autoroot.sh"),
            ctype: "text/plain; charset=utf-8",
        },
        Asset {
            name: "package.json",
            bytes: include_bytes!("../vendor/slopbro/wwwroot/package.json"),
            ctype: "application/json",
        },
        Asset {
            name: "main.js",
            bytes: include_bytes!("../vendor/slopbro/wwwroot/main.js"),
            ctype: "application/javascript; charset=utf-8",
        },
        Asset {
            name: "hbchannel.ipk",
            bytes: include_bytes!("../assets/hbchannel.ipk"),
            ctype: "application/octet-stream",
        },
    ]
}

/// Files the TV is expected to fetch, in the order the payload asks for them.
pub const DOWNLOAD_LIST: &str = "package.json;main.js;hbchannel.ipk";

pub struct Tracker {
    total: usize,
    served: Mutex<HashSet<&'static str>>,
}

impl Tracker {
    pub fn new() -> Arc<Tracker> {
        Arc::new(Tracker {
            total: assets().len(),
            served: Mutex::new(HashSet::new()),
        })
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn count(&self) -> usize {
        self.served.lock().map(|s| s.len()).unwrap_or(0)
    }

    fn mark(&self, name: &'static str) -> Option<usize> {
        let mut served = self.served.lock().ok()?;
        if !served.insert(name) {
            return None;
        }
        Some(served.len())
    }
}

pub struct Server {
    pub port: u16,
    stop: Arc<AtomicBool>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

enum Mode {
    Payload(Arc<Tracker>),
    Test,
}

fn bind() -> Result<(TcpListener, u16), String> {
    // Prefer a stable port so a firewall rule, once granted, keeps working.
    for port in [8080u16, 8081, 8088, 0] {
        if let Ok(listener) = TcpListener::bind(("0.0.0.0", port)) {
            let actual = listener.local_addr().map(|a| a.port()).unwrap_or(port);
            return Ok((listener, actual));
        }
    }
    Err("could not open a local port for the installer (8080-8088 are busy)".into())
}

pub fn start_payload(tx: Sender<Event>, tracker: Arc<Tracker>) -> Result<Server, String> {
    spawn(tx, Mode::Payload(tracker))
}

pub fn start_test(tx: Sender<Event>) -> Result<Server, String> {
    spawn(tx, Mode::Test)
}

fn spawn(tx: Sender<Event>, mode: Mode) -> Result<Server, String> {
    let (listener, port) = bind()?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("socket setup failed: {e}"))?;

    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    thread::spawn(move || {
        loop {
            if worker_stop.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => handle(stream, &tx, &mode),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    });

    Ok(Server { port, stop })
}

fn handle(mut stream: TcpStream, tx: &Sender<Event>, mode: &Mode) {
    // BSD-derived systems (macOS) let an accepted socket inherit O_NONBLOCK
    // from the listening socket, so a non-blocking accept leaves every
    // connection non-blocking too. Without this, a write that outruns the
    // socket buffer returns EAGAIN and the 1.7 MB IPK arrives truncated.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let mut head = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => {
                head.extend_from_slice(&chunk[..n]);
                if head.len() > 16 * 1024 {
                    return;
                }
            }
            Err(_) => return,
        }
    }

    let text = String::from_utf8_lossy(&head);
    let mut first = text.lines().next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("GET");
    let target = first.next().unwrap_or("/");
    let path = target.split('?').next().unwrap_or("/");
    let head_only = method.eq_ignore_ascii_case("HEAD");

    if let Mode::Test = mode {
        let body = b"Here's your slop, bro!\n";
        let _ = respond(&mut stream, 200, "text/plain; charset=utf-8", body, head_only);
        return;
    }

    let name = if path.is_empty() || path == "/" {
        "index.html"
    } else {
        path.trim_start_matches('/')
    };

    let asset = assets().iter().find(|a| a.name == name);
    let Some(asset) = asset else {
        let _ = respond(
            &mut stream,
            404,
            "text/plain; charset=utf-8",
            b"not found\n",
            head_only,
        );
        return;
    };

    let _ = respond(&mut stream, 200, asset.ctype, asset.bytes, head_only);

    let tracker = match mode {
        Mode::Payload(t) => t,
        Mode::Test => return,
    };
    if !head_only {
        if let Some(served) = tracker.mark(asset.name) {
            let _ = tx.send(Event::Log(format!("sent {name} to the TV")));
            let _ = tx.send(Event::Files {
                served,
                total: tracker.total(),
            });
        }
    }
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
    head_only: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        _ => "Not Found",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    if !head_only {
        stream.write_all(body)?;
    }
    stream.flush()
}
