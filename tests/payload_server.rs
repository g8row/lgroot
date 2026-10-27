//! Tests for the two little HTTP servers: the payload server the TV downloads
//! from, and the "can the TV reach me?" test server.

use lgroot::events::Event;
use lgroot::payload::{self, Tracker};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;

struct Response {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

fn request(port: u16, method: &str, path: &str) -> Response {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(
        sock,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .expect("write request");
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).expect("read response");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("status line");
    Response {
        status,
        headers: head,
        body: raw[split + 4..].to_vec(),
    }
}

fn asset(name: &str) -> &'static [u8] {
    payload::assets()
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("no asset named {name}"))
        .bytes
}

#[test]
fn test_server_says_hello() {
    let (tx, _rx) = mpsc::channel::<Event>();
    let server = payload::start_test(tx).expect("start test server");

    for path in ["/", "/anything"] {
        let response = request(server.port, "GET", path);
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"Here's your slop, bro!\n");
    }
}

#[test]
fn payload_server_serves_every_embedded_file_byte_for_byte() {
    let (tx, rx) = mpsc::channel::<Event>();
    let tracker = Tracker::new();
    let server = payload::start_payload(tx, tracker.clone()).expect("start payload server");

    for name in [
        "index.html",
        "autoroot.sh",
        "package.json",
        "main.js",
        "hbchannel.ipk",
    ] {
        let response = request(server.port, "GET", &format!("/{name}"));
        assert_eq!(response.status, 200, "GET /{name}");
        assert_eq!(
            response.body.len(),
            asset(name).len(),
            "/{name} should arrive whole"
        );
        assert_eq!(response.body, asset(name), "/{name} should be byte identical");
        assert!(
            response.headers.to_ascii_lowercase().contains("content-length"),
            "the TV's download manager needs Content-Length"
        );
    }

    // The root path is the exploit page, because that is what the launcher
    // opens.
    let root = request(server.port, "GET", "/");
    assert_eq!(root.status, 200);
    assert_eq!(root.body, asset("index.html"));

    // Every distinct file was counted exactly once, and repeated fetches do not
    // inflate the count.
    assert_eq!(tracker.count(), tracker.total());
    let _ = request(server.port, "GET", "/main.js");
    assert_eq!(tracker.count(), tracker.total());

    // The UI should have been told about the transfers.
    let mut updates = 0;
    while let Ok(event) = rx.try_recv() {
        if let Event::Files { served, total } = event {
            assert!(served <= total);
            updates += 1;
        }
    }
    assert!(updates >= 5, "expected progress events, got {updates}");
}

#[test]
fn payload_server_refuses_paths_it_does_not_have() {
    let (tx, _rx) = mpsc::channel::<Event>();
    let tracker = Tracker::new();
    let server = payload::start_payload(tx, tracker.clone()).expect("start payload server");

    for path in [
        "/nope.txt",
        "/slopbro.py",
        "/../etc/passwd",
        "/%2e%2e/etc/passwd",
        "/wwwroot/index.html",
    ] {
        let response = request(server.port, "GET", path);
        assert_eq!(response.status, 404, "{path} must not be served");
    }
    assert_eq!(tracker.count(), 0, "a 404 is not a delivered file");
}

#[test]
fn head_requests_return_headers_without_a_body() {
    let (tx, _rx) = mpsc::channel::<Event>();
    let tracker = Tracker::new();
    let server = payload::start_payload(tx, tracker.clone()).expect("start payload server");

    let response = request(server.port, "HEAD", "/hbchannel.ipk");
    assert_eq!(response.status, 200);
    assert!(response.body.is_empty(), "HEAD must not send a body");
    assert!(
        response
            .headers
            .to_ascii_lowercase()
            .contains(&format!("content-length: {}", asset("hbchannel.ipk").len())),
        "HEAD still has to advertise the real size"
    );
    assert_eq!(tracker.count(), 0, "a HEAD is not a delivery");
}
