use crate::scanner::device_discovery::{Discovery, NetworkMap};
use serde::Serialize;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PAGE: &str = include_str!("wifi_map.html");
const MAX_HEADER: usize = 8192;

#[derive(Clone, Default, Serialize)]
struct State {
    busy: bool,
    report: Option<NetworkMap>,
    error: Option<String>,
}

type SharedState = Arc<Mutex<State>>;
type Collector = Arc<Mutex<Discovery>>;

pub fn run() -> io::Result<()> {
    if !cfg!(windows) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "--wifi-map currently supports Windows only.",
        ));
    }
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let host = listener.local_addr()?.to_string();
    let state = Arc::new(Mutex::new(State::default()));
    let collector = Arc::new(Mutex::new(Discovery::new()));
    start_scan(&state, &collector, false)?;
    println!("Wi-Fi map: http://{host}/");
    println!("Open this address in your browser. Press Ctrl+C here to stop.");
    println!("Placement is schematic; physical distances are unavailable. Scanning starts only when you press Scan network.");
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(error) = handle_connection(&mut stream, &host, &state, &collector) {
                    if !matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::UnexpectedEof
                    ) {
                        eprintln!("Wi-Fi map request failed: {error}");
                    }
                }
            }
            Err(error) => eprintln!("Wi-Fi map connection failed: {error}"),
        }
    }
    Ok(())
}

fn start_scan(state: &SharedState, collector: &Collector, active: bool) -> io::Result<bool> {
    {
        let mut guard = state
            .lock()
            .map_err(|_| io::Error::other("Map state unavailable"))?;
        if guard.busy {
            return Ok(false);
        }
        guard.busy = true;
        guard.error = None;
    }
    let worker_state = Arc::clone(state);
    let collector = Arc::clone(collector);
    let result = std::thread::Builder::new()
        .name("wifi-map-discovery".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                collector
                    .lock()
                    .map_err(|_| "Discovery worker unavailable.".to_string())?
                    .scan(active)
            }))
            .unwrap_or_else(|_| Err("Discovery worker failed. Restart --wifi-map.".into()));
            if let Ok(mut guard) = worker_state.lock() {
                guard.busy = false;
                match result {
                    Ok(report) => guard.report = Some(report),
                    Err(error) => guard.error = Some(error),
                }
            }
        });
    if let Err(error) = result {
        if let Ok(mut guard) = state.lock() {
            guard.busy = false;
            guard.error = Some(format!("Could not start discovery: {error}"));
        }
        return Err(error);
    }
    Ok(true)
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

fn parse_request(bytes: &[u8]) -> Option<Request> {
    let input = std::str::from_utf8(bytes).ok()?;
    let mut lines = input.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    if first.next()? != "HTTP/1.1" || first.next().is_some() {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return None;
        }
        let name = name.to_ascii_lowercase();
        if headers.iter().any(|(key, _)| key == &name) {
            return None;
        }
        headers.push((name, value.trim().to_string()));
    }
    Some(Request {
        method,
        path,
        headers,
    })
}

fn permitted(request: &Request, host: &str) -> bool {
    // Host validation blocks DNS rebinding; the custom header prevents foreign
    // pages from reading telemetry or triggering probes through simple requests.
    request.header("host") == Some(host)
        && request
            .header("origin")
            .is_none_or(|origin| origin == format!("http://{host}"))
        && request
            .header("sec-fetch-site")
            .is_none_or(|site| matches!(site, "same-origin" | "none"))
        && (!request.path.starts_with("/api/") || request.header("x-unlatched-map") == Some("1"))
}

fn handle_connection(
    stream: &mut TcpStream,
    host: &str,
    state: &SharedState,
    collector: &Collector,
) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut bytes = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return respond(stream, "408 Request Timeout", "text/plain", b"Request timed out");
        }
        stream.set_read_timeout(Some(remaining))?;
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > MAX_HEADER {
            return respond(
                stream,
                "431 Request Header Fields Too Large",
                "text/plain",
                b"Request too large",
            );
        }
        if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let Some(request) = parse_request(&bytes) else {
        return respond(stream, "400 Bad Request", "text/plain", b"Malformed request");
    };
    if !permitted(&request, host) {
        return respond(
            stream,
            "403 Forbidden",
            "text/plain",
            b"Only same-origin local map requests are accepted",
        );
    }
    if request.header("transfer-encoding").is_some()
        || request.header("content-length").is_some_and(|length| length != "0")
    {
        return respond(
            stream,
            "413 Content Too Large",
            "text/plain",
            b"Request bodies are not accepted",
        );
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => respond(stream, "200 OK", "text/html; charset=utf-8", PAGE.as_bytes()),
        ("GET", "/api/state") => {
            let snapshot = state
                .lock()
                .map_err(|_| io::Error::other("Map state unavailable"))?
                .clone();
            let body = serde_json::to_vec(&snapshot).map_err(io::Error::other)?;
            respond(stream, "200 OK", "application/json", &body)
        }
        ("POST", "/api/scan" | "/api/refresh") => {
            match start_scan(state, collector, request.path == "/api/scan") {
                Ok(true) => respond(
                    stream, "202 Accepted", "application/json", b"{\"accepted\":true}",
                ),
                Ok(false) => respond(
                    stream,
                    "409 Conflict",
                    "application/json",
                    b"{\"error\":\"A scan is already running\"}",
                ),
                Err(_) => respond(
                    stream,
                    "500 Internal Server Error",
                    "application/json",
                    b"{\"error\":\"Could not start discovery\"}",
                ),
            }
        }
        _ => respond(stream, "404 Not Found", "text/plain", b"Not found"),
    }
}

fn respond(stream: &mut TcpStream, status: &str, mime: &str, body: &[u8]) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'nonce-unlatched-map'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n\r\n", body.len())?;
    stream.write_all(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_api_rejects_cross_origin_missing_header_and_duplicate_host() {
        let host = "127.0.0.1:12345";
        let request = |headers: &str| {
            parse_request(
                format!("GET /api/state HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n").as_bytes(),
            )
            .unwrap()
        };
        assert!(permitted(&request("X-Unlatched-Map: 1\r\n"), host));
        assert!(!permitted(&request(""), host));
        assert!(!permitted(&request("X-Unlatched-Map: 1\r\nOrigin: http://example.com\r\n"), host));
        assert!(!permitted(&request("X-Unlatched-Map: 1\r\nSec-Fetch-Site: cross-site\r\n"), host));
        assert!(!permitted(&request("X-Unlatched-Map: 1\r\nOrigin: null\r\n"), host));
        assert!(!permitted(&request("X-Unlatched-Map: 1\r\n"), "attacker.example:12345"));
        assert!(parse_request(b"GET / HTTP/1.1\r\nHost: one\r\nhost: two\r\n\r\n").is_none());
    }

    #[test]
    fn http_serves_page_json_and_refuses_untrusted_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host = listener.local_addr().unwrap().to_string();
        let server_host = host.clone();
        let state = Arc::new(Mutex::new(State::default()));
        let collector = Arc::new(Mutex::new(Discovery::new()));
        let server = std::thread::spawn(move || {
            for stream in listener.incoming().take(6) {
                handle_connection(&mut stream.unwrap(), &server_host, &state, &collector).unwrap();
            }
        });
        for (method, path, extra, expected) in [
            ("GET", "/", "", "200 OK"),
            ("GET", "/api/state", "X-Unlatched-Map: 1\r\n", "200 OK"),
            ("POST", "/api/scan", "", "403 Forbidden"),
            ("OPTIONS", "/api/scan", "X-Unlatched-Map: 1\r\n", "404 Not Found"),
            ("POST", "/api/scan", "X-Unlatched-Map: 1\r\nOrigin: https://example.com\r\n", "403 Forbidden"),
            ("GET", "/api/state", "X-Unlatched-Map: 1\r\nContent-Length: 10\r\n", "413 Content Too Large"),
        ] {
            let mut client = TcpStream::connect(&host).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            write!(client, "{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n").unwrap();
            let mut output = String::new();
            client.read_to_string(&mut output).unwrap();
            assert!(output.starts_with(&format!("HTTP/1.1 {expected}")), "{output}");
            assert!(output.contains("Cache-Control: no-store"));
            if path == "/" {
                assert!(output.contains("<canvas"));
            }
            if path == "/api/state" && expected == "200 OK" {
                let body = output.split_once("\r\n\r\n").unwrap().1;
                let json: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(json["busy"], false);
                assert!(json["report"].is_null());
            }
        }
        server.join().unwrap();
    }

    #[test]
    fn repeated_scan_is_rejected_while_busy() {
        let state = Arc::new(Mutex::new(State {
            busy: true,
            ..Default::default()
        }));
        let collector = Arc::new(Mutex::new(Discovery::new()));
        assert!(!start_scan(&state, &collector, true).unwrap());
        assert!(state.lock().unwrap().busy);
    }
}
