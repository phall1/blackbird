//! Loopback HTTP/1.1 adapter over the same JSON-RPC dispatch as `mcp`.
//!
//! One request per connection: read it, write one response, close. `POST /` is
//! the MCP endpoint and `GET /health` is a liveness probe. The caller binds the
//! listener; this module never chooses an address.

#![cfg_attr(
    not(test),
    allow(dead_code, reason = "nothing in the binary serves HTTP yet")
)]

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use blackbird_kernel::Desk;

use crate::mcp;

const MAX_BODY: usize = 1024 * 1024;
/// Headers draw on their own allowance so a body at the cap still fits.
const READ_LIMIT: u64 = MAX_BODY as u64 + 64 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const HEALTH: &[u8] = br#"{"status":"ok"}"#;
const PARSE_ERROR: &[u8] =
    br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}"#;

/// Accepts connections until the listener fails. Each connection gets a thread.
pub fn serve(desk: &Desk, listener: TcpListener) -> io::Result<()> {
    let port = listener.local_addr()?.port();
    thread::scope(|scope| {
        loop {
            let (stream, _) = listener.accept()?;
            scope.spawn(move || handle(desk, port, stream));
        }
    })
}

/// A connection that fails mid-read or mid-write is dropped; the listener keeps going.
fn handle(desk: &Desk, port: u16, stream: TcpStream) {
    let _ = exchange(desk, port, stream);
}

fn exchange(desk: &Desk, port: u16, mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?.take(READ_LIMIT));
    let reply = match read_head(&mut reader) {
        Ok(head) => respond(desk, port, &head, &mut reader)?,
        Err(err) if err.kind() == io::ErrorKind::InvalidData => Reply::text(400),
        Err(err) => return Err(err),
    };
    reply.write_to(&mut stream)
}

struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn read_head<R: BufRead>(reader: &mut R) -> io::Result<Head> {
    let request_line = read_line(reader)?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed("request line"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(malformed("http version"));
    }
    let mut headers = Vec::new();
    loop {
        let line = read_line(reader)?;
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(malformed("header line"));
        };
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    Ok(Head {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
    })
}

fn read_line<R: BufRead>(reader: &mut R) -> io::Result<String> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 || !line.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before the request head ended",
        ));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn malformed(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("malformed {what}"))
}

fn respond<R: BufRead>(desk: &Desk, port: u16, head: &Head, reader: &mut R) -> io::Result<Reply> {
    if !host_allowed(head.header("Host"), port) || !origin_allowed(head.header("Origin")) {
        return Ok(Reply::text(403));
    }
    let path = head
        .target
        .split_once('?')
        .map_or(head.target.as_str(), |(path, _)| path);
    match (path, head.method.as_str()) {
        ("/", "POST") => rpc(desk, head, reader),
        ("/", _) => Ok(Reply::method_not_allowed("POST")),
        ("/health", "GET") => Ok(Reply::json(200, HEALTH)),
        ("/health", _) => Ok(Reply::method_not_allowed("GET")),
        _ => Ok(Reply::text(404)),
    }
}

fn rpc<R: BufRead>(desk: &Desk, head: &Head, reader: &mut R) -> io::Result<Reply> {
    if !is_json(head.header("Content-Type")) {
        return Ok(Reply::text(415));
    }
    let Some(body) = read_body(head, reader)? else {
        return Ok(Reply::text(413));
    };
    let Ok(text) = String::from_utf8(body) else {
        return Ok(Reply::json(400, PARSE_ERROR));
    };
    Ok(match mcp::dispatch(desk, &text) {
        None => Reply::empty(202),
        Some(json) => Reply::json(200, json.into_bytes()),
    })
}

/// `None` means the declared length is over the cap; the body is not read.
/// A request without Content-Length has no body, per HTTP/1.1 framing.
fn read_body<R: BufRead>(head: &Head, reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let length = match head.header("Content-Length") {
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|_| malformed("Content-Length"))?,
        None => 0,
    };
    if length > MAX_BODY {
        return Ok(None);
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

fn is_json(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

/// DNS-rebinding guard: only loopback names, on this listener's port.
fn host_allowed(host: Option<&str>, port: u16) -> bool {
    host.is_none_or(|host| {
        ["127.0.0.1", "localhost"].iter().any(|name| {
            host.eq_ignore_ascii_case(name) || host.eq_ignore_ascii_case(&format!("{name}:{port}"))
        })
    })
}

fn origin_allowed(origin: Option<&str>) -> bool {
    origin
        .filter(|origin| !origin.is_empty())
        .is_none_or(origin_is_loopback)
}

/// Matches the origin's host exactly, so `http://localhost.example` is refused.
fn origin_is_loopback(origin: &str) -> bool {
    ["http://127.0.0.1", "http://localhost"].iter().any(|base| {
        let Some(rest) = origin.strip_prefix(base) else {
            return false;
        };
        rest.is_empty() || rest.strip_prefix(':').is_some_and(port_digits)
    })
}

fn port_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

struct Reply {
    status: u16,
    allow: Option<&'static str>,
    content_type: Option<&'static str>,
    body: Vec<u8>,
}

impl Reply {
    fn text(status: u16) -> Self {
        Self {
            status,
            allow: None,
            content_type: Some("text/plain; charset=utf-8"),
            body: format!("{}\n", reason(status)).into_bytes(),
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            allow: None,
            content_type: None,
            body: Vec::new(),
        }
    }

    fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            allow: None,
            content_type: Some("application/json"),
            body: body.into(),
        }
    }

    fn method_not_allowed(allow: &'static str) -> Self {
        Self {
            allow: Some(allow),
            ..Self::text(405)
        }
    }

    fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        write!(out, "HTTP/1.1 {} {}\r\n", self.status, reason(self.status))?;
        if let Some(allow) = self.allow {
            write!(out, "Allow: {allow}\r\n")?;
        }
        if let Some(content_type) = self.content_type {
            write!(out, "Content-Type: {content_type}\r\n")?;
        }
        write!(
            out,
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.body.len()
        )?;
        out.write_all(&self.body)?;
        out.flush()
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;

    use blackbird_kernel::Desk;

    use super::serve;

    const INITIALIZE: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;

    /// Owns the temp directory so the database outlives the server thread's use of it.
    struct Server {
        port: u16,
        _dir: tempfile::TempDir,
    }

    fn start() -> Server {
        let dir = tempfile::tempdir().expect("temp");
        let desk = Arc::new(Desk::open(dir.path().join("coord.sqlite")).expect("open"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || serve(&desk, listener));
        Server { port, _dir: dir }
    }

    /// Builds a request with a loopback Host and `Connection: close`.
    fn request(port: u16, method: &str, path: &str, extra: &str, body: &[u8]) -> Vec<u8> {
        let mut raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\
             Content-Length: {}\r\n{extra}\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);
        raw
    }

    fn post(port: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
        request(
            port,
            "POST",
            "/",
            &format!("Content-Type: {content_type}\r\n"),
            body,
        )
    }

    struct Answer {
        status: u16,
        head: String,
        body: String,
    }

    fn send(port: u16, raw: &[u8]) -> Answer {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(raw).expect("write");
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).expect("read");
        let text = String::from_utf8(bytes).expect("utf-8 response");
        let (head, body) = text.split_once("\r\n\r\n").expect("head and body");
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status code");
        Answer {
            status,
            head: head.to_owned(),
            body: body.to_owned(),
        }
    }

    #[test]
    fn http_initialize_repeats_without_a_session_header() {
        let server = start();
        for _ in 0..2 {
            let answer = send(
                server.port,
                &post(server.port, "application/json", INITIALIZE),
            );
            assert_eq!(answer.status, 200);
            assert!(answer.body.contains("blackbird-rs"), "{}", answer.body);
            assert!(!answer.head.to_ascii_lowercase().contains("mcp-session-id"));
        }
    }

    #[test]
    fn http_health_is_ok() {
        let server = start();
        let answer = send(
            server.port,
            &request(server.port, "GET", "/health", "", b""),
        );
        assert_eq!(answer.status, 200);
        assert_eq!(answer.body, r#"{"status":"ok"}"#);
        assert!(answer.head.contains("Content-Type: application/json"));
    }

    #[test]
    fn http_bare_brace_is_a_json_rpc_parse_error() {
        let server = start();
        let answer = send(server.port, &post(server.port, "application/json", b"{"));
        assert_eq!(answer.status, 200);
        assert!(answer.body.contains("-32700"), "{}", answer.body);
    }

    #[test]
    fn http_invalid_utf8_is_a_400_parse_error() {
        let server = start();
        let answer = send(
            server.port,
            &post(server.port, "application/json", &[0xff, 0xfe]),
        );
        assert_eq!(answer.status, 400);
        assert_eq!(
            answer.body,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}"#
        );
    }

    #[test]
    fn http_notification_is_202_with_no_body() {
        let server = start();
        let body = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let answer = send(
            server.port,
            &post(server.port, "application/json; charset=utf-8", body),
        );
        assert_eq!(answer.status, 202);
        assert!(answer.body.is_empty());
    }

    #[test]
    fn http_unknown_path_is_404() {
        let server = start();
        let answer = send(server.port, &request(server.port, "GET", "/nope", "", b""));
        assert_eq!(answer.status, 404);
    }

    #[test]
    fn http_wrong_method_is_405_with_allow() {
        let server = start();
        let root = send(server.port, &request(server.port, "GET", "/", "", b""));
        assert_eq!(root.status, 405);
        assert!(root.head.contains("Allow: POST"));
        let health = send(
            server.port,
            &request(server.port, "POST", "/health", "", b""),
        );
        assert_eq!(health.status, 405);
        assert!(health.head.contains("Allow: GET"));
    }

    #[test]
    fn http_non_json_content_type_is_415() {
        let server = start();
        let answer = send(server.port, &post(server.port, "text/plain", INITIALIZE));
        assert_eq!(answer.status, 415);
    }

    #[test]
    fn http_declared_oversize_body_is_413_before_it_is_sent() {
        let server = start();
        let raw = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            server.port,
            super::MAX_BODY + 1
        );
        let answer = send(server.port, raw.as_bytes());
        assert_eq!(answer.status, 413);
    }

    #[test]
    fn http_host_example_com_is_403() {
        let server = start();
        let raw = b"GET /health HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let answer = send(server.port, raw);
        assert_eq!(answer.status, 403);
    }

    #[test]
    fn http_foreign_origin_is_403_and_loopback_origin_passes() {
        let server = start();
        let foreign = request(
            server.port,
            "GET",
            "/health",
            "Origin: http://evil.example\r\n",
            b"",
        );
        assert_eq!(send(server.port, &foreign).status, 403);
        let lookalike = request(
            server.port,
            "GET",
            "/health",
            "Origin: http://localhost.evil.example\r\n",
            b"",
        );
        assert_eq!(send(server.port, &lookalike).status, 403);
        let loopback = request(
            server.port,
            "GET",
            "/health",
            &format!("Origin: http://localhost:{}\r\n", server.port),
            b"",
        );
        assert_eq!(send(server.port, &loopback).status, 200);
    }
}
