use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use friendshub_core::config::{Config, DiscoveryConfig};
use friendshub_core::proto::rest::identity;
use friendshub_core::transport::HttpClient;
use prost::Message;

#[tokio::test(flavor = "current_thread")]
async fn raw_api_and_presigned_uploads_retry_once_after_429() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    listener
        .set_nonblocking(true)
        .expect("fixture listener should be nonblocking");
    let address = listener.local_addr().expect("fixture address");
    let expected_body = b"RIFF1234WEBP".to_vec();

    let server_body = expected_body.clone();
    let server = thread::spawn(move || -> io::Result<()> {
        for attempt in 0..2 {
            let (mut stream, request) = accept_request(&listener)?;
            assert_eq!(request.method, "POST");
            assert_eq!(request.target, "/api/v1/groups/group-1/avatar");
            assert_eq!(request.header("content-type"), Some("image/webp"));
            assert_eq!(request.header("accept"), Some("application/x-protobuf"));
            assert_eq!(request.header("authorization"), Some("Bearer test-session"));
            assert_eq!(request.body, server_body);
            if attempt == 0 {
                write_response_with_retry_after(&mut stream, 429, "application/x-protobuf", b"")?;
            } else {
                let response = identity::AvatarUrlResponse {
                    avatar_url: "/groups/group-1/avatar?v=1".into(),
                }
                .encode_to_vec();
                write_response(&mut stream, 200, "application/x-protobuf", &response)?;
            }
        }

        for attempt in 0..2 {
            let (mut stream, request) = accept_request(&listener)?;
            assert_eq!(request.method, "PUT");
            assert_eq!(request.target, "/storage/upload?signature=secret");
            assert_eq!(request.header("authorization"), None);
            assert_eq!(
                request.header("content-type"),
                Some("application/octet-stream")
            );
            assert_eq!(request.body, server_body);
            if attempt == 0 {
                write_response_with_retry_after(&mut stream, 429, "text/plain", b"slow down")?;
            } else {
                write_response(&mut stream, 200, "text/plain", b"")?;
            }
        }
        Ok(())
    });

    let config = Config {
        db_path: std::env::temp_dir().join("friendshub-http-retry-unused.sqlite"),
        api_base: format!("http://{address}"),
        ws_url: format!("ws://{address}"),
        discovery: DiscoveryConfig {
            enabled: false,
            ..DiscoveryConfig::default()
        },
        log_level: "off".into(),
        log_format: "text".into(),
    };
    let http = HttpClient::new(&config).expect("build HTTP client");

    let response: serde_json::Value = http
        .post_raw(
            "/api/v1/groups/group-1/avatar",
            expected_body.clone(),
            "image/webp",
            Some("test-session"),
        )
        .await
        .expect("protobuf raw upload should retry and decode the response");
    assert_eq!(response["avatar_url"], "/groups/group-1/avatar?v=1");

    http.put_absolute(
        &format!("http://{address}/storage/upload?signature=secret"),
        expected_body,
    )
    .await
    .expect("presigned storage upload should retry without FriendsHub auth");

    server
        .join()
        .expect("loopback server thread should not panic")
        .expect("serve loopback responses");
}

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

fn accept_request(listener: &TcpListener) -> io::Result<(TcpStream, CapturedRequest)> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let request = read_request(&mut stream)?;
                return Ok((stream, request));
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<CapturedRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let body_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .unwrap_or(0);
    let mut body = vec![0; body_length];
    reader.read_exact(&mut body)?;
    Ok(CapturedRequest {
        method,
        target,
        headers,
        body,
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write_response_inner(stream, status, content_type, body, None)
}

fn write_response_with_retry_after(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write_response_inner(stream, status, content_type, body, Some("0"))
}

fn write_response_inner(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    retry_after: Option<&str>,
) -> io::Result<()> {
    let reason = if status == 429 {
        "Too Many Requests"
    } else {
        "OK"
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    )?;
    if let Some(retry_after) = retry_after {
        write!(stream, "Retry-After: {retry_after}\r\n")?;
    }
    write!(stream, "Connection: close\r\n\r\n")?;
    stream.write_all(body)?;
    stream.flush()
}
