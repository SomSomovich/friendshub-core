use std::collections::HashMap;
use std::io::{self, BufRead, BufReader};
use std::net::TcpStream;

#[derive(Debug)]
pub struct CapturedRequest {
    pub method: String,
    pub target: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl CapturedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

#[allow(dead_code)]
pub fn read_request(stream: &mut TcpStream) -> io::Result<CapturedRequest> {
    let mut reader = BufReader::new(stream);
    read_request_from(&mut reader)
}

pub fn read_request_from(reader: &mut impl BufRead) -> io::Result<CapturedRequest> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Err(invalid_data("request line is missing"));
    }
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let target = request_parts.next().unwrap_or_default().to_owned();
    if method.is_empty() || target.is_empty() {
        return Err(invalid_data("request line is malformed"));
    }

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(invalid_data("request headers are incomplete"));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid_data("request header is malformed"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }

    let has_content_length = headers.contains_key("content-length");
    let body = match headers.get("transfer-encoding") {
        Some(encoding) => {
            if has_content_length {
                return Err(invalid_data(
                    "request contains both Transfer-Encoding and Content-Length",
                ));
            }
            if !encoding.eq_ignore_ascii_case("chunked") {
                return Err(invalid_data("unsupported request Transfer-Encoding"));
            }
            read_chunked_body(reader)?
        }
        None => {
            let body_length = headers
                .get("content-length")
                .map(|value| value.parse::<usize>())
                .transpose()
                .map_err(|error| invalid_data(&format!("invalid Content-Length: {error}")))?
                .unwrap_or(0);
            let mut body = vec![0; body_length];
            reader.read_exact(&mut body)?;
            body
        }
    };

    Ok(CapturedRequest {
        method,
        target,
        headers,
        body,
    })
}

fn read_chunked_body(reader: &mut impl BufRead) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line)? == 0 || !size_line.ends_with("\r\n") {
            return Err(invalid_data("chunk size line is incomplete"));
        }
        let size_text = size_line[..size_line.len() - 2]
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let chunk_length = usize::from_str_radix(size_text, 16)
            .map_err(|error| invalid_data(&format!("invalid chunk size: {error}")))?;

        if chunk_length == 0 {
            loop {
                let mut trailer = String::new();
                if reader.read_line(&mut trailer)? == 0 {
                    return Err(invalid_data("chunk trailers are incomplete"));
                }
                if trailer == "\r\n" {
                    return Ok(body);
                }
                if !trailer.ends_with("\r\n") || !trailer.contains(':') {
                    return Err(invalid_data("chunk trailer is malformed"));
                }
            }
        }

        let new_length = body
            .len()
            .checked_add(chunk_length)
            .ok_or_else(|| invalid_data("chunked request body is too large"))?;
        body.resize(new_length, 0);
        reader.read_exact(&mut body[new_length - chunk_length..])?;
        let mut terminator = [0; 2];
        reader.read_exact(&mut terminator)?;
        if terminator != *b"\r\n" {
            return Err(invalid_data("chunk data is not followed by CRLF"));
        }
    }
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}
