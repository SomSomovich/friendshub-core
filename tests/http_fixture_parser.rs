#[path = "support/http_fixture.rs"]
mod http_fixture;

use std::io::Cursor;

#[test]
fn captures_chunked_request_body_and_trailers() {
    let raw = b"POST /bodyless-route HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;kind=fixture\r\npedia\r\n0\r\nX-Fixture: complete\r\n\r\n";
    let mut reader = Cursor::new(raw);

    let request = http_fixture::read_request_from(&mut reader).expect("parse chunked request");

    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/bodyless-route");
    assert_eq!(request.header("transfer-encoding"), Some("chunked"));
    assert_eq!(request.body, b"Wikipedia");
}

#[test]
fn rejects_ambiguous_content_length_and_transfer_encoding() {
    let raw = b"GET /bodyless-route HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let mut reader = Cursor::new(raw);

    let error = http_fixture::read_request_from(&mut reader)
        .expect_err("ambiguous HTTP request framing must not be accepted");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
