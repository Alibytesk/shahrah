use shahrah_protocol::error::ProtocolError;
use shahrah_protocol::framing::untagged;
use shahrah_protocol::startup::{
    Startup, CANCEL_REQUEST_CODE, GSSENC_REQUEST_CODE, SSL_REQUEST_CODE,
};
use shahrah_protocol::writer::Writer;

fn framed(body: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    assert_eq!(writer.begin_untagged(), Ok(()));
    writer.bytes(body);
    assert_eq!(writer.end(), Ok(()));
    match writer.take() {
        Ok(bytes) => bytes,
        Err(error) => panic!("taking the buffer failed: {error}"),
    }
}

fn parse(body: &[u8]) -> Startup<'_> {
    match Startup::parse(body) {
        Ok(startup) => startup,
        Err(error) => panic!("parsing failed: {error}"),
    }
}

#[test]
fn an_ssl_request_is_recognised() {
    let body = SSL_REQUEST_CODE.to_be_bytes();
    assert_eq!(parse(&body), Startup::SslRequest);
}

#[test]
fn a_gssenc_request_is_recognised() {
    let body = GSSENC_REQUEST_CODE.to_be_bytes();
    assert_eq!(parse(&body), Startup::GssEncRequest);
}

#[test]
fn a_cancel_request_carries_the_key() {
    let mut body = Vec::new();
    body.extend_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
    body.extend_from_slice(&4242i32.to_be_bytes());
    body.extend_from_slice(&i32::MIN.to_be_bytes());
    assert_eq!(
        parse(&body),
        Startup::Cancel {
            process_id: 4242,
            secret_key: i32::MIN
        }
    );
}

#[test]
fn a_cancel_request_missing_its_key_is_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
    body.extend_from_slice(&4242i32.to_be_bytes());
    assert!(Startup::parse(&body).is_err());
}

#[test]
fn an_ssl_request_with_a_payload_is_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
    body.push(0);
    assert_eq!(
        Startup::parse(&body),
        Err(ProtocolError::TrailingBytes { trailing: 1 })
    );
}

#[test]
fn a_startup_packet_yields_its_parameters() {
    let mut body = Vec::new();
    body.extend_from_slice(&196_608i32.to_be_bytes());
    body.extend_from_slice(b"user\0alireza\0database\0shahrah\0application_name\0psql\0\0");

    match parse(&body) {
        Startup::Connect {
            major,
            minor,
            parameters,
        } => {
            assert_eq!(major, 3);
            assert_eq!(minor, 0);
            assert_eq!(parameters.get(b"user"), Some(&b"alireza"[..]));
            assert_eq!(parameters.get(b"database"), Some(&b"shahrah"[..]));
            assert_eq!(parameters.get(b"application_name"), Some(&b"psql"[..]));
            assert_eq!(parameters.get(b"missing"), None);
            assert_eq!(parameters.iter().count(), 3);
        }
        other => panic!("expected a connect, got {other:?}"),
    }
}

#[test]
fn a_startup_packet_with_no_parameters_is_legal() {
    let mut body = Vec::new();
    body.extend_from_slice(&196_608i32.to_be_bytes());
    body.push(0);
    match parse(&body) {
        Startup::Connect { parameters, .. } => assert_eq!(parameters.iter().count(), 0),
        other => panic!("expected a connect, got {other:?}"),
    }
}

#[test]
fn an_unterminated_parameter_list_is_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&196_608i32.to_be_bytes());
    body.extend_from_slice(b"user\0alireza\0");
    assert_eq!(
        Startup::parse(&body),
        Err(ProtocolError::UnterminatedString)
    );
}

#[test]
fn a_parameter_without_a_value_is_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&196_608i32.to_be_bytes());
    body.extend_from_slice(b"user\0");
    assert_eq!(
        Startup::parse(&body),
        Err(ProtocolError::UnterminatedString)
    );
}

#[test]
fn an_older_protocol_version_parses_and_reports_itself() {
    let mut body = Vec::new();
    body.extend_from_slice(&131_072i32.to_be_bytes());
    body.push(0);
    match parse(&body) {
        Startup::Connect { major, minor, .. } => {
            assert_eq!(major, 2);
            assert_eq!(minor, 0);
        }
        other => panic!("expected a connect, got {other:?}"),
    }
}

#[test]
fn framing_and_parsing_compose() {
    let mut body = Vec::new();
    body.extend_from_slice(&196_608i32.to_be_bytes());
    body.extend_from_slice(b"user\0alireza\0\0");
    let wire = framed(&body);

    let frame = match untagged(&wire) {
        Ok(Some(frame)) => frame,
        other => panic!("expected a frame, got {other:?}"),
    };
    assert_eq!(frame.consumed, wire.len());

    match parse(frame.body) {
        Startup::Connect { parameters, .. } => {
            assert_eq!(parameters.get(b"user"), Some(&b"alireza"[..]));
        }
        other => panic!("expected a connect, got {other:?}"),
    }
}
