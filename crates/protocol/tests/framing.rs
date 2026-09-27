use shahrah_protocol::error::{ProtocolError, MAX_MESSAGE_BODY};
use shahrah_protocol::framing::{tagged, untagged};

fn tagged_message(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = i32::try_from(body.len().saturating_add(4)).unwrap_or(i32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn untagged_message(body: &[u8]) -> Vec<u8> {
    let length = i32::try_from(body.len().saturating_add(4)).unwrap_or(i32::MAX);
    let mut out = Vec::new();
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[test]
fn a_complete_tagged_message_is_delimited() {
    let wire = tagged_message(b'Q', b"select 1\0");
    match tagged(&wire) {
        Ok(Some(frame)) => {
            assert_eq!(frame.tag, Some(b'Q'));
            assert_eq!(frame.body, b"select 1\0");
            assert_eq!(frame.consumed, wire.len());
        }
        other => panic!("expected a frame, got {other:?}"),
    }
}

#[test]
fn a_message_with_an_empty_body_is_complete() {
    let wire = tagged_message(b'S', b"");
    match tagged(&wire) {
        Ok(Some(frame)) => {
            assert_eq!(frame.body, b"");
            assert_eq!(frame.consumed, 5);
        }
        other => panic!("expected a frame, got {other:?}"),
    }
}

#[test]
fn a_startup_message_carries_no_tag() {
    let wire = untagged_message(&[0x00, 0x03, 0x00, 0x00]);
    match untagged(&wire) {
        Ok(Some(frame)) => {
            assert_eq!(frame.tag, None);
            assert_eq!(frame.body, [0x00, 0x03, 0x00, 0x00]);
            assert_eq!(frame.consumed, 8);
        }
        other => panic!("expected a frame, got {other:?}"),
    }
}

#[test]
fn an_ssl_request_is_delimited() {
    let wire = [0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F];
    match untagged(&wire) {
        Ok(Some(frame)) => {
            assert_eq!(frame.consumed, 8);
            assert_eq!(frame.body, [0x04, 0xD2, 0x16, 0x2F]);
        }
        other => panic!("expected a frame, got {other:?}"),
    }
}

#[test]
fn trailing_bytes_belong_to_the_next_message() {
    let mut wire = tagged_message(b'Q', b"one\0");
    wire.extend_from_slice(&tagged_message(b'Q', b"two\0"));
    match tagged(&wire) {
        Ok(Some(frame)) => {
            assert_eq!(frame.body, b"one\0");
            assert_eq!(frame.consumed, 9);
        }
        other => panic!("expected a frame, got {other:?}"),
    }
}

#[test]
fn a_negative_length_is_rejected() {
    let wire = [b'Q', 0xFF, 0xFF, 0xFF, 0xFF];
    assert_eq!(
        tagged(&wire),
        Err(ProtocolError::NegativeLength { length: -1 })
    );
}

#[test]
fn a_length_below_four_is_rejected() {
    for length in 0..4i32 {
        let mut wire = vec![b'Q'];
        wire.extend_from_slice(&length.to_be_bytes());
        assert_eq!(
            tagged(&wire),
            Err(ProtocolError::LengthTooSmall { length }),
            "length {length}"
        );
    }
}

#[test]
fn an_absurd_length_is_rejected_without_allocating() {
    let mut wire = vec![b'Q'];
    wire.extend_from_slice(&i32::MAX.to_be_bytes());
    match tagged(&wire) {
        Err(ProtocolError::OversizedMessage { limit, .. }) => {
            assert_eq!(limit, MAX_MESSAGE_BODY);
        }
        other => panic!("expected an oversize error, got {other:?}"),
    }
}

#[test]
fn every_split_of_a_stream_is_either_incomplete_or_exact() {
    let mut wire = tagged_message(b'Q', b"select 1\0");
    wire.extend_from_slice(&tagged_message(b'P', b"stmt\0select 2\0"));
    wire.extend_from_slice(&tagged_message(b'S', b""));

    let first = match tagged(&wire) {
        Ok(Some(frame)) => frame,
        other => panic!("expected a frame, got {other:?}"),
    };
    let complete = first.consumed;
    let body = first.body.to_vec();

    for split in 0..wire.len() {
        let partial = match wire.get(..split) {
            Some(partial) => partial,
            None => panic!("split {split} is out of range"),
        };
        match tagged(partial) {
            Ok(None) => assert!(
                split < complete,
                "reported incomplete at {split} bytes, but {complete} are enough"
            ),
            Ok(Some(frame)) => {
                assert!(
                    split >= complete,
                    "reported a complete message at {split} bytes, needs {complete}"
                );
                assert_eq!(frame.body, body.as_slice(), "body differs at split {split}");
                assert_eq!(frame.consumed, complete, "consumed differs at split {split}");
            }
            Err(error) => panic!("split {split} produced {error}"),
        }
    }
}

#[test]
fn a_stream_walked_frame_by_frame_loses_nothing() {
    let bodies: [&[u8]; 4] = [b"one\0", b"", b"three\0", b"a much longer body\0"];
    let mut wire = Vec::new();
    for body in bodies {
        wire.extend_from_slice(&tagged_message(b'Q', body));
    }

    let mut rest = wire.as_slice();
    let mut seen = Vec::new();
    loop {
        match tagged(rest) {
            Ok(Some(frame)) => {
                seen.push(frame.body.to_vec());
                rest = match rest.get(frame.consumed..) {
                    Some(rest) => rest,
                    None => panic!("consumed more than the buffer holds"),
                };
            }
            Ok(None) => break,
            Err(error) => panic!("walking the stream produced {error}"),
        }
    }

    assert_eq!(rest.len(), 0);
    assert_eq!(seen.len(), bodies.len());
    for (got, expected) in seen.iter().zip(bodies) {
        assert_eq!(got.as_slice(), expected);
    }
}
