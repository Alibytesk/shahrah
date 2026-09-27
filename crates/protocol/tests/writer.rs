use shahrah_protocol::error::ProtocolError;
use shahrah_protocol::framing::{tagged, untagged};
use shahrah_protocol::writer::Writer;

#[test]
fn a_tagged_message_gets_its_length_backfilled() {
    let mut writer = Writer::new();
    assert_eq!(writer.begin(b'Q'), Ok(()));
    writer.cstring(b"select 1");
    assert_eq!(writer.end(), Ok(()));

    assert_eq!(writer.as_bytes(), b"Q\x00\x00\x00\x0dselect 1\x00");
}

#[test]
fn a_written_message_reads_back_identically() {
    let mut writer = Writer::new();
    assert_eq!(writer.begin(b'B'), Ok(()));
    writer.cstring(b"portal");
    writer.cstring(b"stmt");
    writer.i16(2);
    writer.i32(-1);
    writer.bytes(&[0xDE, 0xAD]);
    assert_eq!(writer.end(), Ok(()));

    let wire = writer.as_bytes();
    let frame = match tagged(wire) {
        Ok(Some(frame)) => frame,
        other => panic!("expected a frame, got {other:?}"),
    };
    assert_eq!(frame.tag, Some(b'B'));
    assert_eq!(frame.consumed, wire.len());

    let mut reader = frame.reader();
    assert_eq!(reader.cstring(), Ok(&b"portal"[..]));
    assert_eq!(reader.cstring(), Ok(&b"stmt"[..]));
    assert_eq!(reader.i16(), Ok(2));
    assert_eq!(reader.i32(), Ok(-1));
    assert_eq!(reader.bytes(2), Ok(&[0xDE, 0xAD][..]));
    assert_eq!(reader.expect_end(), Ok(()));
}

#[test]
fn an_untagged_message_reads_back_identically() {
    let mut writer = Writer::new();
    assert_eq!(writer.begin_untagged(), Ok(()));
    writer.i32(196_608);
    writer.cstring(b"user");
    writer.cstring(b"alireza");
    writer.u8(0);
    assert_eq!(writer.end(), Ok(()));

    let wire = writer.as_bytes();
    let frame = match untagged(wire) {
        Ok(Some(frame)) => frame,
        other => panic!("expected a frame, got {other:?}"),
    };
    assert_eq!(frame.tag, None);
    assert_eq!(frame.consumed, wire.len());

    let mut reader = frame.reader();
    assert_eq!(reader.i32(), Ok(196_608));
    assert_eq!(reader.cstring(), Ok(&b"user"[..]));
    assert_eq!(reader.cstring(), Ok(&b"alireza"[..]));
    assert_eq!(reader.u8(), Ok(0));
    assert_eq!(reader.expect_end(), Ok(()));
}

#[test]
fn an_empty_body_still_declares_four() {
    let mut writer = Writer::new();
    assert_eq!(writer.begin(b'S'), Ok(()));
    assert_eq!(writer.end(), Ok(()));
    assert_eq!(writer.as_bytes(), b"S\x00\x00\x00\x04");
}

#[test]
fn messages_can_be_appended_and_walked_back() {
    let mut writer = Writer::new();
    for tag in [b'P', b'B', b'E', b'S'] {
        assert_eq!(writer.begin(tag), Ok(()));
        writer.cstring(b"x");
        assert_eq!(writer.end(), Ok(()));
    }

    let wire = writer.as_bytes();
    let mut rest = wire;
    let mut tags = Vec::new();
    while let Ok(Some(frame)) = tagged(rest) {
        tags.push(frame.tag);
        rest = match rest.get(frame.consumed..) {
            Some(rest) => rest,
            None => panic!("consumed more than the buffer holds"),
        };
    }
    assert_eq!(rest.len(), 0);
    assert_eq!(
        tags,
        vec![Some(b'P'), Some(b'B'), Some(b'E'), Some(b'S')]
    );
}

#[test]
fn opening_twice_is_refused() {
    let mut writer = Writer::new();
    assert_eq!(writer.begin(b'Q'), Ok(()));
    assert_eq!(writer.begin(b'Q'), Err(ProtocolError::MessageAlreadyOpen));
    assert_eq!(
        writer.begin_untagged(),
        Err(ProtocolError::MessageAlreadyOpen)
    );
}

#[test]
fn closing_without_opening_is_refused() {
    let mut writer = Writer::new();
    assert_eq!(writer.end(), Err(ProtocolError::NoMessageOpen));
}

#[test]
fn taking_an_open_buffer_is_refused() {
    let mut writer = Writer::new();
    assert_eq!(writer.begin(b'Q'), Ok(()));
    assert_eq!(writer.take(), Err(ProtocolError::MessageAlreadyOpen));
    assert_eq!(writer.end(), Ok(()));
    assert!(writer.take().is_ok());
    assert_eq!(writer.as_bytes(), b"");
}

#[test]
fn clear_drops_a_half_written_message() {
    let mut writer = Writer::new();
    assert_eq!(writer.begin(b'Q'), Ok(()));
    writer.bytes(b"partial");
    writer.clear();
    assert!(!writer.is_message_open());
    assert_eq!(writer.as_bytes(), b"");
    assert_eq!(writer.begin(b'S'), Ok(()));
    assert_eq!(writer.end(), Ok(()));
    assert_eq!(writer.as_bytes(), b"S\x00\x00\x00\x04");
}
