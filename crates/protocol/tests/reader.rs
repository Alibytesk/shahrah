use shahrah_protocol::error::ProtocolError;
use shahrah_protocol::reader::Reader;

#[test]
fn reads_primitives_in_big_endian() {
    let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.u8(), Ok(0x01));
    assert_eq!(reader.i16(), Ok(0x0203));
    assert_eq!(reader.i32(), Ok(0x0405_0607));
    assert_eq!(reader.expect_end(), Ok(()));
}

#[test]
fn negative_values_stay_negative() {
    let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.i16(), Ok(-1));
    assert_eq!(reader.i32(), Ok(-1));
}

#[test]
fn u8_at_its_boundary() {
    assert_eq!(
        Reader::new(&[]).u8(),
        Err(ProtocolError::UnexpectedEnd {
            needed: 1,
            remaining: 0
        })
    );
    assert_eq!(Reader::new(&[7]).u8(), Ok(7));
}

#[test]
fn i16_at_its_boundary() {
    assert_eq!(
        Reader::new(&[0]).i16(),
        Err(ProtocolError::UnexpectedEnd {
            needed: 2,
            remaining: 1
        })
    );
    assert_eq!(Reader::new(&[0, 9]).i16(), Ok(9));
    let extra = [0, 9, 9];
    let mut reader = Reader::new(&extra);
    assert_eq!(reader.i16(), Ok(9));
    assert_eq!(reader.len(), 1);
}

#[test]
fn i32_at_its_boundary() {
    assert_eq!(
        Reader::new(&[0, 0, 0]).i32(),
        Err(ProtocolError::UnexpectedEnd {
            needed: 4,
            remaining: 3
        })
    );
    assert_eq!(Reader::new(&[0, 0, 0, 9]).i32(), Ok(9));
}

#[test]
fn bytes_at_its_boundary() {
    let buffer = [1, 2, 3];
    assert_eq!(
        Reader::new(&buffer).bytes(4),
        Err(ProtocolError::UnexpectedEnd {
            needed: 4,
            remaining: 3
        })
    );
    assert_eq!(Reader::new(&buffer).bytes(3), Ok(&buffer[..]));
    assert_eq!(Reader::new(&buffer).bytes(0), Ok(&[][..]));
}

#[test]
fn cstring_stops_at_the_nul_and_consumes_it() {
    let buffer = *b"user\0rest";
    let mut reader = Reader::new(&buffer);
    assert_eq!(reader.cstring(), Ok(&b"user"[..]));
    assert_eq!(reader.remaining(), b"rest");
}

#[test]
fn an_empty_cstring_is_legal() {
    let buffer = [0u8, 1];
    let mut reader = Reader::new(&buffer);
    assert_eq!(reader.cstring(), Ok(&[][..]));
    assert_eq!(reader.remaining(), &[1]);
}

#[test]
fn a_cstring_without_a_nul_is_rejected() {
    let buffer = *b"user";
    let mut reader = Reader::new(&buffer);
    assert_eq!(reader.cstring(), Err(ProtocolError::UnterminatedString));
    assert_eq!(
        Reader::new(&[]).cstring(),
        Err(ProtocolError::UnterminatedString)
    );
}

#[test]
fn a_cstring_that_is_only_a_nul_reads_empty() {
    let buffer = [0u8];
    let mut reader = Reader::new(&buffer);
    assert_eq!(reader.cstring(), Ok(&[][..]));
    assert_eq!(reader.expect_end(), Ok(()));
}

#[test]
fn expect_end_reports_what_was_left_over() {
    let buffer = [1, 2, 3];
    assert_eq!(
        Reader::new(&buffer).expect_end(),
        Err(ProtocolError::TrailingBytes { trailing: 3 })
    );
}

#[test]
fn a_failed_read_does_not_advance() {
    let buffer = [1, 2, 3];
    let mut reader = Reader::new(&buffer);
    assert!(reader.i32().is_err());
    assert_eq!(reader.len(), 3);
    assert_eq!(reader.u8(), Ok(1));
}
