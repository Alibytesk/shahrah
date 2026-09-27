use crate::error::Result;
use crate::writer::Writer;

pub const TAG_ERROR_RESPONSE: u8 = b'E';
pub const TAG_NOTICE_RESPONSE: u8 = b'N';

pub const FIELD_SEVERITY_LOCALIZED: u8 = b'S';
pub const FIELD_SEVERITY: u8 = b'V';
pub const FIELD_CODE: u8 = b'C';
pub const FIELD_MESSAGE: u8 = b'M';

pub const SEVERITY_FATAL: &[u8] = b"FATAL";
pub const SEVERITY_ERROR: &[u8] = b"ERROR";

pub const SQLSTATE_FEATURE_NOT_SUPPORTED: &[u8] = b"0A000";
pub const SQLSTATE_PROTOCOL_VIOLATION: &[u8] = b"08P01";
pub const SQLSTATE_ADMIN_SHUTDOWN: &[u8] = b"57P01";
pub const SQLSTATE_INVALID_PASSWORD: &[u8] = b"28P01";
pub const SQLSTATE_IN_FAILED_TRANSACTION: &[u8] = b"25P02";
pub const SQLSTATE_CONNECTION_FAILURE: &[u8] = b"08006";
pub const SQLSTATE_TOO_MANY_CONNECTIONS: &[u8] = b"53300";

pub const TRANSACTION_IDLE: u8 = b'I';
pub const TRANSACTION_ACTIVE: u8 = b'T';
pub const TRANSACTION_FAILED: u8 = b'E';
pub const SQLSTATE_UNSUPPORTED_PROTOCOL_VERSION: &[u8] = b"0A000";

pub fn error_response(
    writer: &mut Writer,
    severity: &[u8],
    code: &[u8],
    message: &[u8],
) -> Result<()> {
    writer.begin(TAG_ERROR_RESPONSE)?;
    writer.u8(FIELD_SEVERITY_LOCALIZED);
    writer.cstring(severity);
    writer.u8(FIELD_SEVERITY);
    writer.cstring(severity);
    writer.u8(FIELD_CODE);
    writer.cstring(code);
    writer.u8(FIELD_MESSAGE);
    writer.cstring(message);
    writer.u8(0);
    writer.end()
}

pub const TAG_AUTHENTICATION: u8 = b'R';
pub const TAG_READY_FOR_QUERY: u8 = b'Z';
pub const TAG_BACKEND_KEY_DATA: u8 = b'K';
pub const TAG_PARAMETER_STATUS: u8 = b'S';
pub const TAG_PASSWORD_MESSAGE: u8 = b'p';

pub const AUTH_OK: i32 = 0;
pub const AUTH_KERBEROS_V5: i32 = 2;
pub const AUTH_CLEARTEXT_PASSWORD: i32 = 3;
pub const AUTH_MD5_PASSWORD: i32 = 5;
pub const AUTH_GSS: i32 = 7;
pub const AUTH_GSS_CONTINUE: i32 = 8;
pub const AUTH_SSPI: i32 = 9;
pub const AUTH_SASL: i32 = 10;
pub const AUTH_SASL_CONTINUE: i32 = 11;
pub const AUTH_SASL_FINAL: i32 = 12;

pub fn authentication_code(body: &[u8]) -> Result<i32> {
    let mut reader = crate::reader::Reader::new(body);
    reader.i32()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorFields<'a> {
    pub severity: Option<&'a [u8]>,
    pub code: Option<&'a [u8]>,
    pub message: Option<&'a [u8]>,
}

pub fn parse_error_fields(body: &[u8]) -> Result<ErrorFields<'_>> {
    let mut reader = crate::reader::Reader::new(body);
    let mut fields = ErrorFields {
        severity: None,
        code: None,
        message: None,
    };
    loop {
        let field = reader.u8()?;
        if field == 0 {
            return Ok(fields);
        }
        let value = reader.cstring()?;
        match field {
            FIELD_SEVERITY => fields.severity = Some(value),
            FIELD_CODE => fields.code = Some(value),
            FIELD_MESSAGE => fields.message = Some(value),
            _ => {}
        }
    }
}

#[must_use]
pub const fn authentication_expects_client_response(code: i32) -> bool {
    matches!(
        code,
        AUTH_CLEARTEXT_PASSWORD
            | AUTH_MD5_PASSWORD
            | AUTH_GSS
            | AUTH_GSS_CONTINUE
            | AUTH_SSPI
            | AUTH_SASL
            | AUTH_SASL_CONTINUE
    )
}

pub const TAG_QUERY: u8 = b'Q';
pub const TAG_ROW_DESCRIPTION: u8 = b'T';
pub const TAG_DATA_ROW: u8 = b'D';
pub const TAG_COMMAND_COMPLETE: u8 = b'C';
pub const TAG_EMPTY_QUERY: u8 = b'I';
pub const TAG_NOTICE_RESPONSE_SERVER: u8 = b'N';
pub const TAG_PARSE: u8 = b'P';
pub const TAG_BIND: u8 = b'B';
pub const TAG_DESCRIBE: u8 = b'D';
pub const TAG_DESCRIBE_STATEMENT: u8 = b'D';
pub const TAG_EXECUTE: u8 = b'E';
pub const TAG_CLOSE: u8 = b'C';
pub const TAG_SYNC: u8 = b'S';
pub const TAG_FLUSH: u8 = b'H';
pub const TAG_TERMINATE: u8 = b'X';
pub const TAG_PARSE_COMPLETE: u8 = b'1';
pub const TAG_BIND_COMPLETE: u8 = b'2';
pub const TAG_CLOSE_COMPLETE: u8 = b'3';
pub const TAG_PARAMETER_DESCRIPTION: u8 = b't';
pub const TAG_NO_DATA: u8 = b'n';

pub fn query(writer: &mut Writer, sql: &str) -> Result<()> {
    writer.begin(TAG_QUERY)?;
    writer.cstring(sql.as_bytes());
    writer.end()
}

pub fn sasl_initial_response(writer: &mut Writer, mechanism: &str, message: &str) -> Result<()> {
    writer.begin(TAG_PASSWORD_MESSAGE)?;
    writer.cstring(mechanism.as_bytes());
    let length = i32::try_from(message.len()).unwrap_or(-1);
    writer.i32(length);
    writer.bytes(message.as_bytes());
    writer.end()
}

pub fn sasl_response(writer: &mut Writer, message: &str) -> Result<()> {
    writer.begin(TAG_PASSWORD_MESSAGE)?;
    writer.bytes(message.as_bytes());
    writer.end()
}

pub fn authentication(writer: &mut Writer, code: i32, payload: &[u8]) -> Result<()> {
    writer.begin(TAG_AUTHENTICATION)?;
    writer.i32(code);
    writer.bytes(payload);
    writer.end()
}

pub fn authentication_sasl(writer: &mut Writer, mechanism: &str) -> Result<()> {
    writer.begin(TAG_AUTHENTICATION)?;
    writer.i32(AUTH_SASL);
    writer.cstring(mechanism.as_bytes());
    writer.u8(0);
    writer.end()
}

pub fn ready_for_query(writer: &mut Writer, status: u8) -> Result<()> {
    writer.begin(TAG_READY_FOR_QUERY)?;
    writer.u8(status);
    writer.end()
}

pub fn backend_key_data(writer: &mut Writer, process_id: i32, secret_key: i32) -> Result<()> {
    writer.begin(TAG_BACKEND_KEY_DATA)?;
    writer.i32(process_id);
    writer.i32(secret_key);
    writer.end()
}

pub fn parameter_status(writer: &mut Writer, name: &str, value: &str) -> Result<()> {
    writer.begin(TAG_PARAMETER_STATUS)?;
    writer.cstring(name.as_bytes());
    writer.cstring(value.as_bytes());
    writer.end()
}

pub fn sasl_payload(body: &[u8]) -> Result<&[u8]> {
    let mut reader = crate::reader::Reader::new(body);
    reader.i32()?;
    Ok(reader.remaining())
}

pub fn sasl_initial_payload(body: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut reader = crate::reader::Reader::new(body);
    let mechanism = reader.cstring()?;
    let length = reader.i32()?;
    let payload = if length < 0 {
        &[][..]
    } else {
        let wanted = usize::try_from(length).unwrap_or(0);
        reader.bytes(wanted)?
    };
    Ok((mechanism, payload))
}

pub fn data_row_fields(body: &[u8]) -> Result<Vec<Option<Vec<u8>>>> {
    let mut reader = crate::reader::Reader::new(body);
    let count = reader.i16()?;
    let mut fields = Vec::new();
    for _index in 0..count.max(0) {
        let length = reader.i32()?;
        if length < 0 {
            fields.push(None);
        } else {
            let wanted = usize::try_from(length).unwrap_or(0);
            fields.push(Some(reader.bytes(wanted)?.to_vec()));
        }
    }
    Ok(fields)
}

pub fn row_description(writer: &mut Writer, columns: &[&str]) -> Result<()> {
    writer.begin(TAG_ROW_DESCRIPTION)?;
    writer.i16(i16::try_from(columns.len()).unwrap_or(0));
    for name in columns {
        writer.cstring(name.as_bytes());
        writer.i32(0);
        writer.i16(0);
        writer.i32(25);
        writer.i16(-1);
        writer.i32(-1);
        writer.i16(0);
    }
    writer.end()
}

pub fn data_row(writer: &mut Writer, values: &[Option<&[u8]>]) -> Result<()> {
    writer.begin(TAG_DATA_ROW)?;
    writer.i16(i16::try_from(values.len()).unwrap_or(0));
    for value in values {
        match value {
            Some(bytes) => {
                writer.i32(i32::try_from(bytes.len()).unwrap_or(0));
                writer.bytes(bytes);
            }
            None => writer.i32(-1),
        }
    }
    writer.end()
}

pub fn command_complete(writer: &mut Writer, tag: &str) -> Result<()> {
    writer.begin(TAG_COMMAND_COMPLETE)?;
    writer.cstring(tag.as_bytes());
    writer.end()
}

pub fn bind_complete(writer: &mut Writer) -> Result<()> {
    writer.begin(TAG_BIND_COMPLETE)?;
    writer.end()
}

pub fn close_complete(writer: &mut Writer) -> Result<()> {
    writer.begin(TAG_CLOSE_COMPLETE)?;
    writer.end()
}

pub fn parse_complete(writer: &mut Writer) -> Result<()> {
    writer.begin(TAG_PARSE_COMPLETE)?;
    writer.end()
}

pub struct BindParameters<'a> {
    pub statement: &'a [u8],
    pub formats: Vec<i16>,
    pub values: Vec<Option<&'a [u8]>>,
}

impl BindParameters<'_> {
    #[must_use]
    pub fn format_for(&self, index: usize) -> i16 {
        match self.formats.len() {
            0 => 0,
            1 => self.formats.first().copied().unwrap_or(0),
            _ => self.formats.get(index).copied().unwrap_or(0),
        }
    }
}

pub fn parse_bind(body: &[u8]) -> Result<BindParameters<'_>> {
    let mut reader = crate::reader::Reader::new(body);
    let _portal = reader.cstring()?;
    let statement = reader.cstring()?;

    let format_count = reader.i16()?.max(0);
    let mut formats = Vec::with_capacity(usize::try_from(format_count).unwrap_or(0));
    for _index in 0..format_count {
        formats.push(reader.i16()?);
    }

    let value_count = reader.i16()?.max(0);
    let mut values = Vec::with_capacity(usize::try_from(value_count).unwrap_or(0));
    for _index in 0..value_count {
        let length = reader.i32()?;
        if length < 0 {
            values.push(None);
        } else {
            let wanted = usize::try_from(length).unwrap_or(0);
            values.push(Some(reader.bytes(wanted)?));
        }
    }

    Ok(BindParameters {
        statement,
        formats,
        values,
    })
}

pub fn parse_sql(body: &[u8]) -> Result<&[u8]> {
    let mut reader = crate::reader::Reader::new(body);
    let _name = reader.cstring()?;
    reader.cstring()
}

pub fn parse_param_types(body: &[u8]) -> Result<&[u8]> {
    let mut reader = crate::reader::Reader::new(body);
    reader.cstring()?;
    reader.cstring()?;
    Ok(reader.remaining())
}

pub fn parse_statement_name(body: &[u8]) -> Result<&[u8]> {
    let mut reader = crate::reader::Reader::new(body);
    reader.cstring()
}
