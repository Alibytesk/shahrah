use crate::error::{ProtocolError, Result};
use crate::reader::Reader;

pub const SSL_REQUEST_CODE: i32 = 80_877_103;
pub const CANCEL_REQUEST_CODE: i32 = 80_877_102;
pub const GSSENC_REQUEST_CODE: i32 = 80_877_104;

pub const PROTOCOL_VERSION_3: i32 = 196_608;
pub const PROTOCOL_MAJOR: i16 = 3;
pub const PROTOCOL_MINOR: i16 = 0;

pub const MAX_STARTUP_BODY: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup<'a> {
    SslRequest,
    GssEncRequest,
    Cancel {
        process_id: i32,
        secret_key: i32,
    },
    Connect {
        major: i16,
        minor: i16,
        parameters: Parameters<'a>,
    },
}

impl<'a> Startup<'a> {
    pub fn parse(body: &'a [u8]) -> Result<Self> {
        let mut reader = Reader::new(body);
        let code_bytes = reader.bytes(4)?;
        let code = match <[u8; 4]>::try_from(code_bytes) {
            Ok(array) => i32::from_be_bytes(array),
            Err(_) => {
                return Err(ProtocolError::UnexpectedEnd {
                    needed: 4,
                    remaining: code_bytes.len(),
                })
            }
        };

        match code {
            SSL_REQUEST_CODE => {
                reader.expect_end()?;
                Ok(Self::SslRequest)
            }
            GSSENC_REQUEST_CODE => {
                reader.expect_end()?;
                Ok(Self::GssEncRequest)
            }
            CANCEL_REQUEST_CODE => {
                let process_id = reader.i32()?;
                let secret_key = reader.i32()?;
                reader.expect_end()?;
                Ok(Self::Cancel {
                    process_id,
                    secret_key,
                })
            }
            _ => {
                let (major, minor) = split_version(code_bytes)?;
                let rest = reader.remaining();
                Parameters::validate(rest)?;
                Ok(Self::Connect {
                    major,
                    minor,
                    parameters: Parameters(rest),
                })
            }
        }
    }
}

fn split_version(code_bytes: &[u8]) -> Result<(i16, i16)> {
    let mut reader = Reader::new(code_bytes);
    let major = reader.i16()?;
    let minor = reader.i16()?;
    Ok((major, minor))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters<'a>(&'a [u8]);

impl<'a> Parameters<'a> {
    fn validate(bytes: &'a [u8]) -> Result<()> {
        let mut reader = Reader::new(bytes);
        loop {
            let key = reader.cstring()?;
            if key.is_empty() {
                return reader.expect_end();
            }
            reader.cstring()?;
        }
    }

    #[must_use]
    pub const fn iter(&self) -> ParametersIter<'a> {
        ParametersIter(Reader::new(self.0))
    }

    #[must_use]
    pub fn get(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value)
    }
}

impl<'a> IntoIterator for &Parameters<'a> {
    type Item = (&'a [u8], &'a [u8]);
    type IntoIter = ParametersIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Debug, Clone)]
pub struct ParametersIter<'a>(Reader<'a>);

impl<'a> Iterator for ParametersIter<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.0.cstring().ok()?;
        if key.is_empty() {
            return None;
        }
        let value = self.0.cstring().ok()?;
        Some((key, value))
    }
}
