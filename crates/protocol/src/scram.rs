use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const MECHANISM: &str = "SCRAM-SHA-256";
pub const KEY_LENGTH: usize = 32;
const VERIFIER_PREFIX: &str = "SCRAM-SHA-256$";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScramError {
    #[error("stored verifier is not a SCRAM-SHA-256 verifier")]
    NotScram,

    #[error("stored verifier is malformed")]
    MalformedVerifier,

    #[error("client message is malformed: {0}")]
    MalformedMessage(&'static str),

    #[error("client requested channel binding, which shahrah does not offer")]
    ChannelBindingRequested,

    #[error("channel binding header changed between messages")]
    ChannelBindingMismatch,

    #[error("nonce did not match the one this exchange issued")]
    NonceMismatch,

    #[error("authentication failed")]
    ProofRejected,

    #[error("exchange used out of order")]
    OutOfOrder,
}

type Result<T> = core::result::Result<T, ScramError>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier {
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub stored_key: [u8; KEY_LENGTH],
    pub server_key: [u8; KEY_LENGTH],
}

impl Verifier {
    pub fn parse(text: &str) -> Result<Self> {
        let body = text
            .strip_prefix(VERIFIER_PREFIX)
            .ok_or(ScramError::NotScram)?;
        let (head, keys) = body.split_once('$').ok_or(ScramError::MalformedVerifier)?;
        let (iterations, salt) = head.split_once(':').ok_or(ScramError::MalformedVerifier)?;
        let (stored, server) = keys.split_once(':').ok_or(ScramError::MalformedVerifier)?;

        Ok(Self {
            iterations: iterations
                .parse()
                .map_err(|_| ScramError::MalformedVerifier)?,
            salt: STANDARD
                .decode(salt)
                .map_err(|_| ScramError::MalformedVerifier)?,
            stored_key: fixed_key(stored)?,
            server_key: fixed_key(server)?,
        })
    }
}

fn fixed_key(encoded: &str) -> Result<[u8; KEY_LENGTH]> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| ScramError::MalformedVerifier)?;
    <[u8; KEY_LENGTH]>::try_from(bytes.as_slice()).map_err(|_| ScramError::MalformedVerifier)
}

#[derive(Debug)]
enum Stage {
    AwaitingFirst,
    AwaitingFinal {
        gs2_header: String,
        client_first_bare: String,
        server_first: String,
        nonce: String,
    },
    Done,
}

#[derive(Debug)]
pub struct ServerExchange {
    verifier: Verifier,
    server_nonce: String,
    stage: Stage,
}

impl ServerExchange {
    #[must_use]
    pub fn new(verifier: Verifier, server_nonce: String) -> Self {
        Self {
            verifier,
            server_nonce,
            stage: Stage::AwaitingFirst,
        }
    }

    pub fn first(&mut self, client_first: &[u8]) -> Result<String> {
        if !matches!(self.stage, Stage::AwaitingFirst) {
            return Err(ScramError::OutOfOrder);
        }
        let text =
            core::str::from_utf8(client_first).map_err(|_| ScramError::MalformedMessage("utf-8"))?;

        let (gs2_header, bare) = split_gs2(text)?;
        let client_nonce = field(bare, "r=").ok_or(ScramError::MalformedMessage("missing r="))?;
        if client_nonce.is_empty() {
            return Err(ScramError::MalformedMessage("empty client nonce"));
        }

        let nonce = format!("{client_nonce}{}", self.server_nonce);
        let server_first = format!(
            "r={nonce},s={},i={}",
            STANDARD.encode(&self.verifier.salt),
            self.verifier.iterations
        );

        self.stage = Stage::AwaitingFinal {
            gs2_header: gs2_header.to_owned(),
            client_first_bare: bare.to_owned(),
            server_first: server_first.clone(),
            nonce,
        };
        Ok(server_first)
    }

    pub fn finish(&mut self, client_final: &[u8]) -> Result<String> {
        let Stage::AwaitingFinal {
            gs2_header,
            client_first_bare,
            server_first,
            nonce,
        } = &self.stage
        else {
            return Err(ScramError::OutOfOrder);
        };

        let text =
            core::str::from_utf8(client_final).map_err(|_| ScramError::MalformedMessage("utf-8"))?;
        let (without_proof, proof_field) = text
            .rsplit_once(",p=")
            .ok_or(ScramError::MalformedMessage("missing p="))?;

        let channel =
            field(without_proof, "c=").ok_or(ScramError::MalformedMessage("missing c="))?;
        let decoded = STANDARD
            .decode(channel)
            .map_err(|_| ScramError::MalformedMessage("c= is not base64"))?;
        if decoded.as_slice() != gs2_header.as_bytes() {
            return Err(ScramError::ChannelBindingMismatch);
        }

        let echoed = field(without_proof, "r=").ok_or(ScramError::MalformedMessage("missing r="))?;
        if echoed != nonce {
            return Err(ScramError::NonceMismatch);
        }

        let proof = STANDARD
            .decode(proof_field)
            .map_err(|_| ScramError::MalformedMessage("p= is not base64"))?;
        let proof = <[u8; KEY_LENGTH]>::try_from(proof.as_slice())
            .map_err(|_| ScramError::MalformedMessage("p= is the wrong length"))?;

        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
        let client_signature = mac(&self.verifier.stored_key, auth_message.as_bytes())?;

        let mut client_key = [0u8; KEY_LENGTH];
        for (slot, (left, right)) in client_key
            .iter_mut()
            .zip(proof.iter().zip(client_signature.iter()))
        {
            *slot = left ^ right;
        }

        let candidate: [u8; KEY_LENGTH] = Sha256::digest(client_key).into();
        if candidate.ct_eq(&self.verifier.stored_key).unwrap_u8() != 1 {
            return Err(ScramError::ProofRejected);
        }

        let server_signature = mac(&self.verifier.server_key, auth_message.as_bytes())?;
        self.stage = Stage::Done;
        Ok(format!("v={}", STANDARD.encode(server_signature)))
    }
}

fn split_gs2(message: &str) -> Result<(&str, &str)> {
    if message.starts_with("p=") {
        return Err(ScramError::ChannelBindingRequested);
    }
    if !(message.starts_with("n,") || message.starts_with("y,")) {
        return Err(ScramError::MalformedMessage("bad gs2 flag"));
    }
    let rest = message
        .get(2..)
        .ok_or(ScramError::MalformedMessage("truncated gs2 header"))?;
    let authzid_end = rest
        .find(',')
        .ok_or(ScramError::MalformedMessage("truncated gs2 header"))?;
    let split = authzid_end
        .checked_add(3)
        .ok_or(ScramError::MalformedMessage("truncated gs2 header"))?;
    let header = message
        .get(..split)
        .ok_or(ScramError::MalformedMessage("truncated gs2 header"))?;
    let bare = message
        .get(split..)
        .ok_or(ScramError::MalformedMessage("truncated gs2 header"))?;
    Ok((header, bare))
}

fn field<'a>(message: &'a str, prefix: &str) -> Option<&'a str> {
    message.split(',').find_map(|part| part.strip_prefix(prefix))
}

fn mac(key: &[u8], message: &[u8]) -> Result<[u8; KEY_LENGTH]> {
    let mut hmac = HmacSha256::new_from_slice(key).map_err(|_| ScramError::MalformedVerifier)?;
    hmac.update(message);
    Ok(hmac.finalize().into_bytes().into())
}

#[derive(Debug)]
enum ClientStage {
    AwaitingServerFirst {
        client_first_bare: String,
    },
    AwaitingServerFinal {
        server_signature: [u8; KEY_LENGTH],
    },
    Done,
}

#[derive(Debug)]
pub struct ClientExchange {
    password: String,
    stage: ClientStage,
}

pub const GS2_HEADER: &str = "n,,";
pub const GS2_HEADER_ENCODED: &str = "biws";

impl ClientExchange {
    #[must_use]
    pub fn start(username: &str, password: &str, client_nonce: &str) -> (Self, String) {
        let client_first_bare = format!("n={},r={client_nonce}", saslprep(username));
        let message = format!("{GS2_HEADER}{client_first_bare}");
        (
            Self {
                password: password.to_owned(),
                stage: ClientStage::AwaitingServerFirst { client_first_bare },
            },
            message,
        )
    }

    pub fn respond(&mut self, server_first: &[u8]) -> Result<String> {
        let ClientStage::AwaitingServerFirst { client_first_bare } = &self.stage else {
            return Err(ScramError::OutOfOrder);
        };

        let text =
            core::str::from_utf8(server_first).map_err(|_| ScramError::MalformedMessage("utf-8"))?;
        let nonce = field(text, "r=").ok_or(ScramError::MalformedMessage("missing r="))?;
        let salt = field(text, "s=").ok_or(ScramError::MalformedMessage("missing s="))?;
        let iterations = field(text, "i=").ok_or(ScramError::MalformedMessage("missing i="))?;

        let salt = STANDARD
            .decode(salt)
            .map_err(|_| ScramError::MalformedMessage("s= is not base64"))?;
        let iterations: u32 = iterations
            .parse()
            .map_err(|_| ScramError::MalformedMessage("i= is not a number"))?;

        let salted = salted_password(&self.password, &salt, iterations)?;
        let client_key = mac(&salted, b"Client Key")?;
        let stored_key: [u8; KEY_LENGTH] = Sha256::digest(client_key).into();
        let server_key = mac(&salted, b"Server Key")?;

        let without_proof = format!("c={GS2_HEADER_ENCODED},r={nonce}");
        let auth_message = format!("{client_first_bare},{text},{without_proof}");
        let client_signature = mac(&stored_key, auth_message.as_bytes())?;

        let mut proof = [0u8; KEY_LENGTH];
        for (slot, (left, right)) in proof
            .iter_mut()
            .zip(client_key.iter().zip(client_signature.iter()))
        {
            *slot = left ^ right;
        }

        self.stage = ClientStage::AwaitingServerFinal {
            server_signature: mac(&server_key, auth_message.as_bytes())?,
        };
        Ok(format!("{without_proof},p={}", STANDARD.encode(proof)))
    }

    pub fn verify(&mut self, server_final: &[u8]) -> Result<()> {
        let ClientStage::AwaitingServerFinal { server_signature } = &self.stage else {
            return Err(ScramError::OutOfOrder);
        };
        let text =
            core::str::from_utf8(server_final).map_err(|_| ScramError::MalformedMessage("utf-8"))?;
        if let Some(error) = field(text, "e=") {
            let _reported = error;
            return Err(ScramError::ProofRejected);
        }
        let signature = field(text, "v=").ok_or(ScramError::MalformedMessage("missing v="))?;
        let decoded = STANDARD
            .decode(signature)
            .map_err(|_| ScramError::MalformedMessage("v= is not base64"))?;
        if decoded.ct_eq(server_signature).unwrap_u8() != 1 {
            return Err(ScramError::ProofRejected);
        }
        self.stage = ClientStage::Done;
        Ok(())
    }
}

fn salted_password(password: &str, salt: &[u8], iterations: u32) -> Result<[u8; KEY_LENGTH]> {
    let mut out = [0u8; KEY_LENGTH];
    pbkdf2::pbkdf2::<HmacSha256>(password.as_bytes(), salt, iterations, &mut out)
        .map_err(|_| ScramError::MalformedVerifier)?;
    Ok(out)
}

fn saslprep(name: &str) -> String {
    name.replace('=', "=3D").replace(',', "=2C")
}
