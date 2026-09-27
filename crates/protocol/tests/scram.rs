use shahrah_protocol::scram::{ScramError, ServerExchange, Verifier};

const RFC7677_VERIFIER: &str = "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=";
const CLIENT_FIRST: &[u8] = b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
const SERVER_NONCE: &str = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
const SERVER_FIRST: &str =
    "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const CLIENT_FINAL: &[u8] = b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
const SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

fn verifier() -> Verifier {
    match Verifier::parse(RFC7677_VERIFIER) {
        Ok(verifier) => verifier,
        Err(error) => panic!("the RFC 7677 verifier must parse: {error}"),
    }
}

fn exchange() -> ServerExchange {
    ServerExchange::new(verifier(), SERVER_NONCE.to_owned())
}

#[test]
fn the_verifier_decomposes_the_way_postgres_stores_it() {
    let parsed = verifier();
    assert_eq!(parsed.iterations, 4096);
    assert_eq!(parsed.salt.len(), 16);
    assert_eq!(parsed.stored_key.len(), 32);
    assert_eq!(parsed.server_key.len(), 32);
}

#[test]
fn the_rfc_7677_exchange_reproduces_byte_for_byte() {
    let mut server = exchange();
    assert_eq!(server.first(CLIENT_FIRST), Ok(SERVER_FIRST.to_owned()));
    assert_eq!(server.finish(CLIENT_FINAL), Ok(SERVER_FINAL.to_owned()));
}

#[test]
fn a_wrong_proof_is_rejected() {
    let mut server = exchange();
    assert!(server.first(CLIENT_FIRST).is_ok());
    let tampered = b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=AHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    assert_eq!(server.finish(tampered), Err(ScramError::ProofRejected));
}

#[test]
fn a_replayed_nonce_from_another_exchange_is_rejected() {
    let mut server = ServerExchange::new(verifier(), "a-different-server-nonce".to_owned());
    assert!(server.first(CLIENT_FIRST).is_ok());
    assert_eq!(server.finish(CLIENT_FINAL), Err(ScramError::NonceMismatch));
}

#[test]
fn a_changed_gs2_header_is_rejected() {
    let mut server = exchange();
    assert!(server.first(CLIENT_FIRST).is_ok());
    let lying = b"c=eSws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    assert_eq!(server.finish(lying), Err(ScramError::ChannelBindingMismatch));
}

#[test]
fn a_client_demanding_channel_binding_is_refused() {
    let mut server = exchange();
    assert_eq!(
        server.first(b"p=tls-server-end-point,,n=user,r=abc"),
        Err(ScramError::ChannelBindingRequested)
    );
}

#[test]
fn a_client_that_only_supports_channel_binding_still_works() {
    let mut server = ServerExchange::new(verifier(), SERVER_NONCE.to_owned());
    let first = server.first(b"y,,n=user,r=rOprNGfwEbeRWgbNEkqO");
    assert_eq!(first, Ok(SERVER_FIRST.to_owned()));
}

#[test]
fn the_exchange_refuses_to_run_backwards() {
    let mut server = exchange();
    assert_eq!(server.finish(CLIENT_FINAL), Err(ScramError::OutOfOrder));

    let mut server = exchange();
    assert!(server.first(CLIENT_FIRST).is_ok());
    assert_eq!(server.first(CLIENT_FIRST), Err(ScramError::OutOfOrder));
}

#[test]
fn a_second_finish_after_success_is_refused() {
    let mut server = exchange();
    assert!(server.first(CLIENT_FIRST).is_ok());
    assert!(server.finish(CLIENT_FINAL).is_ok());
    assert_eq!(server.finish(CLIENT_FINAL), Err(ScramError::OutOfOrder));
}

#[test]
fn malformed_messages_are_rejected_without_panicking() {
    for message in [
        &b""[..],
        b"n",
        b"n,",
        b"n,,",
        b"n,,n=user",
        b"n,,r=",
        b"x,,n=user,r=abc",
        &[0xFF, 0xFE][..],
    ] {
        let mut server = exchange();
        assert!(
            server.first(message).is_err(),
            "accepted {message:?} as a client-first message"
        );
    }

    for message in [
        &b""[..],
        b"c=biws",
        b"c=biws,r=x",
        b"c=!!!!,r=x,p=x",
        b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=tooshort",
    ] {
        let mut server = exchange();
        assert!(server.first(CLIENT_FIRST).is_ok());
        assert!(
            server.finish(message).is_err(),
            "accepted {message:?} as a client-final message"
        );
    }
}

#[test]
fn a_verifier_that_is_not_scram_is_refused() {
    assert_eq!(Verifier::parse("md5abcdef"), Err(ScramError::NotScram));
    assert_eq!(
        Verifier::parse("SCRAM-SHA-256$notanumber:AAAA$AAAA:AAAA"),
        Err(ScramError::MalformedVerifier)
    );
}

use shahrah_protocol::scram::ClientExchange;

#[test]
fn the_client_side_reproduces_the_rfc_7677_messages() {
    let (mut client, first) = ClientExchange::start("user", "pencil", "rOprNGfwEbeRWgbNEkqO");
    assert_eq!(first.as_bytes(), CLIENT_FIRST);

    let final_message = match client.respond(SERVER_FIRST.as_bytes()) {
        Ok(message) => message,
        Err(error) => panic!("respond failed: {error}"),
    };
    assert_eq!(final_message.as_bytes(), CLIENT_FINAL);
    assert_eq!(client.verify(SERVER_FINAL.as_bytes()), Ok(()));
}

#[test]
fn the_two_sides_authenticate_each_other() {
    let (mut client, client_first) = ClientExchange::start("user", "pencil", "clientnonce123");
    let mut server = ServerExchange::new(verifier(), "servernonce456".to_owned());

    let server_first = match server.first(client_first.as_bytes()) {
        Ok(message) => message,
        Err(error) => panic!("server first failed: {error}"),
    };
    let client_final = match client.respond(server_first.as_bytes()) {
        Ok(message) => message,
        Err(error) => panic!("client respond failed: {error}"),
    };
    let server_final = match server.finish(client_final.as_bytes()) {
        Ok(message) => message,
        Err(error) => panic!("server finish failed: {error}"),
    };
    assert_eq!(client.verify(server_final.as_bytes()), Ok(()));
}

#[test]
fn a_client_with_the_wrong_password_is_rejected_by_the_server() {
    let (mut client, client_first) = ClientExchange::start("user", "notpencil", "clientnonce123");
    let mut server = ServerExchange::new(verifier(), "servernonce456".to_owned());
    let server_first = match server.first(client_first.as_bytes()) {
        Ok(message) => message,
        Err(error) => panic!("server first failed: {error}"),
    };
    let client_final = match client.respond(server_first.as_bytes()) {
        Ok(message) => message,
        Err(error) => panic!("client respond failed: {error}"),
    };
    assert_eq!(
        server.finish(client_final.as_bytes()),
        Err(ScramError::ProofRejected)
    );
}

#[test]
fn a_forged_server_signature_is_caught_by_the_client() {
    let (mut client, client_first) = ClientExchange::start("user", "pencil", "clientnonce123");
    let mut server = ServerExchange::new(verifier(), "servernonce456".to_owned());
    let server_first = match server.first(client_first.as_bytes()) {
        Ok(message) => message,
        Err(error) => panic!("server first failed: {error}"),
    };
    assert!(client.respond(server_first.as_bytes()).is_ok());
    assert_eq!(
        client.verify(b"v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        Err(ScramError::ProofRejected)
    );
}

#[test]
fn a_username_with_commas_or_equals_is_escaped() {
    let (_client, first) = ClientExchange::start("a,b=c", "pw", "nonce");
    assert_eq!(first, "n,,n=a=2Cb=3Dc,r=nonce");
}
