//! windows-deployment phase 3 — §8 Gherkin for the Windows named-pipe peer-auth transport
//! (windows-peer-auth.md). Runs only on the windows-latest lane; the macOS/Linux dev host
//! cannot exercise impersonation, SID comparison, or name-squatting (spec G3). The
//! different-local-user scenario (§8.2) needs a second account a hosted runner may not have
//! (RISK-003) and is left to the ADR-024 pen test (phase 4).
#![cfg(windows)]

use faradayd_ipc::{connect, Listener, PeerPrincipal};
use tokio::net::windows::named_pipe::ClientOptions;

/// `SECURITY_SQOS_PRESENT` with the impersonation level left at `SECURITY_ANONYMOUS` (0):
/// the client forbids the server from reading its identity.
const SECURITY_SQOS_PRESENT_ANONYMOUS: u32 = 0x0010_0000;

fn temp_token(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("faradayd-ipc-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("conn.token")
}

fn unique_pipe(tag: &str) -> String {
    format!(r"\\.\pipe\faradayd-test-{}-{}", tag, std::process::id())
}

// §8.1 — Happy path: a same-user client is accepted and its derived principal is the daemon's.
#[tokio::test]
async fn happy_path_same_user_yields_the_daemon_principal() {
    let pipe = unique_pipe("happy");
    let token = temp_token("happy");
    let listener = Listener::bind(&pipe, token.to_str().unwrap()).expect("bind");
    let daemon = listener.daemon_principal().clone();

    let pipe2 = pipe.clone();
    let client = tokio::spawn(async move { connect(&pipe2).await });
    let (_conn, principal) = listener.accept().await.expect("accept");
    client.await.unwrap().expect("client connects");

    // The test client runs as the same Windows user as the daemon, so the impersonated SID
    // equals the daemon's own user SID (canonical string form).
    assert_eq!(
        principal, daemon,
        "same-user client must map to the daemon principal"
    );
    match principal {
        PeerPrincipal::Windows(sid) => assert!(sid.starts_with("S-1-"), "canonical SID: {sid}"),
        other => panic!("expected a Windows principal, got {other:?}"),
    }
}

// §8.3 — A client that hides its identity (SECURITY_ANONYMOUS) cannot be resolved to a SID,
// so the derived principal can never equal the daemon's → CLIENT_UID_DENIED downstream.
#[tokio::test]
async fn anonymous_client_does_not_match_the_daemon_principal() {
    let pipe = unique_pipe("anon");
    let token = temp_token("anon");
    let listener = Listener::bind(&pipe, token.to_str().unwrap()).expect("bind");
    let daemon = listener.daemon_principal().clone();

    let pipe2 = pipe.clone();
    let client = tokio::spawn(async move {
        ClientOptions::new()
            .security_qos_flags(SECURITY_SQOS_PRESENT_ANONYMOUS)
            .open(&pipe2)
    });
    let (_conn, principal) = listener.accept().await.expect("accept");
    client.await.unwrap().expect("anonymous client connects");

    assert_ne!(
        principal, daemon,
        "an anonymous client must not resolve to the daemon principal"
    );
}

// §8.5 — Name-squatting is defeated at start-up: FILE_FLAG_FIRST_PIPE_INSTANCE makes a second
// create of the same pipe name fail, so the daemon will not start onto a pre-created pipe.
#[tokio::test]
async fn name_squatting_is_defeated_at_bind() {
    let pipe = unique_pipe("squat");
    let _first =
        Listener::bind(&pipe, temp_token("squat-a").to_str().unwrap()).expect("first bind");
    let second = Listener::bind(&pipe, temp_token("squat-b").to_str().unwrap());
    assert!(
        second.is_err(),
        "a second bind of an existing pipe name must fail (name-squatting defence)"
    );
}
