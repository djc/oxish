use core::{net::Ipv4Addr, time::Duration};
use std::{
    fs,
    panic::resume_unwind,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Once},
};

use proto::{PublicKeyAlgorithm, crypto::CryptoProvider};
use tempfile::TempDir;
use tokio::{io::AsyncWriteExt, net::TcpListener, process::Command, time::timeout};

use crate::{Auth, Connection, Session, SessionState, User, authentication::AuthorizedKey};

/// Exercise a full handshake and session against the aws-lc-rs provider
#[cfg(feature = "aws-lc")]
#[tokio::test]
async fn handshake_ecdsa_aws_lc() {
    handshake(
        aws_lc::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::EcdsaSha2Nistp256,
        Scenario::default(),
    )
    .await;
}

/// Exercise a full handshake and session against the graviola provider
#[cfg(feature = "graviola")]
#[tokio::test]
async fn handshake_ecdsa_graviola() {
    handshake(
        graviola::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::EcdsaSha2Nistp256,
        Scenario::default(),
    )
    .await;
}

/// Exercise an ssh-ed25519 client key against the aws-lc-rs provider
#[cfg(feature = "aws-lc")]
#[tokio::test]
async fn handshake_ed25519_aws_lc() {
    handshake(
        aws_lc::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::Ed25519,
        Scenario::default(),
    )
    .await;
}

/// Exercise an ssh-ed25519 client key against the graviola provider
#[cfg(feature = "graviola")]
#[tokio::test]
async fn handshake_ed25519_graviola() {
    handshake(
        graviola::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::Ed25519,
        Scenario::default(),
    )
    .await;
}

#[cfg(feature = "graviola")]
#[tokio::test]
async fn handshake_ecdsa_graviola_split() {
    handshake(
        graviola::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::EcdsaSha2Nistp256,
        Scenario {
            split: true,
            ..Scenario::default()
        },
    )
    .await;
}

/// Stream more output than a channel window holds, exercising `SSH_MSG_CHANNEL_WINDOW_ADJUST`
#[cfg(feature = "aws-lc")]
#[tokio::test]
async fn bulk_output_aws_lc() {
    handshake(
        aws_lc::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::Ed25519,
        Scenario {
            bulk: true,
            ..Scenario::default()
        },
    )
    .await;
}

/// The same, across the session subprocess handoff
#[cfg(feature = "graviola")]
#[tokio::test]
async fn bulk_output_graviola_split() {
    handshake(
        graviola::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::Ed25519,
        Scenario {
            split: true,
            bulk: true,
        },
    )
    .await;
}

/// Knobs for a single [`handshake`] run
#[derive(Clone, Copy, Default)]
struct Scenario {
    /// Hand the authenticated connection off to a session subprocess
    split: bool,
    /// Emit far more output than one channel window, forcing repeated window adjustments
    bulk: bool,
}

async fn handshake(
    provider: &'static dyn CryptoProvider,
    algorithm: PublicKeyAlgorithm<'_>,
    scenario: Scenario,
) {
    let Scenario { split, bulk } = scenario;
    subscribe();

    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("key");

    // Generate the client key; ssh-keygen writes the private key with 0600
    // permissions, which the ssh client requires.
    let status = Command::new("ssh-keygen")
        .arg("-q") // quiet: suppress the interactive progress output
        .args(keygen_args(&algorithm)) // key type (and size, where applicable)
        .args(["-N", ""]) // empty passphrase, so the private key is not encrypted
        .args(["-C", "oxish-e2e"]) // key comment
        .arg("-f") // output file for the private key (public key gets a .pub suffix)
        .arg(&key_path)
        .status()
        .await
        .expect("failed to run ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");

    let authorized_key = fs::read_to_string(key_path.with_extension("pub")).unwrap();
    let key = AuthorizedKey::from_str(&authorized_key, provider)
        .unwrap()
        .expect("failed to parse generated public key");
    let user = User::new(
        USER.to_string(),
        0,
        0,
        PathBuf::from("/var/empty"),
        vec![key],
    );

    // Start the server on a loopback port and serve exactly one connection.
    let (host_key, _) = provider
        .generate_signing_key(&algorithm)
        .expect("failed to generate host key");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let host_keys = Arc::new([host_key]);
    let session_bin = match split {
        true => Some(session_binary().await),
        false => None,
    };

    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        stream.set_nodelay(true).ok();

        let future = Connection::accept(stream, peer, &*host_keys, provider);
        let Ok((mut conn, session_id, keys)) = future.await else {
            return Err(());
        };

        let auth = Auth::Fixed(user);
        let Ok(user) = auth.authenticate(session_id, &mut conn, provider).await else {
            return Err(());
        };

        let Some(session_bin) = session_bin else {
            return Session::new(conn).run().await;
        };

        let (state, stream) = SessionState::from_connection(conn, keys).map_err(|_| ())?;
        let mut child = state
            .spawn(stream, &session_bin, user, &auth)
            .await
            .expect("failed to hand off connection");

        match child.wait().await {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => {
                println!("session process exited with {status}");
                Err(())
            }
            Err(error) => {
                println!("failed to wait for session process: {error}");
                Err(())
            }
        }
    });

    let mut child = Command::new("ssh")
        .arg("-tt") // force PTY allocation even though our stdin is a pipe, not a terminal
        .args(["-F", "/dev/null"]) // ignore the invoking user's ssh_config
        .args(["-p", &addr.port().to_string()]) // port to connect to
        .arg("-i") // identity (private key) file to authenticate with
        .arg(&key_path)
        .args(["-o", "StrictHostKeyChecking=no"]) // ignore the host key
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "GlobalKnownHostsFile=/dev/null"]) // ignore system known hosts
        .args(["-o", "IdentitiesOnly=yes"]) // don't offer agent keys
        .args(["-o", "LogLevel=DEBUG3"]) // verbose client diagnostics, captured on stderr for failure triage
        .arg(format!("{USER}@{}", addr.ip()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn ssh");

    // In the bulk scenario, emit well over a channel window's worth of output (the client
    // advertises ~1-2 MiB) before the sentinel, so the whole transfer only completes if the
    // server honors the window adjustments the client sends as it drains the data.
    let command = match bulk {
        true => b"seq 1 400000\necho OXISH-$((6*7))\nexit\n".to_vec(),
        false => COMMAND.to_vec(),
    };

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&command).await.unwrap();
    drop(stdin); // close stdin so the session ends after `exit`

    let client_timeout = match bulk {
        true => Duration::from_secs(30),
        false => Duration::from_secs(10),
    };
    let output = timeout(client_timeout, child.wait_with_output())
        .await
        .expect("ssh client timed out")
        .expect("failed to wait for ssh");

    // The server task completes on its own once the ssh client tears down the connection: cleanly
    // (Ok) if the client sent a disconnect, or with Err if it just closed the socket. The client
    // process can be reaped a moment before the server observes that teardown, so give the server a
    // bounded window to finish rather than aborting it out from under that race. Only a genuine hang
    // — the server never noticing the disconnect — should fail the test.
    match timeout(Duration::from_secs(10), server).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(()))) => println!("server task yielded Err(())"),
        Ok(Err(err)) => resume_unwind(err.into_panic()),
        Err(_elapsed) => panic!("server still running after client disconnected"),
    };

    let _ = fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(OUTPUT),
        "expected command output {OUTPUT:?} in session output.\n\
         --- ssh exit status: {status} ---\n\
         --- stdout ({stdout_len} bytes) ---\n{stdout}\n\
         --- stderr ({stderr_len} bytes) ---\n{stderr}",
        status = output.status,
        stdout_len = output.stdout.len(),
        stderr_len = output.stderr.len(),
    );
}

#[tokio::test]
async fn verify_keys() {
    let providers = [
        #[cfg(feature = "aws-lc")]
        aws_lc::DEFAULT_PROVIDER,
        #[cfg(feature = "graviola")]
        graviola::DEFAULT_PROVIDER,
    ];

    for signer in providers {
        for verifier in providers {
            let (signing_key, _) = signer
                .generate_signing_key(&PublicKeyAlgorithm::Ed25519)
                .expect("failed to generate signing key");

            let message = b"the quick brown fox";
            let signature = signing_key.sign(message);
            let verifying_key = verifier
                .verifying_key(signing_key.public_key(), &PublicKeyAlgorithm::Ed25519)
                .expect("failed to build verifying key");

            verifying_key
                .verify(message, &signature)
                .expect("valid signature should verify");

            verifying_key
                .verify(b"the quick brown cat", &signature)
                .expect_err("signature over a different message must not verify");
        }
    }
}

/// Build and locate the `oxish-session` binary
///
/// `cargo test` only builds the crate's binaries as test harnesses, so build the real
/// binary here (a no-op when fresh). Unit tests run from `target/<profile>/deps/`, while
/// cargo places the binary in `target/<profile>/`.
async fn session_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().and_then(|deps| deps.parent()).unwrap();

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.args(["build", "-p", "oxish", "--bin", "oxish-session"]);
    if profile_dir
        .file_name()
        .is_some_and(|name| name == "release")
    {
        command.arg("--release");
    }

    let status = command.status().await.expect("failed to run cargo build");
    assert!(status.success(), "failed to build oxish-session");

    let bin = profile_dir.join("oxish-session");
    assert!(
        bin.is_file(),
        "oxish-session binary not found at `{}`",
        bin.display(),
    );
    bin
}

fn keygen_args(algorithm: &PublicKeyAlgorithm<'_>) -> &'static [&'static str] {
    match algorithm {
        PublicKeyAlgorithm::EcdsaSha2Nistp256 => &["-t", "ecdsa", "-b", "256"],
        PublicKeyAlgorithm::Ed25519 => &["-t", "ed25519"],
        _ => panic!("unsupported key type for ssh-keygen: {algorithm:?}"),
    }
}

fn subscribe() {
    static INSTALL_TRACING_SUBSCRIBER: Once = Once::new();
    INSTALL_TRACING_SUBSCRIBER.call_once(|| {
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
            .with_test_writer()
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

const USER: &str = "oxish-e2e";
const COMMAND: &[u8] = b"echo OXISH-$((6*7))\nexit\n";
const OUTPUT: &str = "OXISH-42";
