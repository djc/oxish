use core::{net::Ipv4Addr, net::SocketAddr, time::Duration};
use std::{env, fs, panic::resume_unwind, path::PathBuf, process::Stdio, sync::Once};

use proto::{
    Decode, Decoded, Encode, EncryptionAlgorithm, HostKeys, PublicKeyAlgorithm,
    crypto::{CryptoProvider, KeySourceSide},
};
use tempfile::TempDir;
use tokio::{io::AsyncWriteExt, net::TcpListener, process::Command, time::timeout};

use crate::{
    SessionState, SideState,
    authentication::{Auth, AuthorizedKey, User},
    server::Server,
};

/// Exercise a full handshake and session against the aws-lc-rs provider
#[cfg(feature = "aws-lc")]
#[tokio::test]
async fn handshake_ecdsa_aws_lc() {
    handshake(
        aws_lc::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::EcdsaSha2Nistp256,
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
    )
    .await;
}

/// Exercise an ssh-ed25519 client key against the aws-lc-rs provider
#[cfg(feature = "aws-lc")]
#[tokio::test]
async fn handshake_ed25519_aws_lc() {
    handshake(aws_lc::DEFAULT_PROVIDER, PublicKeyAlgorithm::Ed25519).await;
}

/// Exercise an ssh-ed25519 client key against the graviola provider
#[cfg(feature = "graviola")]
#[tokio::test]
async fn handshake_ed25519_graviola() {
    handshake(graviola::DEFAULT_PROVIDER, PublicKeyAlgorithm::Ed25519).await;
}

#[cfg(feature = "graviola")]
#[tokio::test]
async fn handshake_ecdsa_graviola_split() {
    handshake(
        graviola::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::EcdsaSha2Nistp256,
    )
    .await;
}

async fn handshake(provider: &'static dyn CryptoProvider, algorithm: PublicKeyAlgorithm<'_>) {
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

    let server = Server::new(
        Auth::Fixed(user),
        HostKeys::try_from(vec![host_key]).unwrap(),
        session_binary().await,
        provider,
    )
    .unwrap();

    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        stream.set_nodelay(true).ok();
        server.accept(stream, peer).await
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

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(COMMAND).await.unwrap();
    drop(stdin); // close stdin so the session ends after `exit`

    let output = timeout(Duration::from_secs(10), child.wait_with_output())
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
        Ok(Ok(Err(error))) => println!("server task yielded {error})"),
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

#[test]
fn session_state_round_trip() {
    let state = SessionState {
        addr: SocketAddr::from(([192, 0, 2, 7], 22022)),
        read: SideState {
            source: KeySourceSide {
                algorithm: EncryptionAlgorithm::Aes128Gcm,
                initial_iv: vec![2; 12],
                encryption_key: vec![1; 16],
            },
            counter: 42,
            sequence_number: 17,
        },
        write: SideState {
            source: KeySourceSide {
                algorithm: EncryptionAlgorithm::Aes128Gcm,
                initial_iv: vec![4; 12],
                encryption_key: vec![3; 16],
            },
            counter: 7,
            sequence_number: 23,
        },
        read_buf: b"pipelined".to_vec(),
    };

    let mut buf = Vec::new();
    state.encode(&mut buf);

    let Decoded {
        value: decoded,
        next,
    } = SessionState::decode(&buf).unwrap();
    assert!(next.is_empty());

    assert_eq!(decoded.addr, state.addr);
    assert_eq!(decoded.read_buf, state.read_buf);
    assert_eq!(
        decoded.read.source.algorithm,
        EncryptionAlgorithm::Aes128Gcm
    );
    assert_eq!(decoded.read.source.encryption_key, [1; 16]);
    assert_eq!(decoded.read.source.initial_iv, [2; 12]);
    assert_eq!(
        decoded.write.source.algorithm,
        EncryptionAlgorithm::Aes128Gcm
    );
    assert_eq!(decoded.write.source.encryption_key, [3; 16]);
    assert_eq!(decoded.write.source.initial_iv, [4; 12]);
    assert_eq!(decoded.read.counter, 42);
    assert_eq!(decoded.read.sequence_number, 17);
    assert_eq!(decoded.write.counter, 7);
    assert_eq!(decoded.write.sequence_number, 23);
}

/// Build and locate the `oxish-session` binary
///
/// `cargo test` only builds the crate's binaries as test harnesses, so build the real
/// binary here (a no-op when fresh). Unit tests run from `target/<profile>/deps/`, while
/// cargo places the binary in `target/<profile>/`.
async fn session_binary() -> PathBuf {
    let exe = env::current_exe().unwrap();
    let profile_dir = exe.parent().and_then(|deps| deps.parent()).unwrap();
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    let mut command = Command::new(cargo);
    command.args(["build", "-p", "oxish", "--bin", "oxish-session"]);
    command
        .arg("--target-dir")
        .arg(profile_dir.parent().unwrap());
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
