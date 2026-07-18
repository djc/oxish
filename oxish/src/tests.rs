use core::{net::Ipv4Addr, time::Duration};
use std::{fs, panic::resume_unwind, path::PathBuf, process::Stdio, sync::Once};

use proto::{crypto::CryptoProvider, PublicKeyAlgorithm};
use tempfile::TempDir;
use tokio::{io::AsyncWriteExt, net::TcpListener, process::Command, time::timeout};

use crate::{authentication::AuthorizedKey, Auth, Connection, IoStream, User};

/// Exercise a full handshake and session against the aws-lc-rs provider.
#[tokio::test]
async fn handshake_aws_lc() {
    handshake(aws_lc::DEFAULT_PROVIDER).await;
}

/// Exercise a full handshake and session against the graviola provider.
#[tokio::test]
async fn handshake_graviola() {
    handshake(graviola::DEFAULT_PROVIDER).await;
}

async fn handshake(provider: &'static dyn CryptoProvider) {
    subscribe();

    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("key");

    // Generate an ecdsa-sha2-nistp256 client key; ssh-keygen writes the private
    // key with 0600 permissions, which the ssh client requires.
    let status = Command::new("ssh-keygen")
        .arg("-q") // quiet: suppress the interactive progress output
        .args(["-t", "ecdsa"]) // key type
        .args(["-b", "256"]) // key size in bits, which selects the nistp256 curve
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
    let user = User::new(USER.to_string(), 0, PathBuf::from("/var/empty"), vec![key]);

    // Start the server on a loopback port and serve exactly one connection.
    let (host_key, _) = provider
        .generate_signing_key(&PublicKeyAlgorithm::Ed25519)
        .expect("failed to generate host key");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        stream.set_nodelay(true).ok();
        let mut io = IoStream::new(stream, peer, provider);

        let Ok(_user) = Auth::Fixed(user)
            .authenticate(&mut io, &*host_key, provider)
            .await
        else {
            return Err(());
        };

        Connection::new(io).run().await
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
