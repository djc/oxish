use core::{net::Ipv4Addr, time::Duration};
use std::{fs, path::PathBuf, process::Stdio, sync::Arc};

use aws_lc_rs::signature::Ed25519KeyPair;
use tempfile::TempDir;
use tokio::{io::AsyncWriteExt, net::TcpListener, process::Command, time::timeout};

use crate::{AuthorizedKey, Connection, User};

#[tokio::test]
async fn handshake() {
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
    let key = AuthorizedKey::from_str(&authorized_key)
        .unwrap()
        .expect("failed to parse generated public key");
    let user = User::new(USER.to_string(), 0, PathBuf::from("/var/empty"), vec![key]);

    // Start the server on a loopback port and serve exactly one connection.
    let host_key = Arc::new(Ed25519KeyPair::generate().expect("failed to generate host key"));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        stream.set_nodelay(true).ok();
        let _ = Connection::new(stream, peer, host_key)
            .for_user(user)
            .run()
            .await;
    });

    // Drive the real ssh client. `-tt` forces PTY allocation (the server only
    // supports shell sessions behind a PTY) even though stdin is a pipe.
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
        .args(["-o", "LogLevel=ERROR"]) // keep client diagnostics out of stderr
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
    server.abort();
    server.await.unwrap();
    let _ = fs::remove_dir_all(&dir);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(OUTPUT),
        "expected command output {OUTPUT:?} in session output.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

const USER: &str = "oxish-e2e";
const COMMAND: &[u8] = b"echo OXISH-$((6*7))\nexit\n";
const OUTPUT: &str = "OXISH-42";
