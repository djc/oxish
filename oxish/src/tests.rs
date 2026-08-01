use core::{net::Ipv4Addr, net::SocketAddr, time::Duration};
use std::{env, fs, panic::resume_unwind, path::Path, path::PathBuf, process::Stdio, sync::Once};

use anyhow::Context;
use proto::{
    Decoded, Encode,
    auth::AuthorizedKey,
    crypto::{CryptoProvider, Digest, KeySourceSide},
    key_exchange::{HostKeys, Identities, ServerHostKey},
    named::{EncryptionAlgorithm, PublicKeyAlgorithm},
};
use tempfile::TempDir;
use tokio::{
    io::AsyncWriteExt, net::TcpListener, process::Command, task::JoinHandle, time::timeout,
};
use zeroize::Zeroizing;

use crate::{
    Config, SessionState, SideState, UserStore, Username,
    authentication::{SingleUser, User},
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
    .await
    .unwrap();
}

/// Exercise a full handshake and session against the graviola provider
#[cfg(feature = "graviola")]
#[tokio::test]
async fn handshake_ecdsa_graviola() {
    handshake(
        graviola::DEFAULT_PROVIDER,
        PublicKeyAlgorithm::EcdsaSha2Nistp256,
    )
    .await
    .unwrap();
}

/// Exercise an ssh-ed25519 client key against the aws-lc-rs provider
#[cfg(feature = "aws-lc")]
#[tokio::test]
async fn handshake_ed25519_aws_lc() {
    handshake(aws_lc::DEFAULT_PROVIDER, PublicKeyAlgorithm::Ed25519)
        .await
        .unwrap();
}

/// Exercise an ssh-ed25519 client key against the graviola provider
#[cfg(feature = "graviola")]
#[tokio::test]
async fn handshake_ed25519_graviola() {
    handshake(graviola::DEFAULT_PROVIDER, PublicKeyAlgorithm::Ed25519)
        .await
        .unwrap();
}

#[cfg(feature = "graviola")]
#[tokio::test]
async fn no_spawn() {
    subscribe();

    let (_key_dir, client, server) = setup(
        &PublicKeyAlgorithm::Ed25519,
        Some(Config {
            spawn: false,
            ..Config::default()
        }),
        graviola::DEFAULT_PROVIDER,
    )
    .await
    .expect("failed to set up test");

    let (_stdout, _stderr) = client
        .run(
            COMMAND,
            // In the rekey scenario, keep the session open long enough for several rekeys before the
            // sentinel; it only arrives if the session survived them.
            Duration::from_secs(10),
            server,
        )
        .await
        .unwrap();
}

/// Exercise a client-initiated rekey against the graviola provider
#[cfg(feature = "graviola")]
#[tokio::test]
#[ignore = "slow"]
async fn rekey_graviola() {
    subscribe();
    let (_key_dir, mut client, server) = setup(
        &PublicKeyAlgorithm::Ed25519,
        None,
        graviola::DEFAULT_PROVIDER,
    )
    .await
    .expect("failed to set up test");

    // A short time-based rekey interval makes the client send a fresh SSH_MSG_KEXINIT every
    // couple of seconds, exercising client-initiated rekeying. A time trigger keeps the
    // session near-idle, avoiding the data volume a byte-based trigger would need.
    client.cmd.args(["-o", "RekeyLimit=default 1"]);

    let (_stdout, stderr) = client
        .run(
            b"sleep 10\necho OXISH-$((6*7))\nexit\n",
            // In the rekey scenario, keep the session open long enough for several rekeys before the
            // sentinel; it only arrives if the session survived them.
            Duration::from_secs(30),
            server,
        )
        .await
        .unwrap();

    // The client logs "SSH2_MSG_KEXINIT received" once per key exchange it observes from the
    // server: once for the initial handshake, then once for each rekey the server answered.
    // More than one proves the server handled a client-initiated rekey.
    let key_exchanges = stderr.matches("SSH2_MSG_KEXINIT received").count();
    assert!(
        key_exchanges >= 2,
        "expected at least one rekey, saw {key_exchanges} key exchange(s).\n\
             --- stderr ({stderr_len} bytes) ---\n{stderr}",
        stderr_len = stderr.len(),
    );
}

async fn handshake(
    provider: &'static dyn CryptoProvider,
    algorithm: PublicKeyAlgorithm<'_>,
) -> anyhow::Result<()> {
    subscribe();

    let (_key_dir, client, server) = setup(&algorithm, None, provider).await?;

    let (_stdout, _stderr) = client
        .run(
            COMMAND,
            // In the rekey scenario, keep the session open long enough for several rekeys before the
            // sentinel; it only arrives if the session survived them.
            Duration::from_secs(10),
            server,
        )
        .await?;

    Ok(())
}

async fn setup(
    algorithm: &PublicKeyAlgorithm<'_>,
    config: Option<Config>,
    provider: &'static dyn CryptoProvider,
) -> anyhow::Result<(TempDir, CliClient, JoinHandle<anyhow::Result<()>>)> {
    let (key_dir, store) = store(algorithm, provider).await?;
    let (_, pkcs8) = provider.generate_signing_key(algorithm)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let client = CliClient::new(addr, &key_dir.path().join("key"));

    let server = Server::new(
        store,
        HostKeys::new([Zeroizing::new(pkcs8)].into_iter(), provider)?,
        session_binary().await?,
        provider,
    )?;

    let server = match config {
        Some(config) => server.with_config(config),
        None => server,
    };

    // Start the server and serve exactly one connection
    let handle = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        server.accept(stream, peer).await
    });

    Ok((key_dir, client, handle))
}

struct CliClient {
    addr: SocketAddr,
    cmd: Command,
}

impl CliClient {
    fn new(addr: SocketAddr, key_path: &Path) -> Self {
        let mut cmd = Command::new("ssh");
        cmd.arg("-tt") // force PTY allocation even though our stdin is a pipe, not a terminal
            .args(["-F", "/dev/null"]) // ignore the invoking user's ssh_config
            .args(["-p", &addr.port().to_string()]) // port to connect to
            .arg("-i") // identity (private key) file to authenticate with
            .arg(key_path)
            .args(["-o", "StrictHostKeyChecking=no"]) // ignore the host key
            .args(["-o", "UserKnownHostsFile=/dev/null"])
            .args(["-o", "GlobalKnownHostsFile=/dev/null"]) // ignore system known hosts
            .args(["-o", "IdentitiesOnly=yes"]) // don't offer agent keys
            .args(["-o", "LogLevel=DEBUG3"]); // verbose client diagnostics, captured on stderr for failure triage

        Self { addr, cmd }
    }

    async fn run(
        mut self,
        command: &[u8],
        wait_for: Duration,
        server: JoinHandle<anyhow::Result<()>>,
    ) -> anyhow::Result<(String, String)> {
        let mut child = self
            .cmd
            .arg(format!("{USER}@{}", self.addr.ip()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(command).await?;
        drop(stdin); // close stdin so the session ends after `exit`

        let output = timeout(wait_for, child.wait_with_output()).await??;

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

        Ok((stdout.into_owned(), stderr.into_owned()))
    }
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
    use crate::DEFAULT_PROVIDER;
    let (key, pkcs8) = DEFAULT_PROVIDER
        .generate_signing_key(&PublicKeyAlgorithm::Ed25519)
        .expect("failed to generate signing key");
    let pkcs8 = Zeroizing::new(pkcs8);
    let host_key = ServerHostKey::from((&pkcs8, &*key));

    let state = SessionState {
        addr: SocketAddr::from(([192, 0, 2, 7], 22022)),
        identities: Identities {
            client: b"client-identity".to_vec(),
            server: b"server-identity".to_vec(),
        },
        strict_kx: None,
        host_key,
        session_id: Digest::new(b"session-id"),
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
    } = SessionState::decode(&buf, DEFAULT_PROVIDER).unwrap();
    assert!(next.is_empty());

    assert_eq!(decoded.addr, state.addr);
    assert_eq!(decoded.identities.client, state.identities.client);
    assert_eq!(decoded.identities.server, state.identities.server);
    assert_eq!(decoded.strict_kx.is_some(), state.strict_kx.is_some());
    assert_eq!(decoded.session_id.as_ref(), state.session_id.as_ref());
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

async fn store(
    algorithm: &PublicKeyAlgorithm<'_>,
    provider: &dyn CryptoProvider,
) -> anyhow::Result<(TempDir, Box<dyn UserStore>)> {
    let dir = TempDir::new()?;
    let key_path = dir.path().join("key");

    // Generate the client key; ssh-keygen writes the private key with 0600
    // permissions, which the ssh client requires.
    let status = Command::new("ssh-keygen")
        .arg("-q") // quiet: suppress the interactive progress output
        .args(match algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => &["-t", "ecdsa", "-b", "256"],
            PublicKeyAlgorithm::Ed25519 => &["-t", "ed25519"][..],
            _ => panic!("unsupported key type for ssh-keygen: {algorithm:?}"),
        }) // key type (and size, where applicable)
        .args(["-N", ""]) // empty passphrase, so the private key is not encrypted
        .args(["-C", "oxish-e2e"]) // key comment
        .arg("-f") // output file for the private key (public key gets a .pub suffix)
        .arg(&key_path)
        .status()
        .await
        .context("failed to run ssh-keygen")?;
    assert!(status.success(), "ssh-keygen failed");

    let authorized_key = fs::read_to_string(key_path.with_extension("pub"))?;
    let key = AuthorizedKey::from_str(&authorized_key, provider)
        .ok_or_else(|| anyhow::anyhow!("failed to parse generated public key"))?;

    let user = User {
        name: Username::try_from(USER.to_string())?,
        id: 1000,
        gid: 1000,
        home_dir: PathBuf::from("/var/empty"),
        shell: PathBuf::from("/bin/sh"),
    };

    Ok((dir, Box::new(SingleUser::with_keys(user, vec![key]))))
}

/// Build and locate the `oxish-session` binary
///
/// `cargo test` only builds the crate's binaries as test harnesses, so build the real
/// binary here (a no-op when fresh). Unit tests run from `target/<profile>/deps/`, while
/// cargo places the binary in `target/<profile>/`.
async fn session_binary() -> anyhow::Result<PathBuf> {
    let exe = env::current_exe()?;
    let profile_dir = exe.parent().and_then(|deps| deps.parent()).unwrap();
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    let mut command = Command::new(cargo);
    command.args(["build", "-q", "-p", "oxish", "--bin", "oxish-session"]);
    command
        .arg("--target-dir")
        .arg(profile_dir.parent().unwrap());
    if profile_dir
        .file_name()
        .is_some_and(|name| name == "release")
    {
        command.arg("--release");
    }

    let status = command.status().await?;
    assert!(status.success(), "failed to build oxish-session");

    let bin = profile_dir.join("oxish-session");
    assert!(
        bin.is_file(),
        "oxish-session binary not found at `{}`",
        bin.display(),
    );
    Ok(bin)
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
