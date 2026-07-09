use core::fmt;
use std::borrow::Cow;

use proto::{
    crypto::{Digest, KeyDerivation, KeySourceSide, HandshakeHash},
    Decode, Decoded, Encode, IncomingPacket, KeyExchangeAlgorithm, KeyExchangeInit, MessageType,
    ProtoError, PublicKeyAlgorithm,
};
use tracing::{debug, error, warn};

use crate::ConnectionContext;

pub(crate) struct EcdhKeyExchange {
    /// The current session id or `None` if this is the initial key exchange.
    session_id: Option<Digest>,
    /// The negotiated key exchange algorithm, which also determines the hash.
    key_exchange: KeyExchangeAlgorithm<'static>,
}

impl EcdhKeyExchange {
    pub(crate) fn advance(
        self,
        ecdh_key_exchange_init: EcdhKeyExchangeInit<'_>,
        mut exchange: HandshakeHash,
        cx: &ConnectionContext,
    ) -> Result<(EcdhKeyExchangeReply, Digest, KeySourceSet), ()> {
        // Write the server's public host key (`K_S`) to the exchange hash

        let mut host_key_buf = Vec::with_capacity(128);
        TaggedPublicKey {
            algorithm: cx.host_key.algorithm(),
            key: Cow::Owned(cx.host_key.public_key().to_owned()),
        }
        .encode(&mut host_key_buf);
        exchange.update(&host_key_buf);

        // Write the client's ephemeral public key (`Q_C`) to the exchange hash

        exchange.prefixed(ecdh_key_exchange_init.client_ephemeral_public_key);

        let Ok(key_exchange) = cx.provider.key_exchange(&self.key_exchange) else {
            warn!(addr = %cx.addr, algorithm = ?self.key_exchange, "unsupported key exchange algorithm");
            return Err(());
        };

        let Ok(kx) = key_exchange.start() else {
            warn!(addr = %cx.addr, "failed to generate key exchange private key");
            return Err(());
        };

        let Ok(completed) = kx.complete(ecdh_key_exchange_init.client_ephemeral_public_key) else {
            warn!(addr = %cx.addr, "key exchange failed");
            return Err(());
        };

        // Write the server's reply public value (`Q_S` / `S_REPLY`) to the exchange hash
        exchange.prefixed(&completed.public_key);
        let secret_bytes = completed.shared_secret.secret_bytes();
        let mut shared_secret = Vec::with_capacity(secret_bytes.len() + 4);
        secret_bytes.encode(&mut shared_secret);
        exchange.update(&shared_secret);

        let exchange_hash = exchange.finish();
        let signature = cx.host_key.sign(exchange_hash.as_ref());
        let key_exchange_reply = EcdhKeyExchangeReply {
            server_public_host_key: TaggedPublicKey {
                algorithm: cx.host_key.algorithm(),
                key: Cow::Owned(cx.host_key.public_key().to_owned()),
            },
            server_ephemeral_public_key: completed.public_key,
            exchange_hash_signature: TaggedSignature {
                algorithm: cx.host_key.algorithm(),
                signature,
            },
        };

        let Ok(hash) = cx.provider.hash(&self.key_exchange) else {
            warn!(addr = %cx.addr, algorithm = ?self.key_exchange, "unsupported hash algorithm");
            return Err(());
        };

        // The first exchange hash is used as session id.
        let session_id = self.session_id.unwrap_or(exchange_hash);
        let derivation = KeyDerivation {
            hash,
            shared_secret,
            exchange_hash,
            session_id,
        };

        Ok((
            key_exchange_reply,
            session_id,
            KeySourceSet {
                client_to_server: KeySourceSide::client_to_server(&derivation),
                server_to_client: KeySourceSide::server_to_client(&derivation),
            },
        ))
    }
}

#[derive(Debug)]
pub(crate) struct EcdhKeyExchangeInit<'a> {
    /// Also known as `Q_C` (<https://www.rfc-editor.org/rfc/rfc5656#section-4>)
    client_ephemeral_public_key: &'a [u8],
}

impl<'a> TryFrom<IncomingPacket<'a>> for EcdhKeyExchangeInit<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        if packet.message_type != MessageType::KeyExchangeEcdhInit {
            return Err(ProtoError::InvalidPacket("unexpected message type"));
        }

        let Decoded {
            value: client_ephemeral_public_key,
            next,
        } = <&[u8]>::decode(packet.payload)?;

        if !next.is_empty() {
            debug!(bytes = ?next, "unexpected trailing bytes");
            return Err(ProtoError::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(Self {
            client_ephemeral_public_key,
        })
    }
}

#[derive(Debug)]
pub(crate) struct EcdhKeyExchangeReply {
    server_public_host_key: TaggedPublicKey<'static>,
    server_ephemeral_public_key: Vec<u8>,
    exchange_hash_signature: TaggedSignature<'static>,
}

impl Encode for EcdhKeyExchangeReply {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::KeyExchangeEcdhReply.encode(buf);
        self.server_public_host_key.encode(buf);
        self.server_ephemeral_public_key.encode(buf);
        self.exchange_hash_signature.encode(buf);
    }
}

#[derive(Debug)]
struct TaggedPublicKey<'a> {
    algorithm: PublicKeyAlgorithm<'a>,
    key: Cow<'a, [u8]>,
}

impl Encode for TaggedPublicKey<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        buf.extend([0; 4]);
        self.algorithm.encode(buf);
        self.key.encode(buf);
        let len = (buf.len() - start - 4) as u32;
        if let Some(dst) = buf.get_mut(start..start + 4) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
    }
}

struct TaggedSignature<'a> {
    algorithm: PublicKeyAlgorithm<'a>,
    signature: Vec<u8>,
}

impl Encode for TaggedSignature<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        buf.extend([0; 4]);
        self.algorithm.encode(buf);
        self.signature.as_slice().encode(buf);
        let len = (buf.len() - start - 4) as u32;
        if let Some(dst) = buf.get_mut(start..start + 4) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
    }
}

impl fmt::Debug for TaggedSignature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaggedSignature")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub(crate) struct KeyExchange {
    /// The current session id or `None` if this is the initial key exchange.
    session_id: Option<Digest>,
}

impl KeyExchange {
    pub(crate) fn advance<'out>(
        self,
        peer_key_exchange_init: KeyExchangeInit<'_>,
        cx: &ConnectionContext,
    ) -> Result<(KeyExchangeInit<'out>, EcdhKeyExchange), ()> {
        let mut cookie = [0; 16];
        if cx.provider.secure_random().fill(&mut cookie).is_err() {
            error!("failed to generate key exchange cookie");
            return Err(());
        };

        let key_exchange_init = match KeyExchangeInit::new(cookie) {
            Ok(kex_init) => kex_init,
            Err(error) => {
                error!(addr = %cx.addr, %error, "failed to create key exchange init");
                return Err(());
            }
        };

        let algorithms = match Algorithms::choose(peer_key_exchange_init, &key_exchange_init) {
            Ok(algorithms) => {
                debug!(addr = %cx.addr, ?algorithms, "chosen algorithms");
                algorithms
            }
            Err(error) => {
                warn!(addr = %cx.addr, %error, "failed to choose algorithms");
                return Err(());
            }
        };

        if algorithms.key_exchange != KeyExchangeAlgorithm::Mlkem768X25519Sha256 {
            warn!(addr = %cx.addr, algorithm = ?algorithms.key_exchange, "unsupported key exchange algorithm");
            return Err(());
        }

        Ok((
            key_exchange_init,
            EcdhKeyExchange {
                session_id: self.session_id,
                key_exchange: algorithms.key_exchange,
            },
        ))
    }
}

#[derive(Debug)]
struct Algorithms {
    key_exchange: KeyExchangeAlgorithm<'static>,
}

impl Algorithms {
    fn choose(
        client: KeyExchangeInit<'_>,
        server: &KeyExchangeInit<'static>,
    ) -> Result<Self, ProtoError> {
        let key_exchange = client
            .key_exchange_algorithms
            .iter()
            .find_map(|&client| {
                server
                    .key_exchange_algorithms
                    .iter()
                    .find(|&&server_alg| server_alg == client)
            })
            .ok_or(ProtoError::NoCommonAlgorithm("key exchange"))?;

        Ok(Self {
            key_exchange: *key_exchange,
        })
    }
}

/// The raw hashes from which we will derive the crypto keys.
///
/// <https://www.rfc-editor.org/rfc/rfc4253#section-7.2>
pub(crate) struct KeySourceSet {
    pub(crate) client_to_server: KeySourceSide,
    pub(crate) server_to_client: KeySourceSide,
}
