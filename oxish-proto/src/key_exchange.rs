use core::{fmt, mem};
use std::borrow::Cow;

use tracing::debug;

use crate::{
    Decode, Decoded, Encode, IncomingPacket, MessageType, Pretty, ProtoError, PublicKeyAlgorithm,
    ReadState, WriteState,
    crypto::{
        CryptoError, CryptoProvider, Digest, HandshakeBuffer, HandshakeHash, KeyDerivation,
        KeySourceSide, OpeningKey, SealingKey, SharedSecret, SigningKey,
    },
    host_keys::{HostKeys, ServerHostKey, SessionHostKey},
    named::{
        CompressionAlgorithm, EncryptionAlgorithm, ExtensionId, ExtensionName, IncomingNameList,
        KeyExchangeAlgorithm, KeyExchangeAlgorithmOrExtensionId, Language, MacAlgorithm,
        OutgoingNameList,
    },
};

/// A server-side initial SSH key exchange, driven one packet at a time
pub enum InitialKeyExchangeState<'a> {
    /// Awaiting the peer's `SSH_MSG_KEXINIT` that begins an exchange
    AwaitingKexInit {
        /// The host keys we may offer the peer
        host_keys: &'a HostKeys,
        /// The exchanged identification strings (`V_C`, `V_S`)
        identities: Identities,
        /// The in-progress exchange hash input
        exchange: HandshakeBuffer,
    },
    /// Sent our `SSH_MSG_KEXINIT`; awaiting the peer's `SSH_MSG_KEX_ECDH_INIT`
    AwaitingEcdhInit {
        /// The negotiated algorithms and in-progress exchange hash
        kx: KeyExchange,
        /// The host keys we may offer the peer
        host_keys: &'a HostKeys,
        /// The exchanged identification strings (`V_C`, `V_S`)
        identities: Identities,
        /// The strict key exchange state, if negotiated
        strict_kx: Option<StrictKeyExchange>,
        /// Extension information to send, if negotiated
        ext_info: Option<ExtInfo<'static>>,
    },
    /// Sent our reply; awaiting the peer's `SSH_MSG_NEWKEYS`
    AwaitingNewKeys {
        /// The negotiated parameters and derived keys
        output: KeyExchangeOutput<'a>,
        /// Extension information to send, if negotiated
        ext_info: Option<ExtInfo<'static>>,
    },
    /// Transient placeholder held only while [`handle()`](Self::handle) transitions states
    Complete,
}

impl<'a> InitialKeyExchangeState<'a> {
    /// Begin the initial key exchange for a freshly accepted connection
    ///
    /// `exchange` must already carry the identification strings (`V_C`, `V_S`).
    pub fn new(exchange: HandshakeBuffer, identities: Identities, host_keys: &'a HostKeys) -> Self {
        Self::AwaitingKexInit {
            host_keys,
            identities,
            exchange,
        }
    }

    /// Advance the exchange by one incoming packet
    pub fn handle(
        &mut self,
        packet: IncomingPacket<'_>,
        write: &mut WriteState,
        provider: &dyn CryptoProvider,
    ) -> Result<Option<Established<'a>>, ProtoError> {
        match mem::replace(self, Self::Complete) {
            Self::AwaitingKexInit {
                host_keys,
                identities,
                exchange,
            } => {
                let (local, mut kx, strict_kx, ext_info) = KeyExchange::start(
                    packet,
                    exchange,
                    host_keys.algorithms().collect(),
                    [ExtensionId::StrictKexServer].into_iter(),
                    provider,
                )?;

                write.encode_kx(&local, Some(&mut kx.exchange))?;
                *self = Self::AwaitingEcdhInit {
                    kx,
                    host_keys,
                    identities,
                    strict_kx,
                    ext_info,
                };

                Ok(None)
            }
            Self::AwaitingEcdhInit {
                kx,
                host_keys,
                identities,
                strict_kx,
                ext_info,
            } => {
                let ecdh_key_exchange_init = EcdhKeyExchangeInit::try_from(packet)?;
                let post_quantum_kx = kx.negotiated.key_exchange.post_quantum_secure();
                let host_key = host_keys.key(&kx.negotiated)?;
                let (reply, session_id, keys) = EcdhKeyExchangeReply::new(
                    ecdh_key_exchange_init,
                    &kx.negotiated,
                    kx.exchange,
                    None,
                    host_key.key,
                    provider,
                )?;

                write.encode(&reply)?;
                *self = Self::AwaitingNewKeys {
                    output: KeyExchangeOutput {
                        identities,
                        host_key,
                        strict_kx,
                        session_id,
                        keys,
                        post_quantum_kx,
                    },
                    ext_info,
                };

                Ok(None)
            }
            Self::AwaitingNewKeys { output, ext_info } => {
                NewKeys::try_from(packet)?;
                *self = Self::Complete;
                Ok(Some(Established {
                    update: KeyUpdate {
                        opener: provider.opening_key(0, &output.keys.client_to_server)?,
                        sealer: provider.sealing_key(0, &output.keys.server_to_client)?,
                        strict_kx: output.strict_kx.as_ref().map(|_| StrictKeyExchange(())),
                    },
                    output,
                    ext_info,
                }))
            }
            Self::Complete => Err(ProtoError::Unreachable(
                "key exchange state machine polled while transitioning",
            )),
        }
    }
}

/// The completed initial key exchange, returned by [`InitialKeyExchangeState::handle()`]
pub struct Established<'a> {
    /// The negotiated connection parameters and derived keys
    pub output: KeyExchangeOutput<'a>,
    /// Updated key material to install
    pub update: KeyUpdate,
    /// Extension information, if negotiated
    pub ext_info: Option<ExtInfo<'static>>,
}

/// A server-side SSH rekey, driven one packet at a time
pub enum RekeyState {
    /// Awaiting the peer's `SSH_MSG_KEXINIT` that begins an exchange
    AwaitingKexInit {
        /// The retained rekey state
        rekey: Rekey,
    },
    /// Sent our `SSH_MSG_KEXINIT`; awaiting the peer's `SSH_MSG_KEX_ECDH_INIT`
    AwaitingEcdhInit {
        /// The negotiated algorithms and in-progress exchange hash
        kx: KeyExchange,
        /// The retained rekey state
        rekey: Rekey,
    },
    /// Sent our reply; awaiting the peer's `SSH_MSG_NEWKEYS`
    AwaitingNewKeys {
        /// The retained rekey state
        rekey: Rekey,
        /// The freshly derived key material
        keys: KeySourceSet,
        /// Whether the newly negotiated key exchange algorithm is post-quantum secure
        post_quantum_kx: bool,
    },
    /// Transient placeholder held only while [`handle()`](Self::handle) transitions states
    Transitioning,
}

impl RekeyState {
    /// Begin a rekey for an already established session
    pub fn new(
        session_id: Digest,
        strict_kx: Option<StrictKeyExchange>,
        identities: Identities,
        host_key: SessionHostKey,
    ) -> Self {
        Self::AwaitingKexInit {
            rekey: Rekey::new(session_id, strict_kx, identities, host_key),
        }
    }

    /// Advance the rekey by one incoming packet
    pub fn handle(
        &mut self,
        packet: IncomingPacket<'_>,
        write: &mut WriteState,
        provider: &dyn CryptoProvider,
    ) -> Result<Option<Rekeyed>, ProtoError> {
        match mem::replace(self, Self::Transitioning) {
            Self::AwaitingKexInit { rekey } => {
                let mut exchange = HandshakeBuffer::default();
                exchange.prefixed(&rekey.identities.client);
                exchange.prefixed(&rekey.identities.server);
                let (local, mut kx, _, _) = KeyExchange::start(
                    packet,
                    exchange,
                    vec![rekey.host_key.algorithm()],
                    [].into_iter(),
                    provider,
                )?;

                write.encode_kx(&local, Some(&mut kx.exchange))?;
                *self = Self::AwaitingEcdhInit { kx, rekey };
                Ok(None)
            }
            Self::AwaitingEcdhInit { kx, rekey } => {
                let ecdh_key_exchange_init = EcdhKeyExchangeInit::try_from(packet)?;
                let post_quantum_kx = kx.negotiated.key_exchange.post_quantum_secure();
                let (reply, _, keys) = EcdhKeyExchangeReply::new(
                    ecdh_key_exchange_init,
                    &kx.negotiated,
                    kx.exchange,
                    Some(rekey.session_id.clone()),
                    &*rekey.host_key.0,
                    provider,
                )?;

                write.encode(&reply)?;
                *self = Self::AwaitingNewKeys {
                    rekey,
                    keys,
                    post_quantum_kx,
                };
                Ok(None)
            }
            Self::AwaitingNewKeys {
                rekey,
                keys,
                post_quantum_kx,
            } => {
                NewKeys::try_from(packet)?;
                let update = KeyUpdate {
                    opener: provider.opening_key(0, &keys.client_to_server)?,
                    sealer: provider.sealing_key(0, &keys.server_to_client)?,
                    strict_kx: rekey.strict_kx.as_ref().map(|_| StrictKeyExchange(())),
                };
                *self = Self::AwaitingKexInit { rekey };
                Ok(Some(Rekeyed {
                    update,
                    post_quantum_kx,
                }))
            }
            Self::Transitioning => Err(ProtoError::Unreachable(
                "key exchange state machine polled while transitioning",
            )),
        }
    }

    /// The peer's identification string
    pub fn client_identity(&self) -> &[u8] {
        match self {
            Self::AwaitingKexInit { rekey }
            | Self::AwaitingEcdhInit { rekey, .. }
            | Self::AwaitingNewKeys { rekey, .. } => &rekey.identities.client,
            Self::Transitioning => b"",
        }
    }

    /// Whether a rekey is in progress, i.e. past the initial `SSH_MSG_KEXINIT`
    ///
    /// While this is `true`, every incoming packet must be fed to [`handle()`](Self::handle);
    /// no other transport-layer traffic is expected until the exchange completes.
    pub fn in_progress(&self) -> bool {
        matches!(
            self,
            Self::AwaitingEcdhInit { .. } | Self::AwaitingNewKeys { .. }
        )
    }
}

/// The completed rekey, returned by [`RekeyState::handle()`]
pub struct Rekeyed {
    /// Updated key material to install
    pub update: KeyUpdate,
    /// Whether the newly negotiated key exchange algorithm is post-quantum secure
    pub post_quantum_kx: bool,
}

/// A pending update to the receive side of a connection after `SSH_MSG_NEWKEYS`
pub struct KeyUpdate {
    /// The new decryption key to install
    pub opener: Box<dyn OpeningKey>,
    /// The new encryption key to install
    pub sealer: Box<dyn SealingKey>,
    /// Whether the newly negotiated key exchange algorithm is strict
    pub strict_kx: Option<StrictKeyExchange>,
}

impl KeyUpdate {
    /// Install the new keys and reset the sequence numbers if necessary
    pub fn apply(self, write: &mut WriteState, read: &mut ReadState) -> Result<(), ProtoError> {
        write.encode(&NewKeys)?;
        write.reset_sequence_number(self.strict_kx.as_ref());
        write.sealer = Some(self.sealer);
        read.reset_sequence_number(self.strict_kx.as_ref());
        read.opener = Some(self.opener);
        Ok(())
    }
}

/// State required for a rekeying exchange
pub struct Rekey {
    host_key: SessionHostKey,
    identities: Identities,
    strict_kx: Option<StrictKeyExchange>,
    session_id: Digest,
}

impl Rekey {
    /// Create a new rekey state from its constituent parts
    fn new(
        session_id: Digest,
        strict_kx: Option<StrictKeyExchange>,
        identities: Identities,
        host_key: SessionHostKey,
    ) -> Self {
        Self {
            host_key,
            identities,
            strict_kx,
            session_id,
        }
    }
}

/// Output from the initial key exchange phase
pub struct KeyExchange {
    /// The in-progress exchange hash computation
    exchange: HandshakeHash,
    /// The negotiated algorithms
    negotiated: Negotiated,
}

impl KeyExchange {
    /// Process the peer's `SSH_MSG_KEXINIT` and negotiate algorithms
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc4253#section-7.1> for the negotiation procedure.
    fn start(
        packet: IncomingPacket<'_>,
        mut exchange: HandshakeBuffer,
        server_host_key_algorithms: Vec<PublicKeyAlgorithm<'static>>,
        extensions: impl Iterator<Item = ExtensionId<'static>>,
        provider: &dyn CryptoProvider,
    ) -> Result<
        (
            KeyExchangeInit<'static>,
            Self,
            Option<StrictKeyExchange>,
            Option<ExtInfo<'static>>,
        ),
        ProtoError,
    > {
        exchange.update(&((packet.payload.len() + 1) as u32).to_be_bytes());
        exchange.update(&[u8::from(packet.message_type)]);
        exchange.update(packet.payload);

        let peer_key_exchange_init = KeyExchangeInit::try_from(packet)?;
        debug!(key_exchange_init = %Pretty(&peer_key_exchange_init), "received key exchange init");

        let mut cookie = [0; 16];
        provider.secure_random().fill(&mut cookie)?;
        let supported = provider.supported_algorithms();
        let mut key_exchange_algorithms = supported
            .key_exchange
            .iter()
            .map(|&alg| KeyExchangeAlgorithmOrExtensionId::KeyExchange(alg))
            .collect::<Vec<_>>();
        key_exchange_algorithms
            .extend(extensions.map(KeyExchangeAlgorithmOrExtensionId::Extension));

        let local = KeyExchangeInit {
            cookie,
            key_exchange_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server: supported.encryption.to_owned(),
            encryption_algorithms_server_to_client: supported.encryption.to_owned(),
            mac_algorithms_client_to_server: supported.mac.to_owned(),
            mac_algorithms_server_to_client: supported.mac.to_owned(),
            compression_algorithms_client_to_server: vec![CompressionAlgorithm::None],
            compression_algorithms_server_to_client: vec![CompressionAlgorithm::None],
            languages_client_to_server: vec![],
            languages_server_to_client: vec![],
            first_kex_packet_follows: false,
            extended: 0,
        };

        let negotiated = Negotiated::choose(peer_key_exchange_init, &local)?;
        let ext_info = negotiated.want_extension_info.then(|| ExtInfo {
            extensions: vec![(
                ExtensionName::ServerSigAlgs,
                Box::new(OutgoingNameList(supported.public_key)),
            )],
        });
        let strict = negotiated
            .strict_key_exchange
            .then_some(StrictKeyExchange(()));

        Ok((
            local,
            Self {
                exchange: exchange.hash(provider.hash(&negotiated.key_exchange)?),
                negotiated,
            },
            strict,
            ext_info,
        ))
    }
}

/// Marker type for whether the client requested strict key exchange
pub struct StrictKeyExchange(());

impl Encode for Option<StrictKeyExchange> {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.is_some().encode(buf);
    }
}

impl Decode<'_> for Option<StrictKeyExchange> {
    fn decode(buf: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded { value, next } = bool::decode(buf)?;
        Ok(Decoded {
            value: value.then_some(StrictKeyExchange(())),
            next,
        })
    }
}

/// The `SSH_MSG_KEXINIT` message
///
/// Lists the algorithms each side supports, in preference order
/// (<https://www.rfc-editor.org/rfc/rfc4253#section-7.1>).
#[derive(Debug)]
pub struct KeyExchangeInit<'a> {
    cookie: [u8; 16],
    key_exchange_algorithms: Vec<KeyExchangeAlgorithmOrExtensionId<'a>>,
    server_host_key_algorithms: Vec<PublicKeyAlgorithm<'a>>,
    encryption_algorithms_client_to_server: Vec<EncryptionAlgorithm<'a>>,
    encryption_algorithms_server_to_client: Vec<EncryptionAlgorithm<'a>>,
    mac_algorithms_client_to_server: Vec<MacAlgorithm<'a>>,
    mac_algorithms_server_to_client: Vec<MacAlgorithm<'a>>,
    compression_algorithms_client_to_server: Vec<CompressionAlgorithm<'a>>,
    compression_algorithms_server_to_client: Vec<CompressionAlgorithm<'a>>,
    languages_client_to_server: Vec<Language<'a>>,
    languages_server_to_client: Vec<Language<'a>>,
    first_kex_packet_follows: bool,
    extended: u32,
}

impl<'a> KeyExchangeInit<'a> {
    fn has_extension(&self, extension: ExtensionId<'_>) -> bool {
        self.key_exchange_algorithms
            .iter()
            .any(|alg| matches!(alg, KeyExchangeAlgorithmOrExtensionId::Extension(ext) if *ext == extension))
    }
}

impl<'a> TryFrom<IncomingPacket<'a>> for KeyExchangeInit<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        packet.expect(&[MessageType::KeyExchangeInit])?;

        let Decoded {
            value: cookie,
            next,
        } = <[u8; 16]>::decode(packet.payload)?;

        let Decoded {
            value: key_exchange_algorithms,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: server_host_key_algorithms,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: encryption_algorithms_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: encryption_algorithms_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: mac_algorithms_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: mac_algorithms_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: compression_algorithms_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: compression_algorithms_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: languages_client_to_server,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: languages_server_to_client,
            next,
        } = IncomingNameList::decode(next)?;

        let Decoded {
            value: first_kex_packet_follows,
            next,
        } = u8::decode(next)?;

        let Decoded {
            value: extended,
            next,
        } = u32::decode(next)?;

        let value = Self {
            cookie,
            key_exchange_algorithms: key_exchange_algorithms.0,
            server_host_key_algorithms: server_host_key_algorithms.0,
            encryption_algorithms_client_to_server: encryption_algorithms_client_to_server.0,
            encryption_algorithms_server_to_client: encryption_algorithms_server_to_client.0,
            mac_algorithms_client_to_server: mac_algorithms_client_to_server.0,
            mac_algorithms_server_to_client: mac_algorithms_server_to_client.0,
            compression_algorithms_client_to_server: compression_algorithms_client_to_server.0,
            compression_algorithms_server_to_client: compression_algorithms_server_to_client.0,
            languages_client_to_server: languages_client_to_server.0,
            languages_server_to_client: languages_server_to_client.0,
            first_kex_packet_follows: first_kex_packet_follows != 0,
            extended,
        };

        if !next.is_empty() {
            debug!(bytes = ?next, "unexpected trailing bytes");
            return Err(ProtoError::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(value)
    }
}

impl Encode for KeyExchangeInit<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self {
            cookie,
            key_exchange_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
            extended,
        } = self;

        MessageType::KeyExchangeInit.encode(buf);
        buf.extend_from_slice(cookie);
        OutgoingNameList(key_exchange_algorithms).encode(buf);
        OutgoingNameList(server_host_key_algorithms).encode(buf);
        OutgoingNameList(encryption_algorithms_client_to_server).encode(buf);
        OutgoingNameList(encryption_algorithms_server_to_client).encode(buf);
        OutgoingNameList(mac_algorithms_client_to_server).encode(buf);
        OutgoingNameList(mac_algorithms_server_to_client).encode(buf);
        OutgoingNameList(compression_algorithms_client_to_server).encode(buf);
        OutgoingNameList(compression_algorithms_server_to_client).encode(buf);
        OutgoingNameList(languages_client_to_server).encode(buf);
        OutgoingNameList(languages_server_to_client).encode(buf);
        buf.push(if *first_kex_packet_follows { 1 } else { 0 });
        buf.extend_from_slice(&extended.to_be_bytes());
    }
}

/// The `SSH_MSG_KEX_ECDH_INIT` message
///
/// Carries the client's ephemeral public key (<https://www.rfc-editor.org/rfc/rfc5656#section-4>).
#[derive(Debug)]
pub struct EcdhKeyExchangeInit<'a> {
    /// Also known as `Q_C` (<https://www.rfc-editor.org/rfc/rfc5656#section-4>)
    client_ephemeral_public_key: &'a [u8],
}

impl<'a> TryFrom<IncomingPacket<'a>> for EcdhKeyExchangeInit<'a> {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        packet.expect(&[MessageType::KeyExchangeEcdhInit])?;

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

/// The `SSH_MSG_KEX_ECDH_REPLY` message
///
/// Carries the server's host key, its ephemeral public key and its signature over the exchange hash
/// (<https://www.rfc-editor.org/rfc/rfc5656#section-4>).
#[derive(Debug)]
pub struct EcdhKeyExchangeReply {
    server_public_host_key: TaggedPublicKey<'static>,
    server_ephemeral_public_key: Vec<u8>,
    exchange_hash_signature: TaggedSignature<'static>,
}

impl EcdhKeyExchangeReply {
    /// Complete the key exchange started by the client's `SSH_MSG_KEX_ECDH_INIT`
    ///
    /// Returns the reply message, the exchange hash and the derived key material
    /// (<https://www.rfc-editor.org/rfc/rfc4253#section-7.2>).
    fn new(
        ecdh_key_exchange_init: EcdhKeyExchangeInit<'_>,
        negotiated: &Negotiated,
        exchange: HandshakeHash,
        session_id: Option<Digest>,
        host_key: &dyn SigningKey,
        provider: &dyn CryptoProvider,
    ) -> Result<(Self, Digest, KeySourceSet), CryptoError> {
        let KeyExchangeStarted {
            shared_secret,
            exchange_hash,
            reply,
        } = KeyExchangeStarted::new(
            exchange,
            ecdh_key_exchange_init.client_ephemeral_public_key,
            negotiated,
            host_key,
            provider,
        )?;

        // The first exchange hash is used as session id.
        let derivation = KeyDerivation {
            hash: provider.hash(&negotiated.key_exchange)?,
            shared_secret,
            exchange_hash: exchange_hash.clone(),
            session_id: session_id.unwrap_or_else(|| exchange_hash.clone()),
        };

        Ok((
            reply,
            exchange_hash,
            KeySourceSet {
                client_to_server: KeySourceSide::client_to_server(
                    &derivation,
                    negotiated.encryption_client_to_server.clone(),
                )?,
                server_to_client: KeySourceSide::server_to_client(
                    &derivation,
                    negotiated.encryption_server_to_client.clone(),
                )?,
            },
        ))
    }
}

impl Encode for EcdhKeyExchangeReply {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self {
            server_public_host_key,
            server_ephemeral_public_key,
            exchange_hash_signature,
        } = self;

        MessageType::KeyExchangeEcdhReply.encode(buf);
        server_public_host_key.encode(buf);
        server_ephemeral_public_key.encode(buf);
        exchange_hash_signature.encode(buf);
    }
}

struct KeyExchangeStarted {
    shared_secret: SharedSecret,
    exchange_hash: Digest,
    reply: EcdhKeyExchangeReply,
}

impl KeyExchangeStarted {
    fn new(
        mut exchange: HandshakeHash,
        client_ephemeral_public_key: &[u8],
        negotiated: &Negotiated,
        host_key: &dyn SigningKey,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, CryptoError> {
        // Write the server's public host key (`K_S`) to the exchange hash

        let mut host_key_buf = Vec::with_capacity(128);
        TaggedPublicKey {
            algorithm: host_key.algorithm(),
            key: Cow::Owned(host_key.public_key().to_owned()),
        }
        .encode(&mut host_key_buf);
        exchange.update(&host_key_buf);

        // Write the client's ephemeral public key (`Q_C`) to the exchange hash

        exchange.prefixed(client_ephemeral_public_key);

        let key_exchange = provider.key_exchange(&negotiated.key_exchange)?;
        let kx = key_exchange.start()?;
        let completed = kx.complete(client_ephemeral_public_key)?;

        // Write the server's reply public value (`Q_S` / `S_REPLY`) to the exchange hash
        exchange.prefixed(&completed.public_key);
        let secret_bytes = completed.shared_secret.secret_bytes();
        let mut shared_secret = Vec::with_capacity(secret_bytes.len() + 5);
        match negotiated.key_exchange {
            // RFC 8731 section 3: `K` is the raw X25519 output encoded as an mpint
            KeyExchangeAlgorithm::Curve25519Sha256 => {
                encode_mpint(secret_bytes, &mut shared_secret)
            }
            // The PQ hybrid draft encodes `K` (a fixed-length hash output) as a string
            _ => secret_bytes.encode(&mut shared_secret),
        }
        exchange.update(&shared_secret);

        let exchange_hash = exchange.finish();
        Ok(Self {
            shared_secret: SharedSecret::from(shared_secret),
            reply: EcdhKeyExchangeReply {
                server_public_host_key: TaggedPublicKey {
                    algorithm: host_key.algorithm(),
                    key: Cow::Owned(host_key.public_key().to_owned()),
                },
                server_ephemeral_public_key: completed.public_key,
                exchange_hash_signature: TaggedSignature {
                    algorithm: host_key.algorithm(),
                    signature: host_key.sign(exchange_hash.as_ref()),
                },
            },
            exchange_hash,
        })
    }
}

#[derive(Debug)]
struct TaggedPublicKey<'a> {
    algorithm: PublicKeyAlgorithm<'a>,
    key: Cow<'a, [u8]>,
}

impl Encode for TaggedPublicKey<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self { algorithm, key } = self;
        let start = buf.len();
        buf.extend([0; 4]);
        algorithm.encode(buf);

        // RFC 5656 section 3.1: an ECDSA public key blob carries the curve
        // identifier between the algorithm name and the point `Q`.
        if matches!(algorithm, PublicKeyAlgorithm::EcdsaSha2Nistp256) {
            "nistp256".as_bytes().encode(buf);
        }

        key.encode(buf);
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
        let Self {
            algorithm,
            signature,
        } = self;
        let start = buf.len();
        buf.extend([0; 4]);
        algorithm.encode(buf);

        match algorithm {
            // RFC 5656 section 3.1.2: the ECDSA signature blob is the pair of
            // integers `r` and `s`, each encoded as an mpint. The signing key
            // hands us the fixed-length `r || s` form, which we split in half.
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
                let blob_start = buf.len();
                buf.extend([0; 4]);
                let (r, s) = signature.split_at(signature.len() / 2);
                encode_mpint(r, buf);
                encode_mpint(s, buf);
                let blob_len = (buf.len() - blob_start - 4) as u32;
                if let Some(dst) = buf.get_mut(blob_start..blob_start + 4) {
                    dst.copy_from_slice(&blob_len.to_be_bytes());
                }
            }
            PublicKeyAlgorithm::Ed25519 => signature.as_slice().encode(buf),
            PublicKeyAlgorithm::Unknown(_) => {
                unreachable!("unknown algorithm should not be used for signing")
            }
        }

        let len = (buf.len() - start - 4) as u32;
        if let Some(dst) = buf.get_mut(start..start + 4) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
    }
}

/// Append `value` to `buf` as an SSH mpint (RFC 4251 section 5)
///
/// Leading zero bytes are stripped, and a single zero byte is prepended when the
/// most significant bit is set so the value is interpreted as positive.
pub(crate) fn encode_mpint(value: &[u8], buf: &mut Vec<u8>) {
    let trimmed = match value.iter().position(|&b| b != 0) {
        Some(first) => &value[first..],
        None => &[],
    };

    let pad = matches!(trimmed.first(), Some(&b) if b & 0x80 != 0);
    let len = trimmed.len() + usize::from(pad);
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    if pad {
        buf.push(0);
    }
    buf.extend_from_slice(trimmed);
}

impl fmt::Debug for TaggedSignature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaggedSignature")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// The algorithms negotiated from the client's and server's `SSH_MSG_KEXINIT`
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-7.1> for the negotiation procedure.
#[derive(Debug)]
pub struct Negotiated {
    /// Negotiated key exchange algorithm
    pub key_exchange: KeyExchangeAlgorithm<'static>,
    pub(crate) server_host_key: PublicKeyAlgorithm<'static>,
    encryption_client_to_server: EncryptionAlgorithm<'static>,
    encryption_server_to_client: EncryptionAlgorithm<'static>,
    /// Whether the client requested `SSH_MSG_EXT_INFO` via `ext-info-c` (RFC 8308)
    pub want_extension_info: bool,
    /// Whether the client requested strict key exchange via `kex-strict-c-v00@openssh.com`
    pub strict_key_exchange: bool,
}

impl Negotiated {
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
                    .find_map(|&server_alg| match (client, server_alg) {
                        (
                            KeyExchangeAlgorithmOrExtensionId::KeyExchange(client_alg),
                            KeyExchangeAlgorithmOrExtensionId::KeyExchange(server_alg),
                        ) if client_alg == server_alg => Some(server_alg),
                        _ => None,
                    })
            })
            .ok_or(ProtoError::NoCommonAlgorithm("key exchange"))?;

        let server_host_key = client
            .server_host_key_algorithms
            .iter()
            .find_map(|client| {
                server
                    .server_host_key_algorithms
                    .iter()
                    .find_map(|server| match (client, server) {
                        (client, server) if client == server => Some(server.clone()),
                        _ => None,
                    })
            })
            .ok_or(ProtoError::NoCommonAlgorithm("host key"))?;

        let encryption_client_to_server = client
            .encryption_algorithms_client_to_server
            .iter()
            .find_map(|client| {
                server
                    .encryption_algorithms_client_to_server
                    .iter()
                    .find_map(|server| match (client, server) {
                        (client, server) if client == server => Some(server.clone()),
                        _ => None,
                    })
            })
            .ok_or(ProtoError::NoCommonAlgorithm(
                "encryption (client to server)",
            ))?;

        let encryption_server_to_client = client
            .encryption_algorithms_server_to_client
            .iter()
            .find_map(|client| {
                server
                    .encryption_algorithms_server_to_client
                    .iter()
                    .find_map(|server| match (client, server) {
                        (client, server) if client == server => Some(server.clone()),
                        _ => None,
                    })
            })
            .ok_or(ProtoError::NoCommonAlgorithm(
                "encryption (server to client)",
            ))?;

        Ok(Self {
            key_exchange,
            server_host_key,
            encryption_client_to_server,
            encryption_server_to_client,
            want_extension_info: client.has_extension(ExtensionId::ExtInfoC),
            strict_key_exchange: client.has_extension(ExtensionId::StrictKexClient),
        })
    }
}

/// The `SSH_MSG_NEWKEYS` message
///
/// Signals that all following packets use the newly negotiated keys and algorithms.
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-7.3>.
#[derive(Debug)]
pub struct NewKeys;

impl<'a> TryFrom<IncomingPacket<'a>> for NewKeys {
    type Error = ProtoError;

    fn try_from(packet: IncomingPacket<'a>) -> Result<Self, Self::Error> {
        packet.expect(&[MessageType::NewKeys])?;

        if !packet.payload.is_empty() {
            debug!(bytes = ?packet.payload, "unexpected trailing bytes");
            return Err(ProtoError::InvalidPacket("unexpected trailing bytes"));
        }

        Ok(Self)
    }
}

impl Encode for NewKeys {
    fn encode(&self, buf: &mut Vec<u8>) {
        MessageType::NewKeys.encode(buf);
    }
}

/// Identities from the connection's initial setup
///
/// Used to derive the session id and the exchange hash for rekeying.
#[derive(Debug)]
pub struct Identities {
    /// Client identity
    pub client: Vec<u8>,
    /// Server identity
    pub server: Vec<u8>,
}

impl Encode for Identities {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self { client, server } = self;
        client.encode(buf);
        server.encode(buf);
    }
}

impl Decode<'_> for Identities {
    fn decode(bytes: &[u8]) -> Result<Decoded<'_, Self>, ProtoError> {
        let Decoded {
            value: client,
            next,
        } = <&[u8]>::decode(bytes)?;
        let Decoded {
            value: server,
            next,
        } = <&[u8]>::decode(next)?;

        Ok(Decoded {
            value: Self {
                client: client.to_vec(),
                server: server.to_vec(),
            },
            next,
        })
    }
}

/// The `SSH_MSG_EXT_INFO` message
///
/// Carries protocol extensions such as `server-sig-algs`
///
/// See <https://www.rfc-editor.org/rfc/rfc8308#section-2.3>.
pub struct ExtInfo<'a> {
    extensions: Vec<(ExtensionName<'a>, Box<dyn Encode + 'a>)>,
}

impl Encode for ExtInfo<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self { extensions } = self;
        MessageType::ExtInfo.encode(buf);
        (extensions.len() as u32).encode(buf);
        for (name, value) in extensions {
            name.encode(buf);
            value.encode(buf);
        }
    }
}

impl fmt::Debug for ExtInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtInfo").finish_non_exhaustive()
    }
}

/// Output of the initial key exchange
pub struct KeyExchangeOutput<'a> {
    /// The identities exchanged after connection acceptance
    pub identities: Identities,
    /// The host key used for the connection
    pub host_key: ServerHostKey<'a>,
    /// The strict key exchange state, if negotiated
    pub strict_kx: Option<StrictKeyExchange>,
    /// The session ID for the connection
    pub session_id: Digest,
    /// The keys derived for the connection
    pub keys: KeySourceSet,
    /// Whether post-quantum key exchange was negotiated
    pub post_quantum_kx: bool,
}

/// The raw hashes from which we will derive the crypto keys.
///
/// See <https://www.rfc-editor.org/rfc/rfc4253#section-7.2>.
pub struct KeySourceSet {
    /// Key material for the client-to-server direction
    pub client_to_server: KeySourceSide,
    /// Key material for the server-to-client direction
    pub server_to_client: KeySourceSide,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_string(bytes: &[u8]) -> (&[u8], &[u8]) {
        let Decoded { value, next } = <&[u8]>::decode(bytes).unwrap();
        (value, next)
    }

    #[test]
    fn mpint_encoding() {
        // Leading zero bytes are stripped.
        let mut buf = Vec::new();
        encode_mpint(&[0x00, 0x00, 0x05, 0x06], &mut buf);
        assert_eq!(buf, [0, 0, 0, 2, 0x05, 0x06]);

        // A set most significant bit forces a leading zero byte.
        buf.clear();
        encode_mpint(&[0x80, 0x01], &mut buf);
        assert_eq!(buf, [0, 0, 0, 3, 0x00, 0x80, 0x01]);

        // An all-zero value encodes as a zero-length mpint.
        buf.clear();
        encode_mpint(&[0x00, 0x00], &mut buf);
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn ecdsa_signature_framing() {
        // `r` has its top bit set (needs padding); `s` has leading zeros (stripped).
        let mut signature = [0x11u8; 64];
        signature[0] = 0x80;
        signature[32] = 0x00;
        signature[33] = 0x00;
        signature[34] = 0x05;

        let tagged = TaggedSignature {
            algorithm: PublicKeyAlgorithm::EcdsaSha2Nistp256,
            signature: signature.to_vec(),
        };

        let mut buf = Vec::new();
        tagged.encode(&mut buf);

        // The whole thing is wrapped in a single string.
        let (inner, next) = decode_string(&buf);
        assert!(next.is_empty());

        let (name, next) = decode_string(inner);
        assert_eq!(name, b"ecdsa-sha2-nistp256");

        // RFC 5656 section 3.1.2: the signature blob is `mpint r || mpint s`.
        let (blob, next) = decode_string(next);
        assert!(next.is_empty());

        let (r, next) = decode_string(blob);
        let (s, next) = decode_string(next);
        assert!(next.is_empty());

        let mut expected_r = vec![0x00, 0x80];
        expected_r.extend([0x11; 31]);
        assert_eq!(r, expected_r);

        let mut expected_s = vec![0x05];
        expected_s.extend([0x11; 29]);
        assert_eq!(s, expected_s);
    }

    #[test]
    fn ecdsa_public_key_framing() {
        // A stand-in uncompressed point: the marker byte plus 64 coordinate bytes.
        let mut point = vec![0x04];
        point.extend([0x42; 64]);

        let tagged = TaggedPublicKey {
            algorithm: PublicKeyAlgorithm::EcdsaSha2Nistp256,
            key: Cow::Borrowed(&point),
        };

        let mut buf = Vec::new();
        tagged.encode(&mut buf);

        // RFC 5656 section 3.1: `ecdsa-sha2-nistp256 || nistp256 || Q`.
        let (inner, next) = decode_string(&buf);
        assert!(next.is_empty());

        let (name, next) = decode_string(inner);
        assert_eq!(name, b"ecdsa-sha2-nistp256");

        let (curve, next) = decode_string(next);
        assert_eq!(curve, b"nistp256");

        let (q, next) = decode_string(next);
        assert_eq!(q, point.as_slice());
        assert!(next.is_empty());
    }

    #[test]
    fn ed25519_public_key_framing() {
        // Ed25519 keys carry no curve identifier (RFC 8709 section 4).
        let key = [0x07u8; 32];
        let tagged = TaggedPublicKey {
            algorithm: PublicKeyAlgorithm::Ed25519,
            key: Cow::Borrowed(&key),
        };

        let mut buf = Vec::new();
        tagged.encode(&mut buf);

        let (inner, next) = decode_string(&buf);
        assert!(next.is_empty());

        let (name, next) = decode_string(inner);
        assert_eq!(name, b"ssh-ed25519");

        let (value, next) = decode_string(next);
        assert_eq!(value, key);
        assert!(next.is_empty());
    }
}
