use zeroize::Zeroizing;

use crate::{
    Decode, Decoded, Encode, ProtoError, PublicKeyAlgorithm,
    crypto::{CryptoError, CryptoProvider, SigningKey},
    key_exchange::Negotiated,
};

/// The server's host keys, used to authenticate the key exchange
#[expect(clippy::type_complexity)]
pub struct HostKeys(Vec<(Zeroizing<Vec<u8>>, Box<dyn SigningKey>)>);

impl HostKeys {
    /// Create a new set of host keys from the given PKCS#8 private keys
    ///
    /// `pkcs8` must have more than 0 and less than 16 elements.
    pub fn new(
        pkcs8: impl Iterator<Item = Zeroizing<Vec<u8>>>,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, ProtoError> {
        let mut keys = Vec::new();
        for pkcs8 in pkcs8 {
            if keys.len() >= Self::MAX_KEYS {
                return Err(ProtoError::TooManyHostKeys);
            }

            let signing_key = provider.signing_key_from_pkcs8(&pkcs8)?;
            keys.push((pkcs8, signing_key));
        }

        if keys.is_empty() {
            return Err(ProtoError::NoHostKeys);
        }

        Ok(Self(keys))
    }

    /// Select the host key matching the negotiated algorithm
    pub fn key<'a>(&'a self, negotiated: &Negotiated) -> Result<ServerHostKey<'a>, CryptoError> {
        let mut iter = self.0.iter();
        match iter.find(|(_, key)| key.algorithm() == negotiated.server_host_key) {
            Some((pkcs8, key)) => Ok(ServerHostKey {
                pkcs8,
                key: key.as_ref(),
            }),
            None => Err(CryptoError::UnknownAlgorithm),
        }
    }

    /// The public key algorithms of the held host keys
    pub fn algorithms(&self) -> impl Iterator<Item = PublicKeyAlgorithm<'static>> + '_ {
        self.0.iter().map(|(_, key)| key.algorithm())
    }

    const MAX_KEYS: usize = 16;
}

/// A borrowed single host key, used to sign the key exchange output
pub struct ServerHostKey<'a> {
    pkcs8: &'a Zeroizing<Vec<u8>>,
    pub(crate) key: &'a dyn SigningKey,
}

impl Encode for ServerHostKey<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        let Self { pkcs8, key: _ } = self;
        pkcs8.encode(buf);
    }
}

#[doc(hidden)] // for testing
impl<'a> From<(&'a Zeroizing<Vec<u8>>, &'a dyn SigningKey)> for ServerHostKey<'a> {
    fn from((pkcs8, key): (&'a Zeroizing<Vec<u8>>, &'a dyn SigningKey)) -> Self {
        Self { pkcs8, key }
    }
}

/// A single host key, used to sign rekeying exchanges
pub struct SessionHostKey(pub(crate) Box<dyn SigningKey>);

impl SessionHostKey {
    /// Create a new session host key from a borrowed server host key
    pub fn from_server(
        host_key: ServerHostKey<'_>,
        provider: &dyn CryptoProvider,
    ) -> Result<Self, ProtoError> {
        Ok(Self(provider.signing_key_from_pkcs8(host_key.pkcs8)?))
    }

    /// Decode a host key from encoded PKCS#8 bytes
    pub fn decode<'a>(
        buf: &'a [u8],
        provider: &dyn CryptoProvider,
    ) -> Result<Decoded<'a, Self>, ProtoError> {
        let Decoded { value: pkcs8, next } = <&[u8]>::decode(buf)?;
        Ok(Decoded {
            value: Self(provider.signing_key_from_pkcs8(pkcs8)?),
            next,
        })
    }

    /// The public key algorithm of this host key
    pub fn algorithm(&self) -> PublicKeyAlgorithm<'static> {
        self.0.algorithm()
    }
}
