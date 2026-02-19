use core::{ffi::c_char, fmt, ops::ControlFlow};
#[cfg(target_vendor = "apple")]
use std::os::darwin::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(all(unix, not(target_vendor = "apple"), not(target_os = "linux")))]
use std::os::unix::fs::MetadataExt;
use std::{
    borrow::Cow,
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    str,
};

use aws_lc_rs::signature::{self, UnparsedPublicKey};
use libc::{getpwnam_r, sysconf, O_DIRECTORY, O_RDONLY, _SC_GETPW_R_SIZE_MAX};
use proto::{Decode, Decoded, Named, ProtoError, PublicKeyAlgorithm, Signature, SignatureData};
use tokio::task::spawn_blocking;
use tracing::{debug, warn};

use crate::Error;

#[derive(Debug)]
pub(crate) struct User {
    pub(crate) name: String,
    #[expect(dead_code)]
    pub(crate) id: u32,
    #[expect(dead_code)]
    pub(crate) home_dir: PathBuf,
    /// Cached authorized keys for the user
    ///
    /// Since finding the authorized keys can be somewhat expensive, prefer to cache them
    /// here so we can reuse them across attempts for the same user.
    pub(crate) authorized_keys: Vec<AuthorizedKey>,
}

impl User {
    pub(crate) fn new(name: &str) -> Result<Self, Error> {
        let c_name = CString::new(name).map_err(|_| Error::InvalidUsername)?;
        let buf_len = match unsafe { sysconf(_SC_GETPW_R_SIZE_MAX) } {
            -1 => 1024,
            n => Ord::min(n as usize, 1_048_576),
        };

        let mut buf = vec![0u8; buf_len];
        let mut pwd = unsafe { core::mem::zeroed() };
        let mut result = core::ptr::null_mut();

        let ret = unsafe {
            getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast::<c_char>(),
                buf_len,
                &mut result,
            )
        };

        let home_dir = if ret != 0 {
            let error = io::Error::from_raw_os_error(ret);
            debug!(%error, %name, "failed to get user information");
            Self::FAKE_HOME
        } else if result.is_null() {
            debug!(%name, "user not found");
            Self::FAKE_HOME
        } else {
            debug!(user = %name, "found home dir");
            pwd.pw_dir
        };

        // SAFETY: if `ret` is 0 (signifying success) and `result` is non-null, `pwd.pw_dir`
        // was populated by `getpwnam_r`, the `pwd` struct and `buf` are still alive, so the
        // pointer is valid; otherwise, `home_dir` is set to a static string. In either case,
        // `home_dir` is a valid pointer to a null-terminated C string.
        let home_dir = PathBuf::from(OsStr::from_bytes(
            unsafe { CStr::from_ptr(home_dir) }.to_bytes(),
        ));

        let id = match (ret, result.is_null()) {
            (0, false) => pwd.pw_uid,
            _ => u32::MAX,
        };

        Ok(Self {
            name: name.to_owned(),
            id,
            authorized_keys: authorized_keys(&home_dir, id),
            home_dir,
        })
    }

    const FAKE_HOME: *const c_char = c"/var/empty".as_ptr().cast::<c_char>();
}

/// Read and parse the `authorized_keys` file for a user
///
/// This is pretty finicky because we need to check that
///
/// - None of the path components have group or other write permissions
/// - Each of the path components are owned by root or the target user
/// - Avoid TOCTOU issues when opening each path component
pub(crate) fn authorized_keys(home_dir: &Path, uid: u32) -> Vec<AuthorizedKey> {
    let home = match File::open(home_dir) {
        Ok(file) => file,
        Err(error) => {
            warn!(%error, ?home_dir, "failed to open home directory");
            return Vec::new();
        }
    };

    match check_permissions(&home, uid, "home directory") {
        ControlFlow::Continue(()) => {}
        ControlFlow::Break(()) => {
            warn!(?home_dir, "bad permissions on home directory");
            return Vec::new();
        }
    };

    let ssh_dir = match open_in_dir(&home, ".ssh", O_DIRECTORY) {
        Ok(file) => file,
        Err(error) => {
            warn!(%error, ?home_dir, "failed to open .ssh directory");
            return Vec::new();
        }
    };

    match check_permissions(&ssh_dir, uid, ".ssh directory") {
        ControlFlow::Continue(()) => {}
        ControlFlow::Break(()) => {
            warn!(?home_dir, "bad permissions on .ssh directory");
            return Vec::new();
        }
    };

    let mut key_file = match open_in_dir(&ssh_dir, "authorized_keys", O_RDONLY) {
        Ok(file) => file,
        Err(error) => {
            warn!(%error, ?home_dir, "failed to open authorized keys file");
            return Vec::new();
        }
    };

    match check_permissions(&key_file, uid, "authorized keys file") {
        ControlFlow::Continue(()) => {}
        ControlFlow::Break(()) => {
            warn!(?home_dir, "bad permissions on authorized keys file");
            return Vec::new();
        }
    };

    let mut contents = String::new();
    if let Err(error) = key_file.read_to_string(&mut contents) {
        warn!(%error, ?home_dir, "failed to read authorized keys file");
        return Vec::new();
    };

    let mut keys = Vec::new();
    for (line, key) in contents.lines().enumerate() {
        let line = line + 1;
        let key = match key.split_once('#') {
            Some((contents, _)) => contents,
            None => key,
        }
        .trim();

        let mut parts = key.split_whitespace();
        let Some(alg) = parts.next() else {
            debug!(line, "missing algorithm");
            continue;
        };

        // TODO: support options before key type
        let algorithm = PublicKeyAlgorithm::typed(alg);
        let alg = match algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => &signature::ECDSA_P256_SHA256_FIXED,
            algorithm => {
                warn!(
                    ?algorithm,
                    line, "unsupported public key algorithm in authorized keys file"
                );
                continue;
            }
        };

        let Some(key_data) = parts.next() else {
            debug!(line, "missing key data");
            continue;
        };

        let Ok(blob) = data_encoding::BASE64.decode(key_data.as_bytes()) else {
            debug!(line, "invalid base64 key data");
            continue;
        };

        let next = match <&[u8]>::decode(&blob) {
            // Unused `key_type` field, should match `alg`
            Ok(Decoded { next, .. }) => next,
            Err(error) => {
                debug!(%error, line, "invalid key type");
                continue;
            }
        };

        let next = match <&[u8]>::decode(next) {
            // Unused `curve_name` field
            Ok(Decoded { next, .. }) => next,
            Err(error) => {
                debug!(%error, line, "invalid curve name");
                continue;
            }
        };

        let q = match <&[u8]>::decode(next) {
            // TODO: what does the trailing data mean?
            Ok(Decoded { value: q, .. }) => q,
            Err(error) => {
                debug!(%error, line, "invalid public key data");
                continue;
            }
        };

        keys.push(AuthorizedKey {
            algorithm: algorithm.to_owned(),
            key: UnparsedPublicKey::new(alg, Cow::Owned(q.to_vec())),
            blob,
        });
    }

    keys
}

fn open_in_dir(dir: &File, name: &str, flags: libc::c_int) -> Result<File, io::Error> {
    let c_name = CString::new(name)?;
    match unsafe { libc::openat(dir.as_raw_fd(), c_name.as_ptr(), flags) } {
        -1 => Err(io::Error::last_os_error()),
        fd => Ok(unsafe { File::from_raw_fd(fd) }),
    }
}

fn check_permissions(file: &File, uid: u32, level: &str) -> ControlFlow<()> {
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => {
            warn!(%error, level, "failed to get metadata");
            return ControlFlow::Break(());
        }
    };

    match meta.st_mode() & 0o022 == 0 && (meta.st_uid() == 0 || meta.st_uid() == uid) {
        true => ControlFlow::Continue(()),
        false => ControlFlow::Break(()),
    }
}

#[derive(Clone)]
pub(crate) struct AuthorizedKey {
    pub(crate) algorithm: PublicKeyAlgorithm<'static>,
    pub(crate) blob: Vec<u8>,
    pub(crate) key: UnparsedPublicKey<Cow<'static, [u8]>>,
}

impl AuthorizedKey {
    pub(crate) fn fake() -> Self {
        Self {
            algorithm: PublicKeyAlgorithm::EcdsaSha2Nistp256,
            blob: Vec::new(),
            key: UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_FIXED,
                Cow::Borrowed(&Self::FAKE_KEY[..]),
            ),
        }
    }

    pub(crate) async fn verify(
        &self,
        message: SignatureData<'_>,
        signature: Signature<'_>,
    ) -> Result<(), ProtoError> {
        match &self.algorithm {
            PublicKeyAlgorithm::EcdsaSha2Nistp256 => {
                let Decoded {
                    value: r,
                    next: rest,
                } = <&[u8]>::decode(signature.signature_blob)?;

                let Decoded { value: s, next } = <&[u8]>::decode(rest)?;
                if !next.is_empty() {
                    return Err(ProtoError::InvalidPacket(
                        "extra data after ECDSA signature components",
                    ));
                }

                let mut fixed = [0u8; 64];
                if mpint_to_fixed(r, &mut fixed[..64 / 2]).is_none() {
                    return Err(ProtoError::InvalidPacket(
                        "failure to decode r in ECDSA signature",
                    ));
                }

                if mpint_to_fixed(s, &mut fixed[64 / 2..]).is_none() {
                    return Err(ProtoError::InvalidPacket(
                        "failure to decode s in ECDSA signature",
                    ));
                }

                let encoded = message.encode();
                let key = self.key.clone();
                spawn_blocking(move || {
                    key.verify(&encoded, &fixed)
                        .map_err(|_| ProtoError::InvalidPacket("invalid signature"))
                })
                .await
                .map_err(|_| ProtoError::InvalidPacket("signature verification task failed"))?
            }
            algorithm => {
                warn!(
                    ?algorithm,
                    "unsupported public key algorithm for verification"
                );
                Err(ProtoError::InvalidPacket(
                    "unsupported public key algorithm for verification",
                ))
            }
        }
    }

    /// A random key used to mitigate timing attacks during authentication.
    ///
    /// When no matching authorized key is found, we still perform signature
    /// verification against this key so the response time is consistent.
    const FAKE_KEY: [u8; 65] = [
        4, 78, 12, 149, 151, 123, 231, 212, 239, 236, 97, 37, 76, 163, 223, 212, 61, 5, 10, 96,
        214, 7, 210, 196, 146, 69, 178, 104, 253, 196, 241, 61, 7, 253, 242, 178, 22, 112, 52, 123,
        76, 129, 155, 245, 233, 144, 111, 94, 173, 252, 107, 114, 3, 36, 2, 237, 66, 51, 119, 181,
        246, 15, 91, 101, 104,
    ];
}

impl fmt::Debug for AuthorizedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedKey")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// Convert an SSH mpint to a fixed-width big-endian representation
fn mpint_to_fixed(mpint: &[u8], out: &mut [u8]) -> Option<()> {
    let data = match mpint.split_first() {
        Some((&0, rest)) if !rest.is_empty() => rest,
        _ => mpint,
    };

    if data.len() > out.len() {
        return None;
    }

    let offset = out.len() - data.len();
    out[offset..].copy_from_slice(data);
    Some(())
}
