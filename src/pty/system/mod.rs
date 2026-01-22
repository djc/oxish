use core::{
    ffi::{c_int, CStr},
    mem::MaybeUninit,
};
use std::{
    io::{self, Error},
    path::PathBuf,
};

use super::cutils::*;
use interface::{GroupId, UserId};

pub(crate) mod interface;

pub(crate) mod term;

pub(crate) fn chown<S: AsRef<CStr>>(
    path: &S,
    uid: impl Into<UserId>,
    gid: impl Into<GroupId>,
) -> io::Result<()> {
    let path = path.as_ref().as_ptr();
    let uid = uid.into();
    let gid = gid.into();

    // SAFETY: path is a valid pointer to a null-terminated C string; chown cannot cause safety
    // issues even if uid and/or gid would be invalid identifiers.
    cerr(unsafe { libc::chown(path, uid.inner(), gid.inner()) }).map(|_| ())
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct User {
    pub(crate) uid: UserId,
    pub(crate) gid: GroupId,
    pub(crate) name: String,
    pub(crate) home: PathBuf,
    pub(crate) shell: PathBuf,
    pub(crate) groups: Vec<GroupId>,
}

impl User {
    /// # Safety
    /// This function expects `pwd` to be a result from a successful call to `getpwXXX_r`.
    /// (It can cause UB if any of `pwd`'s pointed-to strings does not have a null-terminator.)
    unsafe fn from_libc(pwd: &libc::passwd) -> Result<Self, Error> {
        let mut buf_len: c_int = 32;
        let mut groups_buffer: Vec<libc::gid_t>;

        while {
            groups_buffer = vec![0; buf_len as usize];
            // SAFETY: getgrouplist is passed valid pointers
            // in particular `groups_buffer` is an array of `buf.len()` bytes, as required
            let result = unsafe {
                #[allow(trivial_numeric_casts)]
                libc::getgrouplist(
                    pwd.pw_name,
                    pwd.pw_gid as _,
                    groups_buffer.as_mut_ptr().cast(),
                    &mut buf_len,
                )
            };

            result == -1
        } {
            if buf_len >= 65536 {
                panic!("user has too many groups (> 65536), this should not happen");
            }

            buf_len *= 2;
        }

        groups_buffer.resize_with(buf_len as usize, || {
            panic!("invalid groups count returned from getgrouplist, this should not happen")
        });

        // SAFETY: All pointers were initialized by a successful call to `getpwXXX_r` as per the
        // safety invariant of this function.
        unsafe {
            Ok(Self {
                uid: UserId::new(pwd.pw_uid),
                gid: GroupId::new(pwd.pw_gid),
                name: string_from_ptr(pwd.pw_name),
                home: PathBuf::from(os_string_from_ptr(pwd.pw_dir)),
                shell: os_string_from_ptr(pwd.pw_shell).into(),
                groups: groups_buffer
                    .iter()
                    .map(|id| GroupId::new(*id))
                    .collect::<Vec<_>>(),
            })
        }
    }

    pub(crate) fn from_uid(uid: UserId) -> Result<Option<Self>, Error> {
        let max_pw_size = sysconf(libc::_SC_GETPW_R_SIZE_MAX).unwrap_or(16_384);
        let mut buf = vec![0; max_pw_size as usize];
        let mut pwd = MaybeUninit::uninit();
        let mut pwd_ptr = core::ptr::null_mut();
        // SAFETY: getpwuid_r is passed valid (although partly uninitialized) pointers to memory,
        // in particular `buf` points to an array of `buf.len()` bytes, as required.
        // After this call, if `pwd_ptr` is not NULL, `*pwd_ptr` and `pwd` will be aliased;
        // but we never dereference `pwd_ptr`.
        cerr(unsafe {
            libc::getpwuid_r(
                uid.inner(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut pwd_ptr,
            )
        })?;
        if pwd_ptr.is_null() {
            Ok(None)
        } else {
            // SAFETY: pwd_ptr was not null, and getpwuid_r succeeded, so we have assurances that
            // the `pwd` structure was written to by getpwuid_r
            let pwd = unsafe { pwd.assume_init() };
            // SAFETY: `pwd` was obtained by a call to getpwXXX_r, as required.
            unsafe { Self::from_libc(&pwd).map(Some) }
        }
    }

    pub(crate) fn effective_gid() -> GroupId {
        // SAFETY: this function cannot cause memory safety issues
        GroupId::new(unsafe { libc::getegid() })
    }

    pub(crate) fn real_uid() -> UserId {
        // SAFETY: this function cannot cause memory safety issues
        UserId::new(unsafe { libc::getuid() })
    }

    pub(crate) fn real() -> Result<Option<Self>, Error> {
        Self::from_uid(Self::real_uid())
    }
}

pub(crate) struct Group {
    pub(crate) gid: GroupId,
}

impl Group {
    fn from_libc(grp: &libc::group) -> Self {
        Self {
            gid: GroupId::new(grp.gr_gid),
        }
    }

    pub(crate) fn from_name(name_c: &CStr) -> io::Result<Option<Self>> {
        let max_gr_size = sysconf(libc::_SC_GETGR_R_SIZE_MAX).unwrap_or(16_384);
        let mut buf = vec![0; max_gr_size as usize];
        let mut grp = MaybeUninit::uninit();
        let mut grp_ptr = core::ptr::null_mut();
        // SAFETY: analogous to getpwuid_r above
        cerr(unsafe {
            libc::getgrnam_r(
                name_c.as_ptr(),
                grp.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut grp_ptr,
            )
        })?;
        if grp_ptr.is_null() {
            Ok(None)
        } else {
            // SAFETY: grp_ptr was not null, and getgrgid_r succeeded, so we have assurances that
            // the `grp` structure was written to by getgrgid_r
            let grp = unsafe { grp.assume_init() };
            // SAFETY: `pwd` was obtained by a call to getgrXXX_r, as required.
            Ok(Some(Self::from_libc(&grp)))
        }
    }
}
