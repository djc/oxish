use core::ffi::{c_char, c_int, c_long};
use std::{
    ffi::{CStr, OsStr, OsString},
    os::unix::prelude::OsStrExt,
};

pub(crate) fn cerr<Int: Copy + TryInto<c_long>>(res: Int) -> std::io::Result<Int> {
    match res.try_into() {
        Ok(-1) => Err(std::io::Error::last_os_error()),
        _ => Ok(res),
    }
}

extern "C" {
    #[cfg_attr(
        any(target_os = "macos", target_os = "ios", target_os = "freebsd"),
        link_name = "__error"
    )]
    #[cfg_attr(
        any(target_os = "openbsd", target_os = "netbsd", target_os = "android"),
        link_name = "__errno"
    )]
    #[cfg_attr(target_os = "linux", link_name = "__errno_location")]
    fn errno_location() -> *mut c_int;
}

pub(crate) fn set_errno(no: c_int) {
    // SAFETY: errno_location is a thread-local pointer to an integer, so we are the only writers
    unsafe { *errno_location() = no };
}

pub(crate) fn sysconf(name: c_int) -> Option<c_long> {
    set_errno(0);
    // SAFETY: sysconf will always respond with 0 or -1 for every input
    cerr(unsafe { libc::sysconf(name) }).ok()
}

/// Create a Rust string copy from a C string pointer
/// WARNING: This uses `to_string_lossy` so should not be used for data where
/// information loss is unacceptable (use `os_string_from_ptr` instead)
///
/// # Safety
/// This function assumes that the pointer is either a null pointer or that
/// it points to a valid NUL-terminated C string.
pub(crate) unsafe fn string_from_ptr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        // SAFETY: the function contract says that CStr::from_ptr is safe
        let cstr = unsafe { CStr::from_ptr(ptr) };
        cstr.to_string_lossy().to_string()
    }
}

/// Create an `OsString` copy from a C string pointer.
///
/// # Safety
/// This function assumes that the pointer is either a null pointer or that
/// it points to a valid NUL-terminated C string.
pub(crate) unsafe fn os_string_from_ptr(ptr: *const c_char) -> OsString {
    if ptr.is_null() {
        OsString::new()
    } else {
        // SAFETY: the function contract says that CStr::from_ptr is safe
        let cstr = unsafe { CStr::from_ptr(ptr) };
        OsStr::from_bytes(cstr.to_bytes()).to_owned()
    }
}
