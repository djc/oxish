//! Helpers for calling into Win32

use core::{alloc::Layout, iter::once, ptr::NonNull};
use std::{alloc, ffi::OsStr, os::windows::ffi::OsStrExt};

use windows::Win32::System::SystemServices::MEMORY_ALLOCATION_ALIGNMENT;

/// The null-terminated UTF-16 a Win32 call takes in place of a string
pub(super) fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(once(0)).collect()
}

/// A buffer for a Win32 call that asks to be given one, freed whether the call succeeds or not
///
/// Aligned to [`MEMORY_ALLOCATION_ALIGNMENT`] as `HeapAlloc()` would be, which is what a call
/// writing a struct of its own into the buffer expects.
pub(super) struct Buffer {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl Buffer {
    /// Allocate the `len` bytes a Win32 size query asked for
    ///
    /// # Panics
    ///
    /// If `len` is zero or too large to allocate, neither of which a size query returns.
    pub(super) fn new(len: usize) -> Self {
        let layout = Layout::from_size_align(len, MEMORY_ALLOCATION_ALIGNMENT as usize)
            .ok()
            .filter(|layout| layout.size() != 0)
            .expect("Win32 returned a size that cannot be allocated");

        // SAFETY: `layout` has a non-zero size.
        let ptr = unsafe { alloc::alloc(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| alloc::handle_alloc_error(layout));

        Self { ptr, layout }
    }

    pub(super) fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: `new()` allocated the pointer with `self.layout`.
        unsafe { alloc::dealloc(self.ptr.as_ptr(), self.layout) };
    }
}
