//! The extended startup information a process attached to a pseudoconsole needs

use core::ffi::c_void;

use windows::{
    Win32::System::Threading::{
        DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        LPPROC_THREAD_ATTRIBUTE_LIST, UpdateProcThreadAttribute,
    },
    core::Result,
};

use super::utils::Buffer;

/// One attribute for a new process
pub(super) struct Attribute {
    pub(super) kind: usize,
    /// Some attributes point at a value, and some, `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`
    /// among them, are the value itself
    pub(super) value: *const c_void,
    pub(super) len: usize,
}

/// An initialized attribute list, valid until it is dropped
pub(super) struct AttributeList(Buffer);

impl AttributeList {
    pub(super) fn new(attributes: &[Attribute]) -> Result<Self> {
        let count = attributes.len() as u32;
        let mut len = 0;
        // SAFETY: a null list asks for the required size, which is written to `len`.
        let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut len) };

        let buf = Buffer::new(len);
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_ptr().cast());
        // SAFETY: `buf` is live and `len` describes it.
        unsafe { InitializeProcThreadAttributeList(Some(list), count, None, &mut len) }?;

        // Initialized from here on, so an attribute that does not take still has to be deleted.
        let list = Self(buf);
        for attribute in attributes {
            // SAFETY: the list is initialized and has room for every attribute given
            unsafe {
                UpdateProcThreadAttribute(
                    list.as_ptr(),
                    0,
                    attribute.kind,
                    Some(attribute.value),
                    attribute.len,
                    None,
                    None,
                )
            }?;
        }

        Ok(list)
    }

    /// The list lives in the buffer `new()` sized for it
    pub(super) fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.0.as_ptr().cast())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialized
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}
