use std::ptr;

/// A byte buffer passed across the FFI boundary.
///
/// Callers must release it with fh_buffer_free. An empty buffer is
/// { data: null, len: 0, cap: 0 }.
#[repr(C)]
pub struct FhBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl FhBuffer {
    pub const EMPTY: FhBuffer = FhBuffer { data: ptr::null_mut(), len: 0, cap: 0 };

    pub fn from_vec(v: Vec<u8>) -> Self {
        let mut v = std::mem::ManuallyDrop::new(v);
        FhBuffer { data: v.as_mut_ptr(), len: v.len(), cap: v.capacity() }
    }

    /// Rebuilds the Vec and drops it.
    ///
    /// # Safety
    ///
    /// The caller must pass a buffer that was produced by the library and
    /// has not been released yet. After the call the buffer is reset to
    /// `EMPTY`, so a second call on the same value is safe and does nothing.
    ///
    /// Passing a hand-constructed buffer whose `data`, `len` and `cap` did
    /// not come from a single `Vec<u8>` is undefined behaviour: the function
    /// rebuilds a `Vec` from those three fields and drops it.
    pub unsafe fn release(&mut self) {
        if !self.data.is_null() && self.cap > 0 {
            // SAFETY: the fields came from `from_vec`, which produced them
            // from a single Vec, and this is the only place that consumes
            // them.
            unsafe {
                drop(Vec::from_raw_parts(self.data, self.len, self.cap));
            }
        }
        self.data = ptr::null_mut();
        self.len = 0;
        self.cap = 0;
    }
}
