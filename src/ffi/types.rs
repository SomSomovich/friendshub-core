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

    /// Rebuilds the Vec and drops it. Safe to call twice: the second call
    /// sees a null pointer and does nothing.
    pub unsafe fn release(&mut self) {
        if !self.data.is_null() && self.cap > 0 {
            // SAFETY: data, len and cap came from the same Vec via
            // FhBuffer::from_vec, and this is the only place that consumes
            // them. Nothing else has touched them between the two calls.
            unsafe {
                drop(Vec::from_raw_parts(self.data, self.len, self.cap));
            }
        }
        self.data = ptr::null_mut();
        self.len = 0;
        self.cap = 0;
    }
}
