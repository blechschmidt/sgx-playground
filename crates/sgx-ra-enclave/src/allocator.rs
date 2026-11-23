//! Global allocator backed by the SGX SDK's tlibc heap.
//!
//! The enclave heap is sized by `HeapMaxSize` in `Enclave.config.xml` (part
//! of the measured layout). Allocation failure returns null, which makes
//! Rust's `alloc` call the allocation error handler (an abort). Freed
//! blocks are zeroed before they return to the heap.

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

use zeroize::Zeroize;

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn memalign(alignment: usize, size: usize) -> *mut c_void;
}

/// Alignment `malloc` guarantees on x86_64 (tlibc's dlmalloc and glibc).
const MALLOC_ALIGN: usize = 16;

/// A [`GlobalAlloc`] over tlibc `malloc`/`memalign`/`free`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SgxAllocator;

// SAFETY: `malloc`/`memalign` return either null or a block of at least
// `size` bytes aligned to `MALLOC_ALIGN` / `alignment` respectively, which
// is what `GlobalAlloc::alloc` requires; `free` accepts any such block.
unsafe impl GlobalAlloc for SgxAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Zero-size allocations never reach a GlobalAlloc, but stay defensive:
        // malloc(0) may legally return null.
        let size = layout.size().max(1);
        if layout.align() <= MALLOC_ALIGN {
            // SAFETY: plain C allocation with a non-zero size.
            unsafe { malloc(size).cast() }
        } else {
            // SAFETY: `Layout` guarantees a power-of-two alignment.
            unsafe { memalign(layout.align(), size).cast() }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Wipe every block before it returns to the heap, so that freed
        // plaintext, key schedules and Vec reallocation leftovers do not
        // linger in enclave memory (docs/THREAT_MODEL.md, "Zeroization").
        // `zeroize` uses volatile writes: a plain memset before `free` is a
        // dead store that LLVM may delete. The default `realloc` goes
        // through `dealloc`, so the old block of a grown Vec is wiped too.
        // SAFETY: `ptr` was returned by `alloc` for `layout`, so it is valid
        // for writes of `layout.size()` bytes until it is freed below.
        unsafe { core::slice::from_raw_parts_mut(ptr, layout.size()) }.zeroize();
        // SAFETY: `ptr` came from `malloc`/`memalign` in `alloc`.
        unsafe { free(ptr.cast()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_with_requested_alignment() {
        for align in [1usize, 8, 16, 64, 4096] {
            let layout = Layout::from_size_align(100, align).unwrap();
            // SAFETY: non-zero-size layout; the block is freed below.
            unsafe {
                let p = SgxAllocator.alloc(layout);
                assert!(!p.is_null());
                assert_eq!(p as usize % align, 0);
                p.write_bytes(0xa5, 100);
                SgxAllocator.dealloc(p, layout);
            }
        }
    }
}
