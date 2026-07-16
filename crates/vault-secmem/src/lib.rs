//! Locked, zeroized secret memory.
//!
//! [`SecretBytes`] is a fixed-size heap buffer that is
//!   * **locked into physical RAM** (`mlock` on Unix, `VirtualLock` on Windows)
//!     so its contents can't be paged out to swap or a hibernation file, and
//!   * **zeroized on drop**.
//!
//! Locking is *best effort*: the OS may refuse it (e.g. `RLIMIT_MEMLOCK` on
//! Linux caps how much unprivileged memory a process can lock). On failure the
//! buffer still works and still zeroizes — it just isn't swap-protected. Query
//! [`SecretBytes::is_locked`] if you need to know.
//!
//! Use this for key material (see `vault-core`'s `SymmetricKey`). It does not
//! defend against a process reading its own memory (threat T9); it addresses
//! secrets leaking to disk via swap/hibernation (T5).

#![forbid(unsafe_code)]

use region::LockGuard;
use zeroize::Zeroize;

/// A fixed-size, mlock'd, zeroize-on-drop secret buffer.
pub struct SecretBytes {
    // Field order matters for Drop: `guard` is declared first so it drops
    // (unlocking the pages) BEFORE `buf` drops (freeing the heap allocation).
    // Unlocking after the free would touch freed memory.
    // Holds the lock; dropping it unlocks the pages. `None` if locking failed.
    guard: Option<LockGuard>,
    // `Box<[u8]>` has a stable heap address for the buffer's lifetime, so the
    // memory lock stays valid even if the `SecretBytes` value is moved.
    buf: Box<[u8]>,
}

impl SecretBytes {
    /// A zero-filled buffer of `len` bytes, locked into RAM if the OS allows.
    pub fn zeroed(len: usize) -> Self {
        let buf = vec![0u8; len].into_boxed_slice();
        let guard = if buf.is_empty() {
            None
        } else {
            region::lock(buf.as_ptr(), buf.len()).ok()
        };
        Self { buf, guard }
    }

    /// Copy `src` into a fresh locked buffer.
    pub fn from_slice(src: &[u8]) -> Self {
        let mut s = Self::zeroed(src.len());
        s.buf.copy_from_slice(src);
        s
    }

    /// The secret bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// The secret bytes, mutably (e.g. to fill from an RNG).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Whether the buffer is actually locked into RAM (false if the OS refused).
    pub fn is_locked(&self) -> bool {
        self.guard.is_some()
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::from_slice(&self.buf)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Wipe the secret while the pages are still locked; `guard` unlocks
        // afterwards (fields drop after this body runs).
        self.buf.zeroize();
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never reveal secret contents.
        f.debug_struct("SecretBytes")
            .field("len", &self.buf.len())
            .field("locked", &self.is_locked())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_and_returns_the_bytes() {
        let s = SecretBytes::from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(s.as_slice(), &[1, 2, 3, 4, 5]);
        assert_eq!(s.len(), 5);
    }

    #[test]
    fn zeroed_is_zero_and_mutable() {
        let mut s = SecretBytes::zeroed(32);
        assert_eq!(s.as_slice(), &[0u8; 32]);
        s.as_mut_slice()[0] = 0xAB;
        assert_eq!(s.as_slice()[0], 0xAB);
    }

    #[test]
    fn clone_is_an_independent_copy() {
        let a = SecretBytes::from_slice(&[9; 16]);
        let mut b = a.clone();
        b.as_mut_slice()[0] = 0;
        assert_eq!(a.as_slice()[0], 9); // original unchanged
        assert_eq!(b.as_slice()[0], 0);
    }

    #[test]
    fn locks_typical_key_sized_buffers() {
        // A 32-byte key should lock on any normal dev/CI machine (well within
        // RLIMIT_MEMLOCK). If this ever flakes in a constrained sandbox it is a
        // best-effort feature, not a correctness bug — but we assert it so a
        // regression that silently disables locking is caught.
        let s = SecretBytes::zeroed(32);
        assert!(s.is_locked());
    }

    #[test]
    fn empty_is_handled() {
        let s = SecretBytes::zeroed(0);
        assert!(s.is_empty());
        assert!(!s.is_locked());
    }
}
