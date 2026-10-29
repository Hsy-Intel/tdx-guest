// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Bitmap data structures for tracking unaccepted memory.
//!
//! This module provides [`BitmapRef`], a view backed by a slice of atomic 64-bit
//! words (`&'a [AtomicU64]`).

use core::sync::atomic::{AtomicU64, Ordering};

pub(super) type BitIndex = u64;

/// Bitmap view backed by a slice of [`AtomicU64`].
///
/// Supports lock-free queries with acquire semantics and atomic updates
/// (`set_range`, `clear_bit`, `clear_all`) with release semantics.
#[derive(Clone, Copy)]
pub(super) struct BitmapRef<'a> {
    bits: &'a [AtomicU64],
}

impl<'a> BitmapRef<'a> {
    /// Creates a bitmap view from a `u64`-aligned raw pointer.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and aligned to `align_of::<AtomicU64>()`.
    /// - `ptr` must point to at least `len_bytes` bytes of valid memory.
    /// - `len_bytes` must be a multiple of `size_of::<AtomicU64>()`.
    /// - The memory must remain valid for lifetime `'a`.
    pub(super) unsafe fn from_raw(ptr: *const u8, len_bytes: usize) -> Self {
        debug_assert_eq!(len_bytes % core::mem::size_of::<AtomicU64>(), 0);
        let len_words = len_bytes / core::mem::size_of::<AtomicU64>();
        // SAFETY: Caller guarantees alignment, validity, and length constraints.
        let bits = unsafe { core::slice::from_raw_parts(ptr.cast::<AtomicU64>(), len_words) };
        Self { bits }
    }

    /// Returns the total capacity in bits.
    pub(super) const fn capacity(&self) -> u64 {
        (self.bits.len() as u64) * 64
    }

    /// Returns `true` if `bit` is within capacity and set (`1`), using acquire ordering.
    pub(super) fn is_bit_set(&self, bit: BitIndex) -> bool {
        if bit >= self.capacity() {
            return false;
        }
        let bit = bit as usize;
        let word_idx = bit / 64;
        let mask = 1u64 << (bit % 64);
        self.bits[word_idx].load(Ordering::Acquire) & mask != 0
    }

    /// Clears `bit` to `0` using release ordering and returns `true` if it was previously set.
    pub(super) fn clear_bit(&self, bit: BitIndex) -> bool {
        if bit >= self.capacity() {
            return false;
        }
        let bit = bit as usize;
        let word_idx = bit / 64;
        let mask = 1u64 << (bit % 64);
        self.bits[word_idx].fetch_and(!mask, Ordering::Release) & mask != 0
    }

    /// Returns the total number of set bits (count of ones) across the bitmap.
    pub(super) fn pending_unit_count(&self) -> u64 {
        self.bits
            .iter()
            .map(|word| word.load(Ordering::Acquire).count_ones() as u64)
            .sum()
    }

    /// Clears all bits in the bitmap.
    pub(super) fn clear_all(&self) {
        for word in self.bits {
            word.store(0, Ordering::Release);
        }
    }

    /// Finds the first set bit (1) in `[start_bit, end_bit)`.
    pub(super) fn find_next_set(&self, start_bit: BitIndex, end_bit: BitIndex) -> Option<BitIndex> {
        let total_bits = self.capacity();
        if start_bit >= end_bit || start_bit >= total_bits {
            return None;
        }
        let end_bit = end_bit.min(total_bits);

        let start = start_bit as usize;
        let end = end_bit as usize;

        let start_word = start / 64;
        let end_word = (end - 1) / 64;

        for word_idx in start_word..=end_word {
            let word_bit_start = word_idx * 64;
            let lo = start.saturating_sub(word_bit_start);
            let hi = end.min(word_bit_start + 64) - word_bit_start;
            let mask = word_range_mask(lo, hi);

            let word = self.bits[word_idx].load(Ordering::Acquire);
            let match_bits = word & mask;
            if match_bits != 0 {
                let delta = match_bits.trailing_zeros() as usize;
                let found = (word_bit_start + delta) as u64;
                return Some(found);
            }
        }

        None
    }

    /// Sets all bits in `[start_bit, end_bit)` to `1`.
    pub(super) fn set_range(&self, start_bit: BitIndex, end_bit: BitIndex) {
        let total_bits = self.capacity();
        if start_bit >= end_bit || start_bit >= total_bits {
            return;
        }
        let end_bit = end_bit.min(total_bits);

        let start = start_bit as usize;
        let end = end_bit as usize;

        let start_word = start / 64;
        let end_word = (end - 1) / 64;

        for word_idx in start_word..=end_word {
            let word_bit_start = word_idx * 64;
            let lo = start.saturating_sub(word_bit_start);
            let hi = end.min(word_bit_start + 64) - word_bit_start;
            let mask = word_range_mask(lo, hi);

            self.bits[word_idx].fetch_or(mask, Ordering::Release);
        }
    }
}

/// Returns a 64-bit mask with bits in `[lo, hi)` set to `1` and all other bits cleared.
fn word_range_mask(lo: usize, hi: usize) -> u64 {
    debug_assert!(lo <= hi && hi <= 64);
    if lo >= hi {
        0
    } else {
        let mask_hi = if hi == 64 { !0u64 } else { (1u64 << hi) - 1 };
        let mask_lo = (1u64 << lo) - 1;
        mask_hi & !mask_lo
    }
}
