// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Bitmap data structures for tracking unaccepted memory.
//!
//! This module provides [`BitmapRef`], a view backed by a slice of atomic 64-bit
//! words (`&'a [AtomicU64]`).

use core::sync::atomic::{AtomicU64, Ordering};

pub type BitIndex = u64;

/// Bitmap view backed by a slice of [`AtomicU64`].
///
/// Supports lock-free queries (`has_set_bit`, `find_next_set`, etc.) as well
/// as atomic range updates (`set_range`, `clear_range`, `clear_all`) via
/// `AtomicU64`'s relaxed atomic operations.
#[derive(Clone, Copy)]
pub struct BitmapRef<'a> {
    bits: &'a [AtomicU64],
}

impl<'a> BitmapRef<'a> {
    /// Creates a bitmap view from a slice of atomic 64-bit words.
    pub const fn new(bits: &'a [AtomicU64]) -> Self {
        Self { bits }
    }

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

    /// Returns the underlying atomic words.
    pub const fn words(&self) -> &'a [AtomicU64] {
        self.bits
    }

    /// Returns the total capacity in bits.
    pub const fn capacity(&self) -> u64 {
        (self.bits.len() as u64) * 64
    }

    /// Returns `true` if any bit in `[start_bit, end_bit)` is set.
    pub fn has_set_bit(&self, start_bit: BitIndex, end_bit: BitIndex) -> bool {
        let total_bits = self.capacity();
        if start_bit >= end_bit || start_bit >= total_bits {
            return false;
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
            if self.bits[word_idx].load(Ordering::Relaxed) & mask != 0 {
                return true;
            }
        }

        false
    }

    /// Returns the total number of set bits (count of ones) across the bitmap.
    pub fn pending_unit_count(&self) -> u64 {
        self.bits
            .iter()
            .map(|word| word.load(Ordering::Relaxed).count_ones() as u64)
            .sum()
    }

    /// Clears all bits in the bitmap.
    pub fn clear_all(&self) {
        for word in self.bits {
            word.store(0, Ordering::Relaxed);
        }
    }

    /// Finds the first set bit (1) in `[start_bit, end_bit)`.
    pub fn find_next_set(&self, start_bit: BitIndex, end_bit: BitIndex) -> Option<BitIndex> {
        self.find_next_matching(start_bit, end_bit, true)
    }

    /// Finds the first cleared bit (0) in `[start_bit, end_bit)`.
    pub fn find_next_zero(&self, start_bit: BitIndex, end_bit: BitIndex) -> Option<BitIndex> {
        self.find_next_matching(start_bit, end_bit, false)
    }

    /// Sets all bits in `[start_bit, end_bit)` to `1`.
    pub fn set_range(&self, start_bit: BitIndex, end_bit: BitIndex) {
        self.update_range(start_bit, end_bit, true);
    }

    /// Clears all bits in `[start_bit, end_bit)` to `0`.
    pub fn clear_range(&self, start_bit: BitIndex, end_bit: BitIndex) {
        self.update_range(start_bit, end_bit, false);
    }

    fn find_next_matching(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
        target: bool,
    ) -> Option<BitIndex> {
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

            let word = self.bits[word_idx].load(Ordering::Relaxed);
            let match_bits = (if target { word } else { !word }) & mask;
            if match_bits != 0 {
                let delta = match_bits.trailing_zeros() as usize;
                let found = (word_bit_start + delta) as u64;
                return Some(found);
            }
        }

        None
    }

    fn update_range(&self, start_bit: BitIndex, end_bit: BitIndex, set_bits: bool) {
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

            if set_bits {
                self.bits[word_idx].fetch_or(mask, Ordering::Relaxed);
            } else {
                self.bits[word_idx].fetch_and(!mask, Ordering::Relaxed);
            }
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
