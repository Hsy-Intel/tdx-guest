// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Bitmap data structures for tracking unaccepted memory.
//!
//! This module provides three bitmap views with different ownership and
//! synchronization semantics:
//!
//! - [`BitmapMut`] — mutable view backed by `&mut [u8]`, used by the
//!   exclusive (`&mut self`) acceptance and registration paths.
//! - [`UnsyncBitmapMut`] — raw-pointer view that allows non-overlapping
//!   concurrent mutation from multiple CPUs under external synchronization.
//! - [`BitmapRef`] — read-only view backed by `&[u8]`, used for pending
//!   queries without requiring mutable access.
//!
//! `BitmapMut` and `UnsyncBitmapMut` share their scanning and range-manipulation
//! algorithms through the [`BitmapOps`] trait; only the byte-level access
//! primitives differ between the two.

use crate::AcceptError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BitIndex(u64);

impl BitIndex {
    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

/// Mutable bitmap view used by registration/acceptance paths.
///
/// This helper is intentionally non-atomic; callers must provide external
/// synchronization when multiple CPUs could touch the same bitmap.
pub(crate) struct BitmapMut<'a> {
    bits: &'a mut [u8],
}

impl<'a> BitmapOps for BitmapMut<'a> {
    fn byte_len(&self) -> usize {
        self.bits.len()
    }

    fn get_byte(&self, index: usize) -> Result<u8, AcceptError> {
        self.bits
            .get(index)
            .copied()
            .ok_or(AcceptError::OutOfBounds)
    }

    fn put_byte(&mut self, index: usize, value: u8) -> Result<(), AcceptError> {
        *self.bits.get_mut(index).ok_or(AcceptError::OutOfBounds)? = value;
        Ok(())
    }

    fn as_raw_ptr(&self) -> *const u8 {
        self.bits.as_ptr()
    }
}

impl<'a> BitmapMut<'a> {
    pub(crate) fn new(bits: &'a mut [u8]) -> Self {
        Self { bits }
    }

    pub(crate) fn set_bit(&mut self, bit_index: BitIndex) -> Result<(), AcceptError> {
        if self.is_set(bit_index)? {
            return Err(AcceptError::Overlap);
        }
        let (byte_index, mask) = self.get_pos_mask(bit_index)?;
        self.bits[byte_index] |= mask;
        Ok(())
    }
}

/// Raw-pointer bitmap view for concurrent mutation of non-overlapping regions.
///
/// Unlike [`BitmapMut`], this type does not hold a mutable reference, enabling
/// multiple instances to coexist for disjoint bitmap segments under external
/// synchronization.
///
/// # Safety invariants (established at construction)
///
/// - `ptr..ptr+len` must remain valid for reads and writes for the lifetime of
///   this value.
/// - No two `UnsyncBitmapMut` instances (or a `BitmapMut`) may concurrently
///   mutate overlapping byte ranges.
/// - Bulk 64-bit scan operations read 8 consecutive bytes at a time; the
///   caller's external lock must cover at least `[byte_index, byte_index + 8)`
///   for every such read.
pub(crate) struct UnsyncBitmapMut {
    ptr: *mut u8,
    len: usize,
}

impl BitmapOps for UnsyncBitmapMut {
    fn byte_len(&self) -> usize {
        self.len
    }

    fn get_byte(&self, index: usize) -> Result<u8, AcceptError> {
        if index >= self.len {
            return Err(AcceptError::OutOfBounds);
        }
        // SAFETY: Bounds checked above; pointer validity guaranteed by
        // constructor's safety contract.
        Ok(unsafe { self.ptr.add(index).read() })
    }

    fn put_byte(&mut self, index: usize, value: u8) -> Result<(), AcceptError> {
        if index >= self.len {
            return Err(AcceptError::OutOfBounds);
        }
        // SAFETY: Bounds checked above; pointer validity guaranteed by
        // constructor's safety contract.
        unsafe { self.ptr.add(index).write(value) };
        Ok(())
    }

    fn as_raw_ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }
}

impl UnsyncBitmapMut {
    /// Creates a new raw-pointer bitmap view.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and point to at least `len` bytes of valid,
    ///   writable memory that remains valid for the lifetime of the returned
    ///   value.
    /// - The caller must ensure no concurrent mutable access to overlapping
    ///   byte ranges (e.g., by holding a shard lock that covers the entire
    ///   `[ptr, ptr + len)` region, or by guaranteeing disjoint access).
    pub(crate) unsafe fn new(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }
}

/// Trait abstracting byte-level access to a bitmap buffer.
///
/// Implementations supply four primitives; the scanning and range-manipulation
/// algorithms are provided as default methods.
pub(super) trait BitmapOps {
    /// Returns the number of bytes in the backing buffer.
    fn byte_len(&self) -> usize;

    /// Reads one byte at `index`.
    ///
    /// Returns [`AcceptError::OutOfBounds`] if `index >= byte_len()`.
    fn get_byte(&self, index: usize) -> Result<u8, AcceptError>;

    /// Writes one byte at `index`.
    ///
    /// Returns [`AcceptError::OutOfBounds`] if `index >= byte_len()`.
    fn put_byte(&mut self, index: usize, value: u8) -> Result<(), AcceptError>;

    /// Returns a raw const pointer to the backing buffer for bulk 64-bit reads.
    ///
    /// The pointer must remain valid for at least `byte_len()` bytes for the
    /// lifetime of `self`.
    fn as_raw_ptr(&self) -> *const u8;

    fn capacity(&self) -> Result<u64, AcceptError> {
        let len = u64::try_from(self.byte_len()).map_err(|_| AcceptError::OutOfBounds)?;
        len.checked_mul(8).ok_or(AcceptError::ArithmeticOverflow)
    }

    fn get_pos_mask(&self, bit_index: BitIndex) -> Result<(usize, u8), AcceptError> {
        if bit_index.raw() >= self.capacity()? {
            return Err(AcceptError::OutOfBounds);
        }
        let byte_index =
            usize::try_from(bit_index.raw() >> 3).map_err(|_| AcceptError::OutOfBounds)?;
        let mask = 1u8 << (bit_index.raw() & 7);
        Ok((byte_index, mask))
    }

    fn is_set(&self, bit_index: BitIndex) -> Result<bool, AcceptError> {
        let (byte_index, mask) = self.get_pos_mask(bit_index)?;
        Ok((self.get_byte(byte_index)? & mask) != 0)
    }

    fn find_next_set(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<Option<BitIndex>, AcceptError> {
        self.find_next_matching(start_bit, end_bit, true)
    }

    fn find_next_zero(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<Option<BitIndex>, AcceptError> {
        self.find_next_matching(start_bit, end_bit, false)
    }

    fn find_next_matching(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
        target: bool,
    ) -> Result<Option<BitIndex>, AcceptError> {
        let bit_len = self.capacity()?;
        if start_bit.raw() > end_bit.raw() || end_bit.raw() > bit_len {
            return Err(AcceptError::OutOfBounds);
        }
        if start_bit == end_bit {
            return Ok(None);
        }

        let mut scan_bit = start_bit.raw();
        let end_bit_raw = end_bit.raw();

        // Scan leading bits until the index is 64-bit aligned.
        while scan_bit < end_bit_raw && (scan_bit & 63) != 0 {
            if self.is_set(BitIndex::new(scan_bit))? == target {
                return Ok(Some(BitIndex::new(scan_bit)));
            }
            scan_bit += 1;
        }

        // Bulk scan by 64-bit words, then use trailing_zeros for first matching bit.
        while end_bit_raw - scan_bit >= 64 {
            let next = scan_bit + 64;
            let byte_index =
                usize::try_from(scan_bit >> 3).map_err(|_| AcceptError::OutOfBounds)?;

            // SAFETY: Loop condition `end_bit_raw - scan_bit >= 64` guarantees
            // `byte_index + 8 <= byte_len()`. The pointer from `as_raw_ptr()`
            // is valid for at least `byte_len()` bytes per the trait contract.
            let word = unsafe {
                let ptr = self.as_raw_ptr().add(byte_index).cast::<u64>();
                u64::from_le(ptr.read_unaligned())
            };

            let match_word = if target { word } else { !word };
            if match_word != 0 {
                let delta = u64::from(match_word.trailing_zeros());
                let found = scan_bit + delta;
                return Ok(Some(BitIndex::new(found)));
            }

            scan_bit = next;
        }

        // Scan remaining tail bits (< 64).
        while scan_bit < end_bit_raw {
            if self.is_set(BitIndex::new(scan_bit))? == target {
                return Ok(Some(BitIndex::new(scan_bit)));
            }
            scan_bit += 1;
        }

        Ok(None)
    }

    fn clear_range(&mut self, start_bit: BitIndex, end_bit: BitIndex) -> Result<(), AcceptError> {
        let bit_len = self.capacity()?;
        if start_bit.raw() > end_bit.raw() || end_bit.raw() > bit_len {
            return Err(AcceptError::OutOfBounds);
        }
        if start_bit == end_bit {
            return Ok(());
        }

        let (start_byte, end_exclusive_byte, start_off, end_off) =
            byte_range_params(start_bit, end_bit)?;

        if start_byte + 1 == end_exclusive_byte {
            let end_off_eff = if end_off == 0 { 8 } else { end_off };
            let clear_mask = bit_range_mask(start_off, end_off_eff);
            let val = self.get_byte(start_byte)?;
            self.put_byte(start_byte, val & !clear_mask)?;
            return Ok(());
        }

        // Leading partial byte.
        if start_off != 0 {
            let val = self.get_byte(start_byte)?;
            self.put_byte(start_byte, val & low_bits_mask(start_off))?;
        } else {
            self.put_byte(start_byte, 0)?;
        }

        // Middle full bytes.
        let middle_start = start_byte + 1;
        let middle_end = if end_off == 0 {
            end_exclusive_byte
        } else {
            end_exclusive_byte - 1
        };
        for i in middle_start..middle_end {
            self.put_byte(i, 0)?;
        }

        // Trailing partial byte.
        if end_off != 0 {
            let keep_high = !low_bits_mask(end_off);
            let last = end_exclusive_byte - 1;
            let val = self.get_byte(last)?;
            self.put_byte(last, val & keep_high)?;
        }

        Ok(())
    }

    /// Sets all bits in `[start_bit, end_bit)` to `1`.
    fn set_range(&mut self, start_bit: BitIndex, end_bit: BitIndex) -> Result<(), AcceptError> {
        let bit_len = self.capacity()?;
        if start_bit.raw() > end_bit.raw() || end_bit.raw() > bit_len {
            return Err(AcceptError::OutOfBounds);
        }
        if start_bit == end_bit {
            return Ok(());
        }

        let (start_byte, end_exclusive_byte, start_off, end_off) =
            byte_range_params(start_bit, end_bit)?;

        if start_byte + 1 == end_exclusive_byte {
            let end_off_eff = if end_off == 0 { 8 } else { end_off };
            let set_mask = bit_range_mask(start_off, end_off_eff);
            let val = self.get_byte(start_byte)?;
            self.put_byte(start_byte, val | set_mask)?;
            return Ok(());
        }

        // Leading partial byte.
        if start_off != 0 {
            let set_mask = !low_bits_mask(start_off);
            let val = self.get_byte(start_byte)?;
            self.put_byte(start_byte, val | set_mask)?;
        } else {
            self.put_byte(start_byte, 0xFF)?;
        }

        // Middle full bytes.
        let middle_start = start_byte + 1;
        let middle_end = if end_off == 0 {
            end_exclusive_byte
        } else {
            end_exclusive_byte - 1
        };
        for i in middle_start..middle_end {
            self.put_byte(i, 0xFF)?;
        }

        // Trailing partial byte.
        if end_off != 0 {
            let set_mask = low_bits_mask(end_off);
            let last = end_exclusive_byte - 1;
            let val = self.get_byte(last)?;
            self.put_byte(last, val | set_mask)?;
        }

        Ok(())
    }
}

/// Read-only bitmap view for pending-state queries.
pub(crate) struct BitmapRef<'a> {
    bits: &'a [u8],
}

impl<'a> BitmapRef<'a> {
    pub(crate) fn new(bits: &'a [u8]) -> Self {
        Self { bits }
    }

    pub(crate) fn has_set_bit(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<bool, AcceptError> {
        if start_bit >= end_bit {
            return Ok(false);
        }

        let bit_len = self
            .bits
            .len()
            .checked_mul(8)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        let start_bit = usize::try_from(start_bit.raw()).map_err(|_| AcceptError::OutOfBounds)?;
        let end_bit = usize::try_from(end_bit.raw()).map_err(|_| AcceptError::OutOfBounds)?;
        if end_bit > bit_len {
            return Err(AcceptError::OutOfBounds);
        }

        let mut bit = start_bit;

        // Scan head until byte alignment.
        while bit < end_bit && (bit & 7) != 0 {
            let byte_idx = bit >> 3;
            let mask = 1u8 << (bit & 7);
            if (self.bits[byte_idx] & mask) != 0 {
                return Ok(true);
            }
            bit += 1;
        }

        let mut byte_idx = bit >> 3;
        let end_full_byte = end_bit >> 3;

        // Bulk scan by u64 for full bytes.
        while byte_idx + 8 <= end_full_byte {
            // SAFETY: loop condition guarantees 8 readable bytes.
            let word = unsafe {
                let ptr = self.bits.as_ptr().add(byte_idx).cast::<u64>();
                u64::from_le(ptr.read_unaligned())
            };
            if word != 0 {
                return Ok(true);
            }
            byte_idx += 8;
        }

        while byte_idx < end_full_byte {
            if self.bits[byte_idx] != 0 {
                return Ok(true);
            }
            byte_idx += 1;
        }

        // Check tail bits in one masked-byte test.
        let tail_bits = (end_bit & 7) as u8;
        if tail_bits != 0 {
            let tail_mask = low_bits_mask(tail_bits);
            if (self.bits[end_full_byte] & tail_mask) != 0 {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

pub(crate) fn low_bits_mask(count: u8) -> u8 {
    debug_assert!(count <= 8);
    if count == 0 {
        0
    } else {
        u8::MAX >> (8 - count)
    }
}

pub(crate) fn bit_range_mask(start_off: u8, end_off: u8) -> u8 {
    debug_assert!(start_off <= end_off && end_off <= 8);
    if start_off == end_off {
        return 0;
    }

    let width = end_off - start_off;
    low_bits_mask(width) << start_off
}

/// Computes the byte-level parameters shared by `clear_range` / `set_range`.
///
/// Returns `(start_byte, end_exclusive_byte, start_off, end_off)`.
fn byte_range_params(
    start_bit: BitIndex,
    end_bit: BitIndex,
) -> Result<(usize, usize, u8, u8), AcceptError> {
    let start_byte = usize::try_from(start_bit.raw() >> 3).map_err(|_| AcceptError::OutOfBounds)?;
    let end_exclusive_byte = usize::try_from(
        end_bit
            .raw()
            .checked_add(7)
            .ok_or(AcceptError::ArithmeticOverflow)?
            >> 3,
    )
    .map_err(|_| AcceptError::OutOfBounds)?;
    let start_off = u8::try_from(start_bit.raw() & 7).map_err(|_| AcceptError::OutOfBounds)?;
    let end_off = u8::try_from(end_bit.raw() & 7).map_err(|_| AcceptError::OutOfBounds)?;
    Ok((start_byte, end_exclusive_byte, start_off, end_off))
}
