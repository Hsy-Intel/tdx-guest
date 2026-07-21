// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Layout and mapping helpers for unaccepted-memory metadata.
//!
//! This file provides address/bit conversions, coverage ranges, and
//! trailing-bitmap views based on the [`EfiUnacceptedMemory`] type invariants.

use core::{mem::size_of, ops::Range};

use super::{
    bitmap::{BitIndex, BitmapRef},
    EfiUnacceptedMemory, EFI_UNACCEPTED_UNIT_SIZE,
};
use crate::AcceptError;

impl EfiUnacceptedMemory {
    /// Returns the physical address range covered by the bitmap.
    pub fn coverage_range(&self) -> Range<u64> {
        let end = self.phys_base + self.coverage_size();
        self.phys_base..end
    }

    /// Returns the total physical address range size (in bytes) covered by the bitmap.
    pub fn coverage_size(&self) -> u64 {
        self.total_bits() * u64::from(self.unit_size_bytes)
    }

    /// Alias for [`Self::coverage_range`].
    #[inline]
    pub fn bitmap_coverage_range(&self) -> Range<u64> {
        self.coverage_range()
    }

    /// Returns an atomic view of the trailing bitmap.
    pub fn bitmap_ref(&self) -> BitmapRef<'_> {
        let bitmap_len = self.bitmap_size_bytes as usize;
        let bitmap_ptr = core::ptr::from_ref(self)
            .cast::<u8>()
            .wrapping_add(core::mem::size_of::<Self>());
        // SAFETY: The type invariant of `EfiUnacceptedMemory` guarantees that the header
        // is immediately followed by a valid trailing bitmap of `self.bitmap_size_bytes` bytes,
        // aligned to `AtomicU64`, and with length a multiple of `size_of::<AtomicU64>()`.
        unsafe { BitmapRef::from_raw(bitmap_ptr, bitmap_len) }
    }

    pub(super) fn total_bits(&self) -> u64 {
        self.bitmap_size_bytes * 8
    }

    /// Converts a GPA range into an overlapping bitmap bit range.
    ///
    /// Returns `None` when there is no overlap with bitmap coverage.
    pub(super) fn overlapping_bit_range(
        &self,
        start: u64,
        end: u64,
    ) -> Option<(BitIndex, BitIndex, u64)> {
        if start >= end {
            return None;
        }

        let unit_size = u64::from(self.unit_size_bytes);
        let coverage = self.coverage_range();

        let range_start = start.max(coverage.start);
        let range_end = end.min(coverage.end);
        if range_start >= range_end {
            return None;
        }

        let rel_start = range_start - self.phys_base;
        let rel_end = range_end - self.phys_base;

        let first_bit = rel_start / unit_size;
        let last_bit = rel_end.div_ceil(unit_size);

        Some((first_bit, last_bit, unit_size))
    }
}

pub(super) struct BitmapLayout {
    pub(super) coverage_phys_base: u64,
    pub(super) size_bytes: usize,
}

impl BitmapLayout {
    /// Computes the physical base address and required trailing bitmap size (in bytes)
    /// to cover memory within `range`.
    pub(super) fn from_range(range: Range<u64>) -> Result<Self, AcceptError> {
        if range.start >= range.end {
            return Err(AcceptError::OutOfBounds);
        }

        let phys_base = align_down(range.start, EFI_UNACCEPTED_UNIT_SIZE);
        let coverage_end =
            align_up(range.end, EFI_UNACCEPTED_UNIT_SIZE).ok_or(AcceptError::ArithmeticOverflow)?;
        let coverage_size = coverage_end - phys_base;
        let bitmap_bits = coverage_size / EFI_UNACCEPTED_UNIT_SIZE;
        let bitmap_words = bitmap_bits.div_ceil(64);
        let bitmap_size_bytes = bitmap_words * size_of::<u64>() as u64;

        Ok(Self {
            coverage_phys_base: phys_base,
            size_bytes: usize::try_from(bitmap_size_bytes).map_err(|_| AcceptError::OutOfBounds)?,
        })
    }
}

pub(super) fn min_max_from_ranges(ranges: &[Range<u64>]) -> Result<Range<u64>, AcceptError> {
    let first = ranges.first().ok_or(AcceptError::OutOfBounds)?;
    if first.start >= first.end {
        return Err(AcceptError::OutOfBounds);
    }

    let mut min_addr = first.start;
    let mut max_addr = first.end;
    for range in &ranges[1..] {
        if range.start >= range.end {
            return Err(AcceptError::OutOfBounds);
        }
        min_addr = min_addr.min(range.start);
        max_addr = max_addr.max(range.end);
    }

    Ok(min_addr..max_addr)
}

pub(super) fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

pub(super) fn align_up(addr: u64, align: u64) -> Option<u64> {
    addr.checked_add(align - 1).map(|v| v & !(align - 1))
}
