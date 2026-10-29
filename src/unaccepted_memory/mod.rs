// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Support for unaccepted memory in TDX guest environments.
//!
//! This module provides mechanisms to manage and accept
//! unaccepted memory regions in TDX guests.
//! Build an [`EfiUnacceptedMemory`] table with [`EfiUnacceptedMemoryBuilder`],
//! register it with [`init_acceptance_state`], and use [`ensure_accepted`] before
//! accessing pending memory. Bitmap access and acceptance synchronization remain
//! internal to this module.

mod accept;
mod bitmap;
mod layout;
mod register;
#[cfg(test)]
mod tests;

use core::{
    marker::PhantomPinned, mem::size_of, ops::Range, pin::Pin, ptr::NonNull,
    sync::atomic::AtomicU64,
};

pub use accept::{
    ensure_accepted, init_acceptance_state, unaccepted_bytes, unaccepted_memory_table,
};
use layout::BitmapLayout;

use crate::AcceptError;

/// Builder for constructing an [`EfiUnacceptedMemory`] table incrementally without heap allocation.
pub struct EfiUnacceptedMemoryBuilder {
    table: Pin<&'static mut EfiUnacceptedMemory>,
}

impl EfiUnacceptedMemoryBuilder {
    /// Registers a single unaccepted memory range.
    ///
    /// # Safety
    ///
    /// The caller must ensure `start..end` is valid guest-private memory in pending/acceptable state.
    pub unsafe fn register_range(&mut self, start: u64, end: u64) -> Result<(), AcceptError> {
        unsafe { self.table.as_mut().register_range(start, end) }
    }

    /// Consumes the builder and returns the completed pinned [`EfiUnacceptedMemory`] table.
    pub fn build(self) -> Pin<&'static mut EfiUnacceptedMemory> {
        self.table
    }
}

/// Version of the Linux-compatible unaccepted-memory EFI table supported here.
const LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION: u32 = 1;

/// Unit size for unaccepted-memory bitmap entries (2 MiB).
const EFI_UNACCEPTED_UNIT_SIZE: u64 = 2 * 1024 * 1024;

/// Header of the Linux-compatible EFI unaccepted-memory table.
///
/// This type describes only the fixed-size header. The bitmap payload is stored
/// immediately after the header in memory (C-style trailing data):
///
/// ### Memory Layout
/// The total memory footprint is
/// `size_of::<EfiUnacceptedMemory>() + self.bitmap_size_bytes`.
/// The bitmap begins at the first byte following this structure.
///
/// ### Type Invariants
/// Any valid reference (`&Self` or `Pin<&mut Self>`) satisfies the following invariants:
/// - The header is immediately followed in memory by a valid trailing bitmap of
///   `self.bitmap_size_bytes` bytes.
/// - The trailing bitmap starts at a pointer aligned to `align_of::<AtomicU64>()` (8 bytes),
///   and `self.bitmap_size_bytes` is a non-zero multiple of `size_of::<AtomicU64>()` (8 bytes).
/// - `self.unit_size_bytes` is a non-zero power of two.
/// - The physical address range covered by the bitmap (`self.phys_base..self.phys_base + coverage_size`)
///   does not overflow `u64`.
///
/// Because moving an `EfiUnacceptedMemory` would detach it from its trailing bitmap,
/// mutable access requires pinning ([`Pin<&mut Self>`]).
///
/// ### Bitmap Semantics
/// - Each bit in the trailing bitmap represents a memory region of
///   `unit_size_bytes` bytes.
/// - Bit 0 corresponds to the physical address specified by `phys_base`.
/// - A **set bit (1)** indicates memory is unaccepted (pending);
///   a **cleared bit (0)** indicates it has been accepted.
#[derive(Debug)]
#[repr(C, packed)]
pub struct EfiUnacceptedMemory {
    /// The version of the table. Currently, only version 1 is defined.
    version: u32,
    /// The size of the memory region represented by a single bit in the bitmap.
    /// Typically set to 2MiB (0x200000) to align with huge page boundaries.
    unit_size_bytes: u32,
    /// The start physical address of the memory range covered by this bitmap.
    /// Bit 0 of the bitmap corresponds to this address.
    phys_base: u64,
    /// The bitmap payload length in bytes, excluding this header.
    bitmap_size_bytes: u64,
    _pinned: PhantomPinned,
}

impl EfiUnacceptedMemory {
    /// Returns the allocation size required for a table covering `coverage`.
    pub fn required_size_for_range(coverage: Range<u64>) -> Result<usize, AcceptError> {
        let layout = BitmapLayout::from_range(coverage)?;

        size_of::<Self>()
            .checked_add(layout.size_bytes)
            .ok_or(AcceptError::ArithmeticOverflow)
    }

    /// Starts building a table in caller-provided memory covering `coverage`.
    ///
    /// This initializes the header and clears the bitmap, returning an [`EfiUnacceptedMemoryBuilder`]
    /// so the caller can register unaccepted regions one at a time without heap allocation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `table_addr` points to a writable allocation of `allocation_size` bytes;
    /// - `allocation_size` is at least the size returned by [`Self::required_size_for_range`];
    /// - the allocation remains valid for the returned `'static` reference;
    /// - no other reference accesses the allocation while the table exists.
    pub unsafe fn builder(
        table_addr: NonNull<u8>,
        allocation_size: usize,
        coverage: Range<u64>,
    ) -> Result<EfiUnacceptedMemoryBuilder, AcceptError> {
        let bitmap_layout = BitmapLayout::from_range(coverage)?;
        let required_size = size_of::<Self>()
            .checked_add(bitmap_layout.size_bytes)
            .ok_or(AcceptError::ArithmeticOverflow)?;

        let table_raw = table_addr.as_ptr();
        if !table_raw.is_aligned()
            || !table_raw
                .addr()
                .is_multiple_of(core::mem::align_of::<AtomicU64>())
        {
            return Err(AcceptError::InvalidAlignment);
        }
        let bitmap_addr = table_raw
            .addr()
            .checked_add(size_of::<Self>())
            .ok_or(AcceptError::ArithmeticOverflow)?;
        if !bitmap_addr.is_multiple_of(core::mem::align_of::<AtomicU64>()) {
            return Err(AcceptError::InvalidAlignment);
        }
        if allocation_size < required_size {
            return Err(AcceptError::OutOfBounds);
        }

        let table_ptr = table_addr.cast::<Self>();
        table_ptr.as_ptr().write(Self {
            version: LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION,
            unit_size_bytes: EFI_UNACCEPTED_UNIT_SIZE as u32,
            phys_base: bitmap_layout.coverage_phys_base,
            bitmap_size_bytes: bitmap_layout.size_bytes as u64,
            _pinned: PhantomPinned,
        });

        // SAFETY: The caller provides unique access to a sufficiently large,
        // writable allocation that remains valid for the returned reference.
        // The type invariants for header and bitmap layout have been established.
        let table = unsafe { Pin::new_unchecked(&mut *table_ptr.as_ptr()) };
        table.bitmap_ref().clear_all();

        Ok(EfiUnacceptedMemoryBuilder { table })
    }

    /// Returns the unit size represented by one bitmap bit, in bytes.
    pub const fn unit_size_bytes(&self) -> u32 {
        self.unit_size_bytes
    }

    /// Returns the trailing bitmap payload length, in bytes.
    pub const fn bitmap_size_bytes(&self) -> u64 {
        self.bitmap_size_bytes
    }
}
