// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Support for unaccepted memory in TDX guest environments.
//!
//! This module provides mechanisms to manage and accept
//! unaccepted memory regions in TDX guests.
//! The core data structure is [`EfiUnacceptedMemory`],
//! which represents the EFI table header
//! and provides methods to manipulate the unaccepted memory bitmap
//! and perform acceptance operations.

mod bitmap;

use bitmap::{BitIndex, BitmapMut, BitmapOps, BitmapRef, UnsyncBitmapMut};

use crate::{accept_memory, AcceptError};

/// GUID of the Linux-compatible unaccepted-memory EFI table.
pub const LINUX_EFI_UNACCEPTED_MEM_TABLE_GUID: uefi_raw::Guid =
    uefi_raw::guid!("d5d1de3c-105c-44f9-9ea9-bcef98120031");

/// Version of the Linux-compatible unaccepted-memory EFI table supported here.
pub const LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION: u32 = 1;

/// Unit size for unaccepted-memory bitmap entries (2 MiB).
pub const EFI_UNACCEPTED_UNIT_SIZE: u64 = 2 * 1024 * 1024;

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
/// ### Bitmap Semantics
/// - Each bit in the trailing bitmap represents a memory region of
///   `unit_size_bytes` bytes.
/// - Bit 0 corresponds to the physical address specified by `phys_base`.
/// - A **set bit (1)** indicates memory is unaccepted (pending);
///   a **cleared bit (0)** indicates it has been accepted.
///
/// ### Concurrency Contract
/// This type does not provide internal synchronization for bitmap mutation.
/// Callers must serialize mutating operations (for example with a spinlock)
/// before invoking methods like `register_range` or `accept_range`.
#[derive(Copy, Clone, Debug)]
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
}

impl EfiUnacceptedMemory {
    /// Initializes the table header fields for EFI installation.
    pub fn init_header(
        &mut self,
        unit_size_bytes: u32,
        phys_base: u64,
        bitmap_size_bytes: u64,
    ) -> Result<(), AcceptError> {
        if unit_size_bytes == 0 || !unit_size_bytes.is_power_of_two() {
            return Err(AcceptError::InvalidAlignment);
        }

        self.version = LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION;
        self.unit_size_bytes = unit_size_bytes;
        self.phys_base = phys_base;
        self.bitmap_size_bytes = bitmap_size_bytes;
        Ok(())
    }

    /// Returns the version of the table header.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the unit size represented by one bitmap bit, in bytes.
    pub const fn unit_size_bytes(&self) -> u32 {
        self.unit_size_bytes
    }

    /// Returns the start physical address covered by the bitmap.
    pub const fn phys_base(&self) -> u64 {
        self.phys_base
    }

    /// Returns the trailing bitmap payload length, in bytes.
    pub const fn bitmap_size_bytes(&self) -> u64 {
        self.bitmap_size_bytes
    }

    /// Returns whether `(start, size)` overlaps any pending bitmap unit.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This header is followed by at least `self.bitmap_size_bytes` readable bytes
    ///   (i.e., the trailing bitmap payload exists in valid memory).
    /// - No concurrent mutation of overlapping bitmap bytes is in progress.
    pub unsafe fn is_range_pending_by_size(
        &self,
        start: u64,
        size: u64,
    ) -> Result<bool, AcceptError> {
        let Some(end) = start.checked_add(size) else {
            return Err(AcceptError::ArithmeticOverflow);
        };

        // SAFETY: Caller guarantees trailing bitmap validity and no concurrent mutation.
        unsafe { self.is_range_pending(start, end) }
    }

    /// Returns whether `[start, end)` overlaps any pending bitmap unit.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This header is followed by at least `self.bitmap_size_bytes` readable bytes
    ///   (i.e., the trailing bitmap payload exists in valid memory).
    /// - No concurrent mutation of overlapping bitmap bytes is in progress.
    pub unsafe fn is_range_pending(&self, start: u64, end: u64) -> Result<bool, AcceptError> {
        let Some((range_start, range_end, unit_size)) =
            self.clamp_gpa_range_to_bitmap_coverage(start, end)?
        else {
            return Ok(false);
        };

        let (first_bit, last_bit) = self.addr_to_bit_range(range_start, range_end, unit_size)?;
        // SAFETY: Caller guarantees trailing bitmap is valid and readable.
        let bitmap = unsafe { self.as_bitmap_slice()? };
        BitmapRef::new(bitmap).has_set_bit(first_bit, last_bit)
    }

    /// Returns whether every bitmap unit overlapping `[start, end)` is accepted.
    ///
    /// Ranges outside bitmap coverage are considered accepted by definition,
    /// because this table only tracks deferred acceptance inside its own coverage.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This header is followed by at least `self.bitmap_size_bytes` readable bytes
    ///   (i.e., the trailing bitmap payload exists in valid memory).
    /// - No concurrent mutation of overlapping bitmap bytes is in progress.
    pub unsafe fn is_fully_accepted(&self, start: u64, end: u64) -> Result<bool, AcceptError> {
        // SAFETY: Caller guarantees trailing bitmap validity and no concurrent mutation.
        Ok(!unsafe { self.is_range_pending(start, end) }?)
    }

    /// Convenience wrapper for
    /// [`EfiUnacceptedMemory::accept_range`] using
    /// `(start, size)` instead of `(start, end)`.
    ///
    /// Computes `end = start + size` and forwards to the range-based API.
    ///
    /// # Safety
    ///
    /// The caller must ensure `self` is uniquely borrowed for in-place bitmap updates and
    /// points to a valid unaccepted-memory table with writable bitmap memory.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptError::ArithmeticOverflow`] if `start + size` overflows.
    /// Propagates any error from [`EfiUnacceptedMemory::accept_range`].
    pub unsafe fn accept_by_size(&mut self, start: u64, size: u64) -> Result<(), AcceptError> {
        let Some(end) = start.checked_add(size) else {
            return Err(AcceptError::ArithmeticOverflow);
        };

        // SAFETY: Caller guarantees table/bitmap validity and target range correctness.
        unsafe { self.accept_range(start, end) }
    }

    /// Accepts bitmap-marked units that overlap `start..end`, then clears accepted bits.
    ///
    /// The input is interpreted as a half-open GPA interval `[start, end)`.
    ///
    /// Behavior summary:
    /// - The requested range is first clamped to bitmap coverage.
    /// - Any bitmap bit set to `1` and overlapping the clamped range is accepted.
    /// - Successfully accepted bits are cleared to `0` in-place.
    /// - If the clamped range is empty, this is a no-op.
    ///
    /// # Safety
    ///
    /// The caller must ensure this table and bitmap describe pending private-memory units,
    /// and the target GPA ranges are valid for TDX acceptance.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptError::InvalidAlignment`] for invalid unit configuration.
    /// Returns [`AcceptError::ArithmeticOverflow`] for address/index arithmetic overflow.
    /// Returns [`AcceptError::OutOfBounds`] for bitmap index out-of-range accesses.
    /// Returns hardware-originated failures from `accept_memory` via
    /// [`AcceptError::TdCall`].
    pub unsafe fn accept_range(&mut self, start: u64, end: u64) -> Result<(), AcceptError> {
        // SAFETY: Caller guarantees table/bitmap validity and target range correctness.
        let _ = unsafe { self.accept_if_needed_range(start, end) }?;
        Ok(())
    }

    /// Accepts bitmap-marked units that overlap `start..end`
    /// and clears the corresponding bitmap bits.
    ///
    /// Unlike [`Self::accept_range`], this method takes `&self`,
    /// enabling concurrent accept operations on **non-overlapping** bitmap regions
    /// from different CPUs.
    /// The caller must ensure that no two concurrent calls
    /// operate on the same bitmap byte range.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This table and bitmap describe pending private-memory units.
    /// - The target GPA range is valid for TDX acceptance.
    /// - No concurrent call touches the same bitmap bits (e.g., by holding a shard lock
    ///   that covers the target range).
    pub unsafe fn accept_range_concurrent(&self, start: u64, end: u64) -> Result<(), AcceptError> {
        if start >= end {
            return Ok(());
        }

        let (range_start, range_end, unit_size) =
            match self.clamp_gpa_range_to_bitmap_coverage(start, end)? {
                Some(vals) => vals,
                None => return Ok(()),
            };

        let (first_bit, last_bit) = self.addr_to_bit_range(range_start, range_end, unit_size)?;
        let phys_base = PhysAddr::new(self.phys_base);

        let bit_to_gpa_fn = |bit: BitIndex| -> Result<u64, AcceptError> {
            Ok(phys_base.checked_add_units(bit, unit_size)?.raw())
        };

        // SAFETY: Caller guarantees no concurrent access to overlapping bitmap bits;
        // bitmap_raw_parts_mut returns a valid pointer and length.
        let (bitmap_ptr, bitmap_len) = unsafe { self.bitmap_raw_parts_mut()? };
        let mut bitmap = unsafe { UnsyncBitmapMut::new(bitmap_ptr, bitmap_len) };

        let mut scan = first_bit;
        while let Some(run_start) = bitmap.find_next_set(scan, last_bit)? {
            let run_end = bitmap
                .find_next_zero(run_start, last_bit)?
                .unwrap_or(last_bit);

            let run_gpa_start = bit_to_gpa_fn(run_start)?;
            let run_gpa_end = bit_to_gpa_fn(run_end)?;

            // SAFETY: Caller guarantees bitmap/GPA validity for pending private pages.
            unsafe { accept_memory(run_gpa_start, run_gpa_end)? };
            bitmap.clear_range(run_start, run_end)?;
            scan = run_end;
        }

        Ok(())
    }

    /// Accepts a raw physical memory range via TDX TDCALL without touching
    /// the bitmap.
    ///
    /// This is intended for the second phase of the claim-then-accept pattern:
    /// after claiming (and clearing) bitmap bits under a shard lock, the caller
    /// drops the lock and calls this with interrupts enabled.
    ///
    /// # Safety
    ///
    /// The caller must ensure the GPA range is valid for TDX acceptance and
    /// that no other CPU is concurrently accepting the same range.
    pub unsafe fn accept_memory_raw(start: u64, end: u64) -> Result<(), AcceptError> {
        if start >= end {
            return Ok(());
        }
        // SAFETY: Caller guarantees the physical range is valid for TDX acceptance.
        unsafe { accept_memory(start, end) }
    }

    /// Finds the first contiguous run of set bits overlapping `[start, end)`,
    /// clears those bits, and returns the corresponding GPA range.
    ///
    /// This is the "claim" phase of the claim-then-accept pattern: the caller
    /// acquires a shard lock, calls this to atomically identify and clear one
    /// pending run, releases the lock, then performs the slow TDX accept with
    /// interrupts enabled.
    ///
    /// Returns `Ok(None)` when no pending bits remain in the range.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This table and bitmap reside in valid, writable memory.
    /// - No concurrent call touches the same bitmap bits (e.g., shard lock held).
    pub unsafe fn claim_next_pending_run(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Option<(u64, u64)>, AcceptError> {
        if start >= end {
            return Ok(None);
        }

        let (range_start, range_end, unit_size) =
            match self.clamp_gpa_range_to_bitmap_coverage(start, end)? {
                Some(vals) => vals,
                None => return Ok(None),
            };

        let (first_bit, last_bit) = self.addr_to_bit_range(range_start, range_end, unit_size)?;
        let phys_base = PhysAddr::new(self.phys_base);

        let bit_to_gpa_fn = |bit: BitIndex| -> Result<u64, AcceptError> {
            Ok(phys_base.checked_add_units(bit, unit_size)?.raw())
        };

        // SAFETY: Caller guarantees shard-level exclusivity;
        // bitmap_raw_parts_mut returns a valid pointer and length.
        let (bitmap_ptr, bitmap_len) = unsafe { self.bitmap_raw_parts_mut()? };
        let mut bitmap = unsafe { UnsyncBitmapMut::new(bitmap_ptr, bitmap_len) };

        let Some(run_start) = bitmap.find_next_set(first_bit, last_bit)? else {
            return Ok(None);
        };
        let run_end = bitmap
            .find_next_zero(run_start, last_bit)?
            .unwrap_or(last_bit);

        bitmap.clear_range(run_start, run_end)?;

        let gpa_start = bit_to_gpa_fn(run_start)?;
        let gpa_end = bit_to_gpa_fn(run_end)?;
        Ok(Some((gpa_start, gpa_end)))
    }

    /// Re-sets bitmap bits for a GPA range whose TDX accept failed.
    ///
    /// This is the rollback counterpart of [`Self::claim_next_pending_run`].
    /// After a claimed run fails to be accepted, the caller re-acquires the
    /// shard lock and calls this to restore the cleared bits so the range
    /// remains visible as unaccepted.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This table and bitmap reside in valid, writable memory.
    /// - No concurrent call touches the same bitmap bits (e.g., shard lock held).
    /// - The range was previously claimed (bits cleared) and not yet accepted.
    pub unsafe fn restore_pending_range(&self, start: u64, end: u64) -> Result<(), AcceptError> {
        if start >= end {
            return Ok(());
        }

        let (range_start, range_end, unit_size) =
            match self.clamp_gpa_range_to_bitmap_coverage(start, end)? {
                Some(vals) => vals,
                None => return Ok(()),
            };

        let (first_bit, last_bit) = self.addr_to_bit_range(range_start, range_end, unit_size)?;

        // SAFETY: Caller guarantees shard-level exclusivity;
        // bitmap_raw_parts_mut returns a valid pointer and length.
        let (bitmap_ptr, bitmap_len) = unsafe { self.bitmap_raw_parts_mut()? };
        let mut bitmap = unsafe { UnsyncBitmapMut::new(bitmap_ptr, bitmap_len) };

        bitmap.set_range(first_bit, last_bit)
    }

    /// Returns the end GPA (exclusive) covered by the bitmap.
    ///
    /// This is equivalent to `phys_base + total_coverage_size()`.
    pub fn bitmap_coverage_end(&self) -> Option<u64> {
        let base = PhysAddr::new(self.phys_base);
        Some(base.checked_add(self.total_coverage_size()?).ok()?.raw())
    }

    /// Returns an immutable slice view of the trailing bitmap payload.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this header is followed by at least
    /// `self.bitmap_size_bytes` readable bytes in memory.
    pub unsafe fn as_bitmap_slice(&self) -> Result<&[u8], AcceptError> {
        let bitmap_len = self.byte_len()?;
        let bitmap_ptr = core::ptr::from_ref(self)
            .cast::<u8>()
            .add(core::mem::size_of::<Self>());
        // SAFETY: `bitmap_ptr` points to the trailing bitmap bytes immediately
        // after `self`; `bitmap_len` is validated from `self.bitmap_size_bytes`;
        // caller guarantees readable backing memory for the returned slice.
        Ok(unsafe { core::slice::from_raw_parts(bitmap_ptr, bitmap_len) })
    }

    /// Returns a mutable slice view of the trailing bitmap payload.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this header is followed by at least
    /// `self.bitmap_size_bytes` writable bytes in memory, and that no aliased
    /// mutable reference exists while the returned slice is in use.
    pub unsafe fn as_bitmap_slice_mut(&mut self) -> Result<&mut [u8], AcceptError> {
        let bitmap_len = self.byte_len()?;
        let bitmap_ptr_mut = core::ptr::from_mut(self)
            .cast::<u8>()
            .add(core::mem::size_of::<Self>());
        // SAFETY: `bitmap_ptr_mut` points to the trailing bitmap bytes immediately
        // after `self`; `bitmap_len` is validated from `self.bitmap_size_bytes`;
        // caller guarantees writable backing memory and unique mutable access.
        Ok(unsafe { core::slice::from_raw_parts_mut(bitmap_ptr_mut, bitmap_len) })
    }

    /// Processes `start..end` by eagerly accepting required parts and deferring the rest in bitmap.
    ///
    /// This method applies a hybrid policy:
    /// - edge fragments that are not `unit_size`-aligned are accepted immediately;
    /// - aligned interior regions within bitmap coverage are marked as unaccepted bits;
    /// - aligned regions outside bitmap coverage are accepted immediately.
    ///
    /// # Safety
    ///
    /// The caller must ensure the range is valid guest-private memory in pending/acceptable state.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptError::InvalidAlignment`] for invalid unit configuration.
    /// Returns [`AcceptError::ArithmeticOverflow`] for address arithmetic overflow.
    /// Returns [`AcceptError::Overlap`] if the same bitmap unit is registered twice.
    /// Returns hardware-originated errors from `accept_memory`
    /// via [`AcceptError::TdCall`].
    pub unsafe fn register_range(&mut self, start: u64, end: u64) -> Result<(), AcceptError> {
        let table_phys_base = self.phys_base;
        let unit_size = self.validated_unit_size()?;
        if start >= end {
            return Ok(());
        }

        let unit_mask = unit_size - 1;

        if end - start < 2 * unit_size {
            // SAFETY: Caller guarantees the physical range is valid for TDX acceptance.
            return unsafe { Self::try_accept_range(start, end) };
        }

        let mut current_start = start;
        let mut current_end = end;

        if current_start & unit_mask != 0 {
            let Some(aligned_start) = align_up(current_start, unit_size) else {
                return Err(AcceptError::ArithmeticOverflow);
            };
            // SAFETY: Caller guarantees the physical subrange is valid for TDX acceptance.
            unsafe { Self::try_accept_range(current_start, aligned_start)? };
            current_start = aligned_start;
        }

        if current_end & unit_mask != 0 {
            let aligned_end = align_down(current_end, unit_size);
            // SAFETY: Caller guarantees the physical subrange is valid for TDX acceptance.
            unsafe { Self::try_accept_range(aligned_end, current_end)? };
            current_end = aligned_end;
        }

        let Some(bitmap_coverage) = self.total_coverage_size() else {
            return Err(AcceptError::ArithmeticOverflow);
        };

        let Some(bitmap_end) = table_phys_base.checked_add(bitmap_coverage) else {
            return Err(AcceptError::ArithmeticOverflow);
        };

        // 1) Process aligned range before bitmap coverage.
        if current_start < table_phys_base {
            let accept_end = current_end.min(table_phys_base);
            // SAFETY: Caller guarantees the physical subrange is valid for TDX acceptance.
            unsafe { Self::try_accept_range(current_start, accept_end)? };
            current_start = accept_end;
        }

        if current_start >= current_end {
            return Ok(());
        }

        // 2) Process aligned range within bitmap coverage.
        if current_start < bitmap_end {
            let bitmap_range_end = current_end.min(bitmap_end);
            if current_start < bitmap_range_end {
                // SAFETY: GPA range is unit-aligned and within bitmap coverage.
                unsafe {
                    self.mark_range_as_unaccepted(current_start, bitmap_range_end, unit_size)?
                };
            }
            current_start = bitmap_range_end;
        }

        // 3) Process aligned range after bitmap coverage.
        if current_start < current_end {
            // SAFETY: Caller guarantees the physical subrange is valid for TDX acceptance.
            unsafe { Self::try_accept_range(current_start, current_end)? };
        }

        Ok(())
    }

    /// Returns the total physical address range (in bytes) covered by the bitmap.
    ///
    /// Returns `None` if the computation overflows.
    pub fn total_coverage_size(&self) -> Option<u64> {
        let unit_size = u64::from(self.unit_size_bytes);
        self.bitmap_size_bytes
            .checked_mul(unit_size)?
            .checked_mul(8)
    }

    /// Conditionally accepts bitmap-marked units that overlap `start..end`.
    ///
    /// Returns [`AcceptOutcome::AlreadyAccepted`] when the range overlaps the
    /// bitmap but there are no pending bits to process.
    ///
    /// # Safety
    ///
    /// Same requirements as [`Self::accept_range`].
    unsafe fn accept_if_needed_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<AcceptOutcome, AcceptError> {
        if start >= end {
            return Ok(AcceptOutcome::AlreadyAccepted);
        }

        let (range_start, range_end, unit_size) =
            match self.clamp_gpa_range_to_bitmap_coverage(start, end)? {
                Some(vals) => vals,
                None => return Ok(AcceptOutcome::OutOfCoverage),
            };

        let (first_bit, last_bit) = self.addr_to_bit_range(range_start, range_end, unit_size)?;
        let phys_base = PhysAddr::new(self.phys_base);

        let bit_to_gpa_fn = |bit: BitIndex| -> Result<u64, AcceptError> {
            Ok(phys_base.checked_add_units(bit, unit_size)?.raw())
        };

        // SAFETY: Caller guarantees table/bitmap validity and exclusive mutable access.
        let mut bitmap = BitmapMut::new(unsafe { self.as_bitmap_slice_mut()? });
        let mut accepted_units = 0u64;

        let mut scan = first_bit;
        while let Some(run_start) = bitmap.find_next_set(scan, last_bit)? {
            let run_end = bitmap
                .find_next_zero(run_start, last_bit)?
                .unwrap_or(last_bit);

            let run_gpa_start = bit_to_gpa_fn(run_start)?;
            let run_gpa_end = bit_to_gpa_fn(run_end)?;

            // SAFETY: Caller guarantees bitmap/GPA mapping validity for pending private pages.
            unsafe { accept_memory(run_gpa_start, run_gpa_end)? };
            accepted_units = accepted_units
                .checked_add(run_end.raw() - run_start.raw())
                .ok_or(AcceptError::ArithmeticOverflow)?;

            bitmap.clear_range(run_start, run_end)?;

            scan = run_end;
        }

        match accepted_units {
            0 => Ok(AcceptOutcome::AlreadyAccepted),
            n => Ok(AcceptOutcome::AcceptedNow { accepted_units: n }),
        }
    }

    fn total_bits(&self) -> Result<u64, AcceptError> {
        self.bitmap_size_bytes
            .checked_mul(8)
            .ok_or(AcceptError::ArithmeticOverflow)
    }

    fn byte_len(&self) -> Result<usize, AcceptError> {
        usize::try_from(self.bitmap_size_bytes).map_err(|_| AcceptError::OutOfBounds)
    }

    fn validated_unit_size(&self) -> Result<u64, AcceptError> {
        let unit_size = u64::from(self.unit_size_bytes);
        if unit_size == 0 || !unit_size.is_power_of_two() {
            return Err(AcceptError::InvalidAlignment);
        }
        Ok(unit_size)
    }

    fn max_phys_addr_exclusive(&self, unit_size: u64) -> Result<u64, AcceptError> {
        let total_bits = self.total_bits()?;
        let coverage_len = total_bits
            .checked_mul(unit_size)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        self.phys_base
            .checked_add(coverage_len)
            .ok_or(AcceptError::ArithmeticOverflow)
    }

    fn clamp_gpa_range_to_bitmap_coverage(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Option<(u64, u64, u64)>, AcceptError> {
        if start >= end {
            return Ok(None);
        }

        let unit_size = self.validated_unit_size()?;
        let coverage_end = self.max_phys_addr_exclusive(unit_size)?;

        let range_start = start.max(self.phys_base);
        let range_end = end.min(coverage_end);
        if range_start >= range_end {
            return Ok(None);
        }

        Ok(Some((range_start, range_end, unit_size)))
    }

    fn addr_to_bit_range(
        &self,
        start: u64,
        end: u64,
        unit_size: u64,
    ) -> Result<(BitIndex, BitIndex), AcceptError> {
        debug_assert!(start >= self.phys_base);
        debug_assert!(start < end);
        debug_assert!(unit_size.is_power_of_two());

        let rel_start = start - self.phys_base;
        let rel_end = end - self.phys_base;

        let first_bit = rel_start / unit_size;
        // NOTE: last_bit is exclusive and uses ceil-div for overlap semantics.
        // Any unit intersecting [start, end) is considered.
        let last_bit = rel_end
            .checked_add(unit_size - 1)
            .ok_or(AcceptError::ArithmeticOverflow)?
            / unit_size;

        Ok((BitIndex::new(first_bit), BitIndex::new(last_bit)))
    }

    /// Marks unit-aligned bitmap-covered GPA range `start..end` as unaccepted bits.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `self` points to a valid unaccepted-memory table whose trailing bitmap memory is writable;
    /// - mutable access to `self`/bitmap is unique for the duration of this call (no aliasing);
    /// - `start..end` is unit-aligned for `unit_size` and corresponds to this table's
    ///   bitmap coverage semantics.
    unsafe fn mark_range_as_unaccepted(
        &mut self,
        start: u64,
        end: u64,
        unit_size: u64,
    ) -> Result<(), AcceptError> {
        if start >= end {
            return Ok(());
        }

        if start % unit_size != 0 || end % unit_size != 0 {
            return Err(AcceptError::InvalidAlignment);
        }

        let start_bit = BitIndex::new((start - self.phys_base) / unit_size);
        let end_bit = BitIndex::new((end - self.phys_base) / unit_size);
        let total_bits = BitIndex::new(self.total_bits()?);

        let clamped_start_bit = BitIndex::new(start_bit.raw().min(total_bits.raw()));
        let clamped_end_bit = BitIndex::new(end_bit.raw().min(total_bits.raw()));
        if clamped_start_bit >= clamped_end_bit {
            return Ok(());
        }

        // SAFETY: Caller guarantees bitmap memory is writable and uniquely accessible.
        let mut bitmap = BitmapMut::new(unsafe { self.as_bitmap_slice_mut()? });
        for bit in clamped_start_bit.raw()..clamped_end_bit.raw() {
            bitmap.set_bit(BitIndex::new(bit))?;
        }

        Ok(())
    }

    /// Accepts physical memory in `start..end` if the range is non-empty.
    ///
    /// # Safety
    ///
    /// The caller must ensure `start..end` is a valid GPA range for TDX acceptance,
    /// and that accepting this range does not race with other concurrent acceptance or
    /// access operations on the same memory.
    unsafe fn try_accept_range(start: u64, end: u64) -> Result<(), AcceptError> {
        if start >= end {
            return Ok(());
        }
        // SAFETY: Caller guarantees the physical range is valid for TDX acceptance.
        unsafe { accept_memory(start, end) }
    }

    /// Returns the raw mutable pointer and length of the trailing bitmap payload.
    ///
    /// This allows concurrent bitmap mutation through raw pointers when the caller
    /// guarantees that non-overlapping byte ranges are accessed.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - The returned pointer accesses valid, writable memory following this header.
    /// - Concurrent mutable accesses to overlapping bitmap bytes are prevented
    ///   (e.g., by holding a shard lock that covers the target byte range).
    unsafe fn bitmap_raw_parts_mut(&self) -> Result<(*mut u8, usize), AcceptError> {
        let bitmap_len = self.byte_len()?;
        let bitmap_ptr = core::ptr::from_ref(self)
            .cast::<u8>()
            .add(core::mem::size_of::<Self>()) as *mut u8;
        Ok((bitmap_ptr, bitmap_len))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PhysAddr(u64);

impl PhysAddr {
    const fn new(raw: u64) -> Self {
        Self(raw)
    }

    const fn raw(self) -> u64 {
        self.0
    }

    fn checked_add(self, bytes: u64) -> Result<Self, AcceptError> {
        self.0
            .checked_add(bytes)
            .map(Self)
            .ok_or(AcceptError::ArithmeticOverflow)
    }

    fn checked_add_units(self, bits: BitIndex, unit_size: u64) -> Result<Self, AcceptError> {
        let bytes = bits
            .raw()
            .checked_mul(unit_size)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        self.checked_add(bytes)
    }
}

fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

fn align_up(addr: u64, align: u64) -> Option<u64> {
    addr.checked_add(align - 1).map(|v| v & !(align - 1))
}

/// Result of a conditional accept operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptOutcome {
    /// The range overlaps bitmap coverage but no unit is pending (already accepted).
    AlreadyAccepted,
    /// At least one pending unit was accepted and the corresponding bitmap bits were cleared.
    AcceptedNow {
        /// Number of bitmap units accepted by this call.
        accepted_units: u64,
    },
    /// The range does not overlap bitmap coverage.
    OutOfCoverage,
}
