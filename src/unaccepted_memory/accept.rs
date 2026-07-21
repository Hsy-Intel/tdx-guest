// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Acceptance-path operations for unaccepted-memory bitmap ranges.
//!
//! This file contains range acceptance flows, plus pending-run claim/restore helpers.

use super::{bitmap::BitIndex, EfiUnacceptedMemory};
use crate::{accept_memory, AcceptError};

impl EfiUnacceptedMemory {
    /// Accepts bitmap-marked units that overlap `start..end`, then clears accepted bits.
    ///
    /// # Safety
    ///
    /// The caller must ensure this table and bitmap describe pending private-memory units,
    /// and the target GPA ranges are valid for TDX acceptance.
    pub unsafe fn accept_range(&self, start: u64, end: u64) -> Result<(), AcceptError> {
        let Some((first_bit, last_bit, unit_size)) = self.overlapping_bit_range(start, end) else {
            return Ok(());
        };

        let phys_base = self.phys_base;
        let bitmap = self.bitmap_ref();
        let mut scan = first_bit;
        while let Some(run_start) = bitmap.find_next_set(scan, last_bit) {
            let run_end = bitmap
                .find_next_zero(run_start, last_bit)
                .unwrap_or(last_bit);

            let run_gpa_start = Self::bit_to_gpa(phys_base, run_start, unit_size)?;
            let run_gpa_end = Self::bit_to_gpa(phys_base, run_end, unit_size)?;

            // SAFETY: Caller guarantees bitmap/GPA mapping validity for pending private pages.
            unsafe { accept_memory(run_gpa_start, run_gpa_end)? };
            bitmap.clear_range(run_start, run_end);

            scan = run_end;
        }

        Ok(())
    }

    /// Finds the first contiguous run of set bits overlapping `[start, end)`,
    /// clears those bits, and returns the corresponding GPA range.
    /// clears those bits, and returns the corresponding GPA range.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - No concurrent operation touches the same bitmap bits.
    pub unsafe fn claim_next_pending_run(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Option<(u64, u64)>, AcceptError> {
        let Some((first_bit, last_bit, unit_size)) = self.overlapping_bit_range(start, end) else {
            return Ok(None);
        };

        // SAFETY: Public concurrent API contract guarantees valid writable bitmap
        // payload and atomic-access discipline for overlapping ranges.
        let bitmap = self.bitmap_ref();
        let Some(run_start) = bitmap.find_next_set(first_bit, last_bit) else {
            return Ok(None);
        };
        let run_end = bitmap
            .find_next_zero(run_start, last_bit)
            .unwrap_or(last_bit);

        bitmap.clear_range(run_start, run_end);

        let gpa_start = Self::bit_to_gpa(self.phys_base, run_start, unit_size)?;
        let gpa_end = Self::bit_to_gpa(self.phys_base, run_end, unit_size)?;
        Ok(Some((gpa_start, gpa_end)))
    }

    /// Re-sets bitmap bits for a GPA range whose TDX accept failed.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - No concurrent operation touches the same bitmap bits.
    /// - `start..end` is exactly a unit-aligned range previously returned by
    ///   [`Self::claim_next_pending_run`] and has not been accepted or restored.
    pub unsafe fn restore_pending_range(&self, start: u64, end: u64) {
        let Some((first_bit, last_bit, _unit_size)) = self.overlapping_bit_range(start, end) else {
            return;
        };

        // SAFETY: Public concurrent API contract guarantees valid writable bitmap
        // payload and atomic-access discipline for overlapping ranges.
        let bitmap = self.bitmap_ref();
        bitmap.set_range(first_bit, last_bit);
    }

    fn bit_to_gpa(phys_base: u64, bit: BitIndex, unit_size: u64) -> Result<u64, AcceptError> {
        let offset = bit
            .checked_mul(unit_size)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        phys_base
            .checked_add(offset)
            .ok_or(AcceptError::ArithmeticOverflow)
    }
}
