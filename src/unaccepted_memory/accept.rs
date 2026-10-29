// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Acceptance-path operations for unaccepted-memory bitmap ranges.
//!
//! This file contains range acceptance flows and synchronized on-demand
//! acceptance state management.

use core::{
    ops::Range,
    sync::atomic::{AtomicUsize, Ordering},
};

use spin::{Mutex, Once};

use super::{bitmap::BitIndex, EfiUnacceptedMemory};
use crate::{accept_memory, AcceptError};

const SHARD_COUNT: usize = 64;

pub(super) struct AcceptanceState {
    table: &'static EfiUnacceptedMemory,
    shard_locks: [Mutex<()>; SHARD_COUNT],
    unaccepted_bytes: AtomicUsize,
}

static ACCEPTANCE_STATE: Once<AcceptanceState> = Once::new();

impl AcceptanceState {
    pub(super) fn new(table: &'static EfiUnacceptedMemory) -> Self {
        let total_bytes = table.pending_unit_count() * u64::from(table.unit_size_bytes());
        Self {
            table,
            shard_locks: [const { Mutex::new(()) }; SHARD_COUNT],
            unaccepted_bytes: AtomicUsize::new(total_bytes as usize),
        }
    }

    pub(super) fn table(&self) -> &'static EfiUnacceptedMemory {
        self.table
    }

    pub(super) fn unaccepted_bytes(&self) -> usize {
        self.unaccepted_bytes.load(Ordering::Relaxed)
    }

    pub(super) unsafe fn ensure_accepted<G>(
        &self,
        range: Range<u64>,
        disable_local_irq: impl Fn() -> G,
    ) -> Result<(), AcceptError> {
        self.ensure_accepted_with(range, disable_local_irq, |unit_start, unit_end| {
            // SAFETY: The caller guarantees the table and bitmap describe pending
            // private-memory units, and the shard lock + disabled local IRQs ensure
            // exclusive acceptance of this unit.
            unsafe { accept_memory(unit_start, unit_end) }
        })
    }

    pub(super) fn ensure_accepted_with<G>(
        &self,
        range: Range<u64>,
        disable_local_irq: impl Fn() -> G,
        mut accept_unit: impl FnMut(u64, u64) -> Result<(), AcceptError>,
    ) -> Result<(), AcceptError> {
        let Some((first_bit, last_bit, unit_size)) =
            self.table.overlapping_bit_range(range.start, range.end)
        else {
            return Ok(());
        };

        let bitmap = self.table.bitmap_ref();
        if !bitmap.has_set_bit(first_bit, last_bit) {
            return Ok(());
        }

        let phys_base = self.table.phys_base;
        let mut bit = first_bit;
        while let Some(unit_bit) = bitmap.find_next_set(bit, last_bit) {
            let shard_index = (unit_bit as usize) % SHARD_COUNT;
            let _irq_guard = disable_local_irq();
            let shard_guard = self.shard_locks[shard_index].lock();

            if bitmap.is_bit_set(unit_bit) {
                let unit_start = EfiUnacceptedMemory::bit_to_gpa(phys_base, unit_bit, unit_size)?;
                let unit_end = EfiUnacceptedMemory::bit_to_gpa(phys_base, unit_bit + 1, unit_size)?;

                accept_unit(unit_start, unit_end)?;

                let cleared = bitmap.clear_bit(unit_bit);
                debug_assert!(cleared);
                self.unaccepted_bytes
                    .fetch_sub(unit_size as usize, Ordering::Relaxed);
            }

            drop(shard_guard);
            drop(_irq_guard);
            bit = unit_bit + 1;
        }

        Ok(())
    }
}

/// Initializes the global unaccepted-memory acceptance state with `table`.
///
/// Subsequent calls are ignored once initialized.
pub fn init_acceptance_state(table: &'static EfiUnacceptedMemory) {
    ACCEPTANCE_STATE.call_once(|| AcceptanceState::new(table));
}

/// Returns a reference to the registered [`EfiUnacceptedMemory`] table, if initialized.
pub fn unaccepted_memory_table() -> Option<&'static EfiUnacceptedMemory> {
    ACCEPTANCE_STATE.get().map(AcceptanceState::table)
}

/// Returns the number of bytes of physical memory still awaiting acceptance.
pub fn unaccepted_bytes() -> usize {
    ACCEPTANCE_STATE
        .get()
        .map_or(0, AcceptanceState::unaccepted_bytes)
}

/// Ensures that all unaccepted-memory units overlapping `range` have been accepted.
///
/// When this function returns `Ok(())`, every bitmap unit overlapping `range` is
/// guaranteed to have completed TDX memory acceptance.
///
/// # Safety
///
/// The caller must ensure:
/// - The registered [`EfiUnacceptedMemory`] table accurately describes pending
///   guest-private memory units.
/// - `disable_local_irq` disables local interrupts on the current CPU and returns a
///   guard that restores the previous interrupt state when dropped.
pub unsafe fn ensure_accepted<G>(
    range: Range<u64>,
    disable_local_irq: impl Fn() -> G,
) -> Result<(), AcceptError> {
    let Some(state) = ACCEPTANCE_STATE.get() else {
        return Ok(());
    };

    // SAFETY: Forwarded from the caller's safety contract.
    unsafe { state.ensure_accepted(range, disable_local_irq) }
}

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

    pub(super) fn bit_to_gpa(
        phys_base: u64,
        bit: BitIndex,
        unit_size: u64,
    ) -> Result<u64, AcceptError> {
        let offset = bit
            .checked_mul(unit_size)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        phys_base
            .checked_add(offset)
            .ok_or(AcceptError::ArithmeticOverflow)
    }
}
