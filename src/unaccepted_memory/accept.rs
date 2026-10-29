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

struct AcceptanceState {
    table: &'static EfiUnacceptedMemory,
    shard_locks: [Mutex<()>; SHARD_COUNT],
    unaccepted_bytes: AtomicUsize,
}

static ACCEPTANCE_STATE: Once<AcceptanceState> = Once::new();

impl AcceptanceState {
    fn new(table: &'static EfiUnacceptedMemory) -> Self {
        let total_bytes =
            table.bitmap_ref().pending_unit_count() * u64::from(table.unit_size_bytes());
        Self {
            table,
            shard_locks: [const { Mutex::new(()) }; SHARD_COUNT],
            unaccepted_bytes: AtomicUsize::new(total_bytes as usize),
        }
    }

    fn unaccepted_bytes(&self) -> usize {
        self.unaccepted_bytes.load(Ordering::Relaxed)
    }

    fn ensure_accepted_with<G>(
        &self,
        range: Range<u64>,
        disable_local_irq: impl Fn() -> G,
        mut accept_unit: impl FnMut(Range<u64>) -> Result<(), AcceptError>,
    ) -> Result<(), AcceptError> {
        let Some((first_bit, last_bit, unit_size)) =
            self.table.overlapping_bit_range(range.start, range.end)
        else {
            return Ok(());
        };

        let bitmap = self.table.bitmap_ref();
        let phys_base = self.table.phys_base;
        let mut next_bit = first_bit;
        while let Some(unit_bit) = bitmap.find_next_set(next_bit, last_bit) {
            next_bit = unit_bit + 1;
            let shard_index = (unit_bit as usize) % SHARD_COUNT;
            let _irq_guard = disable_local_irq();
            // Reverse drop order releases the lock before restoring IRQs, even on errors.
            let _shard_guard = self.shard_locks[shard_index].lock();

            if !bitmap.is_bit_set(unit_bit) {
                continue;
            }

            let unit_start = Self::bit_to_gpa(phys_base, unit_bit, unit_size)?;
            let unit_end = Self::bit_to_gpa(phys_base, next_bit, unit_size)?;

            accept_unit(unit_start..unit_end)?;

            let cleared = bitmap.clear_bit(unit_bit);
            debug_assert!(cleared);
            self.unaccepted_bytes
                .fetch_sub(unit_size as usize, Ordering::Relaxed);
        }

        Ok(())
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

/// Initializes the global unaccepted-memory acceptance state with `table`.
///
/// Register the table before any calls to [`ensure_accepted`]. Once registered,
/// accept its pending units only through [`ensure_accepted`], not through
/// low-level acceptance APIs.
///
/// Subsequent calls are ignored once initialized.
pub fn init_acceptance_state(table: &'static EfiUnacceptedMemory) {
    ACCEPTANCE_STATE.call_once(|| AcceptanceState::new(table));
}

/// Returns a reference to the registered [`EfiUnacceptedMemory`] table, if initialized.
pub fn unaccepted_memory_table() -> Option<&'static EfiUnacceptedMemory> {
    ACCEPTANCE_STATE.get().map(|state| state.table)
}

/// Returns the number of bytes of physical memory still awaiting acceptance.
///
/// Returns zero if no table has been registered. This is a statistical snapshot,
/// not a synchronization barrier for concurrent acceptance.
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
/// Returns `Ok(())` without performing acceptance if no table has been registered,
/// the range is empty, or it does not overlap the table's coverage. This function
/// does not validate address mappings or accept memory outside that coverage.
///
/// # Errors
///
/// Returns an error if address calculation or TDX memory acceptance fails.
/// Previously completed units remain accepted; the failed unit remains pending
/// in the bitmap. The hardware may have accepted part of that unit; this progress
/// is not rolled back, and the whole unit remains counted as pending until a
/// later call completes it.
///
/// # Safety
///
/// The caller must ensure:
/// - The registered [`EfiUnacceptedMemory`] table accurately describes pending
///   guest-private memory units. If `range` may contain unaccepted memory, the
///   table must be registered before this call.
/// - Memory in `range` outside the table's coverage or with initially cleared
///   bitmap bits is already accepted.
/// - After registration, acceptance of the table's pending units goes exclusively
///   through this API, and accepted units never become unaccepted again.
/// - `disable_local_irq` disables local interrupts on the current CPU and returns a
///   guard that restores the previous interrupt state when dropped.
pub unsafe fn ensure_accepted<G>(
    range: Range<u64>,
    disable_local_irq: impl Fn() -> G,
) -> Result<(), AcceptError> {
    let Some(state) = ACCEPTANCE_STATE.get() else {
        return Ok(());
    };

    state.ensure_accepted_with(range, disable_local_irq, |unit| {
        // SAFETY: The caller guarantees the table describes pending private-memory
        // units and the IRQ callback disables local interrupts. The synchronization
        // core holds the shard lock and IRQ guard throughout this operation.
        unsafe { accept_memory(unit.start, unit.end) }
    })
}

#[cfg(test)]
mod tests;
