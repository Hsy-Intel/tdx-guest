// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Read-only query APIs for unaccepted-memory status.
//!
//! This file implements pending-state checks over GPA ranges using
//! lock-free atomic-word reads backed by [`BitmapRef`].

use super::EfiUnacceptedMemory;

impl EfiUnacceptedMemory {
    /// Returns the number of pending (set) bitmap units in the whole table.
    pub fn pending_unit_count(&self) -> u64 {
        self.bitmap_ref().pending_unit_count()
    }

    /// Checks whether `[start, end)` overlaps any pending (unaccepted) bitmap unit.
    pub fn is_range_pending(&self, start: u64, end: u64) -> bool {
        let Some((first_bit, last_bit, _unit_size)) = self.overlapping_bit_range(start, end) else {
            return false;
        };
        self.bitmap_ref().has_set_bit(first_bit, last_bit)
    }

    /// Returns `true` if all bitmap units overlapping `[start, end)` have been accepted.
    pub fn is_fully_accepted(&self, start: u64, end: u64) -> bool {
        !self.is_range_pending(start, end)
    }
}
