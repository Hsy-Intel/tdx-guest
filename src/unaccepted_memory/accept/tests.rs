// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

use core::{cell::Cell, mem::size_of, ptr::NonNull};
use std::{
    sync::mpsc::{self, TryRecvError},
    thread,
    time::Duration,
};

use super::*;
use crate::unaccepted_memory::EFI_UNACCEPTED_UNIT_SIZE;

const UNIT_SIZE: u64 = EFI_UNACCEPTED_UNIT_SIZE;
const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

fn new_state(pending_units: u64) -> AcceptanceState {
    let coverage = UNIT_SIZE..(pending_units.max(1) + 1) * UNIT_SIZE;
    let size = EfiUnacceptedMemory::required_size_for_range(coverage.clone()).unwrap();
    let words = Box::leak(vec![0u64; size.div_ceil(size_of::<u64>())].into_boxed_slice());
    let table_addr = NonNull::new(words.as_mut_ptr().cast::<u8>()).unwrap();

    // SAFETY: The leaked allocation is aligned, large enough, and exclusively
    // accessed through the table from this point on.
    let table = unsafe { EfiUnacceptedMemory::builder(table_addr, size, coverage) }
        .unwrap()
        .build()
        .into_ref()
        .get_ref();
    // Simulate pending units without executing TDCALL during test setup.
    table.bitmap_ref().set_range(0, pending_units);
    AcceptanceState::new(table)
}

fn unit_range(bit: u64) -> Range<u64> {
    (bit + 1) * UNIT_SIZE..(bit + 2) * UNIT_SIZE
}

struct TestIrqGuard<'a> {
    state: &'a AcceptanceState,
    disabled: &'a Cell<bool>,
    drops: &'a Cell<usize>,
}

impl<'a> TestIrqGuard<'a> {
    fn new(state: &'a AcceptanceState, disabled: &'a Cell<bool>, drops: &'a Cell<usize>) -> Self {
        assert!(!disabled.replace(true));
        assert!(state
            .shard_locks
            .iter()
            .all(|lock| lock.try_lock().is_some()));
        Self {
            state,
            disabled,
            drops,
        }
    }
}

impl Drop for TestIrqGuard<'_> {
    fn drop(&mut self) {
        assert!(self
            .state
            .shard_locks
            .iter()
            .all(|lock| lock.try_lock().is_some()));
        assert!(self.disabled.replace(false));
        self.drops.set(self.drops.get() + 1);
    }
}

#[test]
fn accepts_whole_units_before_publishing_completion() {
    let state = new_state(3);
    let disabled = Cell::new(false);
    let drops = Cell::new(0);
    let mut accepted_units = vec![];
    state
        .ensure_accepted_with(
            UNIT_SIZE + 4096..3 * UNIT_SIZE - 4096,
            || TestIrqGuard::new(&state, &disabled, &drops),
            |unit| {
                let bit = (unit.start - UNIT_SIZE) / UNIT_SIZE;
                assert!(disabled.get());
                assert!(state.shard_locks[bit as usize % SHARD_COUNT]
                    .try_lock()
                    .is_none());
                assert!(state.table.bitmap_ref().is_bit_set(bit));
                assert_eq!(
                    state.unaccepted_bytes(),
                    (3 - accepted_units.len()) * UNIT_SIZE as usize
                );
                accepted_units.push(unit);
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(accepted_units, vec![unit_range(0), unit_range(1)]);
    assert_eq!(drops.get(), 2);
    assert!(!disabled.get());
    assert_eq!(state.unaccepted_bytes(), UNIT_SIZE as usize);
    assert_eq!(state.table.bitmap_ref().find_next_set(0, 2), None);

    state
        .ensure_accepted_with(
            UNIT_SIZE..3 * UNIT_SIZE,
            || panic!("accepted units must not disable interrupts"),
            |_| panic!("accepted units must not be accepted again"),
        )
        .unwrap();
}

#[test]
fn errors_preserve_pending_units_and_release_guards() {
    let state = new_state(3);
    let disabled = Cell::new(false);
    let drops = Cell::new(0);
    let mut attempted_units = vec![];
    let result = state.ensure_accepted_with(
        UNIT_SIZE..4 * UNIT_SIZE,
        || TestIrqGuard::new(&state, &disabled, &drops),
        |unit| {
            assert!(disabled.get());
            attempted_units.push(unit);
            if attempted_units.len() == 2 {
                return Err(AcceptError::InvalidAlignment);
            }
            Ok(())
        },
    );

    assert!(matches!(result, Err(AcceptError::InvalidAlignment)));
    assert_eq!(attempted_units, vec![unit_range(0), unit_range(1)]);
    assert_eq!(drops.get(), 2);
    assert!(!disabled.get());
    assert!(!state.table.bitmap_ref().is_bit_set(0));
    assert!(state.table.bitmap_ref().is_bit_set(1));
    assert!(state.table.bitmap_ref().is_bit_set(2));
    assert_eq!(state.unaccepted_bytes(), 2 * UNIT_SIZE as usize);
}

#[test]
fn rechecks_after_another_caller_accepts_the_unit() {
    let state = new_state(2);
    let disabled = Cell::new(false);
    let drops = Cell::new(0);
    let mut accepted_units = vec![];
    state
        .ensure_accepted_with(
            UNIT_SIZE..3 * UNIT_SIZE,
            || {
                // Complete the selected unit after the scan but before locking.
                if drops.get() == 0 {
                    state
                        .ensure_accepted_with(unit_range(0), || (), |_| Ok(()))
                        .unwrap();
                }
                TestIrqGuard::new(&state, &disabled, &drops)
            },
            |unit| {
                assert!(disabled.get());
                accepted_units.push(unit);
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(accepted_units.as_slice(), &[unit_range(1)]);
    assert_eq!(drops.get(), 2);
    assert!(!disabled.get());
    assert_eq!(state.unaccepted_bytes(), 0);
}

#[test]
fn overlapping_callers_wait_for_acceptance() {
    let state = new_state(2);
    let state = &state;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (waiting_tx, waiting_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();

    thread::scope(|scope| {
        scope.spawn(move || {
            state
                .ensure_accepted_with(
                    unit_range(0),
                    || (),
                    |_| {
                        started_tx.send(()).unwrap();
                        release_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
                        Ok(())
                    },
                )
                .unwrap();
        });
        started_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
        assert!(state.table.bitmap_ref().is_bit_set(0));
        assert_eq!(state.unaccepted_bytes(), 2 * UNIT_SIZE as usize);

        scope.spawn(move || {
            state
                .ensure_accepted_with(
                    unit_range(0),
                    || waiting_tx.send(()).unwrap(),
                    |_| panic!("the same unit must not be accepted twice"),
                )
                .unwrap();
            finished_tx.send(()).unwrap();
        });
        waiting_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
        assert!(matches!(finished_rx.try_recv(), Err(TryRecvError::Empty)));
        release_tx.send(()).unwrap();
        finished_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
    });

    assert!(!state.table.bitmap_ref().is_bit_set(0));
    assert_eq!(state.unaccepted_bytes(), UNIT_SIZE as usize);
}

#[test]
fn different_shards_accept_concurrently() {
    let state = new_state(2);
    let state = &state;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_first_tx, release_first_rx) = mpsc::channel();
    let (release_second_tx, release_second_rx) = mpsc::channel();

    thread::scope(|scope| {
        for (bit, release_rx) in [(0, release_first_rx), (1, release_second_rx)] {
            let started_tx = started_tx.clone();
            scope.spawn(move || {
                state
                    .ensure_accepted_with(
                        unit_range(bit),
                        || (),
                        |_| {
                            started_tx.send(bit).unwrap();
                            release_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
                            Ok(())
                        },
                    )
                    .unwrap();
            });
        }
        let first = started_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
        let second = started_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
        assert_ne!(first, second);
        assert_eq!(state.unaccepted_bytes(), 2 * UNIT_SIZE as usize);
        assert_eq!(state.table.bitmap_ref().pending_unit_count(), 2);
        release_first_tx.send(()).unwrap();
        release_second_tx.send(()).unwrap();
    });

    assert_eq!(state.unaccepted_bytes(), 0);
    assert_eq!(state.table.bitmap_ref().pending_unit_count(), 0);
}

#[test]
fn empty_and_uncovered_ranges_do_not_disable_interrupts() {
    let state = new_state(2);
    let coverage_end = state.table.coverage_range().end;
    for range in [UNIT_SIZE..UNIT_SIZE, 0..UNIT_SIZE, coverage_end..u64::MAX] {
        state
            .ensure_accepted_with(
                range,
                || panic!("no pending units overlap the range"),
                |_| panic!("no units should be accepted"),
            )
            .unwrap();
    }
    assert_eq!(state.unaccepted_bytes(), 2 * UNIT_SIZE as usize);

    let state = new_state(0);
    state
        .ensure_accepted_with(
            unit_range(0),
            || panic!("an empty bitmap must not disable interrupts"),
            |_| panic!("no units should be accepted"),
        )
        .unwrap();
    assert_eq!(state.unaccepted_bytes(), 0);
}

#[test]
fn accepts_units_across_bitmap_words() {
    let state = new_state(65);
    let mut accepted_units = vec![];
    state
        .ensure_accepted_with(
            unit_range(63).start..unit_range(64).end,
            || (),
            |unit| {
                accepted_units.push(unit);
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(accepted_units, vec![unit_range(63), unit_range(64)]);
    assert_eq!(state.unaccepted_bytes(), 63 * UNIT_SIZE as usize);
    assert_eq!(state.table.bitmap_ref().pending_unit_count(), 63);
}
