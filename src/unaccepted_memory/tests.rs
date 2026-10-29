// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

use alloc::vec;
use core::{mem::size_of, ptr::NonNull, sync::atomic::AtomicU64};

#[cfg(test)]
use super::accept::AcceptanceState;
use super::*;
use crate::AcceptError;

#[test]
#[allow(clippy::reversed_empty_ranges, clippy::single_range_in_vec_init)]
fn test_required_size() {
    assert!(matches!(
        EfiUnacceptedMemory::required_size(&[]),
        Err(AcceptError::OutOfBounds)
    ));

    let inverted = Range {
        start: 100,
        end: 50,
    };
    assert!(matches!(
        EfiUnacceptedMemory::required_size(core::slice::from_ref(&inverted)),
        Err(AcceptError::OutOfBounds)
    ));

    // 2 MiB to 6 MiB is 4 MiB = 2 units. 2 bits fit in 1 u64 (8 bytes).
    let range = 0x200_000..0x600_000;
    let size = EfiUnacceptedMemory::required_size(core::slice::from_ref(&range)).unwrap();
    assert_eq!(size, size_of::<EfiUnacceptedMemory>() + 8);
}

#[test]
fn test_new_and_type_invariants() {
    let range = 0x200_000..0x600_000;
    let required_size = EfiUnacceptedMemory::required_size(core::slice::from_ref(&range)).unwrap();

    let mut buf = vec![0u8; required_size + 16];
    // Ensure 8-byte alignment
    let align_offset = buf
        .as_ptr()
        .align_offset(core::mem::align_of::<AtomicU64>());
    let aligned_slice = &mut buf[align_offset..align_offset + required_size];
    let table_addr = NonNull::new(aligned_slice.as_mut_ptr()).unwrap();

    let table = unsafe {
        EfiUnacceptedMemory::new(
            table_addr,
            aligned_slice.len(),
            core::slice::from_ref(&range),
        )
        .unwrap()
    };

    assert_eq!(table.version(), LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION);
    assert_eq!(table.unit_size_bytes(), EFI_UNACCEPTED_UNIT_SIZE as u32);
    assert_eq!(table.phys_base(), 0x200_000);
    assert_eq!(table.bitmap_size_bytes(), 8);
    assert_eq!(table.coverage_range(), 0x200_000..0x8_200_000); // 8 bytes * 8 bits = 64 bits * 2 MiB = 128 MiB
    assert_eq!(table.coverage_size(), 128 * 1024 * 1024);

    // Both units in [0x200_000, 0x600_000) are pending
    assert_eq!(table.pending_unit_count(), 2);
    assert!(table.is_range_pending(0x200_000, 0x600_000));
    assert!(!table.is_fully_accepted(0x200_000, 0x600_000));

    // Range outside coverage or without pending bits
    assert!(!table.is_range_pending(0x600_000, 0x800_000));
    assert!(table.is_fully_accepted(0x600_000, 0x800_000));

    // Clear unit 0 via bitmap_ref
    table.bitmap_ref().clear_range(0, 1);
    assert_eq!(table.pending_unit_count(), 1);
    assert!(!table.is_range_pending(0x200_000, 0x400_000));
    assert!(table.is_range_pending(0x400_000, 0x600_000));

    // Clear all
    table.bitmap_ref().clear_all();
    assert_eq!(table.pending_unit_count(), 0);
    assert!(!table.is_range_pending(0x200_000, 0x600_000));
    assert!(table.is_fully_accepted(0x200_000, 0x600_000));
}

#[test]
fn test_builder_incremental() {
    let coverage = 0x200_000..0x800_000;
    let required_size = EfiUnacceptedMemory::required_size_for_range(coverage.clone()).unwrap();
    let mut buf = vec![0u8; required_size + 16];

    let align_offset = buf
        .as_ptr()
        .align_offset(core::mem::align_of::<AtomicU64>());
    let aligned_slice = &mut buf[align_offset..align_offset + required_size];
    let table_addr = NonNull::new(aligned_slice.as_mut_ptr()).unwrap();

    let mut builder =
        unsafe { EfiUnacceptedMemory::builder(table_addr, aligned_slice.len(), coverage).unwrap() };

    // Register a range of at least 2 * unit_size (>= 4 MiB) to avoid eager accept in unit test
    unsafe {
        builder.register_range(0x200_000, 0x600_000).unwrap();
    }

    let table = builder.build();
    assert_eq!(table.pending_unit_count(), 2);
    assert!(table.is_range_pending(0x200_000, 0x600_000));
    assert!(!table.is_range_pending(0x600_000, 0x800_000));
}

#[test]
fn test_new_invalid_inputs() {
    let range = 0x200_000..0x600_000;
    let required_size = EfiUnacceptedMemory::required_size(core::slice::from_ref(&range)).unwrap();
    let mut buf = vec![0u8; required_size + 16];

    let align_offset = buf
        .as_ptr()
        .align_offset(core::mem::align_of::<AtomicU64>());
    let aligned_slice = &mut buf[align_offset..align_offset + required_size];

    // Too small allocation
    let table_addr = NonNull::new(aligned_slice.as_mut_ptr()).unwrap();
    let res = unsafe {
        EfiUnacceptedMemory::new(table_addr, required_size - 1, core::slice::from_ref(&range))
    };
    assert!(matches!(res, Err(AcceptError::OutOfBounds)));

    // Misaligned pointer
    let unaligned_addr = NonNull::new(unsafe { aligned_slice.as_mut_ptr().add(1) }).unwrap();
    let res = unsafe {
        EfiUnacceptedMemory::new(unaligned_addr, required_size, core::slice::from_ref(&range))
    };
    assert!(matches!(res, Err(AcceptError::InvalidAlignment)));
}

#[test]
fn test_bitmap_word_boundaries() {
    let words = [const { AtomicU64::new(0) }; 4]; // 256 bits
    let ptr = words.as_ptr().cast::<u8>();
    let bitmap = unsafe { BitmapRef::from_raw(ptr, words.len() * 8) };

    assert_eq!(bitmap.capacity(), 256);
    assert!(!bitmap.has_set_bit(0, 256));
    assert_eq!(bitmap.find_next_set(0, 256), None);

    // Set a range spanning word 0 and word 1 (e.g. bits 60..70)
    bitmap.set_range(60, 70);
    assert!(bitmap.has_set_bit(60, 70));
    assert!(bitmap.has_set_bit(0, 65));
    assert!(!bitmap.has_set_bit(0, 60));
    assert!(!bitmap.has_set_bit(70, 256));
    assert_eq!(bitmap.find_next_set(0, 256), Some(60));
    assert_eq!(bitmap.find_next_zero(60, 256), Some(70));
    assert_eq!(bitmap.pending_unit_count(), 10);

    // Check underlying raw word values
    // Bits 60..64 in word 0 are 0xF000_0000_0000_0000
    assert_eq!(
        bitmap.words()[0].load(core::sync::atomic::Ordering::Relaxed),
        0xF000_0000_0000_0000
    );
    // Bits 64..70 (bits 0..6 of word 1) are 0x3F
    assert_eq!(
        bitmap.words()[1].load(core::sync::atomic::Ordering::Relaxed),
        0x3F
    );

    // Clear spanning range
    bitmap.clear_range(62, 68);
    assert_eq!(bitmap.pending_unit_count(), 4); // 60, 61 and 68, 69
    assert_eq!(bitmap.find_next_set(0, 256), Some(60));
    assert_eq!(bitmap.find_next_set(62, 256), Some(68));
    assert_eq!(bitmap.find_next_set(70, 256), None);

    assert!(bitmap.is_bit_set(60));
    assert!(bitmap.clear_bit(60));
    assert!(!bitmap.is_bit_set(60));
    assert!(!bitmap.clear_bit(60));
}

#[test]
fn test_acceptance_state_ensure_accepted() {
    use alloc::boxed::Box;
    use core::cell::Cell;

    let coverage = 0x200_000..0xa00_000;
    let required_size = EfiUnacceptedMemory::required_size_for_range(coverage.clone()).unwrap();
    let aligned_words = required_size.div_ceil(8);
    let leaked_words: &'static mut [u64] = Box::leak(vec![0u64; aligned_words].into_boxed_slice());
    let table_addr = NonNull::new(leaked_words.as_mut_ptr().cast::<u8>()).unwrap();

    let mut builder =
        unsafe { EfiUnacceptedMemory::builder(table_addr, required_size, coverage).unwrap() };
    unsafe {
        builder.register_range(0x200_000, 0x800_000).unwrap();
    }
    let table: &'static EfiUnacceptedMemory = builder.build().into_ref().get_ref();

    let state = AcceptanceState::new(table);
    assert_eq!(
        state.unaccepted_bytes(),
        3 * EFI_UNACCEPTED_UNIT_SIZE as usize
    );

    let irq_disables = Cell::new(0usize);
    let irq_drops = Cell::new(0usize);
    struct TestGuard<'a>(&'a Cell<usize>);
    impl Drop for TestGuard<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    let mut accepted_units = vec![];
    state
        .ensure_accepted_with(
            0x201_000..0x5ff_000,
            || {
                irq_disables.set(irq_disables.get() + 1);
                TestGuard(&irq_drops)
            },
            |start, end| {
                accepted_units.push(start..end);
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(
        accepted_units,
        vec![0x200_000..0x400_000, 0x400_000..0x600_000]
    );
    assert_eq!(irq_disables.get(), 2);
    assert_eq!(irq_drops.get(), 2);
    assert_eq!(state.unaccepted_bytes(), EFI_UNACCEPTED_UNIT_SIZE as usize);

    // Re-running on an already accepted subrange hits the lock-free fast path.
    state
        .ensure_accepted_with(
            0x200_000..0x600_000,
            || {
                irq_disables.set(irq_disables.get() + 1);
                TestGuard(&irq_drops)
            },
            |_, _| panic!("should not re-accept"),
        )
        .unwrap();
    assert_eq!(irq_disables.get(), 2);
}
