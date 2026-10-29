// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

use alloc::{boxed::Box, vec};
use core::{
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    bitmap::BitmapRef, EfiUnacceptedMemory, EFI_UNACCEPTED_UNIT_SIZE,
    LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION,
};
use crate::AcceptError;

fn allocate_table_buffer(size: usize) -> NonNull<u8> {
    let words = Box::leak(vec![0u64; size.div_ceil(size_of::<u64>())].into_boxed_slice());
    NonNull::new(words.as_mut_ptr().cast()).unwrap()
}

#[test]
fn test_required_size_for_range() {
    assert!(matches!(
        EfiUnacceptedMemory::required_size_for_range(0..0),
        Err(AcceptError::OutOfBounds)
    ));

    let inverted = core::ops::Range {
        start: 100,
        end: 50,
    };
    assert!(matches!(
        EfiUnacceptedMemory::required_size_for_range(inverted),
        Err(AcceptError::OutOfBounds)
    ));
    assert!(matches!(
        EfiUnacceptedMemory::required_size_for_range(0..u64::MAX),
        Err(AcceptError::ArithmeticOverflow)
    ));

    // 2 MiB to 6 MiB is 4 MiB = 2 units. 2 bits fit in 1 u64 (8 bytes).
    let size = EfiUnacceptedMemory::required_size_for_range(0x200_000..0x600_000).unwrap();
    assert_eq!(size, size_of::<EfiUnacceptedMemory>() + 8);
}

#[test]
fn test_builder_type_invariants() {
    let coverage = 0x200_000..0x600_000;
    let required_size = EfiUnacceptedMemory::required_size_for_range(coverage.clone()).unwrap();
    let table_addr = allocate_table_buffer(required_size);

    // SAFETY: The allocation is aligned, sufficiently large, and leaked. Only the
    // builder and the resulting table access it.
    let table = unsafe { EfiUnacceptedMemory::builder(table_addr, required_size, coverage) }
        .unwrap()
        .build();

    let version = table.version;
    assert_eq!(version, LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION);
    assert_eq!(table.unit_size_bytes(), EFI_UNACCEPTED_UNIT_SIZE as u32);
    assert_eq!(table.bitmap_size_bytes(), 8);
    assert_eq!(table.coverage_range(), 0x200_000..0x8_200_000); // 8 bytes * 8 bits = 64 bits * 2 MiB = 128 MiB
    assert_eq!(table.bitmap_ref().pending_unit_count(), 0);
}

#[test]
fn test_builder_incremental() {
    let coverage = 0x200_000..0xe00_000;
    let required_size = EfiUnacceptedMemory::required_size_for_range(coverage.clone()).unwrap();
    let table_addr = allocate_table_buffer(required_size);

    // SAFETY: The allocation is aligned, sufficiently large, and leaked. Only the
    // builder and the resulting table access it.
    let mut builder =
        unsafe { EfiUnacceptedMemory::builder(table_addr, required_size, coverage).unwrap() };

    // These aligned two-unit ranges only update the bitmap, without executing TDCALL.
    unsafe {
        builder.register_range(0x200_000, 0x600_000).unwrap();
        builder.register_range(0xa00_000, 0xe00_000).unwrap();
        assert!(matches!(
            builder.register_range(0x200_000, 0x600_000),
            Err(AcceptError::Overlap)
        ));
    }

    let table = builder.build();
    let bitmap = table.bitmap_ref();
    assert_eq!(bitmap.pending_unit_count(), 4);
    assert!(bitmap.is_bit_set(0));
    assert!(bitmap.is_bit_set(1));
    assert!(!bitmap.is_bit_set(2));
    assert!(!bitmap.is_bit_set(3));
    assert!(bitmap.is_bit_set(4));
    assert!(bitmap.is_bit_set(5));
}

#[test]
fn test_builder_invalid_inputs() {
    let coverage = 0x200_000..0x600_000;
    let required_size = EfiUnacceptedMemory::required_size_for_range(coverage.clone()).unwrap();
    let table_addr = allocate_table_buffer(required_size + 1);

    // The builder rejects the undersized buffer before initializing the table.
    let res =
        unsafe { EfiUnacceptedMemory::builder(table_addr, required_size - 1, coverage.clone()) };
    assert!(matches!(res, Err(AcceptError::OutOfBounds)));

    // The builder also rejects misalignment before touching the allocation.
    let unaligned_addr = NonNull::new(table_addr.as_ptr().wrapping_add(1)).unwrap();
    let res = unsafe { EfiUnacceptedMemory::builder(unaligned_addr, required_size, coverage) };
    assert!(matches!(res, Err(AcceptError::InvalidAlignment)));
}

#[test]
fn test_bitmap_word_boundaries() {
    let words = [const { AtomicU64::new(0) }; 4]; // 256 bits
    let ptr = words.as_ptr().cast::<u8>();
    // SAFETY: `words` is an aligned array of initialized atomic words and outlives the view.
    let bitmap = unsafe { BitmapRef::from_raw(ptr, words.len() * 8) };

    assert_eq!(bitmap.capacity(), 256);
    assert_eq!(bitmap.find_next_set(0, 256), None);

    // Set a range spanning word 0 and word 1 (e.g. bits 60..70)
    bitmap.set_range(60, 70);
    assert_eq!(bitmap.find_next_set(60, 70), Some(60));
    assert_eq!(bitmap.find_next_set(0, 65), Some(60));
    assert_eq!(bitmap.find_next_set(0, 60), None);
    assert_eq!(bitmap.find_next_set(70, 256), None);
    assert_eq!(bitmap.find_next_set(0, 256), Some(60));
    assert_eq!(bitmap.pending_unit_count(), 10);

    // Check underlying raw word values
    // Bits 60..64 in word 0 are 0xF000_0000_0000_0000
    assert_eq!(words[0].load(Ordering::Relaxed), 0xF000_0000_0000_0000);
    // Bits 64..70 (bits 0..6 of word 1) are 0x3F
    assert_eq!(words[1].load(Ordering::Relaxed), 0x3F);

    for bit in 62..68 {
        assert!(bitmap.clear_bit(bit));
    }
    assert_eq!(bitmap.pending_unit_count(), 4); // 60, 61 and 68, 69
    assert_eq!(bitmap.find_next_set(0, 256), Some(60));
    assert_eq!(bitmap.find_next_set(62, 256), Some(68));
    assert_eq!(bitmap.find_next_set(70, 256), None);

    assert!(bitmap.is_bit_set(60));
    assert!(bitmap.clear_bit(60));
    assert!(!bitmap.is_bit_set(60));
    assert!(!bitmap.clear_bit(60));
    assert!(!bitmap.is_bit_set(256));
    assert!(!bitmap.clear_bit(256));

    bitmap.clear_all();
    assert_eq!(bitmap.pending_unit_count(), 0);
}
