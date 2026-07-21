// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Functions for finding and validating the unaccepted-memory table from EFI tables.

use core::{
    mem::{align_of, size_of},
    ptr::NonNull,
    sync::atomic::AtomicU64,
};

use super::{
    EfiUnacceptedMemory, LINUX_EFI_UNACCEPTED_MEM_TABLE_GUID,
    LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION,
};

impl EfiUnacceptedMemory {
    /// Locates and validates the unaccepted-memory table from an EFI system table.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - if `systab` is non-null, it points to a valid, readable EFI system table;
    /// - if the system table's configuration table pointer is non-null, it points to a readable
    ///   array containing `number_of_configuration_table_entries` valid entries;
    /// - any non-null vendor table pointer in a matching configuration table entry points to a
    ///   valid, readable [`EfiUnacceptedMemory`] header.
    pub unsafe fn from_system_table(
        systab: *const uefi_raw::table::system::SystemTable,
    ) -> Option<NonNull<Self>> {
        if systab.is_null() || !systab.is_aligned() {
            log::warn!("EFI system table is null or misaligned");
            return None;
        }

        // SAFETY: Caller guarantees `systab` points to a valid, accessible EFI System Table.
        let systab = unsafe { &*systab };

        let configuration_table = systab.configuration_table;
        if configuration_table.is_null() || !configuration_table.is_aligned() {
            log::warn!("EFI configuration table is null or misaligned");
            return None;
        }

        let configuration_table_size = systab
            .number_of_configuration_table_entries
            .checked_mul(size_of::<uefi_raw::table::configuration::ConfigurationTable>());
        if configuration_table_size.is_none_or(|size| size > isize::MAX as usize) {
            log::warn!("EFI configuration table is too large");
            return None;
        }

        // SAFETY: `configuration_table` is non-null, suitably aligned, and its total byte length fits in a slice.
        let entries = unsafe {
            core::slice::from_raw_parts(
                configuration_table,
                systab.number_of_configuration_table_entries,
            )
        };

        // SAFETY: Caller guarantees accessible memory for table pointers.
        unsafe { Self::from_configuration_tables(entries) }
    }

    /// Locates and validates the unaccepted-memory table from EFI configuration table entries.
    ///
    /// # Safety
    ///
    /// The vendor table pointers within matching configuration table entries must point to
    /// valid and accessible memory if present.
    pub unsafe fn from_configuration_tables(
        entries: &[uefi_raw::table::configuration::ConfigurationTable],
    ) -> Option<NonNull<Self>> {
        let table_ptr = entries
            .iter()
            .find(|entry| entry.vendor_guid == LINUX_EFI_UNACCEPTED_MEM_TABLE_GUID)?
            .vendor_table
            .cast::<Self>();

        let non_null_table = NonNull::new(table_ptr)?;
        if !table_ptr.is_aligned() {
            return None;
        }

        // SAFETY: The pointer is non-null and aligned. Caller ensures it points to accessible memory.
        let table = unsafe { non_null_table.as_ref() };

        if table.version() != LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION {
            log::warn!(
                "Unknown unaccepted memory table version: {}",
                table.version()
            );
            return None;
        }

        if table.unit_size_bytes() == 0 || !table.unit_size_bytes().is_power_of_two() {
            log::warn!(
                "Invalid unaccepted memory table unit size: {}",
                table.unit_size_bytes()
            );
            return None;
        }

        let bitmap_addr = table_ptr.addr().checked_add(size_of::<Self>())?;
        if !bitmap_addr.is_multiple_of(align_of::<AtomicU64>())
            || table.bitmap_size_bytes() == 0
            || !table
                .bitmap_size_bytes()
                .is_multiple_of(size_of::<AtomicU64>() as u64)
        {
            log::warn!(
                "Invalid unaccepted memory table bitmap size: {}",
                table.bitmap_size_bytes()
            );
            return None;
        }

        let total_bits = table.bitmap_size_bytes().checked_mul(8)?;
        let total_size = total_bits.checked_mul(u64::from(table.unit_size_bytes()))?;
        if table.phys_base().checked_add(total_size).is_none() {
            log::warn!("Unaccepted memory table coverage overflows");
            return None;
        }

        Some(non_null_table)
    }
}
