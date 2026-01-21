[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9205/badge)](https://www.bestpractices.dev/projects/9205)

## Introducing tdx-guest

The tdx-guest provides a Rust implementation of Intel® Trust Domain Extensions (Intel® TDX) Guest APIs, supporting for TDX Guest specific instructions, structures and functions.

## TDCALL Implementation

| Leaf Num | Name in Specification | Description | Is Implemented | Interface Function Name | TDX version |
|------|--------------|-------------|----------------|-------------------------|------------|
| 0    | TDG.VP.VMCALL | Call a host VM service | ✅ | Please refer [TDVMCALL Implementment](#tdvmcall-implementation) | 1.0, 1.5 |
| 1    | TDG.VP.INFO | Get TD execution environment information | ✅ | `get_tdinfo` | 1.0, 1.5 |
| 2    | TDG.MR.RTMR.EXTEND | Extend a TD run-time measurement register | ✅ | `extend_rtmr` | 1.0, 1.5 |
| 3    | TDG.VP.VEINFO.GET | Get Virtualization Exception Information for the recent #VE exception | ✅ | `get_veinfo` | 1.0, 1.5 |
| 4    | TDG.MR.REPORT | Creates a cryptographic report of the TD | ✅ | `get_report` | 1.0, 1.5 |
| 5    | TDG.VP.CPUIDVE.SET | Control delivery of #VE on CPUID instruction execution | ✅ | `set_cpuidve` | 1.0, 1.5 |
| 6    | TDG.MEM.PAGE.ACCEPT | Accept a pending private page into the TD | ✅ | `accept_page` | 1.0, 1.5 |
| 7    | TDG.VM.RD | Read a TD-scope metadata field | ✅ | `read_td_metadata` | 1.0, 1.5 |
| 8    | TDG.VM.WR | Write a TD-scope metadata field | ✅ | `write_td_metadata` | 1.0, 1.5 |
| 9    | TDG.VP.RD | Read a VCPU-scope metadata field | ✅ | `read_vcpu_metadata` | 1.5 |
| 10   | TDG.VP.WR | Write a VCPU-scope metadata field | ✅ | `write_vcpu_metadata` | 1.5 |
| 11   | TDG.SYS.RD | Read a TDX Module global-scope metadata field | ✅ | `read_sys_metadata` | 1.5 |
| 12   | TDG.SYS.RDALL | Read all guest-readable TDX Module global-scope metadata fields | ❌ | - | 1.5 |
| 13   | TDG.SYS.RDM | Read multiple TDX Module global-scope metadata fields | ❌ | - | 1.5 |
| 14   | TDG.VM.RDM | Read multiple TD-scope metadata fields | ❌ | - | 1.5 |
| 15   | TDG.VM.WRM | Write multiple TD-scope metadata fields | ❌ | - | 1.5 |
| 16   | TDG.VP.RDM | Read multiple VCPU-scope metadata fields | ❌ | - | 1.5 |
| 17   | TDG.VP.WRM | Write multiple VCPU-scope metadata fields | ❌ | - | 1.5 |
| 18   | TDG.SERVTD.RD | Read a target TD metadata field | ✅ | `read_servetd` | 1.5 |
| 19   | TDG.SERVTD.RDM | Read multiple target TD metadata fields | ❌ | - | 1.5 |
| 20   | TDG.SERVTD.WR | Write a target TD metadata field | ✅ | `write_servetd` | 1.5 |
| 21   | TDG.SERVTD.WRM | Write multiple target TD metadata fields | ❌ | - | 1.5 |
| 22   | TDG.MR.VERIFYREPORT | Verify a cryptographic report of a TD, generated on the current platform | ✅ | `verify_report` | 1.5 |
| 23   | TDG.MEM.PAGE.ATTR.RD | Read the GPA mapping and attributes of a TD private page | ✅ | `read_page_attr` | 1.5 |
| 24   | TDG.MEM.PAGE.ATTR.WR | Write the attributes of a private page | ✅ | `write_page_attr` | 1.5 |
| 25   | TDG.VP.ENTER | Enter L2 VCPU operation | ✅ | `enter_l2_vcpu` | 1.5 |
| 26   | TDG.VP.INVEPT | Invalidate cached EPT translations for selected L2 VMs | ✅ | `invalidate_l2_cached_ept` | 1.5 |
| 27   | TDG.VP.INVGLA | Invalidate cached translations for selected pages in an L2 VM | ✅ | `invalidate_l2_gla` | 1.5 |
| 28   | TDG.MR.ASSIGNSVNS | Assign SVN values given TDSIGSTRUCTS and reference TD measurement values | ❌ | - | 1.5 |
| 29   | TDG.MR.KEY.GET | Get a persistent key, customized to the TD’s measurements and policy | ❌ | - | 1.5 |
| 30   | TDG.MEM.PAGE.RELEASE | Release a private page, enabling the host VMM to remove it | ❌ | - | 1.5 |

## TDVMCALL Implementation

| Sub-Function Number | Sub-Function Name in Specification | Is Implemented | Interface Function Name           | TDX version |
|---------------------|------------------------------------|----------------|-----------------------------------|-------------|
| 0x10000             | GetTdVmCallInfo                    | ✅             | `get_tdvmcall_info`               | 1.0, 1.5   |
| 0x10001             | MapGPA                             | ✅             | `map_gpa`                         | 1.0, 1.5   |
| 0x10002             | GetQuote                           | ✅             | `get_quote`                       | 1.0, 1.5   |
| 0x10003             | ReportFatalError                   | ✅             | `report_fatal_error`                                 | 1.0, 1.5   |
| 0x10004             | SetupEventNotifyInterrupt          | ✅             | `setup_event_notify_interrupt`    | 1.0, 1.5   |
| 0x10005             | Service                            | ✅             | `get_td_service`                  | 1.5        |


| Sub-Function Number Bits 15:0 | Sub-Function Name in Specification | Is Implemented | Interface Function Name            | TDX version |
|-------------------------------|------------------------------------|----------------|------------------------------------|-------------|
| 10                            | Instruction.CPUID                  | ✅             | `cpuid`                           | 1.0, 1.5    |
| 12                            | Instruction.HLT                    | ✅             | `hlt`                             | 1.0, 1.5    |
| 30                            | Instruction.IO                     | ✅             | `io_read`, `io_write`             | 1.0, 1.5    |
| 31                            | Instruction.RDMSR                  | ✅             | `rdmsr`                           | 1.0, 1.5    |
| 32                            | Instruction.WRMSR                  | ✅             | `wrmsr`                           | 1.0, 1.5    |
| 48                            | #VE.RequestMMIO                    | ✅             | `read_mmio`, `write_mmio`         | 1.0, 1.5    |
| 54                            | Instruction.WBINVD                 | ✅             | `perform_cache_operation`         | 1.0, 1.5    |
| 65                            | Instruction.PCONFIG                | ✅             | `pconfig`                                 | 1.0, 1.5    |
