// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

mod swo;

use cortex_m_rt::entry;

// We deliberately pull in no device PAC. Without a PAC, `cortex-m-rt` provides a
// default `__INTERRUPTS` vector table whose entries all point at the kernel's
// `DefaultHandler` -- which is exactly how Hubris dispatches every hardware
// interrupt (it recovers the IRQ number from the IPSR). That default table is
// larger than the EFR32MG24's 76 interrupts, but the extra slots are harmless.

/// Vector table base. We boot from main flash, so point VTOR there in case the
/// Secure Element / boot ROM left it at its reset value of 0.
const VTOR: *mut u32 = 0xE000_ED08 as *mut u32;
const FLASH_BASE: u32 = 0x0800_0000;

/// CPU cycles per kernel tick (1 ms). The Secure Element leaves SYSCLK on
/// HFRCODPLL at its 19 MHz startup frequency (confirmed on hardware via
/// `CMU_SYSCLKCTRL`), and we do not reconfigure clocks in this bring-up. If a
/// later stage raises the core clock, update this (and `swo::TRACE_CLK_HZ`) to
/// match, or kernel time scales proportionally.
const CYCLES_PER_MS: u32 = 19_000;

/// Let unprivileged tasks reach peripherals.
///
/// The EFR32 SMU/PPU gates every peripheral to *privileged-only* access at reset
/// (`SMU_PPUPATD0/1` reset to all-ones). Hubris runs drivers as unprivileged
/// tasks and isolates them with the MPU instead, so without this an unprivileged
/// task's peripheral accesses are silently RAZ/WI -- reads return 0, writes are
/// dropped, no fault. We clear the PPU *privileged* bits (leaving the MPU as the
/// sole gate) for all peripherals; the per-task MPU regions still decide which
/// task can reach which peripheral. Secure attribution (`PPUSATD`) is left at its
/// all-secure reset value, which is correct since Hubris runs entirely Secure.
fn enable_unprivileged_peripheral_access() {
    const CMU_CLKEN1: *mut u32 = 0x4000_8068 as *mut u32;
    const CMU_CLKEN1_SMU: u32 = 1 << 14;
    const SMU_LOCK: *mut u32 = 0x4400_8008 as *mut u32;
    const SMU_PPUPATD0: *mut u32 = 0x4400_8040 as *mut u32;
    const SMU_PPUPATD1: *mut u32 = 0x4400_8044 as *mut u32;
    const SMU_UNLOCK_KEY: u32 = 0x00AC_CE55;

    // Safety: fixed CMU/SMU register addresses; runs once, privileged, pre-kernel.
    unsafe {
        // The SMU bus clock is gated at reset; enable it before touching the SMU,
        // or the register access bus-faults (-> HardFault).
        CMU_CLKEN1.write_volatile(CMU_CLKEN1.read_volatile() | CMU_CLKEN1_SMU);
        SMU_LOCK.write_volatile(SMU_UNLOCK_KEY);
        SMU_PPUPATD0.write_volatile(0);
        SMU_PPUPATD1.write_volatile(0);
    }
}

#[entry]
fn main() -> ! {
    unsafe {
        VTOR.write_volatile(FLASH_BASE);
    }
    enable_unprivileged_peripheral_access();
    unsafe {
        swo::init();
    }

    swo::write_str("\r\n[efr32mg24] hubris kernel booting\r\n");

    unsafe { kern::startup::start_kernel(CYCLES_PER_MS) }
}
