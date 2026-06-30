// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal SWO / ITM trace bring-up for the EFR32MG24.
//!
//! This routes the Cortex-M ITM stimulus port 0 out the SWO pin (PA3) so that
//! `main()` (privileged) and unprivileged tasks can emit human-readable log
//! text that a debug probe captures over Serial Wire Output.
//!
//! There are two halves to the setup:
//!
//! 1. **Vendor (Silicon Labs) routing** -- enable the GPIO clock, drive PA3
//!    push-pull, point the Serial Wire Viewer at it, and pick the trace clock.
//!    Register addresses are the *secure* aliases and offsets were taken from
//!    the device headers under `ref/simplicity_sdk` (CMU @ 0x4000_8000, GPIO @
//!    0x4003_C000).
//! 2. **Generic Arm CoreSight** -- DEMCR/TPIU/ITM, configured per the Armv8-M
//!    Architecture Reference Manual so the macrocell emits NRZ (UART-framed)
//!    SWO at a known baud. Doing this in firmware keeps the image self-contained
//!    rather than depending on the probe to program trace.

/// Trace clock feeding the TPIU. `CMU_TRACECLKCTRL` resets to SYSCLK, and the
/// Silicon Labs Secure Element leaves SYSCLK on HFRCODPLL at its 19 MHz startup
/// frequency (`HFRCODPLL_STARTUP_FREQ`) before our `main()` runs -- verified on
/// hardware via `CMU_SYSCLKCTRL.CLKSEL == HFRCODPLL`. So the trace clock is
/// 19 MHz, not the raw-reset FSRCO 20 MHz.
pub const TRACE_CLK_HZ: u32 = 19_000_000;

/// SWO bit rate. 1 Mbaud divides the 19 MHz trace clock evenly (prescaler 18)
/// and is comfortably within range of the WSTK's onboard J-Link. The capturing
/// tool must be told this same baud (`commander-cli swo read --swospeed 1000000`).
pub const SWO_BAUD: u32 = 1_000_000;

// --- Silicon Labs CMU (secure alias) ---------------------------------------
const CMU_BASE: u32 = 0x4000_8000;
const CMU_CLKEN0: *mut u32 = (CMU_BASE + 0x064) as *mut u32;
const CMU_TRACECLKCTRL: *mut u32 = (CMU_BASE + 0x080) as *mut u32;
const CMU_CLKEN0_GPIO: u32 = 1 << 26;
const CMU_TRACECLKCTRL_CLKSEL_SYSCLK: u32 = 0x1; // CLKSEL field, SYSCLK

// --- Silicon Labs GPIO (secure alias) --------------------------------------
const GPIO_BASE: u32 = 0x4003_C000;
// Port A register block starts at offset 0x30 (after IPVERSION + reserved);
// MODEL is the second word of the block (CTRL, MODEL, ...).
const GPIO_PA_MODEL: *mut u32 = (GPIO_BASE + 0x034) as *mut u32;
const GPIO_TRACEROUTEPEN: *mut u32 = (GPIO_BASE + 0x444) as *mut u32;
const GPIO_TRACEROUTEPEN_SWVPEN: u32 = 1 << 0;
// PA3 -> MODE3 nibble (bits 15:12); value 4 = PUSHPULL.
const PA3_MODE_SHIFT: u32 = 3 * 4;
const GPIO_MODE_PUSHPULL: u32 = 0x4;

// --- Arm CoreSight (PPB) ----------------------------------------------------
const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;
const DEMCR_TRCENA: u32 = 1 << 24;

const ITM_STIM0: *mut u32 = 0xE000_0000 as *mut u32;
const ITM_TER: *mut u32 = 0xE000_0E00 as *mut u32; // Trace Enable
const ITM_TPR: *mut u32 = 0xE000_0E40 as *mut u32; // Trace Privilege
const ITM_TCR: *mut u32 = 0xE000_0E80 as *mut u32; // Trace Control
const ITM_LAR: *mut u32 = 0xE000_0FB0 as *mut u32; // Lock Access
const ITM_LAR_UNLOCK: u32 = 0xC5AC_CE55;
const ITM_TCR_ITMENA: u32 = 1 << 0;
const ITM_TCR_TRACE_BUS_ID_1: u32 = 1 << 16;

const TPIU_CSPSR: *mut u32 = 0xE004_0004 as *mut u32; // Current Sync Port Size
const TPIU_ACPR: *mut u32 = 0xE004_0010 as *mut u32; // Async Clock Prescaler
const TPIU_SPPR: *mut u32 = 0xE004_00F0 as *mut u32; // Selected Pin Protocol
const TPIU_FFCR: *mut u32 = 0xE004_0304 as *mut u32; // Formatter and Flush Ctrl
const TPIU_SPPR_NRZ: u32 = 0x2; // SWO, UART/NRZ encoding
const TPIU_FFCR_DISABLE_FORMATTER: u32 = 0x100; // keep TrigIn, formatter off

/// Configure SWO and enable ITM stimulus port 0, including unprivileged access
/// so tasks can write it.
///
/// # Safety
/// Must run once, early in privileged boot (before `start_kernel`), with no
/// other code touching CMU/GPIO trace routing or the ITM/TPIU.
pub unsafe fn init() {
    unsafe {
        // 1. Vendor routing -------------------------------------------------
        // GPIO bus clock is gated off at reset; enable it before touching GPIO.
        CMU_CLKEN0.write_volatile(CMU_CLKEN0.read_volatile() | CMU_CLKEN0_GPIO);
        // Trace clock = SYSCLK (the reset default; set explicitly to be safe).
        CMU_TRACECLKCTRL.write_volatile(CMU_TRACECLKCTRL_CLKSEL_SYSCLK);
        // Drive PA3 push-pull (read-modify-write to preserve other pins).
        let model = GPIO_PA_MODEL.read_volatile() & !(0xF << PA3_MODE_SHIFT);
        GPIO_PA_MODEL
            .write_volatile(model | (GPIO_MODE_PUSHPULL << PA3_MODE_SHIFT));
        // Route the Serial Wire Viewer output to PA3.
        GPIO_TRACEROUTEPEN.write_volatile(GPIO_TRACEROUTEPEN_SWVPEN);

        // 2. Arm CoreSight ITM/TPIU ----------------------------------------
        DEMCR.write_volatile(DEMCR.read_volatile() | DEMCR_TRCENA);
        // TPIU: single-bit async SWO at the configured baud.
        TPIU_CSPSR.write_volatile(1);
        TPIU_ACPR.write_volatile(TRACE_CLK_HZ / SWO_BAUD - 1);
        TPIU_SPPR.write_volatile(TPIU_SPPR_NRZ);
        TPIU_FFCR.write_volatile(TPIU_FFCR_DISABLE_FORMATTER);
        // ITM: unlock, enable, allow unprivileged ports 0-7, enable port 0.
        ITM_LAR.write_volatile(ITM_LAR_UNLOCK);
        ITM_TCR.write_volatile(ITM_TCR_ITMENA | ITM_TCR_TRACE_BUS_ID_1);
        ITM_TPR.write_volatile(0x1);
        ITM_TER.write_volatile(0x1);
    }
}

/// Write a string to ITM stimulus port 0. Safe to call once [`init`] has run.
pub fn write_str(s: &str) {
    for &byte in s.as_bytes() {
        write_byte(byte);
    }
}

fn write_byte(byte: u8) {
    // Spin until the port FIFO can accept a byte (read != 0), but bound the
    // wait so a missing/stalled probe can't hang boot forever.
    for _ in 0..10_000 {
        if unsafe { ITM_STIM0.read_volatile() } != 0 {
            break;
        }
    }
    // Byte-wide store pushes a single byte into the stimulus port.
    unsafe { (ITM_STIM0 as *mut u8).write_volatile(byte) };
}
