// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

// We have to do this if we don't otherwise use it to ensure its vector table
// gets linked in.
extern crate nrf_pac;

use cortex_m_rt::entry;

#[entry]
fn main() -> ! {
    // SysTick is driven by the CPU clock, and this value sets the reload for
    // the 1 kHz kernel tick. The nRF54L15 application core can run up to
    // 128 MHz from the HFPLL; we leave the clock at its reset default and do
    // not reconfigure it in this minimal bring-up. If the boot-default
    // frequency differs from the value below, kernel time (and thus the LED
    // blink rate) scales proportionally -- verify on hardware and adjust.
    const CYCLES_PER_MS: u32 = 64_000;

    unsafe { kern::startup::start_kernel(CYCLES_PER_MS) }
}
