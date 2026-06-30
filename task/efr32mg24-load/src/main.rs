// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A variable CPU hog, used to make the CPU-usage display do something
//! interesting.
//!
//! Each ~300 ms window it picks a pseudo-random duty cycle (0-100%), busy-spins
//! for that fraction, and sleeps the rest -- so its CPU bar (and idle's) wander
//! around rather than pinning at 100%. It starts **stopped** (`start = false`);
//! the console runs/stops it with `kipc::reinit_task`. Its priority sits just
//! above `idle`, so it only soaks up otherwise-idle time.

#![no_std]
#![no_main]

use userlib::*;

const WINDOW_MS: u64 = 300;

#[unsafe(export_name = "main")]
fn main() -> ! {
    // Seed an xorshift PRNG from the kernel clock so the pattern isn't identical
    // every boot. Must be non-zero.
    let mut rng = (sys_get_timer().now as u32) | 1;
    let mut acc: u32 = 1;

    loop {
        rng ^= rng << 13;
        rng ^= rng >> 17;
        rng ^= rng << 5;
        let duty = rng % 101; // 0..=100 %
        let busy_ms = WINDOW_MS * duty as u64 / 100;

        let start = sys_get_timer().now;
        while sys_get_timer().now.wrapping_sub(start) < busy_ms {
            acc = core::hint::black_box(acc)
                .wrapping_mul(2_654_435_761)
                .wrapping_add(1);
        }

        if busy_ms < WINDOW_MS {
            hl::sleep_for(WINDOW_MS - busy_ms);
        }
    }
}
