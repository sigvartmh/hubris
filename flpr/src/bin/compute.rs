// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Program 2: compute coprocessor. For each n, compute its Collatz stopping
//! time and report (n, steps) to the M33, which prints them. A real (if toy)
//! compute task offloaded to the RISC-V core.
//!
//! Uses only 32-bit add/shift/multiply — no division and no 64-bit math, which
//! the FLPR core does not implement (they fault). n is capped so 3n+1 stays
//! within u32.

#![no_std]
#![no_main]

use flpr::*;

/// Throttle between results so the M33/UART can keep up (delay iterations).
const DEFAULT_THROTTLE: u32 = 2_000_000;
/// Largest n to try; Collatz peaks for n <= 1000 stay well within u32.
const MAX_N: u32 = 1000;

/// Collatz stopping time: steps to reach 1. Even -> n>>1, odd -> 3n+1.
fn collatz_steps(start: u32) -> u32 {
    let mut n = start;
    let mut steps = 0u32;
    while n != 1 {
        if n & 1 == 0 {
            n >>= 1;
        } else {
            n = n.wrapping_mul(3).wrapping_add(1);
        }
        steps = steps.wrapping_add(1);
        if steps > 10_000 {
            break; // safety net
        }
    }
    steps
}

#[no_mangle]
extern "C" fn rust_main() -> ! {
    led_init();
    mailbox_init();

    let mut n: u32 = 2;
    loop {
        let steps = collatz_steps(n);
        report2(steps, n); // result_a = steps, result_b = n
        notify_app();

        // Visible pulse per result, then throttle.
        led_on();
        delay(150_000);
        led_off();
        delay(throttle());

        n += 1;
        if n > MAX_N {
            n = 2;
        }
    }
}

fn throttle() -> u32 {
    let p = param();
    if p == 0 {
        DEFAULT_THROTTLE
    } else {
        p
    }
}
