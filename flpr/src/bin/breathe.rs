// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Program 1: "breathing" LED3 via software PWM — smooth fade in/out.
//!
//! The PWM tick delay is fixed (smooth, flicker-free); the fade speed is the
//! number of PWM cycles held at each brightness level, taken straight from the
//! mailbox `param` ("slowness": bigger = slower breathing).

#![no_std]
#![no_main]

use flpr::*;

/// Brightness resolution (PWM ticks per cycle).
const STEPS: u32 = 100;
/// Fixed delay iterations per PWM tick (sets the PWM frequency).
const UNIT: u32 = 30;
/// Default "slowness" (PWM cycles held per brightness step). Small numbers:
/// ~10 is a brisk breath, ~40 is slow. Big values look like a fixed brightness.
const DEFAULT_SLOWNESS: u32 = 15;

#[no_mangle]
extern "C" fn rust_main() -> ! {
    led_init();
    mailbox_init();

    let mut breaths = 0u32;
    loop {
        let hold = slowness();
        for level in 0..=STEPS {
            pwm_hold(level, hold);
        }
        for level in (0..STEPS).rev() {
            pwm_hold(level, hold);
        }

        breaths = breaths.wrapping_add(1);
        report(breaths);
        notify_app(); // one event per full breath
    }
}

fn slowness() -> u32 {
    let p = param();
    if p == 0 {
        DEFAULT_SLOWNESS
    } else {
        p
    }
}

/// Hold brightness `level`/STEPS for `hold` PWM cycles.
fn pwm_hold(level: u32, hold: u32) {
    for _ in 0..hold {
        if level > 0 {
            led_on();
            delay(level * UNIT);
        }
        if level < STEPS {
            led_off();
            delay((STEPS - level) * UNIT);
        }
    }
}
