// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Polls three of the nRF54L15-DK push buttons and drives the user LEDs
//! through the `user-leds` IPC server:
//!
//! | Button | Pin   | Action                                    |
//! |--------|-------|-------------------------------------------|
//! | BTN0   | P1.13 | toggle LED0 (P2.09)                       |
//! | BTN2   | P1.08 | cycle the blink speed of LED2 (P2.07)     |
//!
//! BTN1 (P1.09) is handled by the `flpr-control` task (start/stop the FLPR) and
//! BTN3 (P0.04) by the `uart` task (print a line). The buttons are active-low
//! with internal pull-ups, so a press reads as 0. They are polled every ~20 ms,
//! which also serves as a debounce; LED2 blinks by toggling on a multiple of
//! that poll interval.

#![no_std]
#![no_main]

use drv_user_leds_api::UserLeds;
use nrf_pac::gpio::vals::{Dir, Input, Pull};
use nrf_pac::gpio::Gpio;
use userlib::*;

task_slot!(USER_LEDS, user_leds);

const POLL_INTERVAL_MS: u64 = 20;

const LED2: usize = 2;

/// Blink periods (ms) for LED2, cycled by BTN2: medium, fast, slow.
const BLINK_PERIODS_MS: [u64; 3] = [500, 200, 1000];

/// (GPIO port, pin) for BTN0 and BTN2. Both on port P1.
fn buttons() -> [(Gpio, usize); 2] {
    [
        (nrf_pac::P1_S, 13), // BTN0 -> toggle LED0
        (nrf_pac::P1_S, 8),  // BTN2 -> cycle LED2 blink speed
    ]
}

fn configure_input(gpio: Gpio, pin: usize) {
    gpio.pin_cnf(pin).write(|w| {
        w.set_dir(Dir::Input);
        w.set_input(Input::Connect);
        w.set_pull(Pull::Pullup);
    });
}

/// Active-low: a pressed button reads 0.
fn is_pressed(gpio: Gpio, pin: usize) -> bool {
    !gpio.in_().read().pin(pin)
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let leds = UserLeds::from(USER_LEDS.get_task_id());
    let buttons = buttons();
    for &(gpio, pin) in &buttons {
        configure_input(gpio, pin);
    }

    let mut was_pressed = [false; 2];
    let mut blink_idx = 0usize;
    let mut blink_accum_ms = 0u64;

    loop {
        for (i, &(gpio, pin)) in buttons.iter().enumerate() {
            let now = is_pressed(gpio, pin);
            // Act on the press edge only (not while held, not on release).
            if now && !was_pressed[i] {
                match i {
                    0 => {
                        // BTN0: toggle LED0.
                        let _ = leds.led_toggle(0);
                    }
                    _ => {
                        // BTN2: advance to the next LED2 blink speed.
                        blink_idx = (blink_idx + 1) % BLINK_PERIODS_MS.len();
                        blink_accum_ms = 0;
                    }
                }
            }
            was_pressed[i] = now;
        }

        // Blink LED2 at the currently selected period.
        blink_accum_ms += POLL_INTERVAL_MS;
        if blink_accum_ms >= BLINK_PERIODS_MS[blink_idx] {
            blink_accum_ms = 0;
            let _ = leds.led_toggle(LED2);
        }

        hl::sleep_for(POLL_INTERVAL_MS);
    }
}
