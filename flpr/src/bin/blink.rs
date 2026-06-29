// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Program 0: blink LED3, raising a VEVIF event (and a counter) per blink.

#![no_std]
#![no_main]

use flpr::*;

const DEFAULT_PERIOD: u32 = 8_000_000;

#[no_mangle]
extern "C" fn rust_main() -> ! {
    led_init();
    mailbox_init();

    let mut count = 0u32;
    loop {
        let p = period();
        led_on();
        delay(p);
        led_off();
        delay(p);

        count = count.wrapping_add(1);
        report(count);
        notify_app();
    }
}

fn period() -> u32 {
    let p = param();
    if p == 0 {
        DEFAULT_PERIOD
    } else {
        p
    }
}
