// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Program 3: speed benchmark. Free-run a counter as fast as possible, writing
//! it to the mailbox each iteration. Every ~1M iterations it toggles LED3 and
//! raises a VEVIF event, so you can see it running (a fast LED3 blink) and watch
//! the count climb in `humility ringbuf flpr_control` — the climb rate is the
//! FLPR's loop rate. Uses only 32-bit add/and (no division/64-bit, which the
//! FLPR core does not implement).

#![no_std]
#![no_main]

use flpr::*;

#[no_mangle]
extern "C" fn rust_main() -> ! {
    led_init();
    mailbox_init();

    let mut count: u32 = 0;
    let mut lit = false;
    loop {
        count = count.wrapping_add(1);
        report(count);

        if count & 0x000f_ffff == 0 {
            lit = !lit;
            if lit {
                led_on();
            } else {
                led_off();
            }
            notify_app();
        }
    }
}
