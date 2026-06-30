// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Demoscene **plasma** effect (display mode). Each pixel sums a few animated
//! sine waves (Q16 fixed-point table) and the resulting brightness is rendered
//! to 1bpp with a 4x4 Bayer ordered dither, giving a flowing shaded plasma. Pure
//! gfx -- a display "source" task in the visual/math group.

#![no_std]
#![no_main]

use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 45;
const IDLE_MS: u64 = 250;

// Q16 sine table (one period = 64 steps).
const SIN: [i32; 64] = [
    0, 6424, 12785, 19024, 25080, 30893, 36410, 41576, 46341, 50660, 54491,
    57798, 60547, 62714, 64277, 65220, 65536, 65220, 64277, 62714, 60547, 57798,
    54491, 50660, 46341, 41576, 36410, 30893, 25080, 19024, 12785, 6424, 0,
    -6424, -12785, -19024, -25080, -30893, -36410, -41576, -46341, -50660,
    -54491, -57798, -60547, -62714, -64277, -65220, -65536, -65220, -64277,
    -62714, -60547, -57798, -54491, -50660, -46341, -41576, -36410, -30893,
    -25080, -19024, -12785, -6424,
];

const BAYER: [i32; 16] = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5];

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

#[inline(always)]
fn sin(i: i32) -> i32 {
    SIN[(i & 63) as usize]
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut t: i32 = 0;

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        for y in 0..128i32 {
            let row = (y as usize) * 16;
            let brow = (y & 3) as usize * 4;
            let sy = sin(y / 2 + t);
            for x in 0..128i32 {
                // Sum of animated sines -> brightness, range ~[-3,3] in Q16.
                let v = sin(x / 2 - t) + sy + sin((x + y) / 3 + t * 2);
                // Map to 0..12 and dither against the (scaled) Bayer threshold.
                let level = (v >> 15) + 6;
                let thr = BAYER[brow + (x & 3) as usize] * 3 / 4;
                let bit = x as usize & 7;
                if level > thr {
                    buf[row + (x as usize >> 3)] |= 1 << bit;
                } else {
                    buf[row + (x as usize >> 3)] &= !(1 << bit);
                }
            }
        }

        t = t.wrapping_add(1);
        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
