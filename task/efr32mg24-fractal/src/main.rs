// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Animated **Julia set** fractal (display mode). For each pixel it iterates
//! `z = z^2 + c` in Q16 fixed-point; `c = 0.7885 * e^(i*theta)` rotates a little
//! each frame, morphing the set. The escape-time is rendered to 1bpp with a 4x4
//! ordered (Bayer) dither, so the structure shows up as shading. Pure compute --
//! a display "source" task in the visual/math group.

#![no_std]
#![no_main]

use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 40;
const IDLE_MS: u64 = 250;

const W: i32 = 128;
const H: i32 = 128;
const MAXIT: i32 = 20;
const STEP: i32 = 1638; // (3.2/128) in Q16 -> maps screen to [-1.6, 1.6]
const R: i64 = 51681; // 0.7885 in Q16

// Q16 sine table (cos = sin shifted a quarter turn).
const SIN: [i32; 64] = [
    0, 6424, 12785, 19024, 25080, 30893, 36410, 41576, 46341, 50660, 54491,
    57798, 60547, 62714, 64277, 65220, 65536, 65220, 64277, 62714, 60547, 57798,
    54491, 50660, 46341, 41576, 36410, 30893, 25080, 19024, 12785, 6424, 0,
    -6424, -12785, -19024, -25080, -30893, -36410, -41576, -46341, -50660,
    -54491, -57798, -60547, -62714, -64277, -65220, -65536, -65220, -64277,
    -62714, -60547, -57798, -54491, -50660, -46341, -41576, -36410, -30893,
    -25080, -19024, -12785, -6424,
];

// 4x4 Bayer ordered-dither thresholds, scaled to 0..15.
const BAYER: [i32; 16] = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5];

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

#[inline(always)]
fn mul(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) >> 16) as i32
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut t: usize = 0;

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        // c = R * (cos(theta) + i*sin(theta)); theta = 2*pi*t/64.
        let cr = ((R * SIN[(t + 16) % 64] as i64) >> 16) as i32;
        let ci = ((R * SIN[t % 64] as i64) >> 16) as i32;

        for py in 0..H {
            let zy0 = (py - 64) * STEP;
            let row = (py as usize) * 16;
            let brow = (py & 3) as usize * 4;
            for px in 0..W {
                let mut zr = (px - 64) * STEP;
                let mut zi = zy0;
                let mut it = 0;
                while it < MAXIT {
                    let zr2 = mul(zr, zr);
                    let zi2 = mul(zi, zi);
                    if zr2 + zi2 > (4 << 16) {
                        break;
                    }
                    zi = (mul(zr, zi) << 1) + ci;
                    zr = zr2 - zi2 + cr;
                    it += 1;
                }
                let bright = it * 15 / MAXIT;
                if bright > BAYER[brow + (px & 3) as usize] {
                    buf[row + (px as usize >> 3)] |= 1 << (px & 7);
                } else {
                    buf[row + (px as usize >> 3)] &= !(1 << (px & 7));
                }
            }
        }

        t = t.wrapping_add(1);
        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
