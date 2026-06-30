// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The classic bouncing-logo screensaver: the Oxide logo drifts and bounces off
//! the panel edges. A display "source" task (mode 5). The bitmap is generated
//! from `ref/oxide logo.png` (see `logo_bitmap.rs`).

#![no_std]
#![no_main]

mod logo_bitmap;

use efr32mg24_gfx::{self as gfx, FB_LEN};
use logo_bitmap::{LOGO, LOGO_H, LOGO_W};
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 50;
const IDLE_MS: u64 = 200;

const TW: i32 = LOGO_W as i32;
const TH: i32 = LOGO_H as i32;

/// Nudge a velocity component by -1/0/+1 on a bounce, kept in 1..=3 and keeping
/// its sign, so the logo leaves the wall at a slightly different angle each time.
fn perturb(v: i32, rng: &mut gfx::Rng) -> i32 {
    let mag = (v.abs() + rng.below(3) as i32 - 1).clamp(1, 3);
    v.signum() * mag
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut fb: gfx::Frame = [0xff; FB_LEN];
    let mut rng = gfx::Rng::new(sys_get_timer().now as u32);

    let (mut x, mut y) = (8i32, 8i32);
    let (mut vx, mut vy) = (3i32, 2i32);

    loop {
        x += vx;
        y += vy;
        if x <= 0 {
            x = 0;
            vx = -vx;
            vy = perturb(vy, &mut rng);
        }
        if x + TW >= 128 {
            x = 128 - TW;
            vx = -vx;
            vy = perturb(vy, &mut rng);
        }
        if y <= 0 {
            y = 0;
            vy = -vy;
            vx = perturb(vx, &mut rng);
        }
        if y + TH >= 128 {
            y = 128 - TH;
            vy = -vy;
            vx = perturb(vx, &mut rng);
        }

        gfx::clear(&mut fb);
        gfx::blit(&mut fb, x as usize, y as usize, &LOGO, LOGO_W, LOGO_H);

        let (active, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&fb[..])]);
        hl::sleep_for(if active != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
