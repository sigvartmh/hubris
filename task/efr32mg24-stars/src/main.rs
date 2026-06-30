// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Warp-speed starfield: stars stream outward from the center, accelerating as
//! they go (near stars move fast and draw larger), respawning at the center
//! when they leave the panel. A display "source" task (mode 6).

#![no_std]
#![no_main]

use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 50;
const IDLE_MS: u64 = 200;

const N: usize = 56; // number of stars
const CX: i32 = 64; // center
const CY: i32 = 64;

/// A star travels along the ray (dx, dy) from the center; `t` is how far along
/// it is and grows geometrically each frame, giving the warp acceleration.
#[derive(Clone, Copy)]
struct Star {
    dx: i32,
    dy: i32,
    t: i32,
}

fn spawn(rng: &mut gfx::Rng) -> Star {
    Star {
        dx: rng.below(201) as i32 - 100, // ray direction, -100..=100
        dy: rng.below(201) as i32 - 100,
        t: 12,
    }
}

fn pos(s: &Star) -> (i32, i32) {
    (CX + (s.dx * s.t >> 9), CY + (s.dy * s.t >> 9))
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut fb: gfx::Frame = [0xff; FB_LEN];
    let mut rng = gfx::Rng::new(sys_get_timer().now as u32);
    let mut stars: [Star; N] = core::array::from_fn(|_| spawn(&mut rng));

    loop {
        gfx::clear(&mut fb);
        for s in stars.iter_mut() {
            s.t += s.t / 8 + 1; // accelerate outward
            let (sx, sy) = pos(s);
            if sx < 0 || sx >= 128 || sy < 0 || sy >= 128 {
                *s = spawn(&mut rng);
                continue;
            }
            let (x, y) = (sx as usize, sy as usize);
            if s.t > 260 && x < 127 && y < 127 {
                gfx::fill_rect(&mut fb, x, y, x + 1, y + 1); // near star: 2x2
            } else {
                gfx::fill_rect(&mut fb, x, y, x, y); // far star: single pixel
            }
        }

        let (active, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&fb[..])]);
        hl::sleep_for(if active != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
