// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Conway's Game of Life on a 64x64 toroidal grid, drawn as 2x2 blocks to fill
//! the 128x128 panel. Reseeds from a random soup when it dies out, stagnates,
//! or after a while -- so it never gets boring. A display "source" task (mode
//! 3): renders a frame and sends it to `display`.

#![no_std]
#![no_main]

use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 150; // generations are interesting at ~6 fps
const IDLE_MS: u64 = 200;

const W: usize = 64; // cells across
const H: usize = 64; // cells down
const SCALE: usize = 2; // pixels per cell

// Double-buffered grid (0/1 per cell). Static to keep it off the small stack;
// only this single-threaded task touches it.
static mut CUR: [u8; W * H] = [0; W * H];
static mut NEXT: [u8; W * H] = [0; W * H];

fn seed(rng: &mut gfx::Rng) {
    let cur = unsafe { &mut *(&raw mut CUR) };
    for c in cur.iter_mut() {
        *c = (rng.next() & 1) as u8; // ~50% alive
    }
}

/// Advance one generation; returns the new live-cell count.
fn step() -> u32 {
    let cur = unsafe { &*(&raw const CUR) };
    let next = unsafe { &mut *(&raw mut NEXT) };
    let mut alive = 0u32;
    for y in 0..H {
        for x in 0..W {
            // Toroidal neighbours: (W-1, 0, 1) indexes (x-1, x, x+1) mod W.
            let mut n = 0u8;
            for &dy in &[H - 1, 0, 1] {
                for &dx in &[W - 1, 0, 1] {
                    if dx == 0 && dy == 0 {
                        continue;
                    }
                    n += cur[((y + dy) % H) * W + ((x + dx) % W)];
                }
            }
            let live = cur[y * W + x] == 1;
            let live_next = (live && (n == 2 || n == 3)) || (!live && n == 3);
            next[y * W + x] = live_next as u8;
            alive += live_next as u32;
        }
    }
    unsafe { &mut *(&raw mut CUR) }.copy_from_slice(next);
    alive
}

fn render(fb: &mut gfx::Frame) {
    gfx::clear(fb);
    let cur = unsafe { &*(&raw const CUR) };
    for y in 0..H {
        for x in 0..W {
            if cur[y * W + x] == 1 {
                let (px, py) = (x * SCALE, y * SCALE);
                gfx::fill_rect(fb, px, py, px + SCALE - 1, py + SCALE - 1);
            }
        }
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut fb: gfx::Frame = [0xff; FB_LEN];
    let mut rng = gfx::Rng::new(sys_get_timer().now as u32);

    seed(&mut rng);
    let mut age = 0u32; // generations since the last reseed
    let mut prev_alive = 0u32;
    let mut stable = 0u32;

    loop {
        let alive = step();
        age += 1;

        // Reseed on extinction, a long stall (constant population), or age.
        if alive == prev_alive {
            stable += 1;
        } else {
            stable = 0;
        }
        prev_alive = alive;
        if alive == 0 || stable > 30 || age > 250 {
            seed(&mut rng);
            age = 0;
            stable = 0;
        }

        render(&mut fb);
        let (active, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&fb[..])]);
        hl::sleep_for(if active != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
