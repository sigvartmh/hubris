// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! "Matrix rain" demo (display mode): columns of glyphs cascade down the screen
//! at varying speeds, each leaving a short trail that clears behind it. A pure
//! gfx display "source" task in the visual/math group.

#![no_std]
#![no_main]

use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 70;
const IDLE_MS: u64 = 200;

const CW: usize = 6; // glyph cell width
const CH: usize = 8; // glyph cell height
const COLS: usize = 128 / CW; // 21 columns
const ROWS: usize = 128 / CH; // 16 rows
const TRAIL: i32 = 6; // glyphs visible behind each head

const GLYPHS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$%&*+<>?";

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut rng = gfx::Rng::new(sys_get_timer().now as u32);

    // Per-cell glyph grid (0 = empty) and per-column drop state.
    let mut cell = [[0u8; ROWS]; COLS];
    let mut head = [0i32; COLS];
    let mut speed = [1u8; COLS];
    let mut tick = [0u8; COLS];
    for c in 0..COLS {
        head[c] = -(rng.below(ROWS as u32) as i32);
        speed[c] = 1 + rng.below(4) as u8;
    }

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        for c in 0..COLS {
            tick[c] += 1;
            if tick[c] < speed[c] {
                continue;
            }
            tick[c] = 0;
            let h = head[c];
            if h >= 0 && (h as usize) < ROWS {
                cell[c][h as usize] = GLYPHS[rng.below(GLYPHS.len() as u32) as usize];
            }
            let clear = h - TRAIL;
            if clear >= 0 && (clear as usize) < ROWS {
                cell[c][clear as usize] = 0;
            }
            head[c] += 1;
            if head[c] > ROWS as i32 + TRAIL {
                head[c] = 0;
                speed[c] = 1 + rng.below(4) as u8;
            }
        }

        gfx::clear(buf);
        for c in 0..COLS {
            for r in 0..ROWS {
                let ch = cell[c][r];
                if ch != 0 {
                    gfx::draw_text(buf, c * CW, r * CH, &[ch]);
                }
            }
        }

        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
