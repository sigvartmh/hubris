// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Scrolling total-CPU-load graph: one column per sample, newest on the right,
//! scrolling left over time. Load = 100% minus the idle task's share, from the
//! kernel's per-task tick samples. A display "source" task (mode 4).

#![no_std]
#![no_main]

use core::fmt::Write as _;

use efr32mg24_gfx::{self as gfx, FB_LEN};
use hubris_num_tasks::NUM_TASKS;
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 150;
const IDLE_MS: u64 = 200;

const COLS: usize = 128; // one sample per pixel column
const TOP: usize = 12; // graph area
const BOT: usize = 124;
const HEIGHT: usize = BOT - TOP; // fillable height

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut fb: gfx::Frame = [0xff; FB_LEN];

    let mut hist = [0u8; COLS]; // busy% per column
    let mut prev = [0u32; NUM_TASKS];
    kipc::get_task_cpu_samples(&mut prev);
    let idle = NUM_TASKS - 1; // idle is the last task in app.toml

    loop {
        let mut cur = [0u32; NUM_TASKS];
        let n = kipc::get_task_cpu_samples(&mut cur);
        let mut total = 0u32;
        for i in 0..n {
            total = total.wrapping_add(cur[i].wrapping_sub(prev[i]));
        }
        let idle_d = cur[idle].wrapping_sub(prev[idle]);
        prev = cur;
        let busy = if total > 0 {
            (100 - (idle_d * 100 / total).min(100)) as u8
        } else {
            0
        };

        // Scroll the history left and push the newest sample on the right.
        hist.rotate_left(1);
        hist[COLS - 1] = busy;

        gfx::clear(&mut fb);
        gfx::draw_text(&mut fb, 2, 1, b"CPU LOAD");
        let mut num = gfx::Num::new();
        let _ = write!(num, "{busy}%");
        gfx::draw_text(&mut fb, 98, 1, num.as_bytes());
        gfx::draw_rect(&mut fb, 0, TOP - 1, 127, BOT);
        for (x, &h) in hist.iter().enumerate() {
            let bar = h as usize * HEIGHT / 100;
            if bar > 0 {
                gfx::fill_rect(&mut fb, x, BOT - bar, x, BOT - 1);
            }
        }

        let (active, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&fb[..])]);
        hl::sleep_for(if active != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
