// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Task-viewer: a `humility tasks`-style monitor, rendered with the
//! `embedded-graphics` library into a [`gfx::Frame`] (via the [`gfx::FrameBuf`]
//! `DrawTarget`) and streamed to the `display` server over IPC. Shows each
//! task's index, name, and a smoothed per-task CPU-usage bar.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use efr32mg24_gfx::{self as gfx, FB_LEN};
use embedded_graphics::{
    mono_font::{ascii::FONT_5X8, MonoTextStyle},
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{Line, PrimitiveStyle, Rectangle},
    text::{Baseline, Text},
};
use hubris_num_tasks::NUM_TASKS;
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 100;
const IDLE_MS: u64 = 150;

// CPU bar geometry.
const BAR_X0: i32 = 56;
const BAR_X1: i32 = 124;
const BAR_INNER: i32 = BAR_X1 - BAR_X0 - 2; // fillable width

/// Task names, by index. The kernel doesn't carry names, so mirror the order in
/// `app.toml`. Keep in sync if tasks are added/reordered.
fn task_name(i: usize) -> &'static str {
    match i {
        0 => "JEFE",
        1 => "DISPLAY",
        2 => "CONSOLE",
        3 => "VIEWER",
        4 => "PONG",
        5 => "LIFE",
        6 => "CPUGRAPH",
        7 => "LOGO",
        8 => "STARS",
        9 => "CRYPTO",
        10 => "HELLO",
        11 => "LOAD",
        12 => "CRYPTOSRV",
        13 => "SHAVIZ",
        14 => "MACTAMPER",
        15 => "TRNGRAIN",
        16 => "ED25519",
        17 => "TEMP",
        18 => "SNAKE",
        19 => "FRACTAL",
        20 => "HASHCHAIN",
        21 => "AESAVA",
        22 => "GCM",
        23 => "MATRIX",
        24 => "PLASMA",
        25 => "AESBENCH",
        26 => "ECDH",
        27 => "CRYPTOBENCH",
        28 => "IDLE",
        _ => "?",
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut fb: gfx::Frame = [0xff; FB_LEN];

    let text = MonoTextStyle::new(&FONT_5X8, BinaryColor::On);
    let stroke = PrimitiveStyle::with_stroke(BinaryColor::On, 1);
    let fill = PrimitiveStyle::with_fill(BinaryColor::On);

    // Prime the CPU sample baseline so the first frame shows a rate.
    let mut prev = [0u32; NUM_TASKS];
    kipc::get_task_cpu_samples(&mut prev);
    // Per-task CPU% smoothed with an EMA (alpha = 1/4), 1/16-percent fixed point.
    let mut smooth = [0u32; NUM_TASKS];

    loop {
        let mut cur = [0u32; NUM_TASKS];
        let n = kipc::get_task_cpu_samples(&mut cur);
        let mut delta = [0u32; NUM_TASKS];
        let mut total = 0u32;
        for i in 0..n {
            delta[i] = cur[i].wrapping_sub(prev[i]);
            total = total.wrapping_add(delta[i]);
        }
        prev = cur;

        // Fast white clear (raw fill), then draw the chrome with embedded-graphics.
        gfx::clear(&mut fb);
        {
            let mut t = gfx::FrameBuf::new(&mut fb);
            let _ = Text::with_baseline(
                "HUBRIS EFR32MG24",
                Point::new(2, 1),
                text,
                Baseline::Top,
            )
            .draw(&mut t);
            let _ = Line::new(Point::new(0, 10), Point::new(127, 10))
                .into_styled(stroke)
                .draw(&mut t);

            // Show only running tasks -- the many demo sources are stopped until
            // selected, so listing them all just wastes rows. Packed top-down.
            let mut row = 0i32;
            for i in 0..n {
                if matches!(
                    kipc::read_task_status(i),
                    TaskState::Healthy(SchedState::Stopped)
                ) {
                    continue;
                }
                let y = 12 + row * 8;
                row += 1;

                let mut idx = gfx::Num::new();
                let _ = write!(idx, "{i}");
                let idx_str = core::str::from_utf8(idx.as_bytes()).unwrap_or("?");
                let _ = Text::with_baseline(idx_str, Point::new(2, y), text, Baseline::Top)
                    .draw(&mut t);
                let _ = Text::with_baseline(
                    task_name(i),
                    Point::new(14, y),
                    text,
                    Baseline::Top,
                )
                .draw(&mut t);

                let pct = if total > 0 {
                    (delta[i] * 100 / total).min(100)
                } else {
                    0
                };
                smooth[i] = (smooth[i] * 3 + pct * 16) / 4;
                let bar = (smooth[i] / 16) as i32 * BAR_INNER / 100;

                let _ = Rectangle::new(
                    Point::new(BAR_X0, y),
                    Size::new((BAR_X1 - BAR_X0 + 1) as u32, 8),
                )
                .into_styled(stroke)
                .draw(&mut t);
                if bar > 0 {
                    let _ = Rectangle::new(
                        Point::new(BAR_X0 + 1, y + 1),
                        Size::new(bar as u32, 6),
                    )
                    .into_styled(fill)
                    .draw(&mut t);
                }
            }
        }

        let (active, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&fb[..])]);
        hl::sleep_for(if active != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
