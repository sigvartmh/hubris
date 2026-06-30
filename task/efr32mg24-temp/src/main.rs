// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Die-temperature demo (display mode): a scrolling graph of the MG24's built-in
//! temperature sensor, read straight from the EMU's `TEMP` register (no IADC or
//! external sensor). Newest sample on the right, scrolling left -- same style as
//! the CPU-load graph. A display "source" task.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 200;
const IDLE_MS: u64 = 250;

// EMU (secure alias). TEMP field is quarter-Kelvin: temp_C = raw/4 - 273.15.
const EMU_STATUS: *const u32 = 0x4000_4084 as *const u32;
const EMU_TEMP: *const u32 = 0x4000_4088 as *const u32;
const EMU_STATUS_FIRSTTEMPDONE: u32 = 1 << 1;
const EMU_TEMP_MASK: u32 = 0x7ff; // TEMP[10:2] | TEMPLSB[1:0]

const COLS: usize = 128;
const TOP: usize = 12;
const BOT: usize = 124;
const GH: usize = BOT - TOP; // graph height in px
// Plotted range, in tenths of a degree C (20.0 .. 60.0).
const LO_DC: i32 = 200;
const HI_DC: i32 = 600;

/// Die temperature in tenths of a degree C, or `None` until the first reading.
fn read_temp_dc() -> Option<i32> {
    unsafe {
        if EMU_STATUS.read_volatile() & EMU_STATUS_FIRSTTEMPDONE == 0 {
            return None;
        }
        let raw = (EMU_TEMP.read_volatile() & EMU_TEMP_MASK) as i32;
        // temp_C = raw/4 - 273.15  ->  tenths: raw*10/4 - 2731 = raw*5/2 - 2731.
        Some(raw * 5 / 2 - 2731)
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut fb: gfx::Frame = [0xff; FB_LEN];

    let mut hist = [0u8; COLS]; // graph height per column (0..GH)
    let mut last_dc = 0i32;
    let mut have = false;

    loop {
        if let Some(dc) = read_temp_dc() {
            last_dc = dc;
            have = true;
            // Map LO_DC..HI_DC to 0..GH, clamped.
            let clamped = dc.clamp(LO_DC, HI_DC);
            let h = ((clamped - LO_DC) as usize * GH) / (HI_DC - LO_DC) as usize;
            hist.rotate_left(1);
            hist[COLS - 1] = h as u8;
        }

        gfx::clear(&mut fb);
        gfx::draw_text(&mut fb, 2, 1, b"DIE TEMP");
        if have {
            let mut num = gfx::Num::new();
            let _ = write!(num, "{}.{}C", last_dc / 10, (last_dc % 10).abs());
            gfx::draw_text(&mut fb, 78, 1, num.as_bytes());
        } else {
            gfx::draw_text(&mut fb, 78, 1, b"...");
        }
        gfx::draw_rect(&mut fb, 0, TOP - 1, 127, BOT);
        for (x, &h) in hist.iter().enumerate() {
            if h > 0 {
                gfx::fill_rect(&mut fb, x, BOT - h as usize, x, BOT - 1);
            }
        }

        let (active, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&fb[..])]);
        hl::sleep_for(if active != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
