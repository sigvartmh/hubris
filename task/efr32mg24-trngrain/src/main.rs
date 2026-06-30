// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Entropy "rain" demo (display mode): **hardware TRNG vs software PRNG**, side
//! by side. The left column is fed by the Secure Engine's true random number
//! generator, the right by a software xorshift PRNG. Each frame a fresh row of
//! random bits drops in at the top and the field scrolls down (falling static),
//! with a live 8-bucket byte histogram under each. Both look uniform -- the point
//! is that a good PRNG is statistically *similar*; the real difference is
//! predictability, not appearance.

#![no_std]
#![no_main]

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

const ACTIVE_MS: u64 = 70;
const IDLE_MS: u64 = 200;

const RTOP: usize = 18; // rain region (rows), scrolls down
const RBOT: usize = 92;
const HBASE: usize = 124; // histogram baseline row
const HMAX: usize = 28; // max bar height

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

/// Draw the 8-bucket byte histograms (HW left, SW right), normalized together.
fn draw_hist(buf: &mut [u8; FB_LEN], hw: &[u32; 8], sw: &[u32; 8]) {
    for y in 94..128 {
        buf[y * 16..y * 16 + 16].fill(0);
    }
    let max = hw.iter().chain(sw.iter()).copied().max().unwrap_or(1).max(1);
    for b in 0..8 {
        let hh = (hw[b] as usize * HMAX / max as usize).min(HMAX);
        let hs = (sw[b] as usize * HMAX / max as usize).min(HMAX);
        if hh > 0 {
            gfx::fill_rect(buf, 2 + b * 7, HBASE - hh, 2 + b * 7 + 5, HBASE);
        }
        if hs > 0 {
            gfx::fill_rect(buf, 66 + b * 7, HBASE - hs, 66 + b * 7 + 5, HBASE);
        }
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let srv = CRYPTOSRV.get_task_id();
    let mut prng = gfx::Rng::new(sys_get_timer().now as u32);

    // Static chrome (title + column labels). The rain never touches these rows.
    {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };
        gfx::clear(buf);
        gfx::draw_text(buf, 28, 0, b"TRNG vs PRNG");
        gfx::draw_text(buf, 2, 9, b"HW TRNG");
        gfx::draw_text(buf, 68, 9, b"SW PRNG");
    }

    let mut hist_hw = [0u32; 8];
    let mut hist_sw = [0u32; 8];
    let mut frame = 0u32;

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        // Fresh random row: 8 bytes (64 bits) per column.
        let mut hw = [0u8; 8];
        if crypto::client_se(srv, crypto::SE_CMD_TRNG_GET_RANDOM, &[8], &mut hw)
            != 0
        {
            for b in hw.iter_mut() {
                *b = prng.next() as u8; // fallback if the SE doesn't answer
            }
        }
        let mut sw = [0u8; 8];
        for c in sw.chunks_mut(4) {
            let r = prng.next().to_le_bytes();
            c.copy_from_slice(&r[..c.len()]);
        }

        // Scroll the rain region down one row, then drop the new row in at top.
        for y in (RTOP + 1..=RBOT).rev() {
            buf.copy_within((y - 1) * 16..(y - 1) * 16 + 16, y * 16);
        }
        buf[RTOP * 16..RTOP * 16 + 8].copy_from_slice(&hw);
        buf[RTOP * 16 + 8..RTOP * 16 + 16].copy_from_slice(&sw);

        // Vertical divider at x=63 (byte 7, bit 7) across the rain region.
        for y in RTOP..=RBOT {
            buf[y * 16 + 7] |= 0x80;
        }

        // Histogram by top 3 bits (8 buckets), with gentle decay so it stays live.
        for &v in &hw {
            hist_hw[(v >> 5) as usize] += 1;
        }
        for &v in &sw {
            hist_sw[(v >> 5) as usize] += 1;
        }
        if frame % 8 == 0 {
            for b in 0..8 {
                hist_hw[b] = hist_hw[b] * 7 / 8;
                hist_sw[b] = hist_sw[b] * 7 / 8;
            }
        }
        draw_hist(buf, &hist_hw, &hist_sw);

        frame = frame.wrapping_add(1);
        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
