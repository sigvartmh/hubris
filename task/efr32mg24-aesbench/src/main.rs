// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! AES benchmark demo (display mode). For a range of per-call block sizes, the
//! crypto server AES-128-encrypts `BENCH_TOTAL` bytes on each engine and times
//! it; this shows the throughput of the **RADIOAES** accelerator vs the **Secure
//! Engine mailbox** AES as KB/s bars. Small blocks expose the SE's per-call
//! mailbox cost; as the block grows the SE catches up. The benchmark is slow, so
//! a "running" screen is shown before each measurement. (Room for a software bar.)

#![no_std]
#![no_main]

use core::fmt::Write as _;

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

const ACTIVE_MS: u64 = 100;
const IDLE_MS: u64 = 200;
const HOLD: u32 = 30; // frames to show each result

// Per-call block sizes to sweep (bytes). Must divide BENCH_TOTAL and be <= MAXB.
const SIZES: [u32; 7] = [16, 256, 1024, 2048, 4096, 8192, 16384];
// Key sizes to sweep (bytes): AES-128 then AES-256.
const KEYS: [u32; 2] = [16, 32];

const BAR_X0: usize = 2;
const BAR_W: usize = 124;

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

/// KB/s for `BENCH_TOTAL` bytes in `ms`.
fn kbs(ms: u32) -> u32 {
    (crypto::BENCH_TOTAL / 1024) * 1000 / ms.max(1)
}

fn draw_bar(buf: &mut [u8; FB_LEN], y: usize, label: &[u8], kbs: u32, max: u32) {
    gfx::draw_text(buf, BAR_X0, y, label);
    let mut n = gfx::Num::new();
    let _ = write!(n, "{kbs}");
    let x = gfx::draw_text(buf, 64, y, n.as_bytes());
    gfx::draw_text(buf, x, y, b" KB/s");
    let w = (kbs as usize * BAR_W / max.max(1) as usize).min(BAR_W);
    gfx::draw_rect(buf, BAR_X0, y + 9, BAR_X0 + BAR_W, y + 16);
    if w > 1 {
        gfx::fill_rect(buf, BAR_X0 + 1, y + 10, BAR_X0 + w, y + 15);
    }
}

/// One per-engine summary line: `<label> N.Nx`, where the multiplier is this
/// engine's throughput relative to the slowest of the three engines.
fn speed_line(buf: &mut [u8; FB_LEN], y: usize, label: &[u8], kbs: u32, slow: u32) {
    let r = kbs * 10 / slow.max(1);
    let x = gfx::draw_text(buf, 2, y, label);
    let mut s = gfx::Num::new();
    let _ = write!(s, "{}.{}", r / 10, r % 10);
    let x = gfx::draw_text(buf, x, y, s.as_bytes());
    gfx::draw_text(buf, x, y, b"x");
}

fn header(buf: &mut [u8; FB_LEN], key_bytes: u32, block: u32) {
    gfx::clear(buf);
    let title: &[u8] = if key_bytes == 32 {
        b"AES-256 BENCHMARK"
    } else {
        b"AES-128 BENCHMARK"
    };
    gfx::draw_text(buf, 2, 0, title);
    let mut n = gfx::Num::new();
    let _ = write!(n, "{block}");
    let x = gfx::draw_text(buf, 2, 10, b"block: ");
    let x = gfx::draw_text(buf, x, 10, n.as_bytes());
    gfx::draw_text(buf, x, 10, b" B/call");
}

fn send(display: TaskId, buf: &[u8; FB_LEN]) -> u32 {
    let (rc, _) =
        sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
    rc
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let srv = CRYPTOSRV.get_task_id();

    let mut ki = 0usize;
    let mut si = 0usize;

    loop {
        let key = KEYS[ki];
        let block = SIZES[si];
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        // Show a "running" screen *before* the (slow, blocking) measurement.
        header(buf, key, block);
        gfx::draw_text(buf, 2, 40, b"running...");
        gfx::draw_text(buf, 2, 52, b"RADIOAES vs SE mailbox");
        send(display, buf);

        let mut r = [0u8; crypto::BENCH_REPLY];
        crypto::client_bench(srv, block, key, &mut r);
        let ra = u32::from_le_bytes(r[0..4].try_into().unwrap());
        let se = u32::from_le_bytes(r[4..8].try_into().unwrap());
        let sw = u32::from_le_bytes(r[8..12].try_into().unwrap());
        let ra_kbs = kbs(ra);
        let se_kbs = kbs(se);
        let sw_kbs = kbs(sw);
        let max = ra_kbs.max(se_kbs).max(sw_kbs);

        // Show the result for a while, then move to the next block size.
        for _ in 0..HOLD {
            let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };
            header(buf, key, block);
            draw_bar(buf, 22, b"RADIOAES", ra_kbs, max);
            draw_bar(buf, 44, b"SE mbox", se_kbs, max);
            draw_bar(buf, 66, b"Oberon SW", sw_kbs, max);
            // Per-engine speedup, each relative to the slowest of the three.
            let slow = ra_kbs.min(se_kbs).min(sw_kbs);
            speed_line(buf, 84, b"SE HW ", se_kbs, slow);
            speed_line(buf, 94, b"RADIOAES ", ra_kbs, slow);
            speed_line(buf, 104, b"OBERON ", sw_kbs, slow);

            let rc = send(display, buf);
            hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
        }

        si += 1;
        if si >= SIZES.len() {
            si = 0;
            ki = (ki + 1) % KEYS.len();
        }
    }
}
