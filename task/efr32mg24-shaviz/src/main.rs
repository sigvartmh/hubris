// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! SHA-256 **avalanche** demo (display mode). Hashes a base message with the
//! hardware Secure Engine, then flips **one input bit at a time** and re-hashes,
//! drawing each 256-bit digest as a 16x16 tile grid. A single flipped input bit
//! reshuffles ~half the output bits -- the "avalanche effect" -- shown live as
//! the grid scrambles and a `diff N/256` counter that hovers near 128.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

const ACTIVE_MS: u64 = 90; // one hash + redraw per frame
const IDLE_MS: u64 = 200; // (stopped when it isn't the active mode)

const MSG_LEN: usize = 23; // base message length (bytes); last byte is a counter

// 16x16 digest grid (256 bits). Rectangular 6x4 tiles (7x5 pitch) keep it short
// enough to leave room for the stats line above and the average line below.
const GX0: usize = 8;
const GY0: usize = 18;
const PITCH_X: usize = 7;
const PITCH_Y: usize = 5;

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

/// Number of differing bits between two 32-byte digests (Hamming distance).
fn diff_bits(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    let mut n = 0;
    for i in 0..32 {
        n += (a[i] ^ b[i]).count_ones();
    }
    n
}

fn draw_num(buf: &mut [u8; FB_LEN], x: usize, y: usize, val: u32) -> usize {
    let mut n = gfx::Num::new();
    let _ = write!(n, "{val}");
    gfx::draw_text(buf, x, y, n.as_bytes())
}

/// Draw the digest as a 16x16 grid (bit set -> filled tile) plus the stats.
fn render(buf: &mut [u8; FB_LEN], digest: &[u8; 32], bit: usize, diff: u32, avg: u32) {
    gfx::clear(buf);
    gfx::draw_text(buf, 2, 0, b"SHA-256 AVALANCHE");

    let x = gfx::draw_text(buf, 2, 9, b"bit ");
    let x = draw_num(buf, x, 9, bit as u32);
    let x = gfx::draw_text(buf, x + 4, 9, b"diff ");
    let x = draw_num(buf, x, 9, diff);
    gfx::draw_text(buf, x, 9, b"/256");

    for k in 0..256usize {
        if (digest[k / 8] >> (k % 8)) & 1 != 0 {
            let cx = GX0 + (k % 16) * PITCH_X;
            let cy = GY0 + (k / 16) * PITCH_Y;
            gfx::fill_rect(buf, cx, cy, cx + 5, cy + 3);
        }
    }

    let y = GY0 + 16 * PITCH_Y + 1;
    let x = gfx::draw_text(buf, 2, y, b"avg ");
    let x = draw_num(buf, x, y, avg);
    gfx::draw_text(buf, x, y, b"/256 flipped");
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let srv = CRYPTOSRV.get_task_id();

    // Base message: a fixed label whose last byte is a per-sweep counter, so the
    // baseline digest changes each full pass over the input bits.
    let mut base = [0u8; MSG_LEN];
    base[..MSG_LEN - 1].copy_from_slice(b"HUBRIS-SHA256-AVALANCH");
    let mut counter: u8 = 0;
    base[MSG_LEN - 1] = counter;

    let mut base_digest = [0u8; 32];
    crypto::client_sha256(srv, &base, &mut base_digest);

    let total_bits = MSG_LEN * 8;
    let mut bit = 0usize;
    let (mut sum, mut cnt) = (0u32, 0u32);

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        // Flip one input bit, hash, measure how much of the output changed.
        let mut msg = base;
        msg[bit / 8] ^= 1 << (bit % 8);
        let mut digest = [0u8; 32];
        crypto::client_sha256(srv, &msg, &mut digest);

        let diff = diff_bits(&base_digest, &digest);
        sum += diff;
        cnt += 1;
        render(buf, &digest, bit, diff, sum / cnt);

        bit += 1;
        if bit >= total_bits {
            bit = 0;
            counter = counter.wrapping_add(1);
            base[MSG_LEN - 1] = counter;
            crypto::client_sha256(srv, &base, &mut base_digest);
            sum = 0;
            cnt = 0;
        }

        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
