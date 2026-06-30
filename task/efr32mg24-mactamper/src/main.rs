// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! CMAC **tamper-detect** demo (display mode). A short "message" carries an
//! authentic AES-CMAC tag. The demo alternates the genuine message with one
//! tampered in a **TRNG-randomized number of bit positions**, recomputes the
//! tag, and compares it to the stored authentic tag -- showing AUTHENTIC (tags
//! match) or TAMPERED (any edit avalanches the 128-bit tag). All MACs and the
//! randomness are hardware (Secure Engine), via the crypto server.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

const ACTIVE_MS: u64 = 70;
const IDLE_MS: u64 = 200;
const HOLD: u32 = 26; // frames per scene (genuine / tampered)
const MAX_FLIPS: usize = 12; // up to this many randomly-chosen message bits

const MSG: &[u8] = b"PAY BOB 100 USD";
const MLEN: usize = MSG.len();

const KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f,
];

// 16x8 tag grid (128 bits), 7x5 pitch / 6x4 tiles.
const GX0: usize = 8;
const GY0: usize = 20;
const PITCH_X: usize = 7;
const PITCH_Y: usize = 5;

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

fn diff_bits(a: &[u8; 16], b: &[u8; 16]) -> u32 {
    let mut n = 0;
    for i in 0..16 {
        n += (a[i] ^ b[i]).count_ones();
    }
    n
}

#[allow(clippy::too_many_arguments)]
fn render(
    buf: &mut [u8; FB_LEN],
    msg: &[u8; MLEN],
    changed: &[bool; MLEN],
    tag: &[u8; 16],
    authentic: bool,
    diff: u32,
    flips: u32,
) {
    gfx::clear(buf);
    gfx::draw_text(buf, 2, 0, b"CMAC TAMPER CHECK");

    // The message, with a box around each tampered byte.
    gfx::draw_text(buf, 2, 9, msg);
    for (i, &c) in changed.iter().enumerate() {
        if c {
            let cx = 2 + i * 6;
            gfx::draw_rect(buf, cx - 1, 8, cx + 6, 17);
        }
    }

    // 128-bit tag as a tile grid.
    for k in 0..128usize {
        if (tag[k / 8] >> (k % 8)) & 1 != 0 {
            let cx = GX0 + (k % 16) * PITCH_X;
            let cy = GY0 + (k / 16) * PITCH_Y;
            gfx::fill_rect(buf, cx, cy, cx + 5, cy + 3);
        }
    }

    let verdict: &[u8] = if authentic { b"AUTHENTIC" } else { b"TAMPERED" };
    gfx::draw_text_scaled(buf, 6, 63, verdict, 2);

    let mut n = gfx::Num::new();
    let _ = write!(n, "{flips}");
    let x = gfx::draw_text(buf, 2, 80, b"msg bits flipped: ");
    gfx::draw_text(buf, x, 80, n.as_bytes());

    let mut n = gfx::Num::new();
    let _ = write!(n, "{diff}");
    let x = gfx::draw_text(buf, 2, 89, b"tag bits diff: ");
    let x = gfx::draw_text(buf, x, 89, n.as_bytes());
    gfx::draw_text(buf, x, 89, b"/128");
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let srv = CRYPTOSRV.get_task_id();

    let mut authentic = [0u8; 16];
    crypto::client_mac(srv, false, &KEY, MSG, &mut authentic);

    // Per-scene state (recomputed only at scene boundaries, then held).
    let mut msg = [0u8; MLEN];
    let mut changed = [false; MLEN];
    let mut tag = [0u8; 16];
    let mut is_authentic = true;
    let mut diff = 0u32;
    let mut flips = 0u32;
    let mut frame = 0u32;

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        if frame % HOLD == 0 {
            let tampered = (frame / HOLD) % 2 == 1;
            msg.copy_from_slice(MSG);
            changed = [false; MLEN];
            flips = 0;
            if tampered {
                // TRNG decides how many bits to flip and where.
                let mut r = [0u8; 1 + 2 * MAX_FLIPS];
                crypto::client_se(srv, crypto::SE_CMD_TRNG_GET_RANDOM, &[r.len() as u32], &mut r);
                let k = 1 + (r[0] as usize % MAX_FLIPS);
                for i in 0..k {
                    let idx = r[1 + 2 * i] as usize % MLEN;
                    let bit = r[2 + 2 * i] as usize % 8;
                    msg[idx] ^= 1 << bit;
                    changed[idx] = true;
                    flips += 1;
                }
            }
            crypto::client_mac(srv, false, &KEY, &msg, &mut tag);
            is_authentic = tag == authentic;
            diff = diff_bits(&authentic, &tag);
        }

        render(buf, &msg, &changed, &tag, is_authentic, diff, flips);

        frame = frame.wrapping_add(1);
        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
