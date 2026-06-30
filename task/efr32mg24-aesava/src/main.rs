// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! AES **avalanche** demo (display mode). Encrypts a fixed plaintext block under
//! a fixed key, then flips **one plaintext bit at a time** and re-encrypts
//! (hardware AES-128 via the crypto server), drawing each 128-bit ciphertext as
//! a 16x8 tile grid. A single flipped input bit flips ~half the output bits --
//! AES diffusion -- shown as the grid scrambles and a `diff N/128` counter that
//! hovers near 64.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

const ACTIVE_MS: u64 = 90;
const IDLE_MS: u64 = 200;

const KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
    0xcf, 0x4f, 0x3c,
];
const PT: [u8; 16] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
    0x93, 0x17, 0x2a,
];

// 16x8 ciphertext grid (128 bits), 7x5 pitch / 6x4 tiles.
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

fn draw_num(buf: &mut [u8; FB_LEN], x: usize, y: usize, v: u32) -> usize {
    let mut n = gfx::Num::new();
    let _ = write!(n, "{v}");
    gfx::draw_text(buf, x, y, n.as_bytes())
}

fn render(buf: &mut [u8; FB_LEN], ct: &[u8; 16], bit: usize, diff: u32, avg: u32) {
    gfx::clear(buf);
    gfx::draw_text(buf, 2, 0, b"AES-128 AVALANCHE");
    let x = gfx::draw_text(buf, 2, 9, b"in bit ");
    let x = draw_num(buf, x, 9, bit as u32);
    let x = gfx::draw_text(buf, x + 4, 9, b"diff ");
    let x = draw_num(buf, x, 9, diff);
    gfx::draw_text(buf, x, 9, b"/128");

    for k in 0..128usize {
        if (ct[k / 8] >> (k % 8)) & 1 != 0 {
            let cx = GX0 + (k % 16) * PITCH_X;
            let cy = GY0 + (k / 16) * PITCH_Y;
            gfx::fill_rect(buf, cx, cy, cx + 5, cy + 3);
        }
    }

    let x = gfx::draw_text(buf, 2, 63, b"avg ");
    let x = draw_num(buf, x, 63, avg);
    gfx::draw_text(buf, x, 63, b"/128 flipped");
    gfx::draw_text(buf, 2, 74, b"one input bit flips");
    gfx::draw_text(buf, 2, 84, b"~half the output bits");
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let srv = CRYPTOSRV.get_task_id();

    // Baseline ciphertext for the unmodified plaintext.
    let mut base_ct = [0u8; 16];
    crypto::client_aes(srv, true, &KEY, &PT, &mut base_ct);

    let mut bit = 0usize;
    let (mut sum, mut cnt) = (0u32, 0u32);

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        // Flip one plaintext bit, re-encrypt, measure output change vs baseline.
        let mut pt = PT;
        pt[bit / 8] ^= 1 << (bit % 8);
        let mut ct = [0u8; 16];
        crypto::client_aes(srv, true, &KEY, &pt, &mut ct);

        let diff = diff_bits(&base_ct, &ct);
        sum += diff;
        cnt += 1;
        render(buf, &ct, bit, diff, sum / cnt);

        bit = (bit + 1) % 128;
        if bit == 0 {
            sum = 0;
            cnt = 0;
        }

        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
