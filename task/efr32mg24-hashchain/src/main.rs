// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Hash-chain ("blockchain") demo (display mode). Five blocks, each whose hash is
//! `SHA-256(prev_hash || data)`, so the hashes are linked. The demo periodically
//! tampers one block's data and recomputes the chain: every block from the
//! tampered one onward no longer matches its originally-recorded hash and is
//! flagged broken -- the immutability property of a hash chain. All hashing is
//! hardware (Secure Engine) via the crypto server.

#![no_std]
#![no_main]

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

const ACTIVE_MS: u64 = 90;
const IDLE_MS: u64 = 200;
const HOLD: u32 = 26; // frames per scene (intact / tampered)
const NB: usize = 8; // number of blocks
const PITCH: usize = 14; // vertical px per block row

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

const HEXD: &[u8; 16] = b"0123456789abcdef";

/// Recompute the chain: `hash[i] = SHA256(hash[i-1] || data[i])`, hash[-1] = 0.
fn build_chain(srv: TaskId, data: &[u8; NB], hashes: &mut [[u8; 32]; NB]) {
    let mut prev = [0u8; 32];
    for i in 0..NB {
        let mut input = [0u8; 33];
        input[..32].copy_from_slice(&prev);
        input[32] = data[i];
        crypto::client_sha256(srv, &input, &mut hashes[i]);
        prev = hashes[i];
    }
}

fn put_hex(buf: &mut [u8; FB_LEN], x: usize, y: usize, bytes: &[u8]) -> usize {
    let mut hx = [0u8; 16];
    for (i, b) in bytes.iter().enumerate() {
        hx[i * 2] = HEXD[(b >> 4) as usize];
        hx[i * 2 + 1] = HEXD[(b & 0xf) as usize];
    }
    gfx::draw_text(buf, x, y, &hx[..bytes.len() * 2])
}

fn render(
    buf: &mut [u8; FB_LEN],
    data: &[u8; NB],
    hashes: &[[u8; 32]; NB],
    valid: &[bool; NB],
    tampered: Option<usize>,
) {
    gfx::clear(buf);
    gfx::draw_text(buf, 2, 0, b"HASH CHAIN");

    for i in 0..NB {
        let y = 9 + i * PITCH;
        gfx::draw_rect(buf, 6, y, 121, y + 11);
        // chain link to the previous block
        if i > 0 {
            gfx::draw_rect(buf, 62, y - 2, 63, y);
        }
        // "B{i} {data} {hash4}"
        let mut lbl = gfx::Num::new();
        use core::fmt::Write as _;
        let _ = write!(lbl, "B{i} ");
        let x = gfx::draw_text(buf, 10, y + 2, lbl.as_bytes());
        let x = put_hex(buf, x, y + 2, &data[i..i + 1]);
        let x = put_hex(buf, x + 8, y + 2, &hashes[i][..4]);
        // status marker
        let mark: &[u8] = if valid[i] { b"OK" } else { b"X!" };
        gfx::draw_text(buf, x + 6, y + 2, mark);
        // mark the actually-edited block
        if tampered == Some(i) {
            gfx::draw_rect(buf, 5, y - 1, 122, y + 12);
        }
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let srv = CRYPTOSRV.get_task_id();

    // Original, agreed-upon chain.
    let data0: [u8; NB] =
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let mut orig = [[0u8; 32]; NB];
    build_chain(srv, &data0, &mut orig);

    let mut frame = 0u32;
    let mut data = data0;
    let mut hashes = orig;
    let mut valid = [true; NB];
    let mut tampered: Option<usize> = None;

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        if frame % HOLD == 0 {
            data = data0;
            tampered = None;
            if (frame / HOLD) % 2 == 1 {
                // Tamper a TRNG-chosen block's data, then recompute the chain.
                let mut r = [0u8; 4];
                crypto::client_se(srv, crypto::SE_CMD_TRNG_GET_RANDOM, &[4], &mut r);
                let k = r[0] as usize % NB;
                data[k] ^= 0x80 | (r[1] & 0x7f);
                tampered = Some(k);
            }
            build_chain(srv, &data, &mut hashes);
            for i in 0..NB {
                valid[i] = hashes[i] == orig[i];
            }
        }

        render(buf, &data, &hashes, &valid, tampered);

        frame = frame.wrapping_add(1);
        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
