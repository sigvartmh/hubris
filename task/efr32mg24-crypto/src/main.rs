// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Hardware-AES "decryption reveal" demo (display mode). An image is drawn,
//! then **hardware-encrypted** (RADIOAES, AES-128) into noise, then
//! **hardware-decrypted row by row** so the picture emerges from the noise --
//! one 16-byte AES block per 128px row. A new random key each cycle.
//!
//! This step uses ECB + a software-PRNG key. CTR + the ECB/CTR toggle and the
//! Secure-Engine TRNG key come next.

#![no_std]
#![no_main]

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

const ACTIVE_MS: u64 = 12; // fast frames; the per-frame LCD DMA dominates anyway
const IDLE_MS: u64 = 200; // (crypto is stopped when it isn't the active mode)
const ROWS: usize = 128; // one AES block per row
const REVEAL_PER_FRAME: usize = 1; // decrypt one block at a time, progressively
const HOLD_FRAMES: u32 = 50; // hold the clear image before re-encrypting

/// Word-aligned so AES-block rows (offset r*16) are word-aligned for the DMA.
#[repr(C, align(4))]
struct Aligned<const N: usize>([u8; N]);

// The single shown framebuffer: drawn -> encrypted in place -> decrypted in
// place. Static to keep it off the small task stack.
static mut BUF: Aligned<FB_LEN> = Aligned([0; FB_LEN]);

/// Process one row for the current cipher. ECB: encrypt/decrypt the 16-byte
/// block (via an aligned scratch so input != output for the DMA). CTR: XOR the
/// row with the hardware keystream AES(counter) -- symmetric, so `encrypt` is
/// ignored. Counter block = nonce(12) || big-endian row index(4).
fn process_row(
    srv: TaskId,
    ctr_mode: bool,
    encrypt: bool,
    key: &[u8; 16],
    nonce: &[u8; 12],
    buf: &mut [u8; FB_LEN],
    r: usize,
) {
    if ctr_mode {
        let mut ctr = [0u8; 16];
        ctr[..12].copy_from_slice(nonce);
        ctr[12..].copy_from_slice(&(r as u32).to_be_bytes());
        let mut ks = [0u8; 16];
        crypto::client_aes(srv, true, key, &ctr, &mut ks);
        for i in 0..16 {
            buf[r * 16 + i] ^= ks[i];
        }
    } else {
        let mut inp = [0u8; 16];
        inp.copy_from_slice(&buf[r * 16..r * 16 + 16]);
        let mut out = [0u8; 16];
        crypto::client_aes(srv, encrypt, key, &inp, &mut out);
        buf[r * 16..r * 16 + 16].copy_from_slice(&out);
    }
}

/// Draw the plaintext picture (white-on-black). Big uniform regions make the
/// ECB block-repetition visible in the noise.
fn render_plaintext(buf: &mut [u8; FB_LEN], ctr_mode: bool) {
    gfx::clear(buf);
    gfx::draw_rect(buf, 3, 3, 124, 124);
    gfx::draw_text_scaled(buf, 14, 18, b"HUBRIS", 3);
    let mode: &[u8] = if ctr_mode { b"AES-128 CTR" } else { b"AES-128 ECB" };
    gfx::draw_text(buf, 30, 60, mode);
    gfx::draw_text(buf, 18, 78, b"HARDWARE CRYPTO");
    gfx::fill_rect(buf, 20, 95, 107, 108);
}

fn fill_random(rng: &mut gfx::Rng, out: &mut [u8]) {
    for chunk in out.chunks_mut(4) {
        let bytes = rng.next().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// A fresh key from the Secure Engine's hardware TRNG (via the crypto server),
/// falling back to the software PRNG if the SE doesn't respond.
fn gen_key(srv: TaskId, rng: &mut gfx::Rng, key: &mut [u8; 16]) {
    if crypto::client_se(srv, crypto::SE_CMD_TRNG_GET_RANDOM, &[16], key) != 0 {
        fill_random(rng, key);
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let srv = CRYPTOSRV.get_task_id(); // crypto server owns + clocks the engines
    let mut rng = gfx::Rng::new(sys_get_timer().now as u32);
    let mut key = [0u8; 16];
    let mut nonce = [0u8; 12];
    // Alternates each cycle. Init `true` so the first flip shows ECB first.
    let mut cipher_ctr = true;

    // Start "finished" so the first iteration kicks off a fresh cycle.
    let mut revealed = ROWS;
    let mut hold = 0u32;

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut (*(&raw mut BUF)).0 };

        if revealed >= ROWS && hold == 0 {
            // New cycle: alternate ECB <-> CTR, fresh key + nonce, draw the
            // picture, then hardware-encrypt every row -> noise.
            cipher_ctr = !cipher_ctr;
            gen_key(srv, &mut rng, &mut key); // hardware TRNG (software fallback)
            fill_random(&mut rng, &mut nonce);
            render_plaintext(buf, cipher_ctr);
            for r in 0..ROWS {
                process_row(srv, cipher_ctr, true, &key, &nonce, buf, r);
            }
            revealed = 0;
        } else if revealed < ROWS {
            // Decrypt the next band of rows -> picture emerges top-to-bottom.
            let end = (revealed + REVEAL_PER_FRAME).min(ROWS);
            for r in revealed..end {
                process_row(srv, cipher_ctr, false, &key, &nonce, buf, r);
            }
            revealed = end;
            if revealed >= ROWS {
                hold = HOLD_FRAMES;
            }
        } else {
            hold = hold.saturating_sub(1);
        }

        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
