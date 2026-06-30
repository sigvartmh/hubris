// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! X25519 ECDH key-exchange demo (display mode). Each cycle the Secure Engine
//! generates two keypairs (Alice and Bob); each party derives a shared secret
//! from the other's public key. The demo shows the two public keys (top), the
//! identical derived shared secret as a 16x16 grid (center), and a MATCH verdict
//! -- the essence of Diffie-Hellman. All hardware (Secure Engine).

#![no_std]
#![no_main]

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

const ACTIVE_MS: u64 = 90;
const IDLE_MS: u64 = 200;
const HOLD: u32 = 36; // frames to show each exchange

// Shared-secret grid (256 bits) 16x16, 6x4 tiles.
const SX0: usize = 24;
const SY0: usize = 40;
const PITCH_X: usize = 5;
const PITCH_Y: usize = 4;

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

/// Draw a small 8x4 grid (32 public-key bits) for a party at (x,y).
fn key_grid(buf: &mut [u8; FB_LEN], x: usize, y: usize, key: &[u8; 32]) {
    for k in 0..32usize {
        if (key[k / 8] >> (k % 8)) & 1 != 0 {
            let cx = x + (k % 8) * 4;
            let cy = y + (k / 8) * 4;
            gfx::fill_rect(buf, cx, cy, cx + 2, cy + 2);
        }
    }
}

fn render(buf: &mut [u8; FB_LEN], pa: &[u8; 32], pb: &[u8; 32], secret: &[u8; 32], ok: bool) {
    gfx::clear(buf);
    gfx::draw_text(buf, 2, 0, b"X25519 KEY EXCHANGE");

    gfx::draw_text(buf, 2, 10, b"ALICE");
    key_grid(buf, 2, 18, pa);
    gfx::draw_text(buf, 92, 10, b"BOB");
    key_grid(buf, 92, 18, pb);

    gfx::draw_text(buf, 30, 33, b"shared secret:");
    for k in 0..256usize {
        if (secret[k / 8] >> (k % 8)) & 1 != 0 {
            let cx = SX0 + (k % 16) * PITCH_X;
            let cy = SY0 + (k / 16) * PITCH_Y;
            gfx::fill_rect(buf, cx, cy, cx + 3, cy + 2);
        }
    }

    gfx::draw_text_scaled(buf, 18, 108, if ok { b"MATCH" } else { b"MISMATCH" }, 2);
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let srv = CRYPTOSRV.get_task_id();

    let mut pa = [0u8; 32];
    let mut pb = [0u8; 32];
    let mut secret = [0u8; 32];
    let mut ok = false;
    let mut frame = 0u32;

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        if frame % HOLD == 0 {
            let mut r = [0u8; crypto::ECDH_REPLY];
            crypto::client_ecdh(srv, &mut r);
            ok = r[0] != 0;
            pa.copy_from_slice(&r[1..33]);
            pb.copy_from_slice(&r[33..65]);
            secret.copy_from_slice(&r[65..97]);
        }

        render(buf, &pa, &pb, &secret, ok);

        frame = frame.wrapping_add(1);
        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
