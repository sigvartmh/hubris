// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! AES-GCM authenticated-encryption demo (display mode). The crypto server
//! encrypts a fixed message (AES-128-GCM, with AAD), producing a ciphertext +
//! 128-bit auth tag, then decrypts it (authentic) and decrypts a one-byte
//! tampered ciphertext (the tag check fails). The demo alternates an AUTHENTIC
//! scene (plaintext recovered) and a TAMPERED scene (GCM refuses to release the
//! plaintext), drawing the auth tag as a tile grid. All crypto is hardware.

#![no_std]
#![no_main]

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

const ACTIVE_MS: u64 = 80;
const IDLE_MS: u64 = 200;
const HOLD: u32 = 24; // frames per scene (authentic / tampered)

const MSG: &[u8] = b"ATTACK AT DAWN!!";

// 16x8 tag grid (128 bits), 7x5 pitch / 6x4 tiles.
const GX0: usize = 8;
const GY0: usize = 36;
const PITCH_X: usize = 7;
const PITCH_Y: usize = 5;

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

fn render(buf: &mut [u8; FB_LEN], tag: &[u8; 16], tampered: bool, ok: bool) {
    gfx::clear(buf);
    gfx::draw_text(buf, 2, 0, b"AES-GCM AEAD");
    gfx::draw_text(buf, 2, 9, b"decrypt ->");

    // Plaintext is only released when the tag verifies.
    if tampered {
        gfx::draw_text(buf, 2, 18, b"** REJECTED (bad tag) **");
    } else {
        gfx::draw_text(buf, 2, 18, MSG);
    }
    gfx::draw_text(buf, 2, 28, b"auth tag:");

    for k in 0..128usize {
        if (tag[k / 8] >> (k % 8)) & 1 != 0 {
            let cx = GX0 + (k % 16) * PITCH_X;
            let cy = GY0 + (k / 16) * PITCH_Y;
            gfx::fill_rect(buf, cx, cy, cx + 5, cy + 3);
        }
    }

    let verdict: &[u8] = match (tampered, ok) {
        (false, true) => b"AUTHENTIC",
        (false, false) => b"VERIFY ERR",
        (true, true) => b"TAMPERED",
        (true, false) => b"LEAKED?!",
    };
    gfx::draw_text_scaled(buf, 6, 80, verdict, 2);
    gfx::draw_text(buf, 2, 102, if tampered { b"ciphertext altered" } else { b"tag ok: ct+aad intact" });
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let srv = CRYPTOSRV.get_task_id();

    let mut tag = [0u8; 16];
    let mut auth_ok = false;
    let mut tamper_detected = false;
    let mut frame = 0u32;

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        if frame % (2 * HOLD) == 0 {
            let mut r = [0u8; crypto::GCM_REPLY];
            crypto::client_gcm(srv, &mut r);
            auth_ok = r[0] != 0;
            tamper_detected = r[1] != 0;
            tag.copy_from_slice(&r[18..34]);
        }

        let tampered = (frame / HOLD) % 2 == 1;
        let ok = if tampered { tamper_detected } else { auth_ok };
        render(buf, &tag, tampered, ok);

        frame = frame.wrapping_add(1);
        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
