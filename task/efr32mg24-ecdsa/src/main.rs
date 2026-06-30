// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ed25519 sign/verify demo (display mode). Each cycle the Secure Engine
//! generates a fresh Ed25519 keypair, signs a message, and verifies it -- then
//! verifies a TRNG-forged signature, which must be rejected. The demo alternates
//! a GENUINE scene (signature verifies) and a FORGED scene (random bits flipped
//! -> rejected), drawing the full 512-bit signature as a 32x16 bit grid. All
//! operations are hardware (Secure Engine). NB: P-256 ECDSA sign is rejected by
//! this MG24 part, but Ed25519 (EdDSA) works -- hence this curve.

#![no_std]
#![no_main]

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

const ACTIVE_MS: u64 = 80;
const IDLE_MS: u64 = 200;
const HOLD: u32 = 22; // frames per scene (genuine / forged)

const MSG: &[u8] = b"OXIDE HUBRIS Ed25519";

// Full 512-bit signature as a 32x16 grid (3x4 tiles, 4x5 pitch).
const GX0: usize = 0;
const GY0: usize = 26;
const PITCH_X: usize = 4;
const PITCH_Y: usize = 5;

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

fn render(buf: &mut [u8; FB_LEN], sig: &[u8; 64], forged: bool, ok: bool) {
    gfx::clear(buf);
    gfx::draw_text(buf, 2, 0, b"Ed25519 SIGN/VERIFY");
    gfx::draw_text(buf, 2, 9, b"msg: ");
    gfx::draw_text(buf, 32, 9, MSG);
    gfx::draw_text(buf, 2, 18, if forged { b"signature (forged):" } else { b"signature:" });

    for k in 0..512usize {
        if (sig[k / 8] >> (k % 8)) & 1 != 0 {
            let cx = GX0 + (k % 32) * PITCH_X;
            let cy = GY0 + (k / 32) * PITCH_Y;
            gfx::fill_rect(buf, cx, cy, cx + 2, cy + 3);
        }
    }

    let verdict: &[u8] = match (forged, ok) {
        (false, true) => b"VERIFIED",
        (false, false) => b"FAILED",
        (true, true) => b"REJECTED",
        (true, false) => b"ACCEPTED?!",
    };
    gfx::draw_text_scaled(buf, 8, 110, verdict, 2);
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let srv = CRYPTOSRV.get_task_id();

    let mut sig = [0u8; 64];
    let mut forged_sig = [0u8; 64];
    let mut genuine_ok = false;
    let mut forge_rejected = false;
    let mut keygen_ok = false;
    let mut frame = 0u32;

    loop {
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        // New keypair + sign/verify/forge roundtrip at the start of each cycle.
        if frame % (2 * HOLD) == 0 {
            let mut r = [0u8; crypto::ECDSA_REPLY];
            keygen_ok = crypto::client_ecdsa(srv, MSG, &mut r) == 0;
            genuine_ok = r[0] != 0;
            forge_rejected = r[1] != 0;
            sig.copy_from_slice(&r[2..66]);
            forged_sig.copy_from_slice(&r[66..130]);
        }

        let forged = (frame / HOLD) % 2 == 1;
        if !keygen_ok {
            gfx::clear(buf);
            gfx::draw_text(buf, 2, 0, b"Ed25519");
            gfx::draw_text(buf, 2, 20, b"keygen failed");
        } else if forged {
            render(buf, &forged_sig, true, forge_rejected);
        } else {
            render(buf, &sig, false, genuine_ok);
        }

        frame = frame.wrapping_add(1);
        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
