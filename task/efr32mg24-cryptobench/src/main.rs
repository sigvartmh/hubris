// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Crypto-suite benchmark demo (display mode). Cycles through the algorithms the
//! Secure Engine mailbox and the nRF Oberon software library *both* implement --
//! AES-128/256 ECB, AES-GCM, AES-CMAC, SHA-256, HMAC-SHA256, Ed25519 sign/verify
//! and X25519 ECDH -- and races the **SE hardware** against the **Oberon
//! software** for each, drawing the two throughputs as bars. The crypto server
//! does the timing (time-budgeted loops); this task just displays ops/sec. Bulk
//! algorithms use a 1 KB buffer (so ops/sec == KB/s); the asymmetric ones report
//! operations/sec. The measurement blocks, so a "running" screen is shown first.

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
const HOLD: u32 = 28; // frames to show each result

/// One benchmarked algorithm. Bulk algorithms (`timed = false`) process a 1 KB
/// buffer per op and are reported as throughput (KB/s). The asymmetric ones
/// (`timed = true`: Ed25519, X25519) are reported as time-per-operation (ms),
/// which reads more naturally than ops/sec for a handful of ops per second.
struct Algo {
    name: &'static str,
    timed: bool,
}

const ALGOS: [Algo; crypto::CBENCH_NALGO as usize] = [
    Algo { name: "AES-128 ECB", timed: false },
    Algo { name: "AES-256 ECB", timed: false },
    Algo { name: "AES-GCM", timed: false },
    Algo { name: "AES-CMAC", timed: false },
    Algo { name: "SHA-256", timed: false },
    Algo { name: "HMAC-SHA256", timed: false },
    Algo { name: "Ed25519 sign", timed: true },
    Algo { name: "Ed25519 vrfy", timed: true },
    Algo { name: "X25519 ECDH", timed: true },
];

const BAR_X0: usize = 2;
const BAR_W: usize = 124;

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

/// Operations/second from an op count and the elapsed milliseconds.
fn ops_per_sec(ops: u32, ms: u32) -> u32 {
    ops * 1000 / ms.max(1)
}

/// Per-op time in tenths of a millisecond (for the asymmetric algorithms).
fn tenths_ms_per_op(ops: u32, ms: u32) -> u32 {
    ms * 10 / ops.max(1)
}

/// Draw one engine's row: the bar length always reflects speed (`rate`, ops/sec)
/// so a longer bar is faster, while the printed value is either throughput
/// (KB/s) or, for `timed` algorithms, the per-op time in ms.
fn draw_engine(
    buf: &mut [u8; FB_LEN],
    y: usize,
    label: &[u8],
    ops: u32,
    ms: u32,
    max_rate: u32,
    timed: bool,
) {
    gfx::draw_text(buf, BAR_X0, y, label);
    let rate = ops_per_sec(ops, ms);
    let mut n = gfx::Num::new();
    if timed {
        let t = tenths_ms_per_op(ops, ms);
        let _ = write!(n, "{}.{} ms", t / 10, t % 10);
    } else {
        let _ = write!(n, "{rate} KB/s");
    }
    gfx::draw_text(buf, 60, y, n.as_bytes());
    let w = (rate as usize * BAR_W / max_rate.max(1) as usize).min(BAR_W);
    gfx::draw_rect(buf, BAR_X0, y + 9, BAR_X0 + BAR_W, y + 16);
    if w > 1 {
        gfx::fill_rect(buf, BAR_X0 + 1, y + 10, BAR_X0 + w, y + 15);
    }
}

fn header(buf: &mut [u8; FB_LEN], idx: usize) {
    gfx::clear(buf);
    gfx::draw_text(buf, 2, 0, b"CRYPTO BENCHMARK");
    let mut n = gfx::Num::new();
    let _ = write!(n, "{}/{}", idx + 1, ALGOS.len());
    let x = gfx::draw_text(buf, 2, 10, ALGOS[idx].name.as_bytes());
    gfx::draw_text(buf, x + 4, 10, n.as_bytes());
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

    let mut ai = 0usize;

    loop {
        let algo = &ALGOS[ai];
        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };

        // Show a "running" screen *before* the (slow, blocking) measurement.
        header(buf, ai);
        gfx::draw_text(buf, 2, 40, b"running...");
        gfx::draw_text(buf, 2, 52, b"SE HW vs Oberon SW");
        send(display, buf);

        let mut r = [0u8; crypto::CBENCH_REPLY];
        crypto::client_cbench(srv, ai as u8, &mut r);
        let se_ops = u32::from_le_bytes(r[0..4].try_into().unwrap());
        let se_ms = u32::from_le_bytes(r[4..8].try_into().unwrap());
        let sw_ops = u32::from_le_bytes(r[8..12].try_into().unwrap());
        let sw_ms = u32::from_le_bytes(r[12..16].try_into().unwrap());
        let se = ops_per_sec(se_ops, se_ms);
        let sw = ops_per_sec(sw_ops, sw_ms);
        let max = se.max(sw);

        for _ in 0..HOLD {
            let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };
            header(buf, ai);
            draw_engine(buf, 26, b"SE HW", se_ops, se_ms, max, algo.timed);
            draw_engine(buf, 52, b"Oberon", sw_ops, sw_ms, max, algo.timed);

            // Verdict: which engine won, and by how much (one decimal). Always
            // by speed (rate), whichever unit the value is shown in.
            let (lead, faster, slower) =
                if se >= sw { (b"SE HW".as_slice(), se, sw) } else { (b"Oberon".as_slice(), sw, se) };
            let ratio = if slower > 0 { faster * 10 / slower } else { 0 };
            let x = gfx::draw_text(buf, 2, 80, lead);
            let x = gfx::draw_text(buf, x, 80, b" ");
            let mut s = gfx::Num::new();
            let _ = write!(s, "{}.{}", ratio / 10, ratio % 10);
            let x = gfx::draw_text(buf, x, 80, s.as_bytes());
            gfx::draw_text(buf, x, 80, b"x faster");

            let rc = send(display, buf);
            hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
        }

        ai = (ai + 1) % ALGOS.len();
    }
}
