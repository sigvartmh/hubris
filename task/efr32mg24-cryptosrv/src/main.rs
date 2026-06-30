// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Crypto server: the sole owner of the RADIOAES and Secure-Engine mailbox
//! hardware. Clients (the crypto display mode, the console `se` command) reach
//! the engines only through this task, so accesses are serialized and the
//! shared peripherals never race. Higher priority than its clients.

#![no_std]
#![no_main]

use efr32mg24_crypto as crypto;
use userlib::*;

/// Wall-clock budget (ms) for each engine's loop in the crypto-suite benchmark.
const CBENCH_BUDGET_MS: u32 = 100;

/// Run `$body` in a loop until [`CBENCH_BUDGET_MS`] has elapsed; evaluate to
/// `(op_count, elapsed_ms)`. At least one iteration always runs.
macro_rules! timed {
    ($body:expr) => {{
        let t0 = sys_get_timer().now;
        let mut ops = 0u32;
        loop {
            let _ = $body;
            ops += 1;
            if (sys_get_timer().now - t0) as u32 >= CBENCH_BUDGET_MS {
                break;
            }
        }
        (ops, (sys_get_timer().now - t0) as u32)
    }};
}

/// Word-aligned scratch for the SHA-256 message (the SE input DMA wants aligned
/// buffers). Static to keep it off the small task stack.
#[repr(C, align(4))]
struct Aligned<const N: usize>([u8; N]);
static mut MSG: Aligned<{ crypto::HASH_MSG_MAX }> =
    Aligned([0; crypto::HASH_MSG_MAX]);

/// Word-aligned input/output buffers for the AES benchmark (the engines DMA
/// these; bigger blocks amortize per-call overhead).
static mut BENCH_IN: Aligned<{ crypto::BENCH_MAXB }> = Aligned([0; crypto::BENCH_MAXB]);
static mut BENCH_OUT: Aligned<{ crypto::BENCH_MAXB }> = Aligned([0; crypto::BENCH_MAXB]);

/// Hex-encode `bytes` into `out` (which must be `2*bytes.len()` long).
fn hex(bytes: &[u8], out: &mut [u8]) {
    const D: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = D[(b >> 4) as usize];
        out[i * 2 + 1] = D[(b & 0xf) as usize];
    }
}

/// One-shot self-test: SE-mailbox AES-128 ECB against the FIPS-197 known-answer
/// vector. Logs `SE-AES <PASS|FAIL> <ct-hex>` so the all-SE AES path can be
/// confirmed on hardware in a single flash.
fn se_aes_kat() {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let pt: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    ];
    const EXPECT: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
        0x70, 0xb4, 0xc5, 0x5a,
    ];
    let mut ct = [0u8; 16];
    let st = crypto::se_aes128_ecb(true, &key, &pt, &mut ct);

    let mut line = [0u8; 48];
    line[..7].copy_from_slice(b"SE-AES ");
    let tag: &[u8] = if st == 0 && ct == EXPECT { b"PASS " } else { b"FAIL " };
    line[7..12].copy_from_slice(tag);
    hex(&ct, &mut line[12..44]);
    line[44] = b'\n';
    kipc::log(&line[..45]);
}

/// One-shot ECDSA-P256 self-test: keygen, sign, verify a genuine signature.
/// Logs `ECDSA kg=.. sg=.. vf=..` (SE status of each step; vf=0 => the genuine
/// signature verified) so the sign/verify path can be diagnosed on hardware.
fn ecdsa_kat() {
    const HX: &[u8; 16] = b"0123456789abcdef";
    let nib = |s: u32| HX[((s >> 16) & 0xf) as usize];

    // Mailbox P-256 ECDSA sign is unsupported on this part; confirm keygen works.
    let mut kp = [0u8; 96];
    let p256 = crypto::se_ecc_p256_keygen(&mut kp);

    // Ed25519 (EdDSA) -- sign/verify (works on this part).
    let mut ed = [0u8; 64];
    let ekg = crypto::se_ed25519_keygen(&mut ed);
    let mut sig = [0u8; 64];
    let esg = crypto::se_ed25519_sign(&ed, b"KAT", &mut sig);
    let evf = crypto::se_ed25519_verify(&ed, b"KAT", &sig);

    let mut line = [0u8; 32];
    line[..12].copy_from_slice(b"KEYGEN p256=");
    line[12] = nib(p256);
    line[13..21].copy_from_slice(b" EDDSA k");
    line[21] = nib(ekg);
    line[22..24].copy_from_slice(b" s");
    line[24] = nib(esg);
    line[25..27].copy_from_slice(b" v");
    line[27] = nib(evf);
    line[28] = b'\n';
    kipc::log(&line[..29]);

    // X25519 ECDH (keygen buffer is pub||priv, so the peer pubkey is offset 0).
    let mut alice = [0u8; 64];
    let mut bob = [0u8; 64];
    crypto::se_x25519_keygen(&mut alice);
    crypto::se_x25519_keygen(&mut bob);
    let pa: [u8; 32] = alice[0..32].try_into().unwrap();
    let pb: [u8; 32] = bob[0..32].try_into().unwrap();
    let mut sa = [0u8; 32];
    let mut sb = [0u8; 32];
    crypto::se_x25519_ecdh(&alice, &pb, &mut sa);
    crypto::se_x25519_ecdh(&bob, &pa, &mut sb);
    let mut e = [0u8; 16];
    e[..8].copy_from_slice(b"ECDH eq=");
    e[8] = if sa == sb { b'1' } else { b'0' };
    e[9] = b'\n';
    kipc::log(&e[..10]);
}

/// Confirm the Oberon software AES against the FIPS-197 known-answer vector.
fn oberon_kat() {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let pt: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    ];
    const EXPECT: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
        0x70, 0xb4, 0xc5, 0x5a,
    ];
    let mut ct = [0u8; 16];
    oberon_crypto::aes_ecb_encrypt(&key, &pt, &mut ct);
    let mut line = [0u8; 16];
    line[..11].copy_from_slice(b"OBERON-AES ");
    line[11..16].copy_from_slice(if ct == EXPECT { b"PASS\n" } else { b"FAIL\n" });
    kipc::log(&line[..16]);
}

/// Confirm the **interrupt-driven RADIOAES** path end-to-end: encrypt the
/// FIPS-197 vector via `radioaes_ecb_multi` (which blocks on the AES IRQ) and
/// check the ciphertext. A `RADIOAES PASS` here proves the interrupt actually
/// fires *and* the DMA produced correct output -- not just "it didn't hang".
/// Requires `radioaes_irq_enable()` to have run first.
fn radioaes_kat() {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let pt: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    ];
    const EXPECT: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
        0x70, 0xb4, 0xc5, 0x5a,
    ];
    let mut ct = [0u8; 16];
    crypto::radioaes_ecb_multi(
        true,
        &key,
        &pt,
        &mut ct,
        notifications::AES_IRQ_MASK,
    );

    let mut line = [0u8; 48];
    line[..9].copy_from_slice(b"RADIOAES ");
    let tag: &[u8] = if ct == EXPECT { b"PASS " } else { b"FAIL " };
    line[9..14].copy_from_slice(tag);
    hex(&ct, &mut line[14..46]);
    line[46] = b'\n';
    kipc::log(&line[..47]);
}

/// Stress the pure interrupt path (no backstop) across the large transfer sizes
/// that used to hang -- *many* ops each, since the stale-pending race is
/// intermittent (~per-op probability) and only shows up over a lot of ops. If
/// this completes -- boot reaches `irqsweep ok` -- the end-of-block interrupt is
/// delivered reliably and the path is hang-free with zero per-op overhead. (If
/// the race were still live, boot would stop partway through.)
fn radioaes_irq_sweep() {
    let key = [0u8; 16];
    for &sz in &[2048usize, 4096, 8192, 16384] {
        for _ in 0..200 {
            let inb = unsafe { &(*(&raw const BENCH_IN)).0 };
            let outb = unsafe { &mut (*(&raw mut BENCH_OUT)).0 };
            crypto::radioaes_ecb_multi(
                true,
                &key,
                &inb[..sz],
                &mut outb[..sz],
                notifications::AES_IRQ_MASK,
            );
        }
    }
    kipc::log(b"RADIOAES irqsweep ok\n");
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    crypto::init(); // RADIOAES + SE mailbox clocks
    crypto::radioaes_irq_enable(); // arm the RADIOAES end-of-block interrupt
    radioaes_kat(); // confirm the interrupt-driven RADIOAES path (fires + correct)
    radioaes_irq_sweep(); // confirm the pure IRQ path is hang-free at every size
    se_aes_kat(); // confirm the all-SE AES path on boot
    oberon_kat(); // confirm the Oberon software AES on boot
    ecdsa_kat(); // confirm/diagnose the ECDSA sign/verify path

    let mut req = [0u8; 64];
    loop {
        let msg = sys_recv_open(&mut req, 0);

        match msg.operation as u16 {
            crypto::OP_AES if msg.message_len >= 33 => {
                // [encrypt(1), key(16), input(16)] -> output(16)
                let encrypt = req[0] != 0;
                let key: [u8; 16] = req[1..17].try_into().unwrap();
                let input: [u8; 16] = req[17..33].try_into().unwrap();
                let mut output = [0u8; 16];
                // All-SE AES path: route the visual's AES through the Secure
                // Engine mailbox (was RADIOAES). Reply code = SE status.
                let st = crypto::se_aes128_ecb(encrypt, &key, &input, &mut output);
                sys_reply(msg.sender, st, &output);
            }
            crypto::OP_HASH => {
                // Body = the message bytes. Copy into an aligned buffer so the
                // SE input DMA is word-aligned, then SHA-256 it.
                let n = msg.message_len.min(crypto::HASH_MSG_MAX);
                let buf = unsafe { &mut (*(&raw mut MSG)).0 };
                buf[..n].copy_from_slice(&req[..n]);
                let mut digest = [0u8; 32];
                let st = crypto::se_sha256(&buf[..n], &mut digest);
                sys_reply(msg.sender, st, &digest);
            }
            crypto::OP_MAC if msg.message_len >= 17 => {
                // Body = [hmac(1), key(16), message...]. Copy the message into an
                // aligned buffer, then CMAC (16B tag) or HMAC-SHA256 (32B tag).
                let hmac = req[0] != 0;
                let key: [u8; 16] = req[1..17].try_into().unwrap();
                let mlen =
                    (msg.message_len - 17).min(crypto::MAC_MSG_MAX);
                let buf = unsafe { &mut (*(&raw mut MSG)).0 };
                buf[..mlen].copy_from_slice(&req[17..17 + mlen]);
                if hmac {
                    let mut tag = [0u8; 32];
                    let st = crypto::se_hmac256(&key, &buf[..mlen], &mut tag);
                    sys_reply(msg.sender, st, &tag);
                } else {
                    let mut tag = [0u8; 16];
                    let st = crypto::se_cmac(&key, &buf[..mlen], &mut tag);
                    sys_reply(msg.sender, st, &tag);
                }
            }
            crypto::OP_ECDH => {
                // Alice & Bob X25519 key exchange. Keygen buffer is pub||priv, so
                // each public key is the first 32 bytes; each party derives the
                // shared secret from the other's public key (they must match).
                let mut alice = [0u8; 64];
                let mut bob = [0u8; 64];
                crypto::se_x25519_keygen(&mut alice);
                crypto::se_x25519_keygen(&mut bob);
                let pa: [u8; 32] = alice[0..32].try_into().unwrap();
                let pb: [u8; 32] = bob[0..32].try_into().unwrap();
                let mut sa = [0u8; 32];
                let mut sb = [0u8; 32];
                crypto::se_x25519_ecdh(&alice, &pb, &mut sa);
                crypto::se_x25519_ecdh(&bob, &pa, &mut sb);

                let mut reply = [0u8; crypto::ECDH_REPLY];
                reply[0] = (sa == sb) as u8;
                reply[1..33].copy_from_slice(&pa);
                reply[33..65].copy_from_slice(&pb);
                reply[65..97].copy_from_slice(&sa);
                sys_reply(msg.sender, 0, &reply);
            }
            crypto::OP_BENCH if msg.message_len >= 8 => {
                // Encrypt BENCH_TOTAL bytes in `b`-byte chunks on each engine and
                // time it. Bigger `b` -> fewer (slow) SE mailbox round-trips.
                // `kb` = key length (16 = AES-128, 32 = AES-256).
                let b = (u32::from_le_bytes(req[0..4].try_into().unwrap())
                    as usize)
                    .clamp(16, crypto::BENCH_MAXB);
                let kb = if u32::from_le_bytes(req[4..8].try_into().unwrap())
                    == 32
                {
                    32
                } else {
                    16
                };
                let ops = crypto::BENCH_TOTAL / b as u32;
                let key = [0u8; 32];
                let inb = unsafe { &(*(&raw const BENCH_IN)).0 };
                let outb = unsafe { &mut (*(&raw mut BENCH_OUT)).0 };

                let t0 = sys_get_timer().now;
                for _ in 0..ops {
                    crypto::radioaes_ecb_multi(
                        true,
                        &key[..kb],
                        &inb[..b],
                        &mut outb[..b],
                        notifications::AES_IRQ_MASK,
                    );
                }
                let ra = (sys_get_timer().now - t0) as u32;

                let t0 = sys_get_timer().now;
                for _ in 0..ops {
                    crypto::se_aes_ecb_multi(true, &key[..kb], &inb[..b], &mut outb[..b]);
                }
                let se = (sys_get_timer().now - t0) as u32;

                // Software AES (nRF Oberon, optimized C for Cortex-M33).
                let t0 = sys_get_timer().now;
                for _ in 0..ops {
                    oberon_crypto::aes_ecb_encrypt(&key[..kb], &inb[..b], &mut outb[..b]);
                }
                let sw = (sys_get_timer().now - t0) as u32;

                let mut reply = [0u8; crypto::BENCH_REPLY];
                reply[0..4].copy_from_slice(&ra.to_le_bytes());
                reply[4..8].copy_from_slice(&se.to_le_bytes());
                reply[8..12].copy_from_slice(&sw.to_le_bytes());
                sys_reply(msg.sender, 0, &reply);
            }
            crypto::OP_CBENCH if msg.message_len >= 1 => {
                // Crypto-suite benchmark: for the selected algorithm, run the SE
                // mailbox and the Oberon software implementation in time-budgeted
                // loops. Reply: [se_ops, se_ms, sw_ops, sw_ms] (LE).
                let algo = req[0];
                let inb = unsafe { &(*(&raw const BENCH_IN)).0 };
                let outb = unsafe { &mut (*(&raw mut BENCH_OUT)).0 };
                let buf = &inb[..crypto::CBENCH_BUF];
                let out = &mut outb[..crypto::CBENCH_BUF];
                let k16 = [0u8; 16];
                let k32 = [0u8; 32];
                let iv = [0u8; 12];
                let m = b"oxide-bench-msg";

                let (se_ops, se_ms, sw_ops, sw_ms) = match algo {
                    0 => {
                        // AES-128 ECB, 1 KB/op.
                        let (so, sm) =
                            timed!(crypto::se_aes_ecb_multi(true, &k16, buf, out));
                        let (wo, wm) =
                            timed!(oberon_crypto::aes_ecb_encrypt(&k16, buf, out));
                        (so, sm, wo, wm)
                    }
                    1 => {
                        // AES-256 ECB, 1 KB/op.
                        let (so, sm) =
                            timed!(crypto::se_aes_ecb_multi(true, &k32, buf, out));
                        let (wo, wm) =
                            timed!(oberon_crypto::aes_ecb_encrypt(&k32, buf, out));
                        (so, sm, wo, wm)
                    }
                    2 => {
                        // AES-GCM, 1 KB/op (no AAD).
                        let mut tag = [0u8; 16];
                        let (so, sm) = timed!(crypto::se_gcm_encrypt(
                            &k16, &iv, &[], buf, out, &mut tag
                        ));
                        let (wo, wm) = timed!(oberon_crypto::aes_gcm_encrypt(
                            &k16, &iv, buf, out, &mut tag
                        ));
                        (so, sm, wo, wm)
                    }
                    3 => {
                        // AES-CMAC, 1 KB/op.
                        let mut tag = [0u8; 16];
                        let (so, sm) = timed!(crypto::se_cmac(&k16, buf, &mut tag));
                        let (wo, wm) =
                            timed!(oberon_crypto::aes_cmac(&k16, buf, &mut tag));
                        (so, sm, wo, wm)
                    }
                    4 => {
                        // SHA-256, 1 KB/op.
                        let mut d = [0u8; 32];
                        let (so, sm) = timed!(crypto::se_sha256(buf, &mut d));
                        let (wo, wm) = timed!(oberon_crypto::sha256(buf, &mut d));
                        (so, sm, wo, wm)
                    }
                    5 => {
                        // HMAC-SHA256, 1 KB/op.
                        let mut t = [0u8; 32];
                        let (so, sm) =
                            timed!(crypto::se_hmac256(&k16, buf, &mut t));
                        let (wo, wm) =
                            timed!(oberon_crypto::hmac_sha256(&k16, buf, &mut t));
                        (so, sm, wo, wm)
                    }
                    6 => {
                        // Ed25519 sign (each engine signs with its own key).
                        let mut ed = [0u8; 64];
                        crypto::se_ed25519_keygen(&mut ed);
                        let mut sig = [0u8; 64];
                        let (so, sm) =
                            timed!(crypto::se_ed25519_sign(&ed, m, &mut sig));
                        let sk = [0x42u8; 32];
                        let mut pk = [0u8; 32];
                        oberon_crypto::ed25519_public_key(&sk, &mut pk);
                        let (wo, wm) = timed!(oberon_crypto::ed25519_sign(
                            &sk, &pk, m, &mut sig
                        ));
                        (so, sm, wo, wm)
                    }
                    7 => {
                        // Ed25519 verify (pre-sign one genuine signature each).
                        let mut ed = [0u8; 64];
                        crypto::se_ed25519_keygen(&mut ed);
                        let mut sig = [0u8; 64];
                        crypto::se_ed25519_sign(&ed, m, &mut sig);
                        let (so, sm) =
                            timed!(crypto::se_ed25519_verify(&ed, m, &sig));
                        let sk = [0x42u8; 32];
                        let mut pk = [0u8; 32];
                        oberon_crypto::ed25519_public_key(&sk, &mut pk);
                        let mut osig = [0u8; 64];
                        oberon_crypto::ed25519_sign(&sk, &pk, m, &mut osig);
                        let (wo, wm) =
                            timed!(oberon_crypto::ed25519_verify(&pk, m, &osig));
                        (so, sm, wo, wm)
                    }
                    _ => {
                        // X25519 ECDH (one scalar-mult per op).
                        let mut a = [0u8; 64];
                        let mut b = [0u8; 64];
                        crypto::se_x25519_keygen(&mut a);
                        crypto::se_x25519_keygen(&mut b);
                        let pb: [u8; 32] = b[0..32].try_into().unwrap();
                        let mut sh = [0u8; 32];
                        let (so, sm) =
                            timed!(crypto::se_x25519_ecdh(&a, &pb, &mut sh));
                        let ska = [0x11u8; 32];
                        let skb = [0x22u8; 32];
                        let mut pkb = [0u8; 32];
                        oberon_crypto::x25519_base(&skb, &mut pkb);
                        let (wo, wm) =
                            timed!(oberon_crypto::x25519_ecdh(&ska, &pkb, &mut sh));
                        (so, sm, wo, wm)
                    }
                };

                let mut reply = [0u8; crypto::CBENCH_REPLY];
                reply[0..4].copy_from_slice(&se_ops.to_le_bytes());
                reply[4..8].copy_from_slice(&se_ms.to_le_bytes());
                reply[8..12].copy_from_slice(&sw_ops.to_le_bytes());
                reply[12..16].copy_from_slice(&sw_ms.to_le_bytes());
                sys_reply(msg.sender, 0, &reply);
            }
            crypto::OP_GCM => {
                // AES-GCM AEAD demo: encrypt a fixed message, decrypt it
                // (authentic), then decrypt a 1-byte-tampered ciphertext (the
                // tag check must fail). All fixed inputs.
                let key: [u8; 16] = [
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                    0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                ];
                let iv: [u8; 12] = [
                    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca,
                    0xf8, 0x88,
                ];
                let aad = b"oxide-hdr";
                let pt = b"ATTACK AT DAWN!!";
                let mut ct = [0u8; 16];
                let mut tag = [0u8; 16];
                let e = crypto::se_gcm_encrypt(&key, &iv, aad, pt, &mut ct, &mut tag);
                let mut dec = [0u8; 16];
                let good = crypto::se_gcm_decrypt(&key, &iv, aad, &ct, &tag, &mut dec);
                let mut ct2 = ct;
                ct2[0] ^= 0x01;
                let mut dec2 = [0u8; 16];
                let bad = crypto::se_gcm_decrypt(&key, &iv, aad, &ct2, &tag, &mut dec2);

                let mut reply = [0u8; crypto::GCM_REPLY];
                reply[0] = (e == 0 && good == 0) as u8;
                reply[1] = (bad != 0) as u8; // non-zero status = tamper detected
                reply[2..18].copy_from_slice(&ct);
                reply[18..34].copy_from_slice(&tag);
                sys_reply(msg.sender, e, &reply);
            }
            crypto::OP_ECDSA => {
                // Body = message. Generate a P-256 keypair, sign, verify, then
                // verify a 1-bit-forged signature (must be rejected).
                let n = msg.message_len.min(crypto::HASH_MSG_MAX);
                let buf = unsafe { &mut (*(&raw mut MSG)).0 };
                buf[..n].copy_from_slice(&req[..n]);

                // Ed25519 sign/verify roundtrip (P-256 ECDSA sign is rejected by
                // this part, but EdDSA works). Fresh keypair, sign, verify, then
                // verify a TRNG-forged signature (must reject).
                let mut ed = [0u8; 64];
                let g = crypto::se_ed25519_keygen(&mut ed);
                let mut reply = [0u8; crypto::ECDSA_REPLY];
                if g == 0 {
                    let mut sig = [0u8; 64];
                    let sst = crypto::se_ed25519_sign(&ed, &buf[..n], &mut sig);
                    let good = crypto::se_ed25519_verify(&ed, &buf[..n], &sig);

                    let mut rnd = [0u8; 1 + 2 * 8];
                    crypto::se_execute(
                        crypto::SE_CMD_TRNG_GET_RANDOM,
                        &[rnd.len() as u32],
                        &mut rnd,
                    );
                    let mut forged = sig;
                    let k = 1 + (rnd[0] as usize % 8);
                    for i in 0..k {
                        let pos = (((rnd[1 + 2 * i] as usize) << 8)
                            | rnd[2 + 2 * i] as usize)
                            % 512;
                        forged[pos / 8] ^= 1 << (pos % 8);
                    }
                    let forge = crypto::se_ed25519_verify(&ed, &buf[..n], &forged);

                    reply[0] = (sst == 0 && good == 0) as u8;
                    reply[1] = (forge != 0) as u8; // non-zero = rejected (good)
                    reply[2..66].copy_from_slice(&sig);
                    reply[66..130].copy_from_slice(&forged);
                }
                sys_reply(msg.sender, g, &reply);
            }
            crypto::OP_SE if msg.message_len >= 22 => {
                // [cmd(4), nparams(1), params(4*4), out_len(1)]
                let cmd = u32::from_le_bytes(req[0..4].try_into().unwrap());
                let nparams = (req[4] as usize).min(4);
                let mut params = [0u32; 4];
                for (i, p) in params.iter_mut().take(nparams).enumerate() {
                    *p = u32::from_le_bytes(
                        req[5 + i * 4..9 + i * 4].try_into().unwrap(),
                    );
                }
                let out_len = (req[21] as usize).min(crypto::SE_MAX_OUT);

                let mut out = [0u8; crypto::SE_MAX_OUT];
                let status =
                    crypto::se_execute(cmd, &params[..nparams], &mut out[..out_len]);

                // reply: [status(4), output(out_len)]
                let mut reply = [0u8; 4 + crypto::SE_MAX_OUT];
                reply[0..4].copy_from_slice(&status.to_le_bytes());
                reply[4..4 + out_len].copy_from_slice(&out[..out_len]);
                sys_reply(msg.sender, 0, &reply[..4 + out_len]);
            }
            _ => sys_reply(msg.sender, 1, &[]), // bad op / short message
        }
    }
}

// Generated notification masks (from app.toml `notifications`): AES_IRQ_MASK.
include!(concat!(env!("OUT_DIR"), "/notifications.rs"));
