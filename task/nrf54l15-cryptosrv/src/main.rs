// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Crypto server for the nRF54L15. Owns the CRACEN hardware and serves a
//! CRACEN-vs-Oberon benchmark, mirroring the EFR32MG24 `cryptosrv`.
//!
//! At boot it (1) confirms the AES-128 path on both engines against the
//! FIPS-197 known-answer vector, then (2) renders a throughput table sweeping
//! AES-128-ECB and SHA-256 over block sizes 16 B..4096 B. The table text is
//! published to the shared `crypto_sram` region; the `uart` task prints it on
//! the M33 console. The FLPR `bench` command (via `flpr_control`) re-runs it,
//! and `rng` requests hardware random bytes.

#![no_std]
#![no_main]

mod cracen;
mod ucode;

use core::ptr::{addr_of, addr_of_mut};
use userlib::*;

// Shared crypto region (see memory.toml `crypto_sram`). Written here, read by
// the uart task (table + KAT) and flpr_control (req/rng).
const C_BASE: usize = 0x2002_5c00;
const C_BENCH_SEL: *const u32 = C_BASE as *const u32; // which algorithm(s): SEL_*
const C_BENCH_REQ: *mut u32 = (C_BASE + 4) as *mut u32; // bumped by flpr_control
const C_BENCH_GEN: *mut u32 = (C_BASE + 8) as *mut u32; // bumped when table ready
const C_BENCH_LEN: *mut u32 = (C_BASE + 12) as *mut u32; // table byte length
const C_RNG_REQ: *mut u32 = (C_BASE + 16) as *mut u32;
const C_RNG_GEN: *mut u32 = (C_BASE + 20) as *mut u32;
const C_RNG_LEN: *mut u32 = (C_BASE + 24) as *mut u32;
const C_RNG_DATA: *mut u8 = (C_BASE + 28) as *mut u8; // up to RNG_MAX bytes
const BLOB_OFF: usize = 0x40; // table text starts here
const BLOB_MAX: usize = 0x2000 - BLOB_OFF;
const RNG_MAX: usize = 32;

// Benchmark selector written to C_BENCH_SEL by flpr_control's `bench [alg]`.
// 0 (and any unknown value) means "all", handled by the `_` arm in run_suite.
const SEL_AES: u32 = 1;
const SEL_SHA: u32 = 2;
const SEL_HMAC: u32 = 3;
const SEL_CMAC: u32 = 4;
const SEL_GCM: u32 = 5;
const SEL_ECDH: u32 = 6;
const SEL_ED25519: u32 = 7;
const SEL_P256: u32 = 8;
const SEL_CHACHA: u32 = 9;
const SEL_AES256: u32 = 10;
const SEL_SHA512: u32 = 11;
const SEL_SHA384: u32 = 12;
const SEL_CTR: u32 = 13;
const SEL_CBC: u32 = 14;
const SEL_RSA: u32 = 16;

/// Idle poll interval (ms) while waiting for a request.
const POLL_MS: u64 = 50;
/// Per-measurement time budget (ms). 9 sizes x 10 measurements x this.
const BUDGET_MS: u64 = 30;
/// Fixed 12-byte IV for the GCM benchmark (a benchmark reuses key+IV; that is
/// not safe for real GCM encryption, only for measuring throughput).
const IV: [u8; 12] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab];
/// 16-byte IV / initial counter for AES-CBC / AES-CTR.
const IV16: [u8; 16] = [
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
    0xbc, 0xbd, 0xbe, 0xbf,
];
/// Time budget (ms) for each asymmetric (per-op latency) measurement.
const ASYM_BUDGET_MS: u64 = 100;
/// X25519 test scalar and base u-coordinate (u = 9).
const X_SCALAR: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const X_BASE: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
];
/// Ed25519 test secret key and a 32-byte message (length a multiple of 4).
const ED_SK: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4,
    0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const ED_MSG: [u8; 32] = [
    0x72, 0x65, 0x73, 0x70, 0x65, 0x63, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x63, 0x6f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x6f, 0x72, 0x21,
    0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21,
];
/// Fixed P-256 ECDSA nonce for the benchmark (a real signature needs a fresh
/// random nonce; reusing one is only acceptable for measuring throughput).
const P256_K: [u8; 32] = [0x42; 32];
/// Block sizes swept, in bytes.
const SIZES: [usize; 9] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

// FIPS-197 AES-128 known-answer vector (Appendix B / C.1).
const KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
];
const PT: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff,
];
const EXPECT: [u8; 16] = [
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
    0x70, 0xb4, 0xc5, 0x5a,
];
// AES-256 key (the CRACEN engine infers key size from the descriptor length).
const KEY256: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

const MAXB: usize = 4096;

/// 4-byte-aligned DMA buffers, off the task stack.
#[repr(C, align(4))]
struct Buf([u8; MAXB]);
static mut BENCH_IN: Buf = Buf([0; MAXB]);
static mut BENCH_OUT: Buf = Buf([0; MAXB]);

/// RSA-2048 public exponent 65537 (big-endian) for the CRACEN side.
const RSA_E_BYTES: [u8; 3] = [0x01, 0x00, 0x01];
const RSA_E: u32 = 65537;
// RSA-2048 key material (filled at boot) + Oberon key/scratch buffers. The
// modulus only needs to be odd for a fair CRACEN-vs-Oberon modexp comparison.
static mut RSA_N: [u8; 256] = [0; 256];
static mut RSA_D: [u8; 256] = [0; 256];
static mut RSA_M: [u8; 256] = [0; 256];
static mut RSA_CT: [u8; 256] = [0; 256];
static mut RSA_OT: [u8; 256] = [0; 256];
static mut RSA_KEYMEM: [u32; 128] = [0; 128];
static mut RSA_SCRATCH: [u32; 1664] = [0; 1664];

/// Run `op` (processing `size` bytes per call) for [`BUDGET_MS`] and return the
/// achieved throughput in KiB/s.
fn kib_per_s(size: usize, mut op: impl FnMut()) -> u32 {
    let t0 = sys_get_timer().now;
    let mut ops = 0u64;
    loop {
        op();
        ops += 1;
        let dt = sys_get_timer().now - t0;
        if dt >= BUDGET_MS {
            return ((ops * size as u64 * 1000) / (dt * 1024)) as u32;
        }
    }
}

fn bench_cracen_aes(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let _ = cracen::aes_ecb_encrypt(&KEY, &inp[..sz], &mut out[..sz]);
    })
}
fn bench_oberon_aes(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        oberon_crypto::aes_ecb_encrypt(&KEY, &inp[..sz], &mut out[..sz]);
    })
}
fn bench_cracen_sha(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let mut d = [0u8; 32];
        let _ = cracen::sha256(&inp[..sz], &mut d);
    })
}
fn bench_oberon_sha(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let mut d = [0u8; 32];
        oberon_crypto::sha256(&inp[..sz], &mut d);
    })
}
fn bench_cracen_hmac(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let mut m = [0u8; 32];
        let _ = cracen::hmac_sha256(&KEY, &inp[..sz], &mut m);
    })
}
fn bench_oberon_hmac(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let mut m = [0u8; 32];
        oberon_crypto::hmac_sha256(&KEY, &inp[..sz], &mut m);
    })
}
fn bench_cracen_cmac(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let mut t = [0u8; 16];
        let _ = cracen::aes_cmac(&KEY, &inp[..sz], &mut t);
    })
}
fn bench_oberon_cmac(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let mut t = [0u8; 16];
        oberon_crypto::aes_cmac(&KEY, &inp[..sz], &mut t);
    })
}
fn bench_cracen_gcm(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let mut t = [0u8; 16];
        let _ = cracen::aes_gcm_encrypt(&KEY, &IV, &inp[..sz], &mut out[..sz], &mut t);
    })
}
fn bench_oberon_gcm(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let mut t = [0u8; 16];
        oberon_crypto::aes_gcm_encrypt(&KEY, &IV, &inp[..sz], &mut out[..sz], &mut t);
    })
}
// ChaCha20-Poly1305 uses a 32-byte key (X_SCALAR) and 12-byte nonce (IV).
fn bench_cracen_chacha(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let mut t = [0u8; 16];
        let _ = cracen::chacha20poly1305_encrypt(&X_SCALAR, &IV, &inp[..sz], &mut out[..sz], &mut t);
    })
}
fn bench_oberon_chacha(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let mut t = [0u8; 16];
        oberon_crypto::chacha20_poly1305_encrypt(&X_SCALAR, &IV, &inp[..sz], &mut out[..sz], &mut t);
    })
}
fn bench_cracen_aes256(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let _ = cracen::aes_ecb_encrypt(&KEY256, &inp[..sz], &mut out[..sz]);
    })
}
fn bench_oberon_aes256(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        oberon_crypto::aes_ecb_encrypt(&KEY256, &inp[..sz], &mut out[..sz]);
    })
}
fn bench_cracen_sha512(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let mut d = [0u8; 64];
        let _ = cracen::sha512(&inp[..sz], &mut d);
    })
}
fn bench_oberon_sha512(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let mut d = [0u8; 64];
        oberon_crypto::sha512(&inp[..sz], &mut d);
    })
}
fn bench_cracen_sha384(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let mut d = [0u8; 48];
        let _ = cracen::sha384(&inp[..sz], &mut d);
    })
}
fn bench_oberon_sha384(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let mut d = [0u8; 48];
        oberon_crypto::sha384(&inp[..sz], &mut d);
    })
}
fn bench_cracen_ctr(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let _ = cracen::aes_ctr_encrypt(&KEY, &IV16, &inp[..sz], &mut out[..sz]);
    })
}
fn bench_oberon_ctr(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        oberon_crypto::aes_ctr_encrypt(&KEY, &IV16, &inp[..sz], &mut out[..sz]);
    })
}
fn bench_cracen_cbc(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let _ = cracen::aes_cbc_encrypt(&KEY, &IV16, &inp[..sz], &mut out[..sz]);
    })
}
fn bench_oberon_cbc(sz: usize) -> u32 {
    kib_per_s(sz, || {
        let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        oberon_crypto::aes_cbc_encrypt(&KEY, &IV16, &inp[..sz], &mut out[..sz]);
    })
}

/// Run `op` for [`ASYM_BUDGET_MS`] and return the per-op latency in microseconds.
fn us_per_op(mut op: impl FnMut()) -> u32 {
    let t0 = sys_get_timer().now;
    let mut ops = 0u64;
    loop {
        op();
        ops += 1;
        let dt = sys_get_timer().now - t0;
        if dt >= ASYM_BUDGET_MS {
            return ((dt * 1000) / ops) as u32;
        }
    }
}
fn bench_cracen_x25519() -> u32 {
    us_per_op(|| {
        let mut o = [0u8; 32];
        let _ = cracen::x25519(&X_SCALAR, &X_BASE, &mut o);
    })
}
fn bench_oberon_x25519() -> u32 {
    us_per_op(|| {
        let mut o = [0u8; 32];
        oberon_crypto::x25519_ecdh(&X_SCALAR, &X_BASE, &mut o);
    })
}

/// Append-only writer into the shared `crypto_sram` table blob.
struct Blob {
    pos: usize,
}
impl Blob {
    fn new() -> Self {
        Blob { pos: 0 }
    }
    fn put(&mut self, b: u8) {
        if self.pos < BLOB_MAX {
            unsafe {
                core::ptr::write_volatile(
                    (C_BASE + BLOB_OFF + self.pos) as *mut u8,
                    b,
                );
            }
            self.pos += 1;
        }
    }
    fn s(&mut self, s: &[u8]) {
        for &b in s {
            self.put(b);
        }
    }
    fn u(&mut self, v: u32) {
        let mut d = [0u8; 10];
        let mut n = 0;
        let mut x = v;
        loop {
            d[n] = b'0' + (x % 10) as u8;
            n += 1;
            x /= 10;
            if x == 0 {
                break;
            }
        }
        while n > 0 {
            n -= 1;
            self.put(d[n]);
        }
    }
    fn hx(&mut self, b: u8) {
        const D: &[u8; 16] = b"0123456789abcdef";
        self.put(D[(b >> 4) as usize]);
        self.put(D[(b & 0xf) as usize]);
    }
    /// `v` right-justified in a `w`-wide field.
    fn pad(&mut self, v: u32, w: usize) {
        let mut len = 1;
        let mut x = v;
        while x >= 10 {
            x /= 10;
            len += 1;
        }
        for _ in len..w {
            self.put(b' ');
        }
        self.u(v);
    }
    fn row(&mut self, size: u32, cracen: u32, oberon: u32) {
        self.pad(size, 6);
        self.pad(cracen, 10);
        self.pad(oberon, 10);
        self.s(b"\r\n");
    }
    /// `us` microseconds rendered as `int.frac3` ms, right-justified in `w`.
    fn ms3(&mut self, us: u32, w: usize) {
        let int = us / 1000;
        let mut il = 1;
        let mut x = int;
        while x >= 10 {
            x /= 10;
            il += 1;
        }
        for _ in (il + 4)..w {
            self.put(b' ');
        }
        self.u(int);
        self.put(b'.');
        let frac = us % 1000;
        self.put(b'0' + (frac / 100) as u8);
        self.put(b'0' + (frac / 10 % 10) as u8);
        self.put(b'0' + (frac % 10) as u8);
    }
    fn row_ms(&mut self, label: &[u8], cracen_us: u32, oberon_us: u32) {
        self.s(b" ");
        self.s(label);
        for _ in label.len()..15 {
            self.put(b' ');
        }
        self.ms3(cracen_us, 9);
        self.ms3(oberon_us, 10);
        self.s(b"\r\n");
    }
}

/// Render the benchmark table into the shared blob and bump the ready counter.
/// Append a symmetric size-sweep section (KiB/s) for one algorithm.
fn sweep(b: &mut Blob, name: &[u8], cf: fn(usize) -> u32, of: fn(usize) -> u32) {
    b.s(name);
    b.s(b"\r\n bytes    CRACEN    OBERON\r\n");
    for &sz in &SIZES {
        b.row(sz as u32, cf(sz), of(sz));
    }
}

fn asym_hdr(b: &mut Blob) {
    b.s(b"asymmetric (ms/op)\r\n op              CRACEN    OBERON\r\n");
}

/// Append the X25519 ECDH latency row.
fn asym_ecdh(b: &mut Blob) {
    b.row_ms(b"X25519-ECDH", bench_cracen_x25519(), bench_oberon_x25519());
}

/// Append the Ed25519 sign + verify latency rows.
fn asym_ed25519(b: &mut Blob) {
    let mut pk = [0u8; 32];
    oberon_crypto::ed25519_public_key(&ED_SK, &mut pk);
    let mut osig = [0u8; 64];
    oberon_crypto::ed25519_sign(&ED_SK, &pk, &ED_MSG, &mut osig);
    b.row_ms(
        b"Ed25519-sign",
        us_per_op(|| {
            let mut s = [0u8; 64];
            let _ = cracen::ed25519_sign(&ED_SK, &ED_MSG, &mut s);
        }),
        us_per_op(|| {
            let mut s = [0u8; 64];
            oberon_crypto::ed25519_sign(&ED_SK, &pk, &ED_MSG, &mut s);
        }),
    );
    b.row_ms(
        b"Ed25519-verify",
        us_per_op(|| {
            let _ = cracen::ed25519_verify(&pk, &ED_MSG, &osig);
        }),
        us_per_op(|| {
            let _ = oberon_crypto::ed25519_verify(&pk, &ED_MSG, &osig);
        }),
    );
}

/// Append the P-256 ECDH + ECDSA sign/verify latency rows.
fn asym_p256(b: &mut Blob) {
    let mut h = [0u8; 32];
    let _ = cracen::sha256(&ED_MSG, &mut h);
    let mut pubk = [0u8; 64];
    oberon_crypto::p256_public_key(&X_SCALAR, &mut pubk);
    let mut pub_b = [0u8; 64];
    oberon_crypto::p256_public_key(&ED_SK, &mut pub_b);
    let mut osig = [0u8; 64];
    oberon_crypto::p256_ecdsa_sign_hash(&h, &X_SCALAR, &P256_K, &mut osig);
    b.row_ms(
        b"P256-ECDH",
        us_per_op(|| {
            let mut s = [0u8; 32];
            let _ = cracen::p256_ecdh(&X_SCALAR, &pub_b, &mut s);
        }),
        us_per_op(|| {
            let mut s = [0u8; 32];
            let _ = oberon_crypto::p256_ecdh(&X_SCALAR, &pub_b, &mut s);
        }),
    );
    b.row_ms(
        b"P256-sign",
        us_per_op(|| {
            let mut s = [0u8; 64];
            let _ = cracen::p256_ecdsa_sign(&X_SCALAR, &h, &P256_K, &mut s);
        }),
        us_per_op(|| {
            let mut s = [0u8; 64];
            let _ = oberon_crypto::p256_ecdsa_sign_hash(&h, &X_SCALAR, &P256_K, &mut s);
        }),
    );
    b.row_ms(
        b"P256-verify",
        us_per_op(|| {
            let _ = cracen::p256_ecdsa_verify(&pubk, &h, &osig);
        }),
        us_per_op(|| {
            let _ = oberon_crypto::p256_ecdsa_verify_hash(&h, &pubk, &osig);
        }),
    );
}

/// Append the RSA-2048 public/private modexp latency rows.
fn asym_rsa(b: &mut Blob) {
    b.row_ms(
        b"RSA2048-pub",
        us_per_op(|| {
            let m = unsafe { &*addr_of!(RSA_M) };
            let n = unsafe { &*addr_of!(RSA_N) };
            let o = unsafe { &mut *addr_of_mut!(RSA_CT) };
            let _ = cracen::rsa2048_modexp(m, &RSA_E_BYTES, n, o);
        }),
        us_per_op(|| {
            let m = unsafe { &*addr_of!(RSA_M) };
            let n = unsafe { &*addr_of!(RSA_N) };
            let o = unsafe { &mut *addr_of_mut!(RSA_OT) };
            let km = unsafe { &mut *addr_of_mut!(RSA_KEYMEM) };
            let sc = unsafe { &mut *addr_of_mut!(RSA_SCRATCH) };
            let _ = oberon_crypto::rsa2048_pub_exp(n, RSA_E, m, o, km, sc);
        }),
    );
    b.row_ms(
        b"RSA2048-priv",
        us_per_op(|| {
            let m = unsafe { &*addr_of!(RSA_M) };
            let n = unsafe { &*addr_of!(RSA_N) };
            let d = unsafe { &*addr_of!(RSA_D) };
            let o = unsafe { &mut *addr_of_mut!(RSA_CT) };
            let _ = cracen::rsa2048_modexp(m, d, n, o);
        }),
        us_per_op(|| {
            let m = unsafe { &*addr_of!(RSA_M) };
            let n = unsafe { &*addr_of!(RSA_N) };
            let d = unsafe { &*addr_of!(RSA_D) };
            let o = unsafe { &mut *addr_of_mut!(RSA_OT) };
            let km = unsafe { &mut *addr_of_mut!(RSA_KEYMEM) };
            let sc = unsafe { &mut *addr_of_mut!(RSA_SCRATCH) };
            let _ = oberon_crypto::rsa2048_priv_exp(n, d, m, o, km, sc);
        }),
    );
}

/// Run every correctness self-check (CRACEN vs Oberon) and append the result
/// line. For GCM the auth tag covers the ciphertext, so matching tags imply
/// matching ciphertext.
fn self_check(b: &mut Blob) {
    let inp = unsafe { &(*addr_of!(BENCH_IN)).0 };
    let mut act = [0u8; 16];
    let aes_ok = cracen::aes_ecb_encrypt(&KEY, &PT, &mut act)
        && act == EXPECT
        && {
            oberon_crypto::aes_ecb_encrypt(&KEY, &PT, &mut act);
            act == EXPECT
        };
    let mut a = [0u8; 32];
    let mut o = [0u8; 32];
    let sha_ok = cracen::sha256(&inp[..256], &mut a) && {
        oberon_crypto::sha256(&inp[..256], &mut o);
        a == o
    };
    let hmac_ok = cracen::hmac_sha256(&KEY, &inp[..256], &mut a) && {
        oberon_crypto::hmac_sha256(&KEY, &inp[..256], &mut o);
        a == o
    };
    let mut ta = [0u8; 16];
    let mut to = [0u8; 16];
    let cmac_ok = cracen::aes_cmac(&KEY, &inp[..256], &mut ta) && {
        oberon_crypto::aes_cmac(&KEY, &inp[..256], &mut to);
        ta == to
    };
    let gcm_ok = {
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let c = cracen::aes_gcm_encrypt(&KEY, &IV, &inp[..256], &mut out[..256], &mut ta);
        oberon_crypto::aes_gcm_encrypt(&KEY, &IV, &inp[..256], &mut out[..256], &mut to);
        c && ta == to
    };
    let cc_ok = {
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let c = cracen::chacha20poly1305_encrypt(&X_SCALAR, &IV, &inp[..256], &mut out[..256], &mut ta);
        oberon_crypto::chacha20_poly1305_encrypt(&X_SCALAR, &IV, &inp[..256], &mut out[..256], &mut to);
        c && ta == to
    };
    let aes256_ok = {
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let mut ob = [0u8; 256];
        let c = cracen::aes_ecb_encrypt(&KEY256, &inp[..256], &mut out[..256]);
        oberon_crypto::aes_ecb_encrypt(&KEY256, &inp[..256], &mut ob);
        c && out[..256] == ob
    };
    let mut d5a = [0u8; 64];
    let mut d5o = [0u8; 64];
    let sha512_ok = cracen::sha512(&inp[..256], &mut d5a) && {
        oberon_crypto::sha512(&inp[..256], &mut d5o);
        d5a == d5o
    };
    let mut d3a = [0u8; 48];
    let mut d3o = [0u8; 48];
    let sha384_ok = cracen::sha384(&inp[..256], &mut d3a) && {
        oberon_crypto::sha384(&inp[..256], &mut d3o);
        d3a == d3o
    };
    let ctr_ok = {
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let mut ob = [0u8; 256];
        let c = cracen::aes_ctr_encrypt(&KEY, &IV16, &inp[..256], &mut out[..256]);
        oberon_crypto::aes_ctr_encrypt(&KEY, &IV16, &inp[..256], &mut ob);
        c && out[..256] == ob
    };
    let cbc_ok = {
        let out = unsafe { &mut (*addr_of_mut!(BENCH_OUT)).0 };
        let mut ob = [0u8; 256];
        let c = cracen::aes_cbc_encrypt(&KEY, &IV16, &inp[..256], &mut out[..256]);
        oberon_crypto::aes_cbc_encrypt(&KEY, &IV16, &inp[..256], &mut ob);
        c && out[..256] == ob
    };
    let mut pa = [0u8; 32];
    let mut pb = [0u8; 32];
    let mut sa = [0u8; 32];
    let mut sb = [0u8; 32];
    let mut so = [0u8; 32];
    let ecdh_ok = cracen::x25519(&X_SCALAR, &X_BASE, &mut pa)
        && cracen::x25519(&ED_SK, &X_BASE, &mut pb)
        && cracen::x25519(&X_SCALAR, &pb, &mut sa)
        && cracen::x25519(&ED_SK, &pa, &mut sb)
        && sa == sb
        && {
            oberon_crypto::x25519_ecdh(&X_SCALAR, &pb, &mut so);
            sa == so
        };
    let mut epk = [0u8; 32];
    oberon_crypto::ed25519_public_key(&ED_SK, &mut epk);
    let mut eo = [0u8; 64];
    oberon_crypto::ed25519_sign(&ED_SK, &epk, &ED_MSG, &mut eo);
    let mut ec = [0u8; 64];
    let ed_sign_ok = cracen::ed25519_sign(&ED_SK, &ED_MSG, &mut ec) && ec == eo;
    let ed_verify_ok = cracen::ed25519_verify(&epk, &ED_MSG, &eo) == Some(true);

    // P-256: ECDH agreement + ECDSA sign (same nonce) matches Oberon, verify ok.
    let mut h = [0u8; 32];
    let _ = cracen::sha256(&ED_MSG, &mut h);
    let mut ppa = [0u8; 64];
    oberon_crypto::p256_public_key(&X_SCALAR, &mut ppa);
    let mut ppb = [0u8; 64];
    oberon_crypto::p256_public_key(&ED_SK, &mut ppb);
    let mut psa = [0u8; 32];
    let mut psb = [0u8; 32];
    let mut pso = [0u8; 32];
    let p256_dh_run = cracen::p256_ecdh(&X_SCALAR, &ppb, &mut psa)
        && cracen::p256_ecdh(&ED_SK, &ppa, &mut psb);
    oberon_crypto::p256_ecdh(&X_SCALAR, &ppb, &mut pso);
    let p256_ab = psa == psb; // CRACEN agrees with itself (two-party)
    let p256_ao = psa == pso; // CRACEN matches Oberon
    let p256_ecdh_ok = p256_dh_run && p256_ab && p256_ao;
    let mut pos = [0u8; 64];
    oberon_crypto::p256_ecdsa_sign_hash(&h, &X_SCALAR, &P256_K, &mut pos);
    let mut pcs = [0u8; 64];
    let p256_sign_ok =
        cracen::p256_ecdsa_sign(&X_SCALAR, &h, &P256_K, &mut pcs) && pcs == pos;
    let p256_verify_ok = cracen::p256_ecdsa_verify(&ppa, &h, &pos) == Some(true);

    // RSA-2048: CRACEN modexp vs Oberon modexp over the same key material.
    let rn = unsafe { &*addr_of!(RSA_N) };
    let rm = unsafe { &*addr_of!(RSA_M) };
    let rd = unsafe { &*addr_of!(RSA_D) };
    let rsa_pub_ok = {
        let ct = unsafe { &mut *addr_of_mut!(RSA_CT) };
        let ot = unsafe { &mut *addr_of_mut!(RSA_OT) };
        let km = unsafe { &mut *addr_of_mut!(RSA_KEYMEM) };
        let sc = unsafe { &mut *addr_of_mut!(RSA_SCRATCH) };
        cracen::rsa2048_modexp(rm, &RSA_E_BYTES, rn, ct)
            && oberon_crypto::rsa2048_pub_exp(rn, RSA_E, rm, ot, km, sc)
            && ct == ot
    };
    let rsa_priv_ok = {
        let ct = unsafe { &mut *addr_of_mut!(RSA_CT) };
        let ot = unsafe { &mut *addr_of_mut!(RSA_OT) };
        let km = unsafe { &mut *addr_of_mut!(RSA_KEYMEM) };
        let sc = unsafe { &mut *addr_of_mut!(RSA_SCRATCH) };
        cracen::rsa2048_modexp(rm, rd, rn, ct)
            && oberon_crypto::rsa2048_priv_exp(rn, rd, rm, ot, km, sc)
            && ct == ot
    };

    let yn = |ok: bool| -> &'static [u8] { if ok { b"ok" } else { b"FAIL" } };
    b.s(b"self-check sym:  AES ");
    b.s(yn(aes_ok));
    b.s(b" SHA ");
    b.s(yn(sha_ok));
    b.s(b" HMAC ");
    b.s(yn(hmac_ok));
    b.s(b" CMAC ");
    b.s(yn(cmac_ok));
    b.s(b" GCM ");
    b.s(yn(gcm_ok));
    b.s(b" ChaChaPoly ");
    b.s(yn(cc_ok));
    b.s(b" AES256 ");
    b.s(yn(aes256_ok));
    b.s(b" SHA512 ");
    b.s(yn(sha512_ok));
    b.s(b" SHA384 ");
    b.s(yn(sha384_ok));
    b.s(b" CTR ");
    b.s(yn(ctr_ok));
    b.s(b" CBC ");
    b.s(yn(cbc_ok));
    b.s(b"\r\nself-check asym: ECDH ");
    b.s(yn(ecdh_ok));
    b.s(b" Ed-sign ");
    b.s(yn(ed_sign_ok));
    b.s(b" Ed-vrfy ");
    b.s(yn(ed_verify_ok));
    b.s(b" P256-dh ");
    b.s(yn(p256_ecdh_ok));
    if !p256_ecdh_ok {
        b.s(b"(st=");
        b.u(cracen::p256_ecdh_status(&X_SCALAR, &ppb));
        b.s(b" a==b:");
        b.s(yn(p256_ab));
        b.s(b" a==o:");
        b.s(yn(p256_ao));
        b.s(b" ob=");
        for &x in &pso[..6] {
            b.hx(x);
        }
        // Dump the first 6 bytes of each candidate output slot to find the one
        // that holds Oberon's shared secret X (ob=...).
        for &slot in &[4usize, 5, 11, 12, 13] {
            let mut s = [0u8; 32];
            let _ = cracen::p256_ecdh_read(&X_SCALAR, &ppb, slot, &mut s);
            b.s(b" s");
            b.u(slot as u32);
            b.s(b"=");
            for &x in &s[..6] {
                b.hx(x);
            }
        }
        b.s(b")");
    }
    b.s(b" P256-sign ");
    b.s(yn(p256_sign_ok));
    b.s(b" P256-vrfy ");
    b.s(yn(p256_verify_ok));
    b.s(b" RSA-pub ");
    b.s(yn(rsa_pub_ok));
    b.s(b" RSA-priv ");
    b.s(yn(rsa_priv_ok));
    b.s(b"\r\n");
}

/// Render the benchmark table for the selected algorithm(s) into the shared
/// blob and bump the ready counter.
fn run_suite(sel: u32) {
    let mut b = Blob::new();
    b.s(b"\r\n=== CRACEN vs Oberon ===\r\n");
    match sel {
        SEL_AES => sweep(&mut b, b"AES-128-ECB", bench_cracen_aes, bench_oberon_aes),
        SEL_SHA => sweep(&mut b, b"SHA-256", bench_cracen_sha, bench_oberon_sha),
        SEL_HMAC => {
            sweep(&mut b, b"HMAC-SHA256", bench_cracen_hmac, bench_oberon_hmac)
        }
        SEL_CMAC => {
            sweep(&mut b, b"AES-128-CMAC", bench_cracen_cmac, bench_oberon_cmac)
        }
        SEL_GCM => sweep(&mut b, b"AES-128-GCM", bench_cracen_gcm, bench_oberon_gcm),
        SEL_CHACHA => sweep(
            &mut b,
            b"ChaCha20-Poly1305",
            bench_cracen_chacha,
            bench_oberon_chacha,
        ),
        SEL_AES256 => sweep(&mut b, b"AES-256-ECB", bench_cracen_aes256, bench_oberon_aes256),
        SEL_SHA512 => sweep(&mut b, b"SHA-512", bench_cracen_sha512, bench_oberon_sha512),
        SEL_SHA384 => sweep(&mut b, b"SHA-384", bench_cracen_sha384, bench_oberon_sha384),
        SEL_CTR => sweep(&mut b, b"AES-128-CTR", bench_cracen_ctr, bench_oberon_ctr),
        SEL_CBC => sweep(&mut b, b"AES-128-CBC", bench_cracen_cbc, bench_oberon_cbc),
        SEL_ECDH => {
            asym_hdr(&mut b);
            asym_ecdh(&mut b);
        }
        SEL_ED25519 => {
            asym_hdr(&mut b);
            asym_ed25519(&mut b);
        }
        SEL_P256 => {
            asym_hdr(&mut b);
            asym_p256(&mut b);
        }
        SEL_RSA => {
            asym_hdr(&mut b);
            asym_rsa(&mut b);
        }
        _ => {
            self_check(&mut b);
            sweep(&mut b, b"AES-128-ECB", bench_cracen_aes, bench_oberon_aes);
            sweep(&mut b, b"SHA-256", bench_cracen_sha, bench_oberon_sha);
            sweep(&mut b, b"HMAC-SHA256", bench_cracen_hmac, bench_oberon_hmac);
            sweep(&mut b, b"AES-128-CMAC", bench_cracen_cmac, bench_oberon_cmac);
            sweep(&mut b, b"AES-128-GCM", bench_cracen_gcm, bench_oberon_gcm);
            sweep(
                &mut b,
                b"ChaCha20-Poly1305",
                bench_cracen_chacha,
                bench_oberon_chacha,
            );
            sweep(&mut b, b"AES-256-ECB", bench_cracen_aes256, bench_oberon_aes256);
            sweep(&mut b, b"SHA-512", bench_cracen_sha512, bench_oberon_sha512);
            sweep(&mut b, b"SHA-384", bench_cracen_sha384, bench_oberon_sha384);
            sweep(&mut b, b"AES-128-CTR", bench_cracen_ctr, bench_oberon_ctr);
            sweep(&mut b, b"AES-128-CBC", bench_cracen_cbc, bench_oberon_cbc);
            asym_hdr(&mut b);
            asym_ecdh(&mut b);
            asym_ed25519(&mut b);
            asym_p256(&mut b);
            asym_rsa(&mut b);
        }
    }
    unsafe {
        core::ptr::write_volatile(C_BENCH_LEN, b.pos as u32);
        let g = core::ptr::read_volatile(C_BENCH_GEN).wrapping_add(1);
        core::ptr::write_volatile(C_BENCH_GEN, g);
    }
}

/// Fill the requested random bytes into the shared region; write back the
/// produced length (0 on error) and bump the rng counter last.
fn serve_rng() {
    let n = (unsafe { core::ptr::read_volatile(C_RNG_LEN) } as usize).min(RNG_MAX);
    let mut buf = [0u8; RNG_MAX];
    let ok = cracen::rng_fill(&mut buf[..n]);
    unsafe {
        if ok {
            for (i, &b) in buf[..n].iter().enumerate() {
                core::ptr::write_volatile(C_RNG_DATA.add(i), b);
            }
            core::ptr::write_volatile(C_RNG_LEN, n as u32);
        } else {
            core::ptr::write_volatile(C_RNG_LEN, 0);
        }
        let g = core::ptr::read_volatile(C_RNG_GEN).wrapping_add(1);
        core::ptr::write_volatile(C_RNG_GEN, g);
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    // Fill the input buffer with a non-trivial pattern (so hashing isn't all-zero).
    let buf = unsafe { &mut (*addr_of_mut!(BENCH_IN)).0 };
    for (i, b) in buf.iter_mut().enumerate() {
        *b = i as u8;
    }

    // RSA key material: an odd 2048-bit modulus and a base m < n (only oddness
    // is needed for a fair CRACEN-vs-Oberon modexp comparison).
    {
        let n = unsafe { &mut *addr_of_mut!(RSA_N) };
        for (i, b) in n.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(0x33);
        }
        n[0] |= 0x80;
        n[255] |= 0x01;
        let m = unsafe { &mut *addr_of_mut!(RSA_M) };
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(5).wrapping_add(0x11);
        }
        m[0] = 0x42;
        let d = unsafe { &mut *addr_of_mut!(RSA_D) };
        for (i, b) in d.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(0x77);
        }
    }

    // Nothing prints at boot. The benchmark renders only on an FLPR `bench`
    // request; the selector word says which algorithm(s).
    let mut bench_handled = unsafe { core::ptr::read_volatile(C_BENCH_REQ) };
    let mut rng_handled = unsafe { core::ptr::read_volatile(C_RNG_REQ) };
    loop {
        hl::sleep_for(POLL_MS);
        let bench_req = unsafe { core::ptr::read_volatile(C_BENCH_REQ) };
        if bench_req != bench_handled {
            bench_handled = bench_req;
            let sel = unsafe { core::ptr::read_volatile(C_BENCH_SEL) };
            run_suite(sel);
        }
        let rng_req = unsafe { core::ptr::read_volatile(C_RNG_REQ) };
        if rng_req != rng_handled {
            rng_handled = rng_req;
            serve_rng();
        }
    }
}
