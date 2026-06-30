// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal CRACEN CryptoMaster driver: a single AES-128-ECB block, polled.
//!
//! The CryptoMaster is a Silex scatter-gather DMA engine. To run an operation
//! you build two linked lists of 16-byte descriptors in RAM -- a "fetch" (input)
//! list and a "push" (output) list -- point the engine at their heads, and kick
//! both DMAs. For AES-ECB-128 encrypt the fetch list is three descriptors:
//!
//!   1. the 32-bit config word, routed to the engine's config interface
//!   2. the 16-byte key, routed to the key config register
//!   3. the 16-byte plaintext, routed to the data interface (marked "last")
//!
//! and the push list is one descriptor receiving the 16-byte ciphertext. Key
//! length is inferred from the key descriptor's byte length (16 => AES-128).
//!
//! Register offsets and the descriptor/tag layout are transliterated from the
//! Silex `sxsymcrypt` driver (`sx_blkcipher_ecb_simple`) and the nrfx CRACEN
//! HAL; addresses were cross-checked against `nrf-pac` (CRACEN_S @ 0x5004_8000,
//! CRACENCORE @ 0x5180_0000).

use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

// CRACEN wrapper: ENABLE register at offset 0x400. bit 0 = CryptoMaster, bit 1
// = RNG module, bit 2 = PKE/IKG module.
const CRACEN_ENABLE: *mut u32 = 0x5004_8400 as *mut u32;
const ENABLE_CRYPTOMASTER: u32 = 1 << 0;
const ENABLE_RNG: u32 = 1 << 1;
const ENABLE_PKEIKG: u32 = 1 << 2;

// CryptoMaster scatter-gather DMA registers (CRACENCORE base + offset).
const CM_BASE: usize = 0x5180_0000;
const CM_FETCHADDR: *mut u32 = CM_BASE as *mut u32; // 0x00
const CM_PUSHADDR: *mut u32 = (CM_BASE + 0x10) as *mut u32; // 0x10
const CM_INTSTATRAW: *const u32 = (CM_BASE + 0x28) as *const u32; // 0x28
const CM_CONFIG: *mut u32 = (CM_BASE + 0x34) as *mut u32; // 0x34
const CM_START: *mut u32 = (CM_BASE + 0x38) as *mut u32; // 0x38
const CM_STATUS: *const u32 = (CM_BASE + 0x3c) as *const u32; // 0x3c

const CONFIG_SCATTER_GATHER: u32 = 0x3; // indirect fetch (bit0) + push (bit1)
const START_FETCH_PUSH: u32 = 0x3; // start fetch (bit0) + push (bit1)
const STATUS_BUSY_MASK: u32 = 0x23; // fetcher/pusher busy + pusher-waiting
const ERR_MASK: u32 = (1 << 2) | (1 << 5); // fetcher / pusher bus error

// Descriptor `sz` flags and `next` sentinel.
const SZ_REALIGN: u32 = 1 << 29; // pad block to the engine's FIFO word
const NEXT_STOP: u32 = 1; // a `next` of 0x1 marks the last descriptor

// Descriptor `dmatag` (fetch side): engine select + routing.
const TAG_BA411: u32 = 1; // AES engine
const TAG_CONFIG: u32 = 1 << 4; // route to the engine's config interface
const TAG_LAST: u32 = 1 << 5; // assert the "last block" sideband
const TAG_CFG: u32 = TAG_BA411 | TAG_CONFIG | (0x00 << 8); // config word @ cfg off 0x00
const TAG_KEY: u32 = TAG_BA411 | TAG_CONFIG | (0x08 << 8); // key @ cfg off 0x08
const TAG_DATA_LAST: u32 = TAG_BA411 | TAG_LAST; // plaintext, last fetch block
const TAG_PUSH_LAST: u32 = TAG_LAST; // ciphertext, last push block

// AES config word: mode = ECB (one-hot bit 8), direction = encrypt (bit 0 = 0),
// software-programmed key (bits[7:6] = 0), no context load/save.
const AES128_ECB_ENCRYPT: u32 = 0x0000_0100;
// AES-CBC encrypt (mode one-hot bit 9) and AES-CTR (bit 10); both take a 16-byte IV.
const AES_CBC_ENCRYPT: u32 = 0x0000_0200;
const AES_CTR_ENCRYPT: u32 = 0x0000_0400;

// BA413 hash engine (engine selector 3). One-shot SHA-256: a config word plus
// the message; the engine pads and finalizes in hardware.
const TAG_BA413: u32 = 3;
const TAG_SHA_CFG: u32 = TAG_BA413 | TAG_CONFIG; // 0x13 (config @ offset 0)
const TAG_SHA_DATA_LAST: u32 = TAG_BA413 | TAG_LAST; // 0x23 (message, last block)
// algo = SHA-256 (0x08) | HASH_HW_PAD (1<<9) | HASH_FINAL (1<<10).
const SHA256_MODE: u32 = 0x0000_0608;
// algo = SHA-512 (0x20) | HASH_HW_PAD | HASH_FINAL.
const SHA512_MODE: u32 = 0x0000_0620;
// algo = SHA-384 (0x10) | HASH_HW_PAD | HASH_FINAL.
const SHA384_MODE: u32 = 0x0000_0610;
// HMAC-SHA256: SHA-256 config | BA413_HMAC_CONF (1<<8).
const HMAC_SHA256_MODE: u32 = 0x0000_0708;
const TAG_HMAC_KEY: u32 = TAG_BA413 | (2 << 6) | TAG_LAST; // 0xA3 (HMAC key, last)

// AES-CMAC: mode CMAC (one-hot bit 16), user key, no direction bit.
const AES_CMAC_MODE: u32 = 0x0001_0000;
// AES-GCM encrypt: mode GCM (one-hot bit 14), encrypt, user key.
const AES_GCM_ENCRYPT: u32 = 0x0000_4000;
const TAG_DATA: u32 = TAG_BA411; // 0x01 message data (not last)
const TAG_IV: u32 = TAG_BA411 | TAG_CONFIG | (0x28 << 8); // 0x2811 iv_or_state

// Bounded completion poll so a misbehaving engine can't wedge the task. Sized
// generously so the slowest PKE op (RSA-2048 modexp) completes within budget.
const DONE_BUDGET: u32 = 8_000_000;

/// A CryptoMaster DMA descriptor (16 bytes, 4-byte aligned).
#[repr(C, align(4))]
struct Desc {
    addr: u32,
    next: u32,
    sz: u32,
    tag: u32,
}

/// Point the CryptoMaster at the given fetch/push descriptor-list heads, enable
/// the engine, kick both DMAs, and poll to completion. Returns false on timeout
/// or bus error. The caller's descriptors/buffers must outlive this call.
///
/// Safety: `fetch`/`push` are addresses of live, DMA-reachable descriptor lists.
unsafe fn run_dma(fetch: u32, push: u32) -> bool {
    unsafe {
        // Power on the CryptoMaster module (idempotent).
        let en = core::ptr::read_volatile(CRACEN_ENABLE);
        core::ptr::write_volatile(CRACEN_ENABLE, en | ENABLE_CRYPTOMASTER);

        core::ptr::write_volatile(CM_FETCHADDR, fetch);
        core::ptr::write_volatile(CM_PUSHADDR, push);
        core::ptr::write_volatile(CM_CONFIG, CONFIG_SCATTER_GATHER);

        // Ensure descriptor/buffer writes land before the DMA reads them.
        compiler_fence(Ordering::SeqCst);
        core::ptr::write_volatile(CM_START, START_FETCH_PUSH);

        let mut budget = DONE_BUDGET;
        while core::ptr::read_volatile(CM_STATUS) & STATUS_BUSY_MASK != 0 {
            budget -= 1;
            if budget == 0 {
                return false;
            }
        }
        compiler_fence(Ordering::SeqCst);
        core::ptr::read_volatile(CM_INTSTATRAW) & ERR_MASK == 0
    }
}

/// Encrypt `pt` into `ct` with AES-128-ECB on the CRACEN CryptoMaster. `pt` and
/// `ct` must be equal-length, non-empty multiples of the 16-byte block size (the
/// engine streams each block independently). Returns `true` if the DMA completed
/// without a bus error.
///
/// All descriptors and the config word live on this function's stack (task
/// SRAM, which the CryptoMaster can master) and outlive the synchronous poll.
pub fn aes_ecb_encrypt(key: &[u8], pt: &[u8], ct: &mut [u8]) -> bool {
    debug_assert!(!pt.is_empty() && pt.len() % 16 == 0 && pt.len() == ct.len());
    let len = pt.len() as u32 & 0x00ff_ffff;
    let cmd: u32 = AES128_ECB_ENCRYPT;

    let mut fetch = [
        Desc {
            addr: &cmd as *const u32 as u32,
            next: 0,
            sz: SZ_REALIGN | 4,
            tag: TAG_CFG,
        },
        Desc {
            addr: key.as_ptr() as u32,
            next: 0,
            sz: SZ_REALIGN | key.len() as u32,
            tag: TAG_KEY,
        },
        Desc {
            addr: pt.as_ptr() as u32,
            next: NEXT_STOP,
            sz: SZ_REALIGN | len,
            tag: TAG_DATA_LAST,
        },
    ];
    fetch[0].next = &fetch[1] as *const Desc as u32;
    fetch[1].next = &fetch[2] as *const Desc as u32;

    let push = Desc {
        addr: ct.as_mut_ptr() as u32,
        next: NEXT_STOP,
        sz: SZ_REALIGN | len,
        tag: TAG_PUSH_LAST,
    };

    // Safety: fixed CRACEN MMIO (granted to this task) and stack-resident DMA
    // buffers that outlive the synchronous completion poll inside run_dma.
    unsafe {
        run_dma(
            &fetch[0] as *const Desc as u32,
            &push as *const Desc as u32,
        )
    }
}

/// One-shot hash on the BA413 engine: config word `mode`, message `msg`, into a
/// `digest`-sized push. `msg.len()` must be a multiple of 4 (the hardware pads
/// and finalizes). Returns false on a DMA bus error.
fn hash_oneshot(mode: u32, msg: &[u8], digest: &mut [u8]) -> bool {
    debug_assert!(msg.len() % 4 == 0);
    let len = msg.len() as u32 & 0x00ff_ffff;
    let cfg: u32 = mode;

    let mut fetch = [
        Desc { addr: &cfg as *const u32 as u32, next: 0, sz: SZ_REALIGN | 4, tag: TAG_SHA_CFG },
        Desc { addr: msg.as_ptr() as u32, next: NEXT_STOP, sz: SZ_REALIGN | len, tag: TAG_SHA_DATA_LAST },
    ];
    fetch[0].next = &fetch[1] as *const Desc as u32;

    let push = Desc {
        addr: digest.as_mut_ptr() as u32,
        next: NEXT_STOP,
        sz: SZ_REALIGN | (digest.len() as u32),
        tag: TAG_PUSH_LAST,
    };

    unsafe { run_dma(&fetch[0] as *const Desc as u32, &push as *const Desc as u32) }
}

/// AES-CBC / AES-CTR encrypt of `pt` into `ct` under `key` with a 16-byte `iv`.
/// `pt.len()` must be a multiple of 16. Returns false on a DMA bus error.
fn aes_iv_encrypt(
    mode: u32,
    key: &[u8],
    iv: &[u8; 16],
    pt: &[u8],
    ct: &mut [u8],
) -> bool {
    debug_assert!(pt.len() % 16 == 0 && pt.len() == ct.len());
    let len = pt.len() as u32 & 0x00ff_ffff;
    let cfg: u32 = mode;

    let mut fetch = [
        Desc { addr: &cfg as *const u32 as u32, next: 0, sz: SZ_REALIGN | 4, tag: TAG_CFG },
        Desc { addr: key.as_ptr() as u32, next: 0, sz: SZ_REALIGN | key.len() as u32, tag: TAG_KEY },
        Desc { addr: iv.as_ptr() as u32, next: 0, sz: SZ_REALIGN | 16, tag: TAG_IV },
        Desc { addr: pt.as_ptr() as u32, next: NEXT_STOP, sz: SZ_REALIGN | len, tag: TAG_DATA_LAST },
    ];
    fetch[0].next = &fetch[1] as *const Desc as u32;
    fetch[1].next = &fetch[2] as *const Desc as u32;
    fetch[2].next = &fetch[3] as *const Desc as u32;

    let push = Desc {
        addr: ct.as_mut_ptr() as u32,
        next: NEXT_STOP,
        sz: SZ_REALIGN | len,
        tag: TAG_PUSH_LAST,
    };

    unsafe { run_dma(&fetch[0] as *const Desc as u32, &push as *const Desc as u32) }
}

/// AES-CBC encrypt with a 16-byte IV.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], pt: &[u8], ct: &mut [u8]) -> bool {
    aes_iv_encrypt(AES_CBC_ENCRYPT, key, iv, pt, ct)
}

/// AES-CTR encrypt with a 16-byte initial counter block.
pub fn aes_ctr_encrypt(key: &[u8], iv: &[u8; 16], pt: &[u8], ct: &mut [u8]) -> bool {
    aes_iv_encrypt(AES_CTR_ENCRYPT, key, iv, pt, ct)
}

/// SHA-256 of `msg` (32-byte digest) on the CRACEN BA413 hash engine.
pub fn sha256(msg: &[u8], digest: &mut [u8; 32]) -> bool {
    hash_oneshot(SHA256_MODE, msg, digest)
}

/// SHA-512 of `msg` (64-byte digest) on the CRACEN BA413 hash engine.
pub fn sha512(msg: &[u8], digest: &mut [u8; 64]) -> bool {
    hash_oneshot(SHA512_MODE, msg, digest)
}

/// SHA-384 of `msg` (48-byte digest) on the CRACEN BA413 hash engine.
pub fn sha384(msg: &[u8], digest: &mut [u8; 48]) -> bool {
    hash_oneshot(SHA384_MODE, msg, digest)
}

/// HMAC-SHA256 of `msg` under `key` into `mac` (BA413 hash engine). Returns
/// false on a DMA bus error.
pub fn hmac_sha256(key: &[u8], msg: &[u8], mac: &mut [u8; 32]) -> bool {
    debug_assert!(msg.len() % 4 == 0);
    let klen = key.len() as u32 & 0x00ff_ffff;
    let mlen = msg.len() as u32 & 0x00ff_ffff;
    let cfg: u32 = HMAC_SHA256_MODE;

    let mut fetch = [
        Desc { addr: &cfg as *const u32 as u32, next: 0, sz: SZ_REALIGN | 4, tag: TAG_SHA_CFG },
        Desc { addr: key.as_ptr() as u32, next: 0, sz: SZ_REALIGN | klen, tag: TAG_HMAC_KEY },
        Desc { addr: msg.as_ptr() as u32, next: NEXT_STOP, sz: SZ_REALIGN | mlen, tag: TAG_SHA_DATA_LAST },
    ];
    fetch[0].next = &fetch[1] as *const Desc as u32;
    fetch[1].next = &fetch[2] as *const Desc as u32;

    let push = Desc { addr: mac.as_mut_ptr() as u32, next: NEXT_STOP, sz: SZ_REALIGN | 32, tag: TAG_PUSH_LAST };

    unsafe { run_dma(&fetch[0] as *const Desc as u32, &push as *const Desc as u32) }
}

/// AES-128-CMAC of `msg` under a 16-byte `key` into `tag` (BA411 in CMAC mode).
/// Returns false on a DMA bus error.
pub fn aes_cmac(key: &[u8], msg: &[u8], tag: &mut [u8; 16]) -> bool {
    debug_assert!(msg.len() % 16 == 0);
    let len = msg.len() as u32 & 0x00ff_ffff;
    let cfg: u32 = AES_CMAC_MODE;

    let mut fetch = [
        Desc { addr: &cfg as *const u32 as u32, next: 0, sz: SZ_REALIGN | 4, tag: TAG_CFG },
        Desc { addr: key.as_ptr() as u32, next: 0, sz: SZ_REALIGN | key.len() as u32, tag: TAG_KEY },
        Desc { addr: msg.as_ptr() as u32, next: NEXT_STOP, sz: SZ_REALIGN | len, tag: TAG_DATA_LAST },
    ];
    fetch[0].next = &fetch[1] as *const Desc as u32;
    fetch[1].next = &fetch[2] as *const Desc as u32;

    let push = Desc { addr: tag.as_mut_ptr() as u32, next: NEXT_STOP, sz: SZ_REALIGN | 16, tag: TAG_PUSH_LAST };

    unsafe { run_dma(&fetch[0] as *const Desc as u32, &push as *const Desc as u32) }
}

/// AES-128-GCM encrypt of `pt` into `ct` under a 16-byte `key` and 12-byte `iv`
/// (no AAD), writing the 16-byte auth `tag`. Returns false on a DMA bus error.
pub fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8; 12],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; 16],
) -> bool {
    debug_assert!(pt.len() % 16 == 0 && pt.len() == ct.len());
    let len = pt.len() as u32 & 0x00ff_ffff;
    let cfg: u32 = AES_GCM_ENCRYPT;

    // GHASH length block: 8 bytes AAD bit-length (0) || 8 bytes PT bit-length BE.
    let mut lenblock = [0u8; 16];
    lenblock[8..16].copy_from_slice(&((pt.len() as u64) * 8).to_be_bytes());

    let mut fetch = [
        Desc { addr: &cfg as *const u32 as u32, next: 0, sz: SZ_REALIGN | 4, tag: TAG_CFG },
        Desc { addr: key.as_ptr() as u32, next: 0, sz: SZ_REALIGN | key.len() as u32, tag: TAG_KEY },
        Desc { addr: iv.as_ptr() as u32, next: 0, sz: SZ_REALIGN | 12, tag: TAG_IV },
        Desc { addr: pt.as_ptr() as u32, next: 0, sz: SZ_REALIGN | len, tag: TAG_DATA },
        Desc { addr: lenblock.as_ptr() as u32, next: NEXT_STOP, sz: SZ_REALIGN | 16, tag: TAG_DATA_LAST },
    ];
    fetch[0].next = &fetch[1] as *const Desc as u32;
    fetch[1].next = &fetch[2] as *const Desc as u32;
    fetch[2].next = &fetch[3] as *const Desc as u32;
    fetch[3].next = &fetch[4] as *const Desc as u32;

    let mut push = [
        Desc { addr: ct.as_mut_ptr() as u32, next: 0, sz: SZ_REALIGN | len, tag: 0 },
        Desc { addr: tag.as_mut_ptr() as u32, next: NEXT_STOP, sz: SZ_REALIGN | 16, tag: TAG_PUSH_LAST },
    ];
    push[0].next = &push[1] as *const Desc as u32;

    unsafe { run_dma(&fetch[0] as *const Desc as u32, &push[0] as *const Desc as u32) }
}

// ---------------------------------------------------------------------------
// CRACEN PKE (BA414EP, silexpk): public-key engine for curve25519. Needs the
// microcode loaded once; curve constants live in the microcode (no curve blob).
// ---------------------------------------------------------------------------

const PK_BASE: usize = 0x5180_2000;
const PK_CONFIG: *mut u32 = PK_BASE as *mut u32; // 0x00: A | B<<8 | C<<16 slot ptrs
const PK_COMMAND: *mut u32 = (PK_BASE + 0x04) as *mut u32; // opcode | opsize | flags
const PK_CONTROL: *mut u32 = (PK_BASE + 0x08) as *mut u32; // start / clear-irq
const PK_STATUS: *const u32 = (PK_BASE + 0x0c) as *const u32; // busy + error
const PK_CRYPTORAM: usize = 0x5180_8000; // operand RAM, slot N at +N*SLOT_SZ
const PK_UCODE: usize = 0x5180_c000; // microcode RAM
const SLOT_SZ: usize = 0x200; // 512-byte operand slots

const PK_START: u32 = 0x1;
const PK_CLEAR_IRQ: u32 = 0x2;
const PK_BUSY: u32 = 0x0001_0000;
const PK_ERR_MASK: u32 = 0x0001_fff0;

const PK_OP_MG_PTMUL: u32 = 0x28; // Montgomery (X25519) scalar mult
const CURVE_X25519: u32 = 0x0050_0000; // curve-select flag (in SELCUR_MASK)

static PKE_READY: AtomicBool = AtomicBool::new(false);

/// Enable the PKE module and load the BA414EP microcode (once).
fn pke_init() {
    if PKE_READY.load(Ordering::Relaxed) {
        return;
    }
    unsafe {
        let en = core::ptr::read_volatile(CRACEN_ENABLE);
        core::ptr::write_volatile(CRACEN_ENABLE, en | ENABLE_PKEIKG);
        for (i, &w) in crate::ucode::BA414EP_UCODE.iter().enumerate() {
            core::ptr::write_volatile((PK_UCODE + i * 4) as *mut u32, w);
        }
    }
    PKE_READY.store(true, Ordering::Relaxed);
}

/// Write up to 32 little-endian bytes from `data` (zero-padded) to slot `slot`
/// via word accesses (which the crypto RAM always accepts).
fn pk_write_operand(slot: usize, data: &[u8]) {
    let base = PK_CRYPTORAM + slot * SLOT_SZ;
    for i in 0..8 {
        let b = |j: usize| -> u8 {
            let idx = i * 4 + j;
            if idx < data.len() {
                data[idx]
            } else {
                0
            }
        };
        let w = u32::from_le_bytes([b(0), b(1), b(2), b(3)]);
        unsafe { core::ptr::write_volatile((base + i * 4) as *mut u32, w) };
    }
}

/// Read 32 little-endian bytes from the start of slot `slot` into `out`.
fn pk_read_operand(slot: usize, out: &mut [u8]) {
    let base = PK_CRYPTORAM + slot * SLOT_SZ;
    for i in 0..8 {
        let bytes =
            unsafe { core::ptr::read_volatile((base + i * 4) as *const u32) }
                .to_le_bytes();
        for j in 0..4 {
            let idx = i * 4 + j;
            if idx < out.len() {
                out[idx] = bytes[j];
            }
        }
    }
}

/// Issue a PKE command (optionally writing CONFIG for ops that use the A/B/C
/// slot pointers; EdDSA ops pass None and use microcode-fixed slots). Returns
/// the masked status word (0 = OK), or None on timeout.
fn pk_run(command: u32, config: Option<u32>) -> Option<u32> {
    unsafe {
        core::ptr::write_volatile(PK_COMMAND, command);
        if let Some(c) = config {
            core::ptr::write_volatile(PK_CONFIG, c);
        }
        compiler_fence(Ordering::SeqCst);
        core::ptr::write_volatile(PK_CONTROL, PK_START | PK_CLEAR_IRQ);

        let mut budget = DONE_BUDGET;
        while core::ptr::read_volatile(PK_STATUS) & PK_BUSY != 0 {
            budget -= 1;
            if budget == 0 {
                return None;
            }
        }
        compiler_fence(Ordering::SeqCst);
        Some(core::ptr::read_volatile(PK_STATUS) & PK_ERR_MASK)
    }
}

/// X25519 scalar multiplication: `out = scalar * u` on Curve25519. The scalar
/// and u-coordinate are clamped per RFC 7748. Returns false on engine error.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32], out: &mut [u8; 32]) -> bool {
    pke_init();

    let mut k = *scalar;
    clamp(&mut k);
    let mut uu = *u;
    uu[31] &= 0x7f;

    pk_write_operand(6, &uu); // u-coordinate -> PTR_A
    pk_write_operand(8, &k); // scalar -> PTR_B

    let command = PK_OP_MG_PTMUL | ((32 - 1) << 8) | CURVE_X25519;
    let config = 6 | (8 << 8) | (10 << 16);
    if pk_run(command, Some(config)) != Some(0) {
        return false;
    }
    pk_read_operand(10, out); // shared secret <- PTR_C
    true
}

// Ed25519 on the same PKE: dedicated opcodes do the curve math; the host runs
// SHA-512 (CryptoMaster) and sequences the ops. Curve flag 0x00600000, opsize
// 32. EdDSA ops use microcode-fixed slots, so no CONFIG write.
const ED_PTMUL: u32 = 0x3b | ((32 - 1) << 8) | 0x0060_0000; // R = r*B
const ED_SIGN: u32 = 0x3c | ((32 - 1) << 8) | 0x0060_0000; // S = (r + k*s) mod L
const ED_VERIFY: u32 = 0x3d | ((32 - 1) << 8) | 0x0060_0000;
const ED_FLAG_AX_LSB: u32 = 1 << 29; // A x-coord parity
const ED_FLAG_RX_LSB: u32 = 1 << 30; // R x-coord parity
const ED_INVALID_SIG: u32 = 1 << 9; // STATUS bit: signature invalid
const ED_MAX_MSG: usize = 256;

/// RFC 8032 / 7748 scalar clamp.
fn clamp(s: &mut [u8; 32]) {
    s[0] &= 0xf8;
    s[31] &= 0x7f;
    s[31] |= 0x40;
}

/// EdDSA scalar mult: `encoded` = `scalar` * B (base point). `scalar` is 32 or
/// 64 bytes (low half -> slot 8, high half -> slot 9, zero-padded). The result
/// point is read as Y (slot 11) with the X parity (slot 10) folded into bit 7.
fn ed25519_ptmult(scalar: &[u8], encoded: &mut [u8; 32]) -> bool {
    let split = scalar.len().min(32);
    pk_write_operand(8, &scalar[..split]);
    pk_write_operand(9, if scalar.len() > 32 { &scalar[32..] } else { &[] });
    if pk_run(ED_PTMUL, None) != Some(0) {
        return false;
    }
    let mut x = [0u8; 32];
    pk_read_operand(10, &mut x);
    pk_read_operand(11, encoded);
    encoded[31] |= (x[0] & 1) << 7;
    true
}

/// Ed25519 sign (pure, no context/prehash). `msg.len()` must be a multiple of 4
/// and <= ED_MAX_MSG. Writes the 64-byte signature. Returns false on error.
pub fn ed25519_sign(privkey: &[u8; 32], msg: &[u8], sig: &mut [u8; 64]) -> bool {
    if msg.len() > ED_MAX_MSG || msg.len() % 4 != 0 {
        return false;
    }
    pke_init();

    let mut h = [0u8; 64];
    if !sha512(privkey, &mut h) {
        return false;
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    clamp(&mut s);

    // r = SHA-512(prefix || msg)
    let mut buf = [0u8; 32 + ED_MAX_MSG];
    buf[..32].copy_from_slice(&h[32..]);
    buf[32..32 + msg.len()].copy_from_slice(msg);
    let mut r = [0u8; 64];
    if !sha512(&buf[..32 + msg.len()], &mut r) {
        return false;
    }

    // R = r*B -> first half of the signature.
    let mut rpt = [0u8; 32];
    if !ed25519_ptmult(&r, &mut rpt) {
        return false;
    }
    sig[..32].copy_from_slice(&rpt);

    // A = s*B (public key), needed for k.
    let mut a = [0u8; 32];
    if !ed25519_ptmult(&s, &mut a) {
        return false;
    }

    // k = SHA-512(R || A || msg)
    let mut buf2 = [0u8; 64 + ED_MAX_MSG];
    buf2[..32].copy_from_slice(&rpt);
    buf2[32..64].copy_from_slice(&a);
    buf2[64..64 + msg.len()].copy_from_slice(msg);
    let mut k = [0u8; 64];
    if !sha512(&buf2[..64 + msg.len()], &mut k) {
        return false;
    }

    // S = (r + k*s) mod L -> second half.
    pk_write_operand(6, &k[..32]);
    pk_write_operand(7, &k[32..]);
    pk_write_operand(8, &r[..32]);
    pk_write_operand(9, &r[32..]);
    pk_write_operand(11, &s);
    if pk_run(ED_SIGN, None) != Some(0) {
        return false;
    }
    pk_read_operand(10, &mut sig[32..64]);
    true
}

/// Ed25519 verify (pure). Returns Some(true)/Some(false) for valid/invalid, or
/// None on a hardware error. `msg.len()` must be a multiple of 4 and <= ED_MAX_MSG.
pub fn ed25519_verify(
    pubkey: &[u8; 32],
    msg: &[u8],
    sig: &[u8; 64],
) -> Option<bool> {
    if msg.len() > ED_MAX_MSG || msg.len() % 4 != 0 {
        return None;
    }
    pke_init();

    // k = SHA-512(R || A || msg)
    let mut buf = [0u8; 64 + ED_MAX_MSG];
    buf[..32].copy_from_slice(&sig[..32]);
    buf[32..64].copy_from_slice(pubkey);
    buf[64..64 + msg.len()].copy_from_slice(msg);
    let mut k = [0u8; 64];
    if !sha512(&buf[..64 + msg.len()], &mut k) {
        return None;
    }

    // Decode A and R to y-coordinate + x-parity (parity passed as command flags).
    let mut ay = *pubkey;
    let a_lsb = ay[31] >> 7;
    ay[31] &= 0x7f;
    let mut ry = [0u8; 32];
    ry.copy_from_slice(&sig[..32]);
    let r_lsb = ry[31] >> 7;
    ry[31] &= 0x7f;

    pk_write_operand(6, &k[..32]);
    pk_write_operand(7, &k[32..]);
    pk_write_operand(9, &ay);
    pk_write_operand(10, &sig[32..64]);
    pk_write_operand(11, &ry);

    let mut cmd = ED_VERIFY;
    if a_lsb != 0 {
        cmd |= ED_FLAG_AX_LSB;
    }
    if r_lsb != 0 {
        cmd |= ED_FLAG_RX_LSB;
    }
    match pk_run(cmd, None) {
        Some(0) => Some(true),
        Some(st) if st & ED_INVALID_SIG != 0 => Some(false),
        _ => None,
    }
}

// ChaCha20-Poly1305 AEAD on the BA417 CryptoMaster engine (engine tag 4).
// One-shot encrypt, 12-byte nonce, no AAD, 16-byte Poly1305 tag.
const TAG_BA417: u32 = 4;
const TAG_CP_CFG: u32 = TAG_BA417 | TAG_CONFIG; // 0x014
const TAG_CP_KEY: u32 = TAG_BA417 | TAG_CONFIG | (0x04 << 8); // 0x414
const TAG_CP_CTR: u32 = TAG_BA417 | TAG_CONFIG | (0x28 << 8); // 0x2814 counter
const TAG_CP_NONCE: u32 = TAG_BA417 | TAG_CONFIG | (0x2c << 8); // 0x2C14 nonce
const TAG_CP_DATA: u32 = TAG_BA417; // 0x04 message data (ChaCha engine)
const TAG_CP_DATA_LAST: u32 = TAG_BA417 | TAG_LAST; // 0x24 last (Poly1305 len block)

/// ChaCha20-Poly1305 encrypt of `pt` into `ct` under a 32-byte `key` and 12-byte
/// `nonce` (no AAD), writing the 16-byte tag. `pt.len()` must be a multiple of
/// 16. Returns false on a DMA bus error.
pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; 16],
) -> bool {
    debug_assert!(pt.len() % 16 == 0 && pt.len() == ct.len());
    let len = pt.len() as u32 & 0x00ff_ffff;
    let cfg: u32 = 0; // ChaCha20-Poly1305, encrypt
    let counter: [u8; 4] = [0, 0, 0, 1]; // RFC 8439 initial block counter = 1
    // Poly1305 length block: 8-byte AAD len (0) || 8-byte plaintext len, little-
    // endian, in bytes (RFC 8439) -- unlike GCM's big-endian bit counts.
    let mut lenblock = [0u8; 16];
    lenblock[8..16].copy_from_slice(&(pt.len() as u64).to_le_bytes());

    let mut fetch = [
        Desc { addr: &cfg as *const u32 as u32, next: 0, sz: SZ_REALIGN | 4, tag: TAG_CP_CFG },
        Desc { addr: key.as_ptr() as u32, next: 0, sz: SZ_REALIGN | 32, tag: TAG_CP_KEY },
        Desc { addr: counter.as_ptr() as u32, next: 0, sz: SZ_REALIGN | 4, tag: TAG_CP_CTR },
        Desc { addr: nonce.as_ptr() as u32, next: 0, sz: SZ_REALIGN | 12, tag: TAG_CP_NONCE },
        Desc { addr: pt.as_ptr() as u32, next: 0, sz: SZ_REALIGN | len, tag: TAG_CP_DATA },
        Desc { addr: lenblock.as_ptr() as u32, next: NEXT_STOP, sz: SZ_REALIGN | 16, tag: TAG_CP_DATA_LAST },
    ];
    fetch[0].next = &fetch[1] as *const Desc as u32;
    fetch[1].next = &fetch[2] as *const Desc as u32;
    fetch[2].next = &fetch[3] as *const Desc as u32;
    fetch[3].next = &fetch[4] as *const Desc as u32;
    fetch[4].next = &fetch[5] as *const Desc as u32;

    let mut push = [
        Desc { addr: ct.as_mut_ptr() as u32, next: 0, sz: SZ_REALIGN | len, tag: 0 },
        Desc { addr: tag.as_mut_ptr() as u32, next: NEXT_STOP, sz: SZ_REALIGN | 16, tag: TAG_PUSH_LAST },
    ];
    push[0].next = &push[1] as *const Desc as u32;

    unsafe { run_dma(&fetch[0] as *const Desc as u32, &push[0] as *const Desc as u32) }
}

// NIST P-256 (secp256r1) on the same PKE. P-256 is a SELCUR predefined curve
// (curveflag 0x00100000, no parameter blob loaded), but its Weierstrass opcodes
// are BIG-ENDIAN with operands placed at slot offset 0x1E0 (slot_size - 32).
const P256_OFF: usize = 0x1e0;
const P256_ECDH: u32 = 0x1010_1f22; // ECC_PTMUL | (31<<8) | P256 | BIGENDIAN
const P256_ECDSA_SIGN: u32 = 0x1010_1f30; // ECDSA_GEN
const P256_ECDSA_VERIFY: u32 = 0x1010_1f31; // ECDSA_VER
const P256_ECDH_CONFIG: u32 = 0x000a_080c; // ptrs A=12, B=8, C=10

/// Write a 32-byte big-endian operand to slot `slot` (at offset 0x1E0).
fn pk_write_be(slot: usize, data: &[u8]) {
    let base = PK_CRYPTORAM + slot * SLOT_SZ + P256_OFF;
    for i in 0..8 {
        let b = |j: usize| -> u8 {
            let idx = i * 4 + j;
            if idx < data.len() {
                data[idx]
            } else {
                0
            }
        };
        let w = u32::from_le_bytes([b(0), b(1), b(2), b(3)]);
        unsafe { core::ptr::write_volatile((base + i * 4) as *mut u32, w) };
    }
}

/// Read a 32-byte big-endian operand from slot `slot` (at offset 0x1E0).
fn pk_read_be(slot: usize, out: &mut [u8]) {
    let base = PK_CRYPTORAM + slot * SLOT_SZ + P256_OFF;
    for i in 0..8 {
        let bytes =
            unsafe { core::ptr::read_volatile((base + i * 4) as *const u32) }
                .to_le_bytes();
        for j in 0..4 {
            let idx = i * 4 + j;
            if idx < out.len() {
                out[idx] = bytes[j];
            }
        }
    }
}

/// P-256 ECDH: shared-secret X-coordinate = `d` * peer point. `peer_pub` is the
/// 64-byte big-endian X||Y public key. Returns false on engine error.
pub fn p256_ecdh(d: &[u8; 32], peer_pub: &[u8; 64], out_x: &mut [u8; 32]) -> bool {
    pke_init();
    pk_write_be(8, d);
    pk_write_be(12, &peer_pub[..32]);
    pk_write_be(13, &peer_pub[32..]);
    if pk_run(P256_ECDH, Some(P256_ECDH_CONFIG)) != Some(0) {
        return false;
    }
    pk_read_be(10, out_x);
    true
}

/// Diagnostic: run the P-256 ECDH point-mult and return the raw masked PKE
/// status (0 = OK; bit4=not-on-curve, bit6=out-of-range, 0xffff_ffff=timeout).
pub fn p256_ecdh_status(d: &[u8; 32], peer_pub: &[u8; 64]) -> u32 {
    pke_init();
    pk_write_be(8, d);
    pk_write_be(12, &peer_pub[..32]);
    pk_write_be(13, &peer_pub[32..]);
    pk_run(P256_ECDH, Some(P256_ECDH_CONFIG)).unwrap_or(0xffff_ffff)
}

/// Diagnostic: run the P-256 ECDH point-mult and read the result from an
/// arbitrary `slot`, to locate which output slot holds the shared secret.
pub fn p256_ecdh_read(
    d: &[u8; 32],
    peer_pub: &[u8; 64],
    slot: usize,
    out: &mut [u8; 32],
) -> bool {
    pke_init();
    pk_write_be(8, d);
    pk_write_be(12, &peer_pub[..32]);
    pk_write_be(13, &peer_pub[32..]);
    if pk_run(P256_ECDH, Some(P256_ECDH_CONFIG)) != Some(0) {
        return false;
    }
    pk_read_be(slot, out);
    true
}

/// P-256 ECDSA sign of a 32-byte `hash` under private key `d` with nonce `k`;
/// writes the 64-byte signature (r||s). All big-endian. Returns false on error
/// (e.g. r or s == 0 -- the caller should retry with a fresh nonce).
pub fn p256_ecdsa_sign(
    d: &[u8; 32],
    hash: &[u8; 32],
    k: &[u8; 32],
    sig: &mut [u8; 64],
) -> bool {
    pke_init();
    pk_write_be(6, d);
    pk_write_be(7, k);
    pk_write_be(12, hash);
    if pk_run(P256_ECDSA_SIGN, None) != Some(0) {
        return false;
    }
    pk_read_be(10, &mut sig[..32]);
    pk_read_be(11, &mut sig[32..]);
    true
}

/// P-256 ECDSA verify of `sig` (r||s) over `hash` with public key `pub_key`
/// (X||Y). All big-endian. Some(true)/Some(false) = valid/invalid, None on
/// hardware error.
pub fn p256_ecdsa_verify(
    pub_key: &[u8; 64],
    hash: &[u8; 32],
    sig: &[u8; 64],
) -> Option<bool> {
    pke_init();
    pk_write_be(8, &pub_key[..32]);
    pk_write_be(9, &pub_key[32..]);
    pk_write_be(10, &sig[..32]);
    pk_write_be(11, &sig[32..]);
    pk_write_be(12, hash);
    match pk_run(P256_ECDSA_VERIFY, None) {
        Some(0) => Some(true),
        Some(st) if st & ED_INVALID_SIG != 0 => Some(false),
        _ => None,
    }
}

// RSA-2048 modular exponentiation on the PKE. Plain modexp (the cracen RSA
// driver uses full-d, not CRT, even for the private op). Operands are 2048-bit
// (256-byte), big-endian, at slot offset 0x100 (slot_size - op_size).
const RSA_OFF: usize = 0x100;
const RSA_MODEXP: u32 = 0x9000_ff10; // PK_OP_MDEXP(0x10) | RESQUARE | BIGENDIAN | (256-1)<<8
const RSA_CONFIG: u32 = 0x000a_0806; // ptrs A=6 (base m), B=8 (exp), C=10 (result)

/// Write `data` (big-endian) right-aligned into the 256-byte operand field at
/// slot `slot` offset 0x100, zero-padding the high bytes (for short exponents).
fn pk_write_rsa(slot: usize, data: &[u8]) {
    let base = PK_CRYPTORAM + slot * SLOT_SZ + RSA_OFF;
    let pad = 256 - data.len();
    for i in 0..64 {
        let b = |j: usize| -> u8 {
            let idx = i * 4 + j;
            if idx >= pad {
                data[idx - pad]
            } else {
                0
            }
        };
        let w = u32::from_le_bytes([b(0), b(1), b(2), b(3)]);
        unsafe { core::ptr::write_volatile((base + i * 4) as *mut u32, w) };
    }
}

/// Read the 256-byte big-endian result from slot `slot` offset 0x100.
fn pk_read_rsa(slot: usize, out: &mut [u8; 256]) {
    let base = PK_CRYPTORAM + slot * SLOT_SZ + RSA_OFF;
    for i in 0..64 {
        let bytes =
            unsafe { core::ptr::read_volatile((base + i * 4) as *const u32) }
                .to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
}

/// RSA-2048 modular exponentiation: `out = base^exp mod modulus`. `base` and
/// `modulus` are 256-byte big-endian; `exp` is big-endian (any length <= 256,
/// e.g. 3 bytes for 65537 or 256 for the private exponent). Returns false on a
/// PKE error or timeout.
pub fn rsa2048_modexp(
    base: &[u8; 256],
    exp: &[u8],
    modulus: &[u8; 256],
    out: &mut [u8; 256],
) -> bool {
    pke_init();
    pk_write_rsa(0, modulus); // n -> slot 0
    pk_write_rsa(6, base); // m -> slot 6
    pk_write_rsa(8, exp); // exponent -> slot 8 (right-aligned)
    if pk_run(RSA_MODEXP, Some(RSA_CONFIG)) != Some(0) {
        return false;
    }
    pk_read_rsa(10, out);
    true
}

// ---------------------------------------------------------------------------
// CRACEN RNG (BA431 NDRNG): free-running ring oscillators -> FIFO, with on-chip
// AES-CBC-MAC conditioning. Not a register DRBG -- we read the FIFO directly.
// ---------------------------------------------------------------------------

const RNG_BASE: usize = 0x5180_1000;
const RNG_CONTROL: *mut u32 = RNG_BASE as *mut u32; // 0x00
const RNG_FIFOLEVEL: *const u32 = (RNG_BASE + 0x04) as *const u32; // words available
const RNG_KEY0: *mut u32 = (RNG_BASE + 0x10) as *mut u32; // KEY0..KEY3 @ 0x10..0x1c
const RNG_STATUS: *const u32 = (RNG_BASE + 0x30) as *const u32;
const RNG_FIFODATA: *const u32 = (RNG_BASE + 0x80) as *const u32; // read pops a word

const CTRL_ENABLE: u32 = 1 << 0;
const CTRL_SOFTRST: u32 = 1 << 8;
const CTRL_NB128_4: u32 = 4 << 16; // 4 128-bit blocks per AES conditioning
const CTRL_RUN: u32 = CTRL_ENABLE | CTRL_NB128_4;

const RNG_BUDGET: u32 = 1_000_000;

/// FSM state from STATUS bits[3:1]: 0=RESET, 1=STARTUP, 2/3=IDLE, 4=FILL, 5=ERROR.
fn rng_state() -> u32 {
    (unsafe { core::ptr::read_volatile(RNG_STATUS) } >> 1) & 0x7
}

/// Reset + start the RNG (conditioned mode), then wait for the startup tests to
/// pass. Returns false on a health-test error or timeout.
fn rng_start() -> bool {
    unsafe {
        core::ptr::write_volatile(RNG_CONTROL, CTRL_SOFTRST);
        core::ptr::write_volatile(RNG_CONTROL, 0);
        core::ptr::write_volatile(RNG_CONTROL, CTRL_RUN);
    }
    let mut budget = RNG_BUDGET;
    loop {
        match rng_state() {
            5 => return false,            // ERROR
            2 | 3 | 4 => return true,     // past startup, producing
            _ => {}                       // RESET / STARTUP: keep waiting
        }
        budget -= 1;
        if budget == 0 {
            return false;
        }
    }
}

/// Wait until at least `words` 32-bit words are in the FIFO.
fn rng_wait_level(words: u32) -> bool {
    let mut budget = RNG_BUDGET;
    while unsafe { core::ptr::read_volatile(RNG_FIFOLEVEL) } < words {
        budget -= 1;
        if budget == 0 {
            return false;
        }
    }
    true
}

/// Fill `out` with hardware random bytes from the CRACEN TRNG. Returns false on
/// a health-test error or timeout. Uses the conditioned path: derive the AES
/// conditioning key from raw entropy, restart, then read the conditioned FIFO.
pub fn rng_fill(out: &mut [u8]) -> bool {
    if out.is_empty() {
        return true;
    }
    unsafe {
        let en = core::ptr::read_volatile(CRACEN_ENABLE);
        core::ptr::write_volatile(CRACEN_ENABLE, en | ENABLE_RNG);
    }

    // First run: produce entropy under the default key, take 4 words as the
    // real conditioning key, load it, and restart to flush the default-key data.
    if !rng_start() || !rng_wait_level(4) {
        return false;
    }
    unsafe {
        for i in 0..4 {
            let w = core::ptr::read_volatile(RNG_FIFODATA);
            core::ptr::write_volatile(RNG_KEY0.add(i), w);
        }
    }
    if !rng_start() {
        return false;
    }

    // Read the conditioned output, one popped word at a time.
    let words = out.len().div_ceil(4) as u32;
    if !rng_wait_level(words) {
        return false;
    }
    let mut i = 0;
    while i < out.len() {
        let w = unsafe { core::ptr::read_volatile(RNG_FIFODATA) }.to_le_bytes();
        let n = (out.len() - i).min(4);
        out[i..i + n].copy_from_slice(&w[..n]);
        i += n;
    }
    true
}
