// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bare-metal EFR32MG24 hardware crypto, no SDK, plus a tiny IPC protocol so a
//! single owner task can arbitrate the engines.
//!
//! - `RADIOAES` (Silex BA411E) -- memory-mapped AES, scatter-gather DMA.
//! - `SEMAILBOX` (Secure Engine) -- a command FIFO (TRNG, status, version, ...).
//!
//! The RADIOAES and SE engines are single shared resources with no hardware
//! arbitration, so exactly one task (the crypto server) should drive them; other
//! tasks reach them over IPC via [`client_aes`] / [`client_se`].

#![no_std]

use userlib::{
    sys_irq_control_clear_pending, sys_recv_notification, sys_send, TaskId,
};

// ----- clocks -------------------------------------------------------------
const CMU_CLKEN0: *mut u32 = 0x4000_8064 as *mut u32;
const CMU_CLKEN0_RADIOAES: u32 = 1 << 2;
const CMU_CLKEN1: *mut u32 = 0x4000_8068 as *mut u32;
const CMU_CLKEN1_SEMAILBOXHOST: u32 = 1 << 10;

// ----- RADIOAES (BA411E) registers, secure alias --------------------------
const RADIOAES_FETCHADDR: *mut u32 = 0x4400_0000 as *mut u32;
const RADIOAES_PUSHADDR: *mut u32 = 0x4400_0010 as *mut u32;
const RADIOAES_IEN: *mut u32 = 0x4400_001c as *mut u32; // interrupt enable
const RADIOAES_IF: *const u32 = 0x4400_0028 as *const u32; // interrupt flags (raw)
const RADIOAES_IF_CLR: *mut u32 = 0x4400_0030 as *mut u32; // interrupt-flag clear
const RADIOAES_CTRL: *mut u32 = 0x4400_0034 as *mut u32;
const RADIOAES_CMD: *mut u32 = 0x4400_0038 as *mut u32;
const RADIOAES_STATUS: *const u32 = 0x4400_003c as *const u32; // busy flags (single-block path)
const AES_CFG_ECB: u32 = 0x100; // ECB | NO_CX | AES128
const AES_DECRYPT: u32 = 0x1;
/// SYMCRYPTO IEN/IF bit 3 = PUSHERENDOFBLOCK: the pusher finished writing the
/// output block. This is the proper "operation complete" interrupt, but it only
/// fires if the pusher descriptor sets [`AES_DESCR_INT_ENABLE`] in its length
/// word (matching SiLabs's `DMA_AXI_DESCR_INT_ENABLE`).
const AES_INT_PUSHER_ENDOFBLOCK: u32 = 1 << 3;
/// Descriptor length-word flag: raise the end-of-block interrupt when this
/// descriptor completes. Without it the engine signals completion only via the
/// busy bits in `STATUS` (which is how SiLabs's own driver waits).
const AES_DESCR_INT_ENABLE: u32 = 0x8000_0000;
/// All SYMCRYPTO interrupt-flag bits (fetcher/pusher end/stop/error) -- used to
/// clear stale flags when arming and to ack after completion.
const AES_INT_ALL: u32 = 0x3f;

// ----- Secure Engine mailbox (SEMAILBOX_HOST), secure alias ---------------
const SE_FIFO: *mut u32 = 0x4c00_0000 as *mut u32;
const SE_TX_STATUS: *const u32 = 0x4c00_0040 as *const u32;
const SE_RX_STATUS: *const u32 = 0x4c00_0044 as *const u32;
const SE_TX_HEADER: *mut u32 = 0x4c00_0050 as *mut u32;
const SE_RX_HEADER: *const u32 = 0x4c00_0054 as *const u32;
const SE_TXINT: u32 = 1 << 20;
const SE_RXINT: u32 = 1 << 20;
const SE_DT_STOP: u32 = 0x1;
const SE_DT_REALIGN: u32 = 0x2000_0000;
const SE_RESPONSE_MASK: u32 = 0x000f_0000;

/// `se_execute` returns this when the SE mailbox didn't respond.
pub const SE_NO_RESPONSE: u32 = 0xffff_ffff;

/// A few SE mailbox command words (see the EFR32 SE reference).
pub const SE_CMD_TRNG_GET_RANDOM: u32 = 0x0700_0000;
pub const SE_CMD_GET_STATUS: u32 = 0xfe01_0000;
pub const SE_CMD_SE_VERSION: u32 = 0x4308_0000;
pub const SE_CMD_READ_SERIAL: u32 = 0xfe00_0000;
pub const SE_CMD_GET_CHALLENGE: u32 = 0xfd00_0001;
pub const SE_CMD_OTP_VERSION: u32 = 0x4308_0100;
pub const SE_CMD_READ_RSTCAUSE: u32 = 0x4322_0000;

// SE AES-128 ECB command pieces (the "all-SE" AES path). The command word is
// `AES_ENCRYPT|DECRYPT | MODE_ECB | CONTEXT_WHOLE(0)`. Parameters are the key's
// keyspec word and the message length; the key bytes and message ride in on the
// data-in DMA chain (see `se_aes128_ecb`).
const SE_CMD_AES_ENCRYPT: u32 = 0x0400_0000;
const SE_CMD_AES_DECRYPT: u32 = 0x0401_0000;
const SE_OPT_MODE_ECB: u32 = 0x0000_0100; // | CONTEXT_WHOLE (0)
/// Keyspec for an external-plaintext AES-128 key (type RAW, mode UNPROTECTED,
/// sym-size 16). Derived from `sli_se_key_to_keyspec`.
const SE_KEYSPEC_AES128: u32 = 0x0000_0010;

/// Word-aligned 16-byte block (the AES DMA needs aligned buffers).
#[repr(C, align(4))]
struct Blk([u8; 16]);

/// Word-aligned 32-byte block (SHA-256 digest output for the SE DMA).
#[repr(C, align(4))]
struct Blk32([u8; 32]);

/// SHA-256 hash command word (`HASH | OPTION_HASH_SHA256`).
pub const SE_CMD_HASH_SHA256: u32 = 0x0300_0400;

/// Enable the RADIOAES + SE mailbox bus clocks. Call once before any op. The SE
/// mailbox bus-faults if accessed unclocked.
pub fn init() {
    unsafe {
        CMU_CLKEN0
            .write_volatile(CMU_CLKEN0.read_volatile() | CMU_CLKEN0_RADIOAES);
        CMU_CLKEN1.write_volatile(
            CMU_CLKEN1.read_volatile() | CMU_CLKEN1_SEMAILBOXHOST,
        );
    }
}

/// AES-128 ECB of one 16-byte block (`encrypt = false` decrypts). Buffers may be
/// any alignment -- copied through internal aligned scratch.
pub fn aes128_ecb(
    encrypt: bool,
    key: &[u8; 16],
    input: &[u8; 16],
    output: &mut [u8; 16],
) {
    let config: u32 = AES_CFG_ECB | if encrypt { 0 } else { AES_DECRYPT };
    let mut k = Blk(*key);
    let i = Blk(*input);
    let mut o = Blk([0; 16]);

    // Fetcher chain key -> config -> data; pusher = output. tags: key 0x811,
    // config 0x11, data/pusher 0x21; nextDescr 0x1 = STOP.
    let d_data: [u32; 4] = [i.0.as_ptr() as u32, 0x1, 16, 0x21];
    let d_config: [u32; 4] =
        [(&config as *const u32) as u32, d_data.as_ptr() as u32, 4, 0x11];
    let d_key: [u32; 4] =
        [k.0.as_mut_ptr() as u32, d_config.as_ptr() as u32, 16, 0x811];
    let d_push: [u32; 4] = [o.0.as_mut_ptr() as u32, 0x1, 16, 0x21];

    unsafe {
        core::arch::asm!("dsb sy");
        RADIOAES_CTRL.write_volatile(0x3); // fetcher + pusher scatter-gather
        RADIOAES_FETCHADDR.write_volatile(d_key.as_ptr() as u32);
        RADIOAES_PUSHADDR.write_volatile(d_push.as_ptr() as u32);
        RADIOAES_CMD.write_volatile(0x3); // start
        for _ in 0..100_000 {
            if RADIOAES_STATUS.read_volatile() & 0x3 == 0 {
                break;
            }
        }
        core::arch::asm!("dsb sy");
    }
    output.copy_from_slice(&o.0);
}

/// Execute a raw Secure Engine mailbox command. `params` are the command's
/// parameter words; `out` (any alignment) receives the command's output data,
/// which the SE DMAs in. Returns the SE response status (0 = OK) or
/// [`SE_NO_RESPONSE`]. Loops are bounded so a wedged SE can't hang us.
pub fn se_execute(cmd: u32, params: &[u32], out: &mut [u8]) -> u32 {
    let mut desc = [0u32; 3];
    let data_out = if out.is_empty() {
        0
    } else {
        desc = [
            out.as_mut_ptr() as u32,
            SE_DT_STOP,
            out.len() as u32 | SE_DT_REALIGN,
        ];
        &desc as *const _ as u32
    };

    unsafe {
        let mut ready = false;
        for _ in 0..100_000 {
            if SE_TX_STATUS.read_volatile() & SE_TXINT != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return SE_NO_RESPONSE;
        }

        core::arch::asm!("dsb sy");
        SE_TX_HEADER.write_volatile(4 * (4 + params.len() as u32));
        SE_FIFO.write_volatile(cmd);
        SE_FIFO.write_volatile(0); // data_in = none
        SE_FIFO.write_volatile(data_out);
        for &p in params {
            SE_FIFO.write_volatile(p);
        }

        let mut done = false;
        for _ in 0..1_000_000 {
            if SE_RX_STATUS.read_volatile() & SE_RXINT != 0 {
                done = true;
                break;
            }
        }
        if !done {
            return SE_NO_RESPONSE;
        }
        let status = SE_RX_HEADER.read_volatile() & SE_RESPONSE_MASK;
        core::arch::asm!("dsb sy");
        status
    }
}

/// AES-128 ECB of one 16-byte block via the **Secure Engine mailbox** (the
/// all-SE AES path -- slower than RADIOAES, a full mailbox round-trip per block,
/// but uses only the SE). `encrypt = false` decrypts. Returns the SE status
/// (0 = OK) or [`SE_NO_RESPONSE`]. Buffers may be any alignment (copied through
/// aligned scratch the SE DMA can reach).
pub fn se_aes128_ecb(
    encrypt: bool,
    key: &[u8; 16],
    input: &[u8; 16],
    output: &mut [u8; 16],
) -> u32 {
    // Aligned, stable copies for the SE DMA.
    let k = Blk(*key);
    let i = Blk(*input);
    let mut o = Blk([0; 16]);
    let auth: u32 = 0; // length-0 auth segment; its data pointer is unused

    // data-in chain (each descriptor = {data, next, length|flags}): the SE wants
    // key metadata (auth) -> key bytes -> message, with STOP on the last.
    let seg_in: [u32; 3] = [i.0.as_ptr() as u32, SE_DT_STOP, 16 | SE_DT_REALIGN];
    let seg_key: [u32; 3] =
        [k.0.as_ptr() as u32, seg_in.as_ptr() as u32, 16 | SE_DT_REALIGN];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_out: [u32; 3] =
        [o.0.as_mut_ptr() as u32, SE_DT_STOP, 16 | SE_DT_REALIGN];

    let cmd = if encrypt { SE_CMD_AES_ENCRYPT } else { SE_CMD_AES_DECRYPT }
        | SE_OPT_MODE_ECB;
    let params = [SE_KEYSPEC_AES128, 16u32];

    unsafe {
        let mut ready = false;
        for _ in 0..100_000 {
            if SE_TX_STATUS.read_volatile() & SE_TXINT != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return SE_NO_RESPONSE;
        }

        core::arch::asm!("dsb sy");
        SE_TX_HEADER.write_volatile(4 * (4 + params.len() as u32));
        SE_FIFO.write_volatile(cmd);
        SE_FIFO.write_volatile(seg_auth.as_ptr() as u32); // data_in (chain head)
        SE_FIFO.write_volatile(seg_out.as_ptr() as u32); // data_out
        for &p in &params {
            SE_FIFO.write_volatile(p);
        }

        let mut done = false;
        for _ in 0..1_000_000 {
            if SE_RX_STATUS.read_volatile() & SE_RXINT != 0 {
                done = true;
                break;
            }
        }
        if !done {
            return SE_NO_RESPONSE;
        }
        let status = SE_RX_HEADER.read_volatile() & SE_RESPONSE_MASK;
        core::arch::asm!("dsb sy");
        output.copy_from_slice(&o.0);
        status
    }
}

/// Enable the RADIOAES pusher-stopped interrupt at the peripheral. Call once
/// before using the interrupt-driven [`radioaes_ecb_multi`]; the NVIC line is
/// armed per-operation (via `sys_irq_control`) inside that function. Idempotent.
pub fn radioaes_irq_enable() {
    unsafe {
        RADIOAES_IF_CLR.write_volatile(AES_INT_ALL); // clear any stale flags
        RADIOAES_IEN.write_volatile(AES_INT_PUSHER_ENDOFBLOCK);
    }
}

/// Multi-block AES-ECB via **RADIOAES** for a 16- or 32-byte `key` (AES-128 or
/// AES-256). `input`/`output` are a multiple of 16 bytes, word-aligned. One
/// descriptor chain processes the whole buffer. Output is written directly.
///
/// Completion is **interrupt-driven**: after kicking the DMA this blocks on the
/// AES end-of-block interrupt (`irq_mask` is the caller's notification bit for
/// IRQ 48), so the CPU is free during the transfer instead of busy-polling. The
/// interrupt is generated by the pusher descriptor's `INT_ENABLE` bit and is
/// delivered reliably for all transfer sizes. [`radioaes_irq_enable`] must have
/// been called once first.
pub fn radioaes_ecb_multi(
    encrypt: bool,
    key: &[u8],
    input: &[u8],
    output: &mut [u8],
    irq_mask: u32,
) {
    // ECB | NO_CX | (AES256 bit 0x4 for a 32-byte key) | DECRYPT bit.
    let keysz: u32 = if key.len() == 32 { 0x4 } else { 0 };
    let config: u32 = AES_CFG_ECB | keysz | if encrypt { 0 } else { AES_DECRYPT };
    let mut k = Blk32([0; 32]);
    k.0[..key.len()].copy_from_slice(key);
    let len = input.len() as u32;
    let d_data: [u32; 4] = [input.as_ptr() as u32, 0x1, len, 0x21];
    let d_config: [u32; 4] =
        [(&config as *const u32) as u32, d_data.as_ptr() as u32, 4, 0x11];
    let d_key: [u32; 4] =
        [k.0.as_mut_ptr() as u32, d_config.as_ptr() as u32, key.len() as u32, 0x811];
    // The pusher's last (only) descriptor sets INT_ENABLE so it raises the
    // end-of-block interrupt when the output is fully written -- the completion
    // signal we block on below.
    let d_push: [u32; 4] =
        [output.as_mut_ptr() as u32, 0x1, len | AES_DESCR_INT_ENABLE, 0x21];
    unsafe {
        // Clear any stale interrupt flag *before* arming so the wakeup can only
        // be this operation's completion, then kick the fetcher + pusher. The
        // descriptors live on this stack frame and stay valid across the wait.
        RADIOAES_IF_CLR.write_volatile(AES_INT_ALL);
        core::arch::asm!("dsb sy");
        RADIOAES_CTRL.write_volatile(0x3);
        RADIOAES_FETCHADDR.write_volatile(d_key.as_ptr() as u32);
        RADIOAES_PUSHADDR.write_volatile(d_push.as_ptr() as u32);
        RADIOAES_CMD.write_volatile(0x3);
    }
    // Enable the NVIC line, then block until the end-of-block interrupt fires.
    // The kernel auto-disables the line on delivery; we ack the AES flag after.
    //
    // Clear pending *while* enabling: this is a level source whose IF flag stays
    // asserted from completion until our IF_CLR below, so the NVIC re-pends the
    // line in that window. Without clearing, that stale pending bit fires the
    // next op's wait spuriously (before its DMA finishes), desyncing the loop and
    // eventually stalling the engine -> intermittent hang. Clearing is safe: a
    // still-asserted IF immediately re-pends, so a just-completed transfer isn't
    // lost.
    sys_irq_control_clear_pending(irq_mask, true);
    sys_recv_notification(irq_mask);
    unsafe {
        RADIOAES_IF_CLR.write_volatile(AES_INT_ALL);
        core::arch::asm!("dsb sy");
    }
}

/// Diagnostic twin of [`radioaes_ecb_multi`]: same descriptor setup (pusher
/// INT_ENABLE set), but waits by **bounded** `STATUS` polling instead of the
/// interrupt, then samples the raw interrupt-flag register. Returns
/// `(spins, if_flags, timed_out)` so a caller can see, for a given transfer
/// size, how the engine actually signals completion: which `IF` bits it raises
/// (bit3 = PUSHERENDOFBLOCK, bit4 = PUSHERSTOPPED, bit5 = PUSHERERROR, bits0-2 =
/// fetcher equivalents) and whether `STATUS` ever went idle. Used to pin down why
/// the end-of-block interrupt fires for small transfers but not large ones.
/// Cannot hang (the poll is bounded).
pub fn radioaes_ecb_diag(
    key: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> (u32, u32, bool) {
    let config: u32 = AES_CFG_ECB | if key.len() == 32 { 0x4 } else { 0 };
    let mut k = Blk32([0; 32]);
    k.0[..key.len()].copy_from_slice(key);
    let len = input.len() as u32;
    let d_data: [u32; 4] = [input.as_ptr() as u32, 0x1, len, 0x21];
    let d_config: [u32; 4] =
        [(&config as *const u32) as u32, d_data.as_ptr() as u32, 4, 0x11];
    let d_key: [u32; 4] =
        [k.0.as_mut_ptr() as u32, d_config.as_ptr() as u32, key.len() as u32, 0x811];
    let d_push: [u32; 4] =
        [output.as_mut_ptr() as u32, 0x1, len | AES_DESCR_INT_ENABLE, 0x21];
    unsafe {
        RADIOAES_IF_CLR.write_volatile(AES_INT_ALL);
        core::arch::asm!("dsb sy");
        RADIOAES_CTRL.write_volatile(0x3);
        RADIOAES_FETCHADDR.write_volatile(d_key.as_ptr() as u32);
        RADIOAES_PUSHADDR.write_volatile(d_push.as_ptr() as u32);
        RADIOAES_CMD.write_volatile(0x3);
        let mut spins = 0u32;
        let mut timed_out = false;
        while RADIOAES_STATUS.read_volatile() & 0x3 != 0 {
            spins += 1;
            if spins >= 5_000_000 {
                timed_out = true;
                break;
            }
        }
        let if_flags = RADIOAES_IF.read_volatile();
        core::arch::asm!("dsb sy");
        (spins, if_flags, timed_out)
    }
}

/// Multi-block AES-ECB via the **SE mailbox** for a 16- or 32-byte `key`
/// (AES-128/256). `input`/`output` a multiple of 16 bytes, aligned. One mailbox
/// command encrypts the whole buffer. Returns the SE status.
pub fn se_aes_ecb_multi(
    encrypt: bool,
    key: &[u8],
    input: &[u8],
    output: &mut [u8],
) -> u32 {
    let mut k = Blk32([0; 32]);
    k.0[..key.len()].copy_from_slice(key);
    // Keyspec for a RAW symmetric key: sym-size = key length (0x10 or 0x20).
    let keyspec = key.len() as u32;
    let len = input.len() as u32;
    let auth: u32 = 0;
    let seg_in: [u32; 3] =
        [input.as_ptr() as u32, SE_DT_STOP, len | SE_DT_REALIGN];
    let seg_key: [u32; 3] = [
        k.0.as_ptr() as u32,
        seg_in.as_ptr() as u32,
        key.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_out: [u32; 3] =
        [output.as_mut_ptr() as u32, SE_DT_STOP, len | SE_DT_REALIGN];
    let cmd = if encrypt { SE_CMD_AES_ENCRYPT } else { SE_CMD_AES_DECRYPT }
        | SE_OPT_MODE_ECB;
    unsafe {
        se_run(
            cmd,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[keyspec, len],
        )
    }
}

/// SHA-256 of `message` via the Secure Engine mailbox. Writes the 32-byte digest
/// to `digest`. Returns the SE status (0 = OK) or [`SE_NO_RESPONSE`]. `message`
/// should be word-aligned (the SE realigns, but callers pass aligned buffers).
pub fn se_sha256(message: &[u8], digest: &mut [u8; 32]) -> u32 {
    let mut d = Blk32([0; 32]);
    // Single-segment data-in (the message) and data-out (the digest).
    let seg_in: [u32; 3] = [
        message.as_ptr() as u32,
        SE_DT_STOP,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_out: [u32; 3] =
        [d.0.as_mut_ptr() as u32, SE_DT_STOP, 32 | SE_DT_REALIGN];
    let len = message.len() as u32;

    unsafe {
        let mut ready = false;
        for _ in 0..100_000 {
            if SE_TX_STATUS.read_volatile() & SE_TXINT != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return SE_NO_RESPONSE;
        }

        core::arch::asm!("dsb sy");
        SE_TX_HEADER.write_volatile(4 * (4 + 1)); // 1 parameter (message size)
        SE_FIFO.write_volatile(SE_CMD_HASH_SHA256);
        SE_FIFO.write_volatile(seg_in.as_ptr() as u32); // data_in
        SE_FIFO.write_volatile(seg_out.as_ptr() as u32); // data_out
        SE_FIFO.write_volatile(len);

        let mut done = false;
        for _ in 0..1_000_000 {
            if SE_RX_STATUS.read_volatile() & SE_RXINT != 0 {
                done = true;
                break;
            }
        }
        if !done {
            return SE_NO_RESPONSE;
        }
        let status = SE_RX_HEADER.read_volatile() & SE_RESPONSE_MASK;
        core::arch::asm!("dsb sy");
        digest.copy_from_slice(&d.0);
        status
    }
}

// AES-CMAC and HMAC-SHA256 command words. Both take a symmetric key the same way
// AES does (keyspec + key metadata + key bytes on the data-in chain).
const SE_CMD_AES_CMAC: u32 = 0x0404_0000;
const SE_CMD_HMAC_SHA256: u32 = 0x0302_0400;

/// Keyed MAC over `message` (`auth -> key -> message` data-in chain, params
/// `[keyspec, msg_len]`, tag DMAed to `out`). Shared by [`se_cmac`] and
/// [`se_hmac256`]. Returns the SE status (0 = OK) or [`SE_NO_RESPONSE`].
fn se_keyed_mac(cmd: u32, key: &[u8; 16], message: &[u8], out: &mut [u8]) -> u32 {
    let k = Blk(*key);
    let mut o = Blk32([0; 32]);
    let out_len = out.len().min(32);
    let auth: u32 = 0;

    let seg_msg: [u32; 3] = [
        message.as_ptr() as u32,
        SE_DT_STOP,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_key: [u32; 3] =
        [k.0.as_ptr() as u32, seg_msg.as_ptr() as u32, 16 | SE_DT_REALIGN];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_out: [u32; 3] =
        [o.0.as_mut_ptr() as u32, SE_DT_STOP, out_len as u32 | SE_DT_REALIGN];
    let params = [SE_KEYSPEC_AES128, message.len() as u32];

    unsafe {
        let mut ready = false;
        for _ in 0..100_000 {
            if SE_TX_STATUS.read_volatile() & SE_TXINT != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return SE_NO_RESPONSE;
        }

        core::arch::asm!("dsb sy");
        SE_TX_HEADER.write_volatile(4 * (4 + params.len() as u32));
        SE_FIFO.write_volatile(cmd);
        SE_FIFO.write_volatile(seg_auth.as_ptr() as u32); // data_in
        SE_FIFO.write_volatile(seg_out.as_ptr() as u32); // data_out
        for &p in &params {
            SE_FIFO.write_volatile(p);
        }

        let mut done = false;
        for _ in 0..1_000_000 {
            if SE_RX_STATUS.read_volatile() & SE_RXINT != 0 {
                done = true;
                break;
            }
        }
        if !done {
            return SE_NO_RESPONSE;
        }
        let status = SE_RX_HEADER.read_volatile() & SE_RESPONSE_MASK;
        core::arch::asm!("dsb sy");
        out.copy_from_slice(&o.0[..out_len]);
        status
    }
}

/// AES-CMAC (16-byte tag) of `message` under a 16-byte key, via the SE mailbox.
pub fn se_cmac(key: &[u8; 16], message: &[u8], tag: &mut [u8; 16]) -> u32 {
    se_keyed_mac(SE_CMD_AES_CMAC, key, message, tag)
}

/// HMAC-SHA256 (32-byte tag) of `message` under a 16-byte key, via the SE mailbox.
pub fn se_hmac256(key: &[u8; 16], message: &[u8], tag: &mut [u8; 32]) -> u32 {
    se_keyed_mac(SE_CMD_HMAC_SHA256, key, message, tag)
}

// ----- AES-GCM (Secure Engine authenticated encryption) -------------------

const SE_CMD_GCM_ENCRYPT: u32 = 0x0402_0000;
// Decrypt encodes the tag length in bits [15:8]; we always use a 16-byte tag.
const SE_CMD_GCM_DECRYPT: u32 = 0x0403_0000 | (16 << 8);

/// Word-aligned 12-byte block (GCM IV / nonce).
#[repr(C, align(4))]
struct Blk12([u8; 12]);

/// AES-128-GCM encrypt-and-tag. `iv` is the 12-byte nonce, `aad` the additional
/// authenticated data (may be empty), `pt` the plaintext. Writes the ciphertext
/// (same length as `pt`) to `ct` and the 16-byte auth tag to `tag`. Returns the
/// SE status (0 = OK). Reuses the AES-128 keyspec.
pub fn se_gcm_encrypt(
    key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; 16],
) -> u32 {
    let k = Blk(*key);
    let ivb = Blk12(*iv);
    let mut tg = Blk(*tag);
    let auth: u32 = 0;
    // data-in: auth -> key -> iv -> aad -> plaintext
    let seg_pt: [u32; 3] =
        [pt.as_ptr() as u32, SE_DT_STOP, pt.len() as u32 | SE_DT_REALIGN];
    let seg_aad: [u32; 3] = [
        aad.as_ptr() as u32,
        seg_pt.as_ptr() as u32,
        aad.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_iv: [u32; 3] =
        [ivb.0.as_ptr() as u32, seg_aad.as_ptr() as u32, 12 | SE_DT_REALIGN];
    let seg_key: [u32; 3] =
        [k.0.as_ptr() as u32, seg_iv.as_ptr() as u32, 16 | SE_DT_REALIGN];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    // data-out: ciphertext -> tag
    let seg_tag: [u32; 3] =
        [tg.0.as_mut_ptr() as u32, SE_DT_STOP, 16 | SE_DT_REALIGN];
    let seg_ct: [u32; 3] = [
        ct.as_mut_ptr() as u32,
        seg_tag.as_ptr() as u32,
        ct.len() as u32 | SE_DT_REALIGN,
    ];
    let st = unsafe {
        se_run(
            SE_CMD_GCM_ENCRYPT,
            seg_auth.as_ptr() as u32,
            seg_ct.as_ptr() as u32,
            &[SE_KEYSPEC_AES128, aad.len() as u32, pt.len() as u32],
        )
    };
    tag.copy_from_slice(&tg.0);
    st
}

/// AES-128-GCM authenticated decrypt. Verifies `tag` over `aad || ct`; on success
/// writes the recovered plaintext to `pt` and returns 0, otherwise returns
/// [`SE_INVALID_SIGNATURE`] (tampering detected) and `pt` is unspecified.
pub fn se_gcm_decrypt(
    key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
    pt: &mut [u8],
) -> u32 {
    let k = Blk(*key);
    let ivb = Blk12(*iv);
    let tg = Blk(*tag);
    let auth: u32 = 0;
    // data-in: auth -> key -> iv -> aad -> ciphertext -> tag
    let seg_tag: [u32; 3] =
        [tg.0.as_ptr() as u32, SE_DT_STOP, 16 | SE_DT_REALIGN];
    let seg_ct: [u32; 3] = [
        ct.as_ptr() as u32,
        seg_tag.as_ptr() as u32,
        ct.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_aad: [u32; 3] = [
        aad.as_ptr() as u32,
        seg_ct.as_ptr() as u32,
        aad.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_iv: [u32; 3] =
        [ivb.0.as_ptr() as u32, seg_aad.as_ptr() as u32, 12 | SE_DT_REALIGN];
    let seg_key: [u32; 3] =
        [k.0.as_ptr() as u32, seg_iv.as_ptr() as u32, 16 | SE_DT_REALIGN];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_out: [u32; 3] = [
        pt.as_mut_ptr() as u32,
        SE_DT_STOP,
        pt.len() as u32 | SE_DT_REALIGN,
    ];
    unsafe {
        se_run(
            SE_CMD_GCM_DECRYPT,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[SE_KEYSPEC_AES128, aad.len() as u32, ct.len() as u32],
        )
    }
}

// ----- ECDSA P-256 (Secure Engine) ----------------------------------------

const SE_CMD_CREATE_KEY: u32 = 0x0200_0000;
// Sign/verify with the SE hashing the (raw) message itself (SHA-256 option).
const SE_CMD_SIGN: u32 = 0x0600_0400; // SIGNATURE_SIGN | HASH_SHA256
const SE_CMD_VERIFY: u32 = 0x0601_0400; // SIGNATURE_VERIFY | HASH_SHA256
// P-256 keyspecs (Weierstrass type 0x8<<28, size 32 -> field (32-1)=0x1f, plus
// the private (1<<14) / public (1<<13) attribute bits). From sli_se_key_to_keyspec.
const SE_KEYSPEC_P256_PRIV: u32 = 0x8000_401f;
const SE_KEYSPEC_P256_PUB: u32 = 0x8000_201f;
const SE_KEYSPEC_P256_PAIR: u32 = 0x8000_601f;

/// SE response code for a signature that did not validate.
pub const SE_INVALID_SIGNATURE: u32 = 0x0003_0000;

#[repr(C, align(4))]
struct Blk64([u8; 64]);
#[repr(C, align(4))]
struct Blk96([u8; 96]);

/// Issue one SE mailbox command and return its status. `data_in`/`data_out` are
/// the descriptor-chain head pointers (0 if none). Used by the slower ECC ops;
/// the symmetric paths inline their own copy.
unsafe fn se_run(cmd: u32, data_in: u32, data_out: u32, params: &[u32]) -> u32 {
    unsafe {
        let mut ready = false;
        for _ in 0..100_000 {
            if SE_TX_STATUS.read_volatile() & SE_TXINT != 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return SE_NO_RESPONSE;
        }
        core::arch::asm!("dsb sy");
        SE_TX_HEADER.write_volatile(4 * (4 + params.len() as u32));
        SE_FIFO.write_volatile(cmd);
        SE_FIFO.write_volatile(data_in);
        SE_FIFO.write_volatile(data_out);
        for &p in params {
            SE_FIFO.write_volatile(p);
        }
        // ECC point math is far slower than AES, so allow a generous spin.
        let mut done = false;
        for _ in 0..8_000_000 {
            if SE_RX_STATUS.read_volatile() & SE_RXINT != 0 {
                done = true;
                break;
            }
        }
        if !done {
            return SE_NO_RESPONSE;
        }
        let status = SE_RX_HEADER.read_volatile() & SE_RESPONSE_MASK;
        core::arch::asm!("dsb sy");
        status
    }
}

/// Generate a fresh P-256 keypair into `out` = `priv(32) || pubX(32) || pubY(32)`.
pub fn se_ecc_p256_keygen(out: &mut [u8; 96]) -> u32 {
    let mut o = Blk96([0; 96]);
    let auth: u32 = 0;
    let seg_auth: [u32; 3] =
        [(&auth as *const u32) as u32, SE_DT_STOP, 0 | SE_DT_REALIGN];
    let seg_out: [u32; 3] =
        [o.0.as_mut_ptr() as u32, SE_DT_STOP, 96 | SE_DT_REALIGN];
    let st = unsafe {
        se_run(
            SE_CMD_CREATE_KEY,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[SE_KEYSPEC_P256_PAIR],
        )
    };
    out.copy_from_slice(&o.0);
    st
}

/// Diagnostic: raw ECDSA sign with an explicit `cmd` word, `keyspec`, and key
/// input (`key` is copied into 96-byte aligned scratch; `keylen` bytes are sent).
/// Lets a self-test sweep command/keyspec/key-length combos to find what the SE
/// accepts. Returns the SE status. `inline(never)` so a sweep of several calls
/// shares one stack frame instead of ballooning the caller's.
#[inline(never)]
pub fn se_ecdsa_sign_raw(
    cmd: u32,
    keyspec: u32,
    key: &[u8],
    keylen: usize,
    message: &[u8],
    sig: &mut [u8; 64],
) -> u32 {
    let mut kbuf = Blk96([0; 96]);
    kbuf.0[..key.len().min(96)].copy_from_slice(&key[..key.len().min(96)]);
    let mut s = Blk64([0; 64]);
    let auth: u32 = 0;
    let seg_msg: [u32; 3] = [
        message.as_ptr() as u32,
        SE_DT_STOP,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_key: [u32; 3] = [
        kbuf.0.as_ptr() as u32,
        seg_msg.as_ptr() as u32,
        keylen as u32 | SE_DT_REALIGN,
    ];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_out: [u32; 3] =
        [s.0.as_mut_ptr() as u32, SE_DT_STOP, 64 | SE_DT_REALIGN];
    let st = unsafe {
        se_run(
            cmd,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[keyspec, message.len() as u32],
        )
    };
    sig.copy_from_slice(&s.0);
    st
}

/// ECDSA-P256 sign of `message` (the SE hashes it with SHA-256) with a `keypair`
/// (the 96-byte `priv || pubX || pubY` from [`se_ecc_p256_keygen`], fed back
/// whole with the PAIR keyspec). Writes the 64-byte signature `r || s`.
pub fn se_ecdsa_p256_sign(
    keypair: &[u8; 96],
    message: &[u8],
    sig: &mut [u8; 64],
) -> u32 {
    let k = Blk96(*keypair);
    let mut s = Blk64([0; 64]);
    let auth: u32 = 0;
    let seg_msg: [u32; 3] = [
        message.as_ptr() as u32,
        SE_DT_STOP,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_key: [u32; 3] =
        [k.0.as_ptr() as u32, seg_msg.as_ptr() as u32, 96 | SE_DT_REALIGN];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_out: [u32; 3] =
        [s.0.as_mut_ptr() as u32, SE_DT_STOP, 64 | SE_DT_REALIGN];
    let st = unsafe {
        se_run(
            SE_CMD_SIGN,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[SE_KEYSPEC_P256_PAIR, message.len() as u32],
        )
    };
    sig.copy_from_slice(&s.0);
    st
}

/// ECDSA-P256 verify of `sig` over a pre-hashed `message` (32-byte SHA-256
/// digest) with a `keypair` (the 96-byte buffer, fed whole with the PAIR
/// keyspec). Returns 0 if valid, [`SE_INVALID_SIGNATURE`] if not (or an error).
pub fn se_ecdsa_p256_verify(
    keypair: &[u8; 96],
    message: &[u8],
    sig: &[u8; 64],
) -> u32 {
    let k = Blk96(*keypair);
    let s = Blk64(*sig);
    let auth: u32 = 0;
    // Verify input chain (non-EdDSA): key -> message -> signature.
    let seg_sig: [u32; 3] =
        [s.0.as_ptr() as u32, SE_DT_STOP, 64 | SE_DT_REALIGN];
    let seg_msg: [u32; 3] = [
        message.as_ptr() as u32,
        seg_sig.as_ptr() as u32,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_key: [u32; 3] =
        [k.0.as_ptr() as u32, seg_msg.as_ptr() as u32, 96 | SE_DT_REALIGN];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    unsafe {
        se_run(
            SE_CMD_VERIFY,
            seg_auth.as_ptr() as u32,
            0,
            &[SE_KEYSPEC_P256_PAIR, message.len() as u32],
        )
    }
}

// ----- Ed25519 (EdDSA) sign/verify -----------------------------------------
//
// A different curve family (Edwards, type 0xc) and opcode than P-256 ECDSA --
// may be accepted where Weierstrass ECDSA sign is not. Keypair is 64 bytes
// (priv32 || pub32), plaintext (auth length 0). EdDSA feeds the message twice on
// sign; verify order is signature then message.

const SE_CMD_EDDSA_SIGN: u32 = 0x0602_0000;
const SE_CMD_EDDSA_VERIFY: u32 = 0x0603_0000;
/// Ed25519, type ECC_EDDSA (0xc<<28), size 32, private+public.
const SE_KEYSPEC_ED25519: u32 = 0xc000_601f;

/// Generate an Ed25519 keypair into `out` = `priv(32) || pub(32)` (plaintext).
pub fn se_ed25519_keygen(out: &mut [u8; 64]) -> u32 {
    let mut o = Blk64([0; 64]);
    let auth: u32 = 0;
    let seg_auth: [u32; 3] =
        [(&auth as *const u32) as u32, SE_DT_STOP, 0 | SE_DT_REALIGN];
    let seg_out: [u32; 3] =
        [o.0.as_mut_ptr() as u32, SE_DT_STOP, 64 | SE_DT_REALIGN];
    let st = unsafe {
        se_run(
            SE_CMD_CREATE_KEY,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[SE_KEYSPEC_ED25519],
        )
    };
    out.copy_from_slice(&o.0);
    st
}

/// Ed25519 sign of `message` with `keypair` (64-byte `priv||pub`). Writes the
/// 64-byte signature. Returns the SE status.
pub fn se_ed25519_sign(keypair: &[u8; 64], message: &[u8], sig: &mut [u8; 64]) -> u32 {
    let k = Blk64(*keypair);
    let mut s = Blk64([0; 64]);
    let auth: u32 = 0;
    // EdDSA data-in: auth -> key -> message -> message (the message is fed twice).
    let seg_msg2: [u32; 3] = [
        message.as_ptr() as u32,
        SE_DT_STOP,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_msg1: [u32; 3] = [
        message.as_ptr() as u32,
        seg_msg2.as_ptr() as u32,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_key: [u32; 3] =
        [k.0.as_ptr() as u32, seg_msg1.as_ptr() as u32, 64 | SE_DT_REALIGN];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_out: [u32; 3] =
        [s.0.as_mut_ptr() as u32, SE_DT_STOP, 64 | SE_DT_REALIGN];
    let st = unsafe {
        se_run(
            SE_CMD_EDDSA_SIGN,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[SE_KEYSPEC_ED25519, message.len() as u32],
        )
    };
    sig.copy_from_slice(&s.0);
    st
}

/// Ed25519 verify of `sig` over `message` with `keypair`. Returns 0 if valid,
/// [`SE_INVALID_SIGNATURE`] if not.
pub fn se_ed25519_verify(keypair: &[u8; 64], message: &[u8], sig: &[u8; 64]) -> u32 {
    let k = Blk64(*keypair);
    let s = Blk64(*sig);
    let auth: u32 = 0;
    // EdDSA verify data-in: auth -> key -> signature -> message.
    let seg_msg: [u32; 3] = [
        message.as_ptr() as u32,
        SE_DT_STOP,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_sig: [u32; 3] =
        [s.0.as_ptr() as u32, seg_msg.as_ptr() as u32, 64 | SE_DT_REALIGN];
    let seg_key: [u32; 3] =
        [k.0.as_ptr() as u32, seg_sig.as_ptr() as u32, 64 | SE_DT_REALIGN];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    unsafe {
        se_run(
            SE_CMD_EDDSA_VERIFY,
            seg_auth.as_ptr() as u32,
            0,
            &[SE_KEYSPEC_ED25519, message.len() as u32],
        )
    }
}

// ----- X25519 ECDH key exchange --------------------------------------------
//
// Montgomery curve (type 0xb) -- like Ed25519, a different family than the
// P-256 Weierstrass curve, so its private-key DH op works on this part. Keypair
// is 64 bytes (priv32 || pub32). The shared secret output is a RAW symmetric key.

const SE_CMD_DH: u32 = 0x0e00_0000;
const SE_KEYSPEC_X25519_PAIR: u32 = 0xb000_601f; // Montgomery, size 32, priv+pub
const SE_KEYSPEC_X25519_PRIV: u32 = 0xb000_401f; // private only
const SE_KEYSPEC_DH_OUT: u32 = 0x0000_0020; // RAW symmetric, 32-byte shared secret

/// Generate an X25519 keypair into `out` = `priv(32) || pub(32)` (plaintext).
pub fn se_x25519_keygen(out: &mut [u8; 64]) -> u32 {
    let mut o = Blk64([0; 64]);
    let auth: u32 = 0;
    let seg_auth: [u32; 3] =
        [(&auth as *const u32) as u32, SE_DT_STOP, 0 | SE_DT_REALIGN];
    let seg_out: [u32; 3] =
        [o.0.as_mut_ptr() as u32, SE_DT_STOP, 64 | SE_DT_REALIGN];
    let st = unsafe {
        se_run(
            SE_CMD_CREATE_KEY,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[SE_KEYSPEC_X25519_PAIR],
        )
    };
    out.copy_from_slice(&o.0);
    st
}

/// Diagnostic X25519 ECDH that optionally byte-reverses the private scalar and/or
/// the peer public key, so a self-test can find the byte order the SE wants.
#[inline(never)]
pub fn se_x25519_ecdh_dbg(
    keypair: &[u8; 64],
    peer_pub: &[u8; 32],
    rev_priv: bool,
    rev_pub: bool,
    shared: &mut [u8; 32],
) -> u32 {
    let mut kp = Blk64(*keypair);
    if rev_priv {
        for i in 0..16 {
            kp.0.swap(i, 31 - i);
        }
    }
    let mut pbb = *peer_pub;
    if rev_pub {
        for i in 0..16 {
            pbb.swap(i, 31 - i);
        }
    }
    let pb = Blk32(pbb);
    let mut sh = Blk32([0; 32]);
    let auth: u32 = 0;
    let seg_pub: [u32; 3] =
        [pb.0.as_ptr() as u32, SE_DT_STOP, 32 | SE_DT_REALIGN];
    let seg_key: [u32; 3] =
        [kp.0.as_ptr() as u32, seg_pub.as_ptr() as u32, 64 | SE_DT_REALIGN];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_out: [u32; 3] =
        [sh.0.as_mut_ptr() as u32, SE_DT_STOP, 32 | SE_DT_REALIGN];
    let st = unsafe {
        se_run(
            SE_CMD_DH,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[SE_KEYSPEC_X25519_PAIR, SE_KEYSPEC_DH_OUT],
        )
    };
    shared.copy_from_slice(&sh.0);
    st
}

/// X25519 ECDH: combine our `my_keypair` (64-byte `priv||pub`) with the peer's
/// `peer_pub` (32 bytes) into the 32-byte `shared` secret. The private op takes
/// the whole keypair + PAIR keyspec. Returns the SE status.
pub fn se_x25519_ecdh(
    my_keypair: &[u8; 64],
    peer_pub: &[u8; 32],
    shared: &mut [u8; 32],
) -> u32 {
    let kp = Blk64(*my_keypair);
    let pb = Blk32(*peer_pub);
    let mut sh = Blk32([0; 32]);
    let auth: u32 = 0;
    // data-in: auth -> my keypair (64) -> peer public key (32). The keygen buffer
    // is pub||priv, so the caller passes the peer's *offset-0* 32 bytes here.
    let seg_pub: [u32; 3] =
        [pb.0.as_ptr() as u32, SE_DT_STOP, 32 | SE_DT_REALIGN];
    let seg_key: [u32; 3] =
        [kp.0.as_ptr() as u32, seg_pub.as_ptr() as u32, 64 | SE_DT_REALIGN];
    let seg_auth: [u32; 3] = [
        (&auth as *const u32) as u32,
        seg_key.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_out: [u32; 3] =
        [sh.0.as_mut_ptr() as u32, SE_DT_STOP, 32 | SE_DT_REALIGN];
    let st = unsafe {
        se_run(
            SE_CMD_DH,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[SE_KEYSPEC_X25519_PAIR, SE_KEYSPEC_DH_OUT],
        )
    };
    shared.copy_from_slice(&sh.0);
    st
}

// ----- ECDSA P-256 with an internal VOLATILE key (Secure Vault) -----------
//
// Plaintext private keys are rejected for signing on this part; the supported
// path keeps the key inside the SE. We generate the keypair into volatile slot 0
// (it never leaves the SE), then sign/verify by referencing that slot. The
// keyspec carries MODE_VOLATILE + slot 0; the key input is length 0 (no key
// bytes); the auth buffer is the 8-byte default (zeros).

/// P-256, MODE_VOLATILE (1<<26), slot 0, private+public, size 32.
const SE_KEYSPEC_P256_VOLATILE: u32 = 0x8400_601f;

/// Word-aligned 8-byte default auth buffer (zeros) for internal keys.
#[repr(C, align(4))]
struct Auth8([u32; 2]);

/// Generate a P-256 keypair into internal volatile slot 0 (stays in the SE).
pub fn se_ecc_p256_keygen_volatile() -> u32 {
    let auth = Auth8([0, 0]);
    let dummy: u32 = 0;
    let seg_auth: [u32; 3] =
        [auth.0.as_ptr() as u32, SE_DT_STOP, 8 | SE_DT_REALIGN];
    // Volatile key output is internal -> a length-0 output descriptor.
    let seg_out: [u32; 3] =
        [(&dummy as *const u32) as u32, SE_DT_STOP, 0 | SE_DT_REALIGN];
    unsafe {
        se_run(
            SE_CMD_CREATE_KEY,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[SE_KEYSPEC_P256_VOLATILE],
        )
    }
}

/// Diagnostic: volatile-key sign with an explicit `cmd` word and `keyspec`, so a
/// self-test can sweep configs. Auth = 8-byte default, key input = length 0
/// (slot reference). Returns the SE status.
#[inline(never)]
pub fn se_ecdsa_sign_vol_dbg(
    cmd: u32,
    keyspec: u32,
    message: &[u8],
    sig: &mut [u8; 64],
) -> u32 {
    let auth = Auth8([0, 0]);
    let dummy: u32 = 0;
    let mut s = Blk64([0; 64]);
    let seg_msg: [u32; 3] = [
        message.as_ptr() as u32,
        SE_DT_STOP,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_key: [u32; 3] = [
        (&dummy as *const u32) as u32,
        seg_msg.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_auth: [u32; 3] =
        [auth.0.as_ptr() as u32, seg_key.as_ptr() as u32, 8 | SE_DT_REALIGN];
    let seg_out: [u32; 3] =
        [s.0.as_mut_ptr() as u32, SE_DT_STOP, 64 | SE_DT_REALIGN];
    let st = unsafe {
        se_run(
            cmd,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[keyspec, message.len() as u32],
        )
    };
    sig.copy_from_slice(&s.0);
    st
}

/// ECDSA-P256 sign of `message` (SE hashes it) with the volatile slot-0 key.
pub fn se_ecdsa_p256_sign_volatile(message: &[u8], sig: &mut [u8; 64]) -> u32 {
    let auth = Auth8([0, 0]);
    let dummy: u32 = 0;
    let mut s = Blk64([0; 64]);
    // data-in: auth(8) -> key(len 0, slot reference) -> message
    let seg_msg: [u32; 3] = [
        message.as_ptr() as u32,
        SE_DT_STOP,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_key: [u32; 3] = [
        (&dummy as *const u32) as u32,
        seg_msg.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_auth: [u32; 3] =
        [auth.0.as_ptr() as u32, seg_key.as_ptr() as u32, 8 | SE_DT_REALIGN];
    let seg_out: [u32; 3] =
        [s.0.as_mut_ptr() as u32, SE_DT_STOP, 64 | SE_DT_REALIGN];
    let st = unsafe {
        se_run(
            SE_CMD_SIGN,
            seg_auth.as_ptr() as u32,
            seg_out.as_ptr() as u32,
            &[SE_KEYSPEC_P256_VOLATILE, message.len() as u32],
        )
    };
    sig.copy_from_slice(&s.0);
    st
}

/// ECDSA-P256 verify of `sig` over `message` with the volatile slot-0 key.
/// Returns 0 if valid, [`SE_INVALID_SIGNATURE`] if not.
pub fn se_ecdsa_p256_verify_volatile(message: &[u8], sig: &[u8; 64]) -> u32 {
    let auth = Auth8([0, 0]);
    let dummy: u32 = 0;
    let s = Blk64(*sig);
    // data-in: auth(8) -> key(len 0) -> message -> signature
    let seg_sig: [u32; 3] =
        [s.0.as_ptr() as u32, SE_DT_STOP, 64 | SE_DT_REALIGN];
    let seg_msg: [u32; 3] = [
        message.as_ptr() as u32,
        seg_sig.as_ptr() as u32,
        message.len() as u32 | SE_DT_REALIGN,
    ];
    let seg_key: [u32; 3] = [
        (&dummy as *const u32) as u32,
        seg_msg.as_ptr() as u32,
        0 | SE_DT_REALIGN,
    ];
    let seg_auth: [u32; 3] =
        [auth.0.as_ptr() as u32, seg_key.as_ptr() as u32, 8 | SE_DT_REALIGN];
    unsafe {
        se_run(
            SE_CMD_VERIFY,
            seg_auth.as_ptr() as u32,
            0,
            &[SE_KEYSPEC_P256_VOLATILE, message.len() as u32],
        )
    }
}

// ----- IPC protocol (clients <-> the crypto server) -----------------------

/// AES-128 ECB op. Body: `[encrypt(1), key(16), input(16)]`; reply: `output(16)`.
pub const OP_AES: u16 = 1;
/// Raw SE command op. Body: `[cmd(4), nparams(1), params(4*4), out_len(1)]`;
/// reply: `[status(4), output(out_len)]`.
pub const OP_SE: u16 = 2;
/// SHA-256 op. Body: the message bytes; reply: the 32-byte digest, reply code =
/// SE status (0 = OK).
pub const OP_HASH: u16 = 3;
/// Keyed-MAC op. Body: `[hmac(1), key(16), message...]`; reply: the tag (16 for
/// CMAC, 32 for HMAC-SHA256), reply code = SE status.
pub const OP_MAC: u16 = 4;
/// Ed25519 sign/verify demo op. Body: the message. The server generates a fresh
/// Ed25519 keypair, signs, verifies, then verifies a TRNG-forged signature (must
/// reject). Reply: `[genuine_ok(1), forgery_rejected(1), sig(64), forged_sig(64)]`;
/// reply code = keygen status. (P-256 ECDSA sign is rejected by this part, but
/// Ed25519 EdDSA works.)
pub const OP_ECDSA: u16 = 5;
/// `OP_ECDSA` reply length.
pub const ECDSA_REPLY: usize = 2 + 64 + 64;
/// AES-GCM demo op. Body: ignored. The server encrypts a fixed message, decrypts
/// it (authentic), and decrypts a 1-byte-tampered ciphertext (must fail the tag).
/// Reply: `[auth_ok(1), tamper_detected(1), ct(16), tag(16)]`; code = encrypt status.
pub const OP_GCM: u16 = 6;
/// `OP_GCM` reply length.
pub const GCM_REPLY: usize = 2 + 16 + 16;
/// X25519 ECDH demo op. Body: ignored. The server generates Alice & Bob X25519
/// keypairs, each derives the shared secret from the other's public key. Reply:
/// `[match(1), pubA(32), pubB(32), shared(32)]`; reply code 0 = OK.
pub const OP_ECDH: u16 = 8;
/// `OP_ECDH` reply length.
pub const ECDH_REPLY: usize = 1 + 32 + 32 + 32;

/// AES benchmark op. Body: `block_size(4, LE)` -- the bytes per AES call. The
/// server encrypts [`BENCH_TOTAL`] bytes in `block_size` chunks on each engine
/// and times it; bigger chunks amortize the SE's per-call mailbox cost. Reply:
/// `[radioaes_ms(4), se_ms(4), sw_ms(4)]` (little-endian; sw = Oberon software).
pub const OP_BENCH: u16 = 7;
/// `OP_BENCH` reply length.
pub const BENCH_REPLY: usize = 12;
/// Total bytes encrypted per engine, per run (constant across block sizes).
pub const BENCH_TOTAL: u32 = 65536;
/// Largest per-call block the benchmark buffers support.
pub const BENCH_MAXB: usize = 16384;

/// Crypto-suite benchmark op. Body: `[algo(1)]` (see [`CBENCH_NALGO`]). For the
/// selected algorithm the server runs the **SE mailbox** and the **Oberon
/// software** implementation in time-budgeted loops and returns each engine's op
/// count and elapsed milliseconds, so the client can compute ops/sec. These are
/// the algorithms *both* engines support (AES, GCM, CMAC, SHA-256, HMAC, Ed25519
/// sign/verify, X25519 ECDH). Reply: `[se_ops(4), se_ms(4), sw_ops(4), sw_ms(4)]`
/// (little-endian).
pub const OP_CBENCH: u16 = 9;
/// `OP_CBENCH` reply length.
pub const CBENCH_REPLY: usize = 16;
/// Number of algorithms the crypto-suite benchmark sweeps.
pub const CBENCH_NALGO: u8 = 9;
/// Per-op buffer size for the bulk algorithms in the crypto-suite benchmark.
pub const CBENCH_BUF: usize = 1024;

/// Largest message hashed in one [`OP_HASH`] (bounded by the server recv buffer).
pub const HASH_MSG_MAX: usize = 60;
/// Largest message MACed in one [`OP_MAC`] (recv buffer minus the 17-byte header).
pub const MAC_MSG_MAX: usize = 47;

/// Largest SE output we marshal in one reply.
pub const SE_MAX_OUT: usize = 48;
const SE_MAX_PARAMS: usize = 4;

/// Client side of [`OP_AES`]: ask the crypto server to AES one block.
pub fn client_aes(
    srv: TaskId,
    encrypt: bool,
    key: &[u8; 16],
    input: &[u8; 16],
    output: &mut [u8; 16],
) {
    let mut req = [0u8; 33];
    req[0] = encrypt as u8;
    req[1..17].copy_from_slice(key);
    req[17..33].copy_from_slice(input);
    sys_send(srv, OP_AES, &req, output, &[]);
}

/// Client side of [`OP_SE`]: ask the crypto server to run an SE command. Fills
/// `out` with the SE output and returns the SE status (0 = OK).
pub fn client_se(srv: TaskId, cmd: u32, params: &[u32], out: &mut [u8]) -> u32 {
    let np = params.len().min(SE_MAX_PARAMS);
    let mut req = [0u8; 22];
    req[0..4].copy_from_slice(&cmd.to_le_bytes());
    req[4] = np as u8;
    for (i, p) in params.iter().take(np).enumerate() {
        req[5 + i * 4..9 + i * 4].copy_from_slice(&p.to_le_bytes());
    }
    req[21] = out.len().min(SE_MAX_OUT) as u8;

    let mut reply = [0u8; 4 + SE_MAX_OUT];
    let (_code, len) = sys_send(srv, OP_SE, &req, &mut reply, &[]);
    let status = u32::from_le_bytes(reply[0..4].try_into().unwrap());
    let n = len.saturating_sub(4).min(out.len());
    out[..n].copy_from_slice(&reply[4..4 + n]);
    status
}

/// Client side of [`OP_HASH`]: ask the crypto server to SHA-256 `message`
/// (truncated to [`HASH_MSG_MAX`]). Returns the SE status (0 = OK).
pub fn client_sha256(srv: TaskId, message: &[u8], digest: &mut [u8; 32]) -> u32 {
    let n = message.len().min(HASH_MSG_MAX);
    let (code, _len) = sys_send(srv, OP_HASH, &message[..n], digest, &[]);
    code
}

/// Client side of [`OP_ECDSA`]: ask the crypto server to run a full P-256
/// sign/verify roundtrip over `message`. `out` must be [`ECDSA_REPLY`] bytes:
/// `[genuine_ok(1), forgery_rejected(1), sig(64)]`. Returns the keygen status.
pub fn client_ecdsa(srv: TaskId, message: &[u8], out: &mut [u8; ECDSA_REPLY]) -> u32 {
    let n = message.len().min(HASH_MSG_MAX);
    let (code, _len) = sys_send(srv, OP_ECDSA, &message[..n], out, &[]);
    code
}

/// Client side of [`OP_ECDH`]: run an Alice/Bob X25519 key exchange. `out` is
/// `[match(1), pubA(32), pubB(32), shared(32)]`. Returns the reply code.
pub fn client_ecdh(srv: TaskId, out: &mut [u8; ECDH_REPLY]) -> u32 {
    let (code, _len) = sys_send(srv, OP_ECDH, &[], out, &[]);
    code
}

/// Client side of [`OP_BENCH`]: run the RADIOAES-vs-SE AES benchmark with
/// `block_size` bytes per call and a `key_bytes`-byte key (16 = AES-128, 32 =
/// AES-256). `out` is `[radioaes_ms(4), se_ms(4)]`. Returns the reply code.
pub fn client_bench(
    srv: TaskId,
    block_size: u32,
    key_bytes: u32,
    out: &mut [u8; BENCH_REPLY],
) -> u32 {
    let mut body = [0u8; 8];
    body[0..4].copy_from_slice(&block_size.to_le_bytes());
    body[4..8].copy_from_slice(&key_bytes.to_le_bytes());
    let (code, _len) = sys_send(srv, OP_BENCH, &body, out, &[]);
    code
}

/// Client side of [`OP_CBENCH`]: benchmark algorithm `algo` (SE vs Oberon).
/// `out` is `[se_ops(4), se_ms(4), sw_ops(4), sw_ms(4)]`. Returns the reply code.
pub fn client_cbench(srv: TaskId, algo: u8, out: &mut [u8; CBENCH_REPLY]) -> u32 {
    let (code, _len) = sys_send(srv, OP_CBENCH, &[algo], out, &[]);
    code
}

/// Client side of [`OP_GCM`]: run the AES-GCM authenticated-encryption demo.
/// `out` must be [`GCM_REPLY`] bytes. Returns the encrypt status (0 = OK).
pub fn client_gcm(srv: TaskId, out: &mut [u8; GCM_REPLY]) -> u32 {
    let (code, _len) = sys_send(srv, OP_GCM, &[], out, &[]);
    code
}

/// Client side of [`OP_MAC`]: ask the crypto server for a keyed MAC of `message`
/// (`hmac` selects HMAC-SHA256 over AES-CMAC). `out` must be 16 bytes for CMAC or
/// 32 for HMAC. Returns the SE status (0 = OK).
pub fn client_mac(
    srv: TaskId,
    hmac: bool,
    key: &[u8; 16],
    message: &[u8],
    out: &mut [u8],
) -> u32 {
    let n = message.len().min(MAC_MSG_MAX);
    let mut req = [0u8; 17 + MAC_MSG_MAX];
    req[0] = hmac as u8;
    req[1..17].copy_from_slice(key);
    req[17..17 + n].copy_from_slice(&message[..n]);
    let (code, _len) = sys_send(srv, OP_MAC, &req[..17 + n], out, &[]);
    code
}
