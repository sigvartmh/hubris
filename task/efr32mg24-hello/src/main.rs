// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Heartbeat task for the EFR32MG24 bring-up image.
//!
//! Every ~500 ms it:
//!   1. toggles LED0 (PB02) -- a visible blink,
//!   2. records the beat in a `ringbuf` (read it with `humility ringbuf`), and
//!   3. logs a line to SWO via the `Log` kipc.
//!
//! The SWO line is the interesting part: an unprivileged task can't reach the
//! ITM stimulus port directly on this core, so it hands the bytes to the kernel
//! (privileged) via `kipc::log`, which does the ITM write. That makes
//! task-originated text show up on SWO live, alongside the humility-readable
//! ringbuf.

#![no_std]
#![no_main]

use core::fmt::Write;

use ringbuf::{ringbuf, ringbuf_entry};
use userlib::*;

/// GPIO secure alias base. Port B = `P[1]` at base + 0x30 + 0x30; MODEL is the
/// 2nd word of the block, DOUT the 5th. LED0 is PB02 on the BRD4187x + WSTK.
const GPIO_BASE: u32 = 0x4003_c000;
const GPIO_PB_MODEL: *mut u32 = (GPIO_BASE + 0x064) as *mut u32;
const GPIO_PB_DOUT: *mut u32 = (GPIO_BASE + 0x070) as *mut u32;
const LED_PIN: u32 = 2;
const MODE_PUSHPULL: u32 = 0x4;

const BLINK_MS: u64 = 500;

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    None,
    Heartbeat(u32),
}
ringbuf!(Trace, 16, Trace::None);

/// Tiny stack buffer implementing `core::fmt::Write`, so we can `writeln!` a
/// line and hand the bytes to `kipc::log` without any allocator.
struct LogBuf {
    buf: [u8; 96],
    len: usize,
}

impl Write for LogBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &byte in s.as_bytes() {
            if self.len < self.buf.len() {
                self.buf[self.len] = byte;
                self.len += 1;
            }
        }
        Ok(())
    }
}

/// Direct (unprivileged) write to ITM stimulus port 0, the way bare-metal code
/// would (matching the reference `ITM_WriteCharUnprivileged`), but with a
/// *bounded* FIFO-ready wait so a denied unprivileged read (which returns 0
/// forever) can't hang the task.
fn direct_itm(bytes: &[u8]) {
    const ITM_STIM0: *mut u32 = 0xE000_0000 as *mut u32;
    for &byte in bytes {
        for _ in 0..1000 {
            if unsafe { ITM_STIM0.read_volatile() } != 0 {
                break;
            }
        }
        unsafe { (ITM_STIM0 as *mut u8).write_volatile(byte) };
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    // Drive PB02 push-pull (MODEL holds 4 bits per pin; PB02 is the MODE2 nibble).
    unsafe {
        let model = GPIO_PB_MODEL.read_volatile() & !(0xF << (LED_PIN * 4));
        GPIO_PB_MODEL.write_volatile(model | (MODE_PUSHPULL << (LED_PIN * 4)));
    }

    let mut count: u32 = 0;
    loop {
        unsafe {
            let dout = GPIO_PB_DOUT.read_volatile();
            GPIO_PB_DOUT.write_volatile(dout ^ (1 << LED_PIN));
        }

        ringbuf_entry!(Trace::Heartbeat(count));

        // Hand the line to the kernel, which does the privileged ITM write
        // (-> SWO). The kernel prepends "kernel<-t<N>: ".
        let mut line = LogBuf { buf: [0; 96], len: 0 };
        let _ = writeln!(line, "heartbeat #{count}\r");
        kipc::log(&line.buf[..line.len]);

        // ITM unprivileged-access probe (kept on request). Report what *this
        // unprivileged task* reads from the ITM registers -- main() set TCR,
        // TER and TPR to 0x10001 / 0x1 / 0x1. If we read those back, unprivileged
        // *reads* work; if we read 0, the core RAZ/WIs unprivileged ITM entirely.
        // Then try a direct stimulus write: "[direct] ..." appears on SWO only if
        // unprivileged *writes* work (they don't, on this core).
        let tcr = unsafe { (0xE000_0E80 as *const u32).read_volatile() };
        let ter = unsafe { (0xE000_0E00 as *const u32).read_volatile() };
        let tpr = unsafe { (0xE000_0E40 as *const u32).read_volatile() };
        let stim = unsafe { (0xE000_0000 as *const u32).read_volatile() };
        let mut probe = LogBuf { buf: [0; 96], len: 0 };
        let _ = writeln!(
            probe,
            "itm TCR={tcr:#x} TER={ter:#x} TPR={tpr:#x} STIM0={stim:#x}\r"
        );
        kipc::log(&probe.buf[..probe.len]);
        direct_itm(b"[direct] hello\r\n");

        count = count.wrapping_add(1);
        hl::sleep_for(BLINK_MS);
    }
}
