// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Shared runtime + helpers for the nRF54L15 FLPR (RISC-V) demo programs.
//!
//! Provides the reset stub (`_start`), the panic handler, and hand-rolled
//! access to the one LED, the shared mailbox, and the VEVIF event the FLPR uses
//! to interrupt the M33. Each program crate (src/bin/*.rs) supplies its own
//! `rust_main`.

#![no_std]

use core::arch::global_asm;
use core::ptr::{read_volatile, write_volatile};

// Reset entry (shared by every program): set the stack pointer to the top of
// the FLPR SRAM (from link.x), install a trap handler so a fault halts safely
// instead of running off into garbage (the FLPR is a secure bus master, so a
// runaway could corrupt the M33), then call the program's `rust_main`.
global_asm!(
    ".section .text.init, \"ax\"",
    ".global _start",
    "_start:",
    "  la sp, _stack_top",
    "  la t0, _trap",
    "  csrw 0x305, t0", // mtvec = _trap
    "  call rust_main",
    "1: j 1b",
    "_trap:",
    "  j _trap", // any trap: stop here rather than corrupt the system
);

// ---- LED3 = P1.14 (active-high), secure GPIO alias --------------------------

const P1_BASE: usize = 0x500d_8200;
const P1_OUTSET: *mut u32 = (P1_BASE + 0x04) as *mut u32;
const P1_OUTCLR: *mut u32 = (P1_BASE + 0x08) as *mut u32;
const P1_PIN_CNF14: *mut u32 = (P1_BASE + 0x80 + 14 * 4) as *mut u32;
const LED3_BIT: u32 = 1 << 14;
const PIN_CNF_OUTPUT: u32 = 0b11; // DIR=output, INPUT=disconnect

#[inline]
pub fn led_init() {
    unsafe { write_volatile(P1_PIN_CNF14, PIN_CNF_OUTPUT) };
}
#[inline]
pub fn led_on() {
    unsafe { write_volatile(P1_OUTSET, LED3_BIT) };
}
#[inline]
pub fn led_off() {
    unsafe { write_volatile(P1_OUTCLR, LED3_BIT) };
}

// ---- Shared mailbox (top of FLPR SRAM; layout matches flpr-control) ---------

const MAILBOX: usize = 0x2003_fb00;
const MB_MAGIC: *mut u32 = MAILBOX as *mut u32; //          FLPR -> app: "alive"
const MB_RESULT_A: *mut u32 = (MAILBOX + 0x04) as *mut u32; // FLPR -> app
const MB_PARAM: *const u32 = (MAILBOX + 0x08) as *const u32; // app  -> FLPR
const MB_RESULT_B: *mut u32 = (MAILBOX + 0x0c) as *mut u32; // FLPR -> app
const MAILBOX_MAGIC: u32 = 0x464c_5052; // "FLPR"

/// Mark the mailbox live and clear the result words.
#[inline]
pub fn mailbox_init() {
    unsafe {
        write_volatile(MB_RESULT_A, 0);
        write_volatile(MB_RESULT_B, 0);
        write_volatile((MAILBOX + 0x14) as *mut u32, 0); // line generation
        write_volatile(MB_MAGIC, MAILBOX_MAGIC);
    }
}
/// Publish the primary result word.
#[inline]
pub fn report(a: u32) {
    unsafe { write_volatile(MB_RESULT_A, a) };
}
/// Publish both result words (e.g. an input and its computed output).
#[inline]
pub fn report2(a: u32, b: u32) {
    unsafe {
        write_volatile(MB_RESULT_B, b);
        write_volatile(MB_RESULT_A, a);
    }
}
/// Read the app-supplied parameter (e.g. a rate). 0 means "unset".
#[inline]
pub fn param() -> u32 {
    unsafe { read_volatile(MB_PARAM) }
}

// ---- VEVIF: interrupt the application core ----------------------------------

/// VEVIF event index (matches the cpuapp events-mask and app-side IRQ 76).
const VEVIF_EVENT: u32 = 20;

/// Raise the VEVIF event: a rising edge on the Nordic VPR EVENTS CSR (0x7E2)
/// pulses the app-side `EVENTS_TRIGGERED[20]` (IRQ 76), then we clear it.
#[inline]
pub fn notify_app() {
    let mask: u32 = 1 << VEVIF_EVENT;
    unsafe {
        core::arch::asm!(
            "csrs 0x7e2, {m}",
            "csrw 0x7e2, zero",
            m = in(reg) mask,
        );
    }
}

// ---- Line transfer to the M33 (in the mailbox) ------------------------------

const MB_LINE_GEN: *mut u32 = (MAILBOX + 0x14) as *mut u32; // FLPR -> app: bumped per line
const MB_LINE_LEN: *mut u32 = (MAILBOX + 0x18) as *mut u32; // FLPR -> app: 0..=64
const MB_LINE_DATA: *mut u8 = (MAILBOX + 0x20) as *mut u8; //  FLPR -> app: up to 64 bytes
pub const LINE_MAX: usize = 64;

/// Hand a completed line to the M33: copy it into the mailbox, publish the
/// length and a bumped generation, then raise the VEVIF event.
pub fn send_line(line: &[u8]) {
    let n = line.len().min(LINE_MAX);
    unsafe {
        for i in 0..n {
            write_volatile(MB_LINE_DATA.add(i), line[i]);
        }
        write_volatile(MB_LINE_LEN, n as u32);
        let gen = read_volatile(MB_LINE_GEN as *const u32).wrapping_add(1);
        write_volatile(MB_LINE_GEN, gen); // publish last
    }
    notify_app();
}

// Response channel: the M33's reply to a command line.
const MB_RESP_GEN: *const u32 = (MAILBOX + 0x6c) as *const u32;
const MB_RESP_LEN: *const u32 = (MAILBOX + 0x70) as *const u32;
const MB_RESP_DATA: *const u8 = (MAILBOX + 0x74) as *const u8;
const RESP_MAX: usize = 140; // up to the end of the 256-byte mailbox

/// Send `line` as a command to the M33 and print the M33's response on the
/// console (UART30). Bounded-spin while waiting so a missing reply can't hang.
pub fn send_command(line: &[u8]) {
    let prev = unsafe { read_volatile(MB_RESP_GEN) };
    send_line(line);

    let mut spins: u32 = 0;
    loop {
        if unsafe { read_volatile(MB_RESP_GEN) } != prev {
            let len =
                (unsafe { read_volatile(MB_RESP_LEN) } as usize).min(RESP_MAX);
            for i in 0..len {
                uart_putc(unsafe { read_volatile(MB_RESP_DATA.add(i)) });
            }
            return;
        }
        spins = spins.wrapping_add(1);
        if spins > 50_000_000 {
            uart_puts(b"(no response)\r\n");
            return;
        }
    }
}

// ---- UART30: the FLPR's own console (TX P0.00, RX P0.01, secure) -------------

const UART30: usize = 0x5010_4000;
const U_ENABLE: *mut u32 = (UART30 + 0x500) as *mut u32;
const U_BAUDRATE: *mut u32 = (UART30 + 0x524) as *mut u32;
const U_PSEL_TXD: *mut u32 = (UART30 + 0x604) as *mut u32;
const U_PSEL_RXD: *mut u32 = (UART30 + 0x60c) as *mut u32;
const U_DMA_RX_PTR: *mut u32 = (UART30 + 0x704) as *mut u32;
const U_DMA_RX_MAXCNT: *mut u32 = (UART30 + 0x708) as *mut u32;
const U_DMA_TX_PTR: *mut u32 = (UART30 + 0x73c) as *mut u32;
const U_DMA_TX_MAXCNT: *mut u32 = (UART30 + 0x740) as *mut u32;
const U_TASKS_RX_START: *mut u32 = (UART30 + 0x28) as *mut u32;
const U_TASKS_TX_START: *mut u32 = (UART30 + 0x50) as *mut u32;
const U_EVENTS_RX_END: *mut u32 = (UART30 + 0x14c) as *mut u32;
const U_EVENTS_TX_END: *mut u32 = (UART30 + 0x168) as *mut u32;

// GPIO P0 pin-config registers for the UART30 pins.
const P0_BASE: usize = 0x5010_a000;
const P0_PIN_CNF0: *mut u32 = (P0_BASE + 0x80) as *mut u32; // TX P0.00
const P0_PIN_CNF1: *mut u32 = (P0_BASE + 0x84) as *mut u32; // RX P0.01
const BAUD_115200: u32 = 0x01d6_0000;

/// Bring up UART30 at 115200 8N1: TX = P0.00 (output), RX = P0.01 (input, pull-up).
pub fn uart_init() {
    unsafe {
        write_volatile(P0_PIN_CNF0, 0b11); // dir=output, input=disconnect
        write_volatile(P0_PIN_CNF1, 0x0c); // dir=input, input=connect, pull=up
        write_volatile(U_PSEL_TXD, 0); // P0.00
        write_volatile(U_PSEL_RXD, 1); // P0.01
        write_volatile(U_BAUDRATE, BAUD_115200);
        write_volatile(U_ENABLE, 8); // UARTE enabled
    }
}

/// Blocking single-byte receive via EasyDMA (RX is re-armed per byte).
pub fn uart_getc() -> u8 {
    let mut b: u8 = 0;
    unsafe {
        write_volatile(U_DMA_RX_PTR, core::ptr::addr_of_mut!(b) as u32);
        write_volatile(U_DMA_RX_MAXCNT, 1);
        write_volatile(U_EVENTS_RX_END, 0);
        write_volatile(U_TASKS_RX_START, 1);
        while read_volatile(U_EVENTS_RX_END as *const u32) == 0 {}
        // The DMA (not Rust) wrote `b`, so read it volatile or the compiler
        // returns the stale original value.
        read_volatile(core::ptr::addr_of!(b))
    }
}

/// Blocking single-byte transmit via EasyDMA.
pub fn uart_putc(c: u8) {
    let mut b: u8 = 0;
    unsafe {
        // Volatile write so the byte is really in memory for the DMA to read
        // (a plain `let b = c` can be dead-store-eliminated -> sends a null).
        write_volatile(core::ptr::addr_of_mut!(b), c);
        write_volatile(U_DMA_TX_PTR, core::ptr::addr_of!(b) as u32);
        write_volatile(U_DMA_TX_MAXCNT, 1);
        write_volatile(U_EVENTS_TX_END, 0);
        write_volatile(U_TASKS_TX_START, 1);
        while read_volatile(U_EVENTS_TX_END as *const u32) == 0 {}
    }
}

/// Transmit a byte string.
pub fn uart_puts(s: &[u8]) {
    for &c in s {
        uart_putc(c);
    }
}

// ---- Misc -------------------------------------------------------------------

/// Crude busy-wait of `iters` iterations (volatile nop, not optimized away).
#[inline(never)]
pub fn delay(iters: u32) {
    for _ in 0..iters {
        unsafe { core::arch::asm!("nop") };
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
