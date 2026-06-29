// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal UARTE20 transmit driver for nRF54L15-DK bring-up.
//!
//! Initializes UARTE20 (TX on P1.04, 115200 8N1) and emits a startup banner
//! followed by a periodic heartbeat over EasyDMA. This exists to prove the
//! UART path works during board bring-up; it does not yet expose an IPC
//! `write` server for other tasks to log through. Promoting it to a proper
//! Idol server (a `write([u8])` op like `drv-lpc55-usart`) is the natural
//! next step.
//!
//! Note: the nRF54L15-DK virtual COM port is on UARTE20, P1.04 (TX) /
//! P1.05 (RX). The peripheral drives the pin directly via PSEL.
//!
//! This task also owns push button BTN3 (P0.04) and prints a line each time it
//! is pressed, so the loop polls at a short interval and emits the heartbeat
//! once per second.

#![no_std]
#![no_main]

use nrf_pac::gpio::vals::{Dir, Input, Pull};
use nrf_pac::shared::vals::Connect;
use nrf_pac::uarte::vals::{Baudrate, Enable};
use userlib::hl;

const UART: nrf_pac::uarte::Uarte = nrf_pac::UARTE20_S;

// The DK virtual COM port TX is on P1.04 (GPIO port 1, pin 4).
const TX_PORT: u8 = 1;
const TX_PIN: usize = 4;

// BTN3 is on P0.04, active-low with an internal pull-up.
const BTN3_PIN: usize = 4;

const POLL_INTERVAL_MS: u64 = 20;

// Shared-mailbox channels (top of FLPR SRAM). Line: a line shipped by the FLPR
// console program. Status: program-switch notices posted by flpr-control.
const MB_LINE_GEN: *const u32 = (0x2003_fb00 + 0x14) as *const u32;
const MB_LINE_LEN: *const u32 = (0x2003_fb00 + 0x18) as *const u32;
const MB_LINE_DATA: *const u8 = (0x2003_fb00 + 0x20) as *const u8;
const LINE_MAX: usize = 64;
const MB_STATUS_GEN: *const u32 = (0x2003_fb00 + 0x60) as *const u32;
const MB_STATUS_CODE: *const u32 = (0x2003_fb00 + 0x64) as *const u32;
const MB_STATUS_ARG: *const u32 = (0x2003_fb00 + 0x68) as *const u32;
// Enable flag for the periodic "print task" (set by flpr-control).
const MB_PRINT: *const u8 = (0x2003_fb00 + 0x11) as *const u8;
const PRINT_EVERY: u32 = 50; // 50 * 20 ms = 1 s
// Crypto results posted by cryptosrv in the shared `crypto_sram` region.
const C_BASE: usize = 0x2002_5c00;
const C_BENCH_GEN: *const u32 = (C_BASE + 8) as *const u32; // bumped per table render
const C_BENCH_LEN: *const u32 = (C_BASE + 12) as *const u32; // table byte length
const BLOB_OFF: usize = 0x40; // table text in crypto_sram
const BLOB_MAX: usize = 0x2000 - BLOB_OFF;

/// FLPR program names (program id = index), for status messages.
const PROG_NAMES: [&[u8]; 5] =
    [b"blink", b"breathe", b"compute", b"benchmark", b"console"];

fn uart_init() {
    // On nRF54L the UARTE does not configure its own GPIO: the pad has to be
    // set up as a driven output first, or nothing reaches the pin. (Matches
    // Zephyr's pinctrl, which always sets UART TX pins to output; the pin's
    // CTRLSEL stays at its default "GPIO" value, which is correct for UART.)
    let txport = nrf_pac::P1_S;
    txport.outset().write(|w| w.set_pin(TX_PIN, true)); // idle high
    txport.pin_cnf(TX_PIN).write(|w| {
        w.set_dir(Dir::Output);
        w.set_input(Input::Disconnect);
        w.set_pull(Pull::Disabled);
    });

    UART.psel().txd().write(|w| {
        w.set_port(TX_PORT);
        w.set_pin(TX_PIN as u8);
        w.set_connect(Connect::Connected);
    });
    UART.baudrate().write(|w| w.set_baudrate(Baudrate::Baud115200));
    UART.enable().write(|w| w.set_enable(Enable::Enabled));
}

/// Transmits `bytes` over UARTE20 via EasyDMA, blocking until complete.
fn uart_write(bytes: &[u8]) {
    // EasyDMA can only fetch from RAM, so stage the data in a stack buffer
    // (the task stack lives in SRAM) rather than pointing the DMA engine at a
    // flash/RRAM literal.
    let mut buf = [0u8; 96];
    let n = bytes.len().min(buf.len());
    buf[..n].copy_from_slice(&bytes[..n]);

    UART.dma().tx().ptr().write_value(buf.as_ptr() as u32);
    UART.dma().tx().maxcnt().write(|w| w.set_maxcnt(n as u16));
    UART.events_dma().tx().end().write_value(0);
    UART.tasks_dma().tx().start().write_value(1);
    while UART.events_dma().tx().end().read() == 0 {
        // Spin until EasyDMA signals the transfer is done. The buffer must
        // outlive this loop, which it does (it is on our stack).
    }
}

fn btn3_init() {
    nrf_pac::P0_S.pin_cnf(BTN3_PIN).write(|w| {
        w.set_dir(Dir::Input);
        w.set_input(Input::Connect);
        w.set_pull(Pull::Pullup);
    });
}

/// Active-low: a pressed button reads 0.
fn btn3_pressed() -> bool {
    !nrf_pac::P0_S.in_().read().pin(BTN3_PIN)
}

/// Append raw bytes to `buf` at `pos` (bounded).
fn append(buf: &mut [u8], pos: &mut usize, s: &[u8]) {
    for &b in s {
        if *pos < buf.len() {
            buf[*pos] = b;
            *pos += 1;
        }
    }
}

/// Append `val` in decimal to `buf` at `pos`.
fn fmt_u32(buf: &mut [u8], pos: &mut usize, val: u32) {
    let mut d = [0u8; 10];
    let mut n = 0;
    let mut v = val;
    loop {
        d[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while n > 0 {
        n -= 1;
        append(buf, pos, &[d[n]]);
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    uart_init();
    btn3_init();
    uart_write(b"\r\nHubris is alive on the nRF54L15-DK\r\n");

    let mut btn3_was_pressed = false;
    let mut prev_line_gen =
        unsafe { core::ptr::read_volatile(MB_LINE_GEN) };
    let mut prev_status_gen =
        unsafe { core::ptr::read_volatile(MB_STATUS_GEN) };
    let mut print_ticks: u32 = 0;
    let mut print_seq: u32 = 0;
    // Print the benchmark table whenever cryptosrv renders a new one. Seed from
    // the current value so a stale/retained table isn't reprinted at boot.
    let mut prev_bench_gen = unsafe { core::ptr::read_volatile(C_BENCH_GEN) };

    loop {
        // The benchmark table: print it (chunked) whenever a new one is ready.
        let bgen = unsafe { core::ptr::read_volatile(C_BENCH_GEN) };
        if bgen != prev_bench_gen {
            prev_bench_gen = bgen;
            let len = (unsafe { core::ptr::read_volatile(C_BENCH_LEN) } as usize)
                .min(BLOB_MAX);
            let mut off = 0;
            while off < len {
                let n = (len - off).min(64);
                let mut chunk = [0u8; 64];
                for (i, slot) in chunk[..n].iter_mut().enumerate() {
                    *slot = unsafe {
                        core::ptr::read_volatile(
                            (C_BASE + BLOB_OFF + off + i) as *const u8,
                        )
                    };
                }
                uart_write(&chunk[..n]);
                off += n;
            }
        }

        // BTN3 -> print on the press edge.
        let now = btn3_pressed();
        if now && !btn3_was_pressed {
            uart_write(b"BTN3 (P0.04) pressed\r\n");
        }
        btn3_was_pressed = now;

        // Program-switch notice from flpr-control.
        let sgen = unsafe { core::ptr::read_volatile(MB_STATUS_GEN) };
        if sgen != prev_status_gen {
            prev_status_gen = sgen;
            let code = unsafe { core::ptr::read_volatile(MB_STATUS_CODE) };
            let arg = unsafe { core::ptr::read_volatile(MB_STATUS_ARG) } as usize;
            let mut buf = [0u8; 48];
            let mut pos = 0;
            if code == 0 && arg < PROG_NAMES.len() {
                append(&mut buf, &mut pos, b"FLPR: started ");
                append(&mut buf, &mut pos, PROG_NAMES[arg]);
            } else {
                append(&mut buf, &mut pos, b"FLPR: stopped");
            }
            append(&mut buf, &mut pos, b"\r\n");
            uart_write(&buf[..pos]);
        }

        // A line shipped by the FLPR console program.
        let lgen = unsafe { core::ptr::read_volatile(MB_LINE_GEN) };
        if lgen != prev_line_gen {
            prev_line_gen = lgen;
            let len = (unsafe { core::ptr::read_volatile(MB_LINE_LEN) } as usize)
                .min(LINE_MAX);
            let mut buf = [0u8; LINE_MAX + 16];
            let mut pos = 0;
            append(&mut buf, &mut pos, b"flpr msg: ");
            for i in 0..len {
                let b = unsafe { core::ptr::read_volatile(MB_LINE_DATA.add(i)) };
                append(&mut buf, &mut pos, &[b]);
            }
            append(&mut buf, &mut pos, b"\r\n");
            uart_write(&buf[..pos]);
        }

        // The M33 "print task": once a second while enabled from the shell.
        if unsafe { core::ptr::read_volatile(MB_PRINT) } != 0 {
            print_ticks += 1;
            if print_ticks >= PRINT_EVERY {
                print_ticks = 0;
                let mut buf = [0u8; 32];
                let mut pos = 0;
                append(&mut buf, &mut pos, b"M33 print task: tick ");
                fmt_u32(&mut buf, &mut pos, print_seq);
                append(&mut buf, &mut pos, b"\r\n");
                uart_write(&buf[..pos]);
                print_seq = print_seq.wrapping_add(1);
            }
        } else {
            print_ticks = 0;
        }

        hl::sleep_for(POLL_INTERVAL_MS);
    }
}
