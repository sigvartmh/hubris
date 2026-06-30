// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Loads, launches, and controls FLPR (RISC-V) demo programs.
//!
//! Several programs are embedded (program id = index): 0 blink, 1 breathe,
//! 2 compute, 3 benchmark. Control:
//!
//!   * **BTN1 (P1.09)** toggles the currently-selected program on/off.
//!   * **humility** selects/starts a program by writing the mailbox command
//!     word (0x2003_fb10): a program id (0..=3) starts it; 0xFF stops.
//!       humility -a <archive> writemem 0x2003fb10 0x00000002   # start compute
//!       humility -a <archive> writemem 0x2003fb10 0x000000ff   # stop
//!
//! While a program runs it blinks/drives LED3; this task lights LED1 as a
//! "running" indicator and records the FLPR's VEVIF events (IRQ 76) in a
//! ringbuf.

#![no_std]
#![no_main]

use drv_user_leds_api::UserLeds;
use nrf_pac::gpio::vals::{Dir, Input, Pull};
use nrf_pac::vpr::vals::CpurunEn;
use ringbuf::ringbuf_entry;
use userlib::*;

task_slot!(USER_LEDS, user_leds);

const VPR: nrf_pac::vpr::Vpr = nrf_pac::VPR00_S;

/// FLPR execution SRAM base (global address); matches the firmware's link.x.
const FLPR_EXEC_BASE: usize = 0x2002_7c00;
/// SPU00 slave index of the VPR: (0x5004_c000 - 0x5004_0000) >> 12.
const VPR_SPU_SLAVE: usize = 0xc;
/// VEVIF event the FLPR raises -> VPR.EVENTS_TRIGGERED[20] -> IRQ 76.
const VEVIF_BLINK_EVENT: usize = 20;

const BTN1_PIN: usize = 9; // P1.09, active-low pull-up
const LED_RUNNING: usize = 1; // P1.10 steady = running
const LED_FLPR: usize = 3; // P1.14, driven by the FLPR

const POLL_INTERVAL_MS: u32 = 20;

// Mailbox words (app side; layout matches the FLPR lib).
const MB_PARAM: *mut u32 = (0x2003_fb00 + 0x08) as *mut u32; // app -> FLPR
const MB_RESULT_A: *const u32 = (0x2003_fb00 + 0x04) as *const u32; // FLPR -> app
// A single command byte (robust to byte- or word-width debug writes).
const MB_COMMAND: *mut u8 = (0x2003_fb00 + 0x10) as *mut u8; // humility -> us
const CMD_IDLE: u8 = 0xEE; // no command pending / our ack value
const CMD_STOP: u8 = 0xFF;

// Status channel: we post program-switch notices here for the uart task to
// print on the M33 console.
const MB_STATUS_GEN: *mut u32 = (0x2003_fb00 + 0x60) as *mut u32;
const MB_STATUS_CODE: *mut u32 = (0x2003_fb00 + 0x64) as *mut u32; // 0=start 1=stop
const MB_STATUS_ARG: *mut u32 = (0x2003_fb00 + 0x68) as *mut u32; // program id

fn post_status(code: u32, arg: u32) {
    unsafe {
        core::ptr::write_volatile(MB_STATUS_CODE, code);
        core::ptr::write_volatile(MB_STATUS_ARG, arg);
        let g =
            core::ptr::read_volatile(MB_STATUS_GEN as *const u32).wrapping_add(1);
        core::ptr::write_volatile(MB_STATUS_GEN, g);
    }
}

// Shell command line (FLPR -> us) and our response (us -> FLPR).
const MB_LINE_GEN: *const u32 = (0x2003_fb00 + 0x14) as *const u32;
const MB_LINE_LEN: *const u32 = (0x2003_fb00 + 0x18) as *const u32;
const MB_LINE_DATA: *const u8 = (0x2003_fb00 + 0x20) as *const u8;
const LINE_MAX: usize = 64;
const MB_RESP_GEN: *mut u32 = (0x2003_fb00 + 0x6c) as *mut u32;
const MB_RESP_LEN: *mut u32 = (0x2003_fb00 + 0x70) as *mut u32;
const MB_RESP_DATA: *mut u8 = (0x2003_fb00 + 0x74) as *mut u8;
const RESP_MAX: usize = 140; // up to the end of the 256-byte mailbox

// Crypto benchmark hand-off in the shared `crypto_sram` region: we bump
// C_BENCH_REQ to ask cryptosrv for a run, then wait for C_BENCH_DONE to change.
const C_BASE: usize = 0x2002_5c00;
// Benchmark: write C_BENCH_SEL (which algorithm), bump C_BENCH_REQ to ask
// cryptosrv to render the table (printed on the M33 console), then wait for
// C_BENCH_GEN to change.
const C_BENCH_SEL: *mut u32 = C_BASE as *mut u32;
const C_BENCH_REQ: *mut u32 = (C_BASE + 4) as *mut u32;
// CRACEN TRNG: write C_RNG_LEN, bump C_RNG_REQ, wait for C_RNG_GEN; cryptosrv
// writes back the produced length (0 = error) and the bytes at C_RNG_DATA.
const C_RNG_REQ: *mut u32 = (C_BASE + 16) as *mut u32;
const C_RNG_GEN: *const u32 = (C_BASE + 20) as *const u32;
const C_RNG_LEN: *mut u32 = (C_BASE + 24) as *mut u32;
const C_RNG_DATA: *const u8 = (C_BASE + 28) as *const u8;
const RNG_MAX: usize = 32;

/// Builds a response string and publishes it to the FLPR console.
struct Resp {
    buf: [u8; RESP_MAX],
    pos: usize,
}

impl Resp {
    fn new() -> Self {
        Self {
            buf: [0; RESP_MAX],
            pos: 0,
        }
    }
    fn s(&mut self, s: &[u8]) {
        for &b in s {
            if self.pos < RESP_MAX {
                self.buf[self.pos] = b;
                self.pos += 1;
            }
        }
    }
    fn u(&mut self, mut v: u32) {
        let mut d = [0u8; 10];
        let mut n = 0;
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
            let b = d[n];
            self.s(&[b]);
        }
    }
    fn hx(&mut self, b: u8) {
        const D: &[u8; 16] = b"0123456789abcdef";
        self.s(&[D[(b >> 4) as usize], D[(b & 0xf) as usize]]);
    }
    fn send(&self) {
        unsafe {
            for i in 0..self.pos {
                core::ptr::write_volatile(MB_RESP_DATA.add(i), self.buf[i]);
            }
            core::ptr::write_volatile(MB_RESP_LEN, self.pos as u32);
            let g = core::ptr::read_volatile(MB_RESP_GEN as *const u32)
                .wrapping_add(1);
            core::ptr::write_volatile(MB_RESP_GEN, g);
        }
    }
}

fn parse_usize(w: &[u8]) -> Option<usize> {
    if w.is_empty() {
        return None;
    }
    let mut v = 0usize;
    for &b in w {
        if b.is_ascii_digit() {
            v = v * 10 + (b - b'0') as usize;
        } else {
            return None;
        }
    }
    Some(v)
}

fn prog_id(name: &[u8]) -> Option<usize> {
    match name {
        b"blink" => Some(0),
        b"breathe" => Some(1),
        b"compute" => Some(2),
        b"benchmark" => Some(3),
        b"console" => Some(4),
        _ => None,
    }
}

/// Parse and execute a shell command line, replying to the FLPR console.
fn handle_command(state: &mut State) {
    let len = (unsafe { core::ptr::read_volatile(MB_LINE_LEN) } as usize)
        .min(LINE_MAX);
    let mut line = [0u8; LINE_MAX];
    for (i, slot) in line.iter_mut().enumerate().take(len) {
        *slot = unsafe { core::ptr::read_volatile(MB_LINE_DATA.add(i)) };
    }
    let line = &line[..len];

    let mut words = line.split(|&b| b == b' ').filter(|w| !w.is_empty());
    let cmd = words.next().unwrap_or(&[]);
    let mut r = Resp::new();

    match cmd {
        b"" => return,
        // The FLPR console prints `help` locally; this is a fallback only.
        b"help" => r.s(b"see local help (type 'help' on this console)\r\n"),
        b"led" => {
            let n = words.next().and_then(parse_usize);
            let act = words.next().unwrap_or(&[]);
            match (n, act) {
                (Some(n), b"on") if n < 4 => {
                    state.leds.led_on(n).ok();
                    r.s(b"LED ");
                    r.u(n as u32);
                    r.s(b" on\r\n");
                }
                (Some(n), b"off") if n < 4 => {
                    state.leds.led_off(n).ok();
                    r.s(b"LED ");
                    r.u(n as u32);
                    r.s(b" off\r\n");
                }
                (Some(n), b"tog" | b"toggle") if n < 4 => {
                    state.leds.led_toggle(n).ok();
                    r.s(b"LED ");
                    r.u(n as u32);
                    r.s(b" toggled\r\n");
                }
                _ => r.s(b"usage: led <0-3> <on|off|tog>\r\n"),
            }
        }
        b"blink" => match words.next().and_then(parse_usize) {
            Some(n) if n < 4 => {
                // Start an M33-side LED-blink "task" via the user-leds server.
                state.leds.led_blink(n).ok();
                r.s(b"LED ");
                r.u(n as u32);
                r.s(b" blinking (M33 task); 'led ");
                r.u(n as u32);
                r.s(b" off' to stop\r\n");
            }
            _ => r.s(b"usage: blink <0-3>\r\n"),
        },
        b"print" => match words.next().unwrap_or(&[]) {
            b"on" | b"start" => {
                unsafe { core::ptr::write_volatile(MB_PRINT, 1) };
                r.s(b"M33 print task started (watch the M33 console)\r\n");
            }
            b"off" | b"stop" => {
                unsafe { core::ptr::write_volatile(MB_PRINT, 0) };
                r.s(b"M33 print task stopped\r\n");
            }
            _ => r.s(b"usage: print <on|off>\r\n"),
        },
        b"breathe" => {
            let n = words
                .next()
                .and_then(parse_usize)
                .map(|v| v as u32)
                .unwrap_or(DEFAULT_PARAMS[1]);
            r.s(b"breathing, slowness ");
            r.u(n);
            r.s(b" (BTN1 returns to shell)\r\n");
            r.send();
            state.start_with(1, n);
            return;
        }
        b"time" => {
            r.s(b"uptime: ");
            r.u(sys_get_timer().now as u32);
            r.s(b" ms\r\n");
        }
        b"echo" => {
            if line.len() > 5 {
                r.s(&line[5..]);
            }
            r.s(b"\r\n");
        }
        b"run" => {
            let prog = words.next().unwrap_or(&[]);
            if let Some(id) = prog_id(prog) {
                r.s(b"starting ");
                r.s(prog);
                r.s(b" (BTN1 returns to shell)\r\n");
                r.send();
                state.start(id);
                return;
            }
            r.s(b"unknown program (try: blink breathe compute benchmark console)\r\n");
        }
        b"stop" => {
            state.stop();
            r.s(b"stopped\r\n");
        }
        b"crypto" | b"bench" => {
            // `bench [alg]` -- default (no arg) runs every algorithm.
            let sel: u32 = match words.next() {
                None | Some(b"all") => 0,
                Some(b"aes") | Some(b"aes-ecb") => 1,
                Some(b"sha") | Some(b"sha256") => 2,
                Some(b"hmac") => 3,
                Some(b"cmac") => 4,
                Some(b"gcm") | Some(b"aes-gcm") => 5,
                Some(b"ecdh") | Some(b"x25519") => 6,
                Some(b"ed25519") | Some(b"eddsa") => 7,
                Some(b"p256") | Some(b"ecdsa") => 8,
                Some(b"chacha") | Some(b"chachapoly") => 9,
                Some(b"aes256") => 10,
                Some(b"sha512") => 11,
                Some(b"sha384") => 12,
                Some(b"ctr") => 13,
                Some(b"cbc") => 14,
                Some(b"rsa") => 16,
                Some(_) => {
                    r.s(b"algs: all aes aes256 ctr cbc sha sha512 sha384 hmac cmac gcm chacha ecdh ed25519 p256 rsa\r\n");
                    r.send();
                    return;
                }
            };
            // Ask cryptosrv (which owns CRACEN) to render the benchmark and
            // reply immediately -- the full table takes several seconds and is
            // large, so it prints on the M33 console while cryptosrv runs it.
            unsafe {
                core::ptr::write_volatile(C_BENCH_SEL, sel);
                let req =
                    core::ptr::read_volatile(C_BENCH_REQ).wrapping_add(1);
                core::ptr::write_volatile(C_BENCH_REQ, req);
            }
            r.s(b"benchmark running -- see M33 console\r\n");
        }
        b"rng" => {
            // Ask cryptosrv for `n` hardware-random bytes (default 16).
            let n = words
                .next()
                .and_then(parse_usize)
                .unwrap_or(16)
                .clamp(1, RNG_MAX);
            let prev = unsafe { core::ptr::read_volatile(C_RNG_GEN) };
            unsafe {
                core::ptr::write_volatile(C_RNG_LEN, n as u32);
                let req = core::ptr::read_volatile(C_RNG_REQ).wrapping_add(1);
                core::ptr::write_volatile(C_RNG_REQ, req);
            }
            let mut done = false;
            for _ in 0..30 {
                hl::sleep_for(20);
                if unsafe { core::ptr::read_volatile(C_RNG_GEN) } != prev {
                    done = true;
                    break;
                }
            }
            if !done {
                r.s(b"rng: timed out\r\n");
            } else if unsafe { core::ptr::read_volatile(C_RNG_LEN) } == 0 {
                r.s(b"rng: hardware error\r\n");
            } else {
                r.s(b"rng: ");
                for i in 0..n {
                    r.hx(unsafe { core::ptr::read_volatile(C_RNG_DATA.add(i)) });
                }
                r.s(b"\r\n");
            }
        }
        _ => {
            r.s(b"unknown command: ");
            r.s(cmd);
            r.s(b" (try help)\r\n");
        }
    }
    r.send();
}

/// FLPR program images, indexed by program id (matches `cargo xtask flpr`).
static PROGRAMS: [&[u8]; 5] = [
    include_bytes!(concat!(env!("OUT_DIR"), "/blink.bin")),
    include_bytes!(concat!(env!("OUT_DIR"), "/breathe.bin")),
    include_bytes!(concat!(env!("OUT_DIR"), "/compute.bin")),
    include_bytes!(concat!(env!("OUT_DIR"), "/benchmark.bin")),
    include_bytes!(concat!(env!("OUT_DIR"), "/console.bin")),
];

/// Default `param` handed to each program (blink rate, breathe slowness,
/// compute throttle, benchmark + console unused).
const DEFAULT_PARAMS: [u32; 5] = [8_000_000, 15, 2_000_000, 0, 0];

/// Program id of the shell/console.
const PROG_CONSOLE: usize = 4;

/// Enable flag for the M33-side periodic "print task" (read by the uart task).
const MB_PRINT: *mut u8 = (0x2003_fb00 + 0x11) as *mut u8;

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    None,
    Start { program: u8, param: u32 },
    Stop,
    Event(u32),
}
ringbuf::ringbuf!(Trace, 32, Trace::None);

fn btn1_init() {
    nrf_pac::P1_S.pin_cnf(BTN1_PIN).write(|w| {
        w.set_dir(Dir::Input);
        w.set_input(Input::Connect);
        w.set_pull(Pull::Pullup);
    });
}

fn btn1_pressed() -> bool {
    !nrf_pac::P1_S.in_().read().pin(BTN1_PIN)
}

/// Hold (`true`) or release (`false`) the FLPR core in reset via its Debug
/// Module. Activate the DM first, then drive ndmreset. FLPR domain only.
fn flpr_set_reset(asserted: bool) {
    let dm = VPR.debugif();
    dm.dmcontrol().write(|w| w.set_dmactive(true));
    dm.dmcontrol().write(|w| {
        w.set_dmactive(true);
        w.set_ndmreset(asserted);
    });
}

fn start_program(id: usize, param: u32) {
    let img = PROGRAMS[id];
    unsafe {
        core::ptr::copy_nonoverlapping(
            img.as_ptr(),
            FLPR_EXEC_BASE as *mut u8,
            img.len(),
        );
        core::ptr::write_volatile(MB_PARAM, param);
    }

    // Make the VPR secure-accessible (or our secure writes bus-fault), enable
    // its VEVIF event-20 interrupt, point it at the entry, and release it.
    nrf_pac::SPU00_S
        .periph(VPR_SPU_SLAVE)
        .perm()
        .modify(|w| w.set_secattr(true));
    VPR.inten().write(|w| w.set_triggered20(true));
    VPR.initpc().write_value(FLPR_EXEC_BASE as u32);
    VPR.cpurun().write(|w| w.set_en(CpurunEn::Running));
    flpr_set_reset(false);
}

fn stop_program() {
    VPR.cpurun().write(|w| w.set_en(CpurunEn::Stopped));
    flpr_set_reset(true);
}

struct State {
    leds: UserLeds,
    running: bool,
    program: usize,
}

impl State {
    fn start(&mut self, id: usize) {
        self.start_with(id, DEFAULT_PARAMS[id]);
    }

    fn start_with(&mut self, id: usize, param: u32) {
        if self.running {
            stop_program();
        }
        self.program = id;
        start_program(id, param);
        self.running = true;
        self.leds.led_on(LED_RUNNING).ok();
        post_status(0, id as u32);
        ringbuf_entry!(Trace::Start {
            program: id as u8,
            param,
        });
    }

    fn stop(&mut self) {
        if self.running {
            stop_program();
            self.running = false;
            self.leds.led_off(LED_RUNNING).ok();
            self.leds.led_off(LED_FLPR).ok();
            post_status(1, 0);
            ringbuf_entry!(Trace::Stop);
        }
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let mut state = State {
        leds: UserLeds::from(USER_LEDS.get_task_id()),
        running: false,
        program: 0,
    };
    btn1_init();
    state.leds.led_off(LED_RUNNING).ok();
    state.leds.led_off(LED_FLPR).ok();
    unsafe {
        core::ptr::write_volatile(MB_COMMAND, CMD_IDLE);
        core::ptr::write_volatile(MB_STATUS_GEN, 0);
        core::ptr::write_volatile(MB_PRINT, 0);
    }

    let mut was_pressed = false;
    let mut prev_line_gen =
        unsafe { core::ptr::read_volatile(MB_LINE_GEN) };

    sys_irq_control(notifications::VEVIF_IRQ_MASK, true);
    set_timer_relative(POLL_INTERVAL_MS, notifications::TIMER_MASK);

    loop {
        let bits = sys_recv_notification(
            notifications::TIMER_MASK | notifications::VEVIF_IRQ_MASK,
        )
        .get_raw_bits();

        if bits & notifications::TIMER_MASK != 0 {
            // humility command word (edge-triggered: we ack by clearing it).
            let cmd = unsafe { core::ptr::read_volatile(MB_COMMAND) };
            if cmd != CMD_IDLE {
                unsafe { core::ptr::write_volatile(MB_COMMAND, CMD_IDLE) };
                if cmd == CMD_STOP {
                    state.stop();
                } else if (cmd as usize) < PROGRAMS.len() {
                    state.start(cmd as usize);
                }
            }
            // (`cmd` is a byte; the debug write may have left the upper bytes of
            // the word non-idle, but we only ever read/ack the low byte.)

            // BTN1 (re)launches the shell/console — a physical "back to shell".
            let now = btn1_pressed();
            if now && !was_pressed {
                state.start(PROG_CONSOLE);
            }
            was_pressed = now;

            // Shell command line from the FLPR console program.
            let lgen = unsafe { core::ptr::read_volatile(MB_LINE_GEN) };
            if lgen != prev_line_gen {
                prev_line_gen = lgen;
                handle_command(&mut state);
            }

            set_timer_relative(POLL_INTERVAL_MS, notifications::TIMER_MASK);
        }

        // VEVIF event from the FLPR: clear it, record the reported value.
        if bits & notifications::VEVIF_IRQ_MASK != 0 {
            VPR.events_triggered(VEVIF_BLINK_EVENT).write_value(0);
            let a = unsafe { core::ptr::read_volatile(MB_RESULT_A) };
            ringbuf_entry!(Trace::Event(a));
            sys_irq_control(notifications::VEVIF_IRQ_MASK, true);
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/notifications.rs"));
