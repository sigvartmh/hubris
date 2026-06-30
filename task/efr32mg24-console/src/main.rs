// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Interactive serial shell on the WSTK virtual COM port (EUSART0, 115200 8N1).
//!
//! Brings up EUSART0 as an async UART (TX=PA08, RX=PA09, VCOM enable=PB00),
//! prints a banner, and runs a tiny line-oriented shell. Commands:
//!   help          list commands
//!   ps / tasks    task list with state + a quick CPU-usage sample
//!   uptime        kernel uptime
//!
//! RX is drained from the EUSART's hardware FIFO on a ~10 ms poll, so the task
//! sleeps between polls instead of busy-waiting. This works now that the SMU/PPU
//! lets unprivileged tasks reach peripherals; the EUSART functional clock is
//! EM01GRPACLK, which defaults to HFRCODPLL at 19 MHz.

#![no_std]
#![no_main]

use core::fmt::Write;

use efr32mg24_crypto as crypto;
use efr32mg24_gfx::{self as gfx, FB_LEN};
use embedded_graphics::{
    mono_font::{ascii::FONT_5X8, MonoTextStyle},
    pixelcolor::BinaryColor,
    prelude::*,
    text::{Baseline, Text},
};
use hubris_num_tasks::NUM_TASKS;
use userlib::*;

task_slot!(DISPLAY, display);
task_slot!(CRYPTOSRV, cryptosrv);

/// Task-table index of the CPU-hog `load` task. We control it with
/// `kipc::reinit_task` (which sends to the kernel, not to `load`), so we don't
/// use a `task-slot` -- that would trip Hubris's priority-inversion check. Keep
/// in sync with `app.toml` (and `task_name` below).
const LOAD_INDEX: usize = 11;

// --- registers -------------------------------------------------------------

const CMU_CLKEN1: *mut u32 = 0x4000_8068 as *mut u32;
const CMU_CLKEN1_EUSART0: u32 = 1 << 22;

// GPIO Port A (TX/RX/RTS) and Port B (VCOM enable), secure alias.
const GPIO_A_MODEL: *mut u32 = 0x4003_c034 as *mut u32; // PA00 (RTS) mode
const GPIO_A_MODEH: *mut u32 = 0x4003_c03c as *mut u32; // PA08/PA09 modes
const GPIO_A_DOUT: *mut u32 = 0x4003_c040 as *mut u32;
const GPIO_B_MODEL: *mut u32 = 0x4003_c064 as *mut u32; // PB00 mode
const GPIO_B_DOUT: *mut u32 = 0x4003_c070 as *mut u32;
const GPIO_EUSART0_ROUTEEN: *mut u32 = 0x4003_c494 as *mut u32;
const GPIO_EUSART0_RXROUTE: *mut u32 = 0x4003_c4a4 as *mut u32;
const GPIO_EUSART0_TXROUTE: *mut u32 = 0x4003_c4ac as *mut u32;
const ROUTEEN_RXPEN: u32 = 1 << 2;
const ROUTEEN_TXPEN: u32 = 1 << 4;
const ROUTE_PIN_SHIFT: u32 = 16;

// EUSART0 (secure alias).
const EUSART0_EN: *mut u32 = 0x4b01_0004 as *mut u32;
const EUSART0_CFG0: *mut u32 = 0x4b01_0008 as *mut u32;
const EUSART0_FRAMECFG: *mut u32 = 0x4b01_0014 as *mut u32;
const EUSART0_CLKDIV: *mut u32 = 0x4b01_0030 as *mut u32;
const EUSART0_CMD: *mut u32 = 0x4b01_0038 as *mut u32;
const EUSART0_RXDATA: *const u32 = 0x4b01_003c as *const u32;
const EUSART0_TXDATA: *mut u32 = 0x4b01_0044 as *mut u32;
const EUSART0_STATUS: *const u32 = 0x4b01_0048 as *const u32;
const EUSART0_SYNCBUSY: *const u32 = 0x4b01_0054 as *const u32;

const EN_EN: u32 = 1 << 0;
const CMD_RXEN: u32 = 1 << 0;
const CMD_TXEN: u32 = 1 << 2;
const STATUS_TXFL: u32 = 1 << 6;
const STATUS_RXFL: u32 = 1 << 7;

// 8 data bits (DATABITS=EIGHT=2), no parity, 1 stop bit (STOPBITS=ONE=1<<12).
const FRAMECFG_8N1: u32 = 0x2 | (1 << 12);
// 115200 baud, OVS16, 19 MHz: clkdiv = (32*f)/(baud*16) - 32, then *8.
// (32*19_000_000)/(115200*16) = 329; (329-32)*8 = 2376.
const CLKDIV_115200: u32 = 2376;

const POLL_MS: u64 = 10;
const LINE_MAX: usize = 64;

// LCD "terminal mirror" (display mode 2). We tee every byte the console prints
// into a small character grid and render it with embedded-graphics' FONT_5X8
// (full ASCII, real lowercase): 24 cols x 12 rows at 5px x 10px = 120x120,
// inside the 128x128 panel. 24 cols fits the `ps` table rows exactly.
const COLS: usize = 24;
const ROWS: usize = 12;
const ROW_H: usize = 10;
// Frame-send cadence in POLL_MS ticks: ~80 ms shown, ~200 ms hidden.
const ACTIVE_TICKS: u32 = 8;
const IDLE_TICKS: u32 = 20;

const MODE_INPUT: u32 = 0x1;
const MODE_PUSHPULL: u32 = 0x4;

// --- low level -------------------------------------------------------------

fn uart_init() {
    unsafe {
        // EUSART0 bus clock.
        CMU_CLKEN1.write_volatile(CMU_CLKEN1.read_volatile() | CMU_CLKEN1_EUSART0);

        // PA08 (TX) push-pull idle-high; PA09 (RX) input. (Pins are *disabled*
        // at reset, not input -- the RX pin must be set to input explicitly.)
        GPIO_A_DOUT.write_volatile(GPIO_A_DOUT.read_volatile() | (1 << 8));
        let modeh = GPIO_A_MODEH.read_volatile() & !((0xF << 0) | (0xF << 4));
        GPIO_A_MODEH.write_volatile(
            modeh | (MODE_PUSHPULL << 0) | (MODE_INPUT << 4),
        );

        // PA00 = RTS, driven low (asserted = "ready to receive"). Harmless if the
        // board controller's VCOM isn't using flow control; required if it is.
        GPIO_A_DOUT.write_volatile(GPIO_A_DOUT.read_volatile() & !(1 << 0));
        let model = GPIO_A_MODEL.read_volatile() & !(0xF << 0);
        GPIO_A_MODEL.write_volatile(model | (MODE_PUSHPULL << 0));

        // PB00 = VCOM enable, push-pull high.
        GPIO_B_DOUT.write_volatile(GPIO_B_DOUT.read_volatile() | (1 << 0));
        let model = GPIO_B_MODEL.read_volatile() & !(0xF << 0); // MODE0
        GPIO_B_MODEL.write_volatile(model | (MODE_PUSHPULL << 0));

        // Configure EUSART (all CFG before EN).
        EUSART0_CFG0.write_volatile(0); // async, OVS16, LSB-first
        EUSART0_FRAMECFG.write_volatile(FRAMECFG_8N1);
        EUSART0_CLKDIV.write_volatile(CLKDIV_115200);
        EUSART0_EN.write_volatile(EN_EN);

        // Route TX->PA08, RX->PA09 and enable the pins.
        GPIO_EUSART0_TXROUTE.write_volatile(8 << ROUTE_PIN_SHIFT);
        GPIO_EUSART0_RXROUTE.write_volatile(9 << ROUTE_PIN_SHIFT);
        GPIO_EUSART0_ROUTEEN.write_volatile(ROUTEEN_TXPEN | ROUTEEN_RXPEN);

        // Enable TX + RX.
        EUSART0_CMD.write_volatile(CMD_TXEN | CMD_RXEN);
        for _ in 0..10_000 {
            if EUSART0_SYNCBUSY.read_volatile() == 0 {
                break;
            }
        }
    }
}

fn tx_byte(b: u8) {
    unsafe {
        for _ in 0..100_000 {
            if EUSART0_STATUS.read_volatile() & STATUS_TXFL != 0 {
                break;
            }
        }
        EUSART0_TXDATA.write_volatile(b as u32);
    }
    // Mirror everything we print to the LCD terminal view.
    screen_push(b);
}

fn rx_byte() -> Option<u8> {
    unsafe {
        if EUSART0_STATUS.read_volatile() & STATUS_RXFL != 0 {
            Some((EUSART0_RXDATA.read_volatile() & 0xff) as u8)
        } else {
            None
        }
    }
}

/// `core::fmt::Write` sink over the UART.
struct Uart;

impl Write for Uart {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if b == b'\n' {
                tx_byte(b'\r');
            }
            tx_byte(b);
        }
        Ok(())
    }
}

fn puts(s: &str) {
    let _ = Uart.write_str(s);
}

// --- LCD terminal mirror ---------------------------------------------------

/// A tiny scrolling character grid. Every byte written to the UART is also fed
/// here (see `tx_byte`), so the LCD shows the same text as the serial terminal.
struct Screen {
    cells: [[u8; COLS]; ROWS],
    row: usize,
    col: usize,
}

impl Screen {
    const fn new() -> Self {
        Self { cells: [[b' '; COLS]; ROWS], row: 0, col: 0 }
    }

    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 >= ROWS {
            // Scroll: drop the top line, blank the new bottom line.
            self.cells.rotate_left(1);
            self.cells[ROWS - 1] = [b' '; COLS];
        } else {
            self.row += 1;
        }
    }

    fn push(&mut self, b: u8) {
        match b {
            b'\n' => self.newline(),
            b'\r' => self.col = 0,
            0x08 => self.col = self.col.saturating_sub(1), // backspace
            0x20..=0x7e => {
                if self.col >= COLS {
                    self.newline();
                }
                self.cells[self.row][self.col] = b;
                self.col += 1;
            }
            _ => {}
        }
    }
}

// Single-task-owned: only `tx_byte` (writes) and `render_screen` (reads) touch
// it, and never concurrently (the task is single-threaded with no ISRs here).
static mut SCREEN: Screen = Screen::new();

fn screen_push(b: u8) {
    unsafe { (*(&raw mut SCREEN)).push(b) }
}

fn render_screen(fb: &mut gfx::Frame) {
    gfx::clear(fb);
    let style = MonoTextStyle::new(&FONT_5X8, BinaryColor::On);
    let mut t = gfx::FrameBuf::new(fb);
    let screen = unsafe { &*(&raw const SCREEN) };
    for (r, line) in screen.cells.iter().enumerate() {
        let s = core::str::from_utf8(line).unwrap_or("");
        let _ = Text::with_baseline(s, Point::new(1, (r * ROW_H) as i32 + 1), style, Baseline::Top)
            .draw(&mut t);
    }
}

// --- shell -----------------------------------------------------------------

fn task_name(i: usize) -> &'static str {
    match i {
        0 => "jefe",
        1 => "display",
        2 => "console",
        3 => "viewer",
        4 => "pong",
        5 => "life",
        6 => "cpugraph",
        7 => "logo",
        8 => "stars",
        9 => "crypto",
        10 => "hello",
        11 => "load",
        12 => "cryptosrv",
        13 => "shaviz",
        14 => "mactamper",
        15 => "trngrain",
        16 => "ed25519",
        17 => "temp",
        18 => "snake",
        19 => "fractal",
        20 => "hashchain",
        21 => "aesava",
        22 => "gcm",
        23 => "matrix",
        24 => "plasma",
        25 => "aesbench",
        26 => "ecdh",
        27 => "idle",
        _ => "?",
    }
}

fn state_str(state: TaskState) -> &'static str {
    match state {
        TaskState::Faulted { .. } => "FAULT",
        TaskState::Healthy(s) => match s {
            SchedState::Stopped => "stop",
            SchedState::Runnable => "RUN",
            SchedState::InRecv(_) => "recv",
            SchedState::InReply(_) => "reply",
            SchedState::InSend(_) => "send",
        },
    }
}

fn cmd_ps() {
    // Quick CPU sample over a short window.
    let mut a = [0u32; NUM_TASKS];
    let mut b = [0u32; NUM_TASKS];
    let n = kipc::get_task_cpu_samples(&mut a);
    hl::sleep_for(200);
    kipc::get_task_cpu_samples(&mut b);
    let mut total = 0u32;
    for i in 0..n {
        total = total.wrapping_add(b[i].wrapping_sub(a[i]));
    }

    puts("ID NAME      STATE  CPU\r\n");
    for i in 0..n {
        let pct = if total > 0 {
            (b[i].wrapping_sub(a[i]) as usize * 100 / total as usize).min(100)
        } else {
            0
        };
        let _ = writeln!(
            Uart,
            "{i:>2} {:<9} {:<6} {pct:>3}%",
            task_name(i),
            state_str(kipc::read_task_status(i)),
        );
    }
}

fn cmd_uptime() {
    let now = sys_get_timer().now; // milliseconds since boot
    let secs = now / 1000;
    let _ = writeln!(
        Uart,
        "up {}h {:02}m {:02}s ({} ms)",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
        now
    );
}

fn parse_int(tok: &[u8], radix: u32) -> Option<u32> {
    if tok.is_empty() || tok.len() > 8 {
        return None;
    }
    let mut v = 0u32;
    for &c in tok {
        let d = (c as char).to_digit(radix)?;
        v = v.wrapping_mul(radix).wrapping_add(d);
    }
    Some(v)
}

fn hexline(bytes: &[u8]) {
    for &b in bytes {
        let _ = write!(Uart, "{b:02x}");
    }
    puts("\r\n");
}

/// `se <subcommand>` -- talk to the Secure Engine via the crypto server.
fn cmd_se(line: &[u8]) {
    let srv = CRYPTOSRV.get_task_id();
    let mut toks = line.split(|&b| b == b' ').filter(|t| !t.is_empty());
    let _ = toks.next(); // "se"
    match toks.next() {
        Some(b"rand") => {
            let n = toks
                .next()
                .and_then(|t| parse_int(t, 10))
                .unwrap_or(16)
                .min(crypto::SE_MAX_OUT as u32) as usize;
            let mut out = [0u8; crypto::SE_MAX_OUT];
            let st = crypto::client_se(
                srv,
                crypto::SE_CMD_TRNG_GET_RANDOM,
                &[n as u32],
                &mut out[..n],
            );
            if st == 0 {
                puts("TRNG: ");
                hexline(&out[..n]);
            } else {
                let _ = writeln!(Uart, "TRNG: SE status {st:#x}");
            }
        }
        Some(b"version") => {
            let mut out = [0u8; 4];
            let st =
                crypto::client_se(srv, crypto::SE_CMD_SE_VERSION, &[], &mut out);
            if st == 0 {
                let v = u32::from_le_bytes(out);
                let _ = writeln!(
                    Uart,
                    "SE FW version {}.{}.{} ({v:#010x})",
                    (v >> 16) & 0xff,
                    (v >> 8) & 0xff,
                    v & 0xff
                );
            } else {
                let _ = writeln!(Uart, "version: SE status {st:#x}");
            }
        }
        Some(b"status") => cmd_se_status(srv),
        Some(b"serial") => se_read_hex(srv, crypto::SE_CMD_READ_SERIAL, 16, "serial"),
        Some(b"challenge") => {
            se_read_hex(srv, crypto::SE_CMD_GET_CHALLENGE, 16, "challenge")
        }
        Some(b"otp") => {
            let mut out = [0u8; 4];
            let st = crypto::client_se(srv, crypto::SE_CMD_OTP_VERSION, &[], &mut out);
            if st == 0 {
                let _ = writeln!(Uart, "OTP version {:#010x}", u32::from_le_bytes(out));
            } else {
                let _ = writeln!(Uart, "otp: SE status {st:#x}");
            }
        }
        Some(b"rstcause") => cmd_se_rstcause(srv),
        Some(b"hash") => {
            // Message = raw bytes after the "hash" token (preserve spaces).
            let msg = word_rest(line, 2);
            let mut digest = [0u8; 32];
            let st = crypto::client_sha256(srv, msg, &mut digest);
            if st == 0 {
                puts("sha256: ");
                hexline(&digest);
            } else {
                let _ = writeln!(Uart, "hash: SE status {st:#x}");
            }
        }
        Some(b"cmac") => cmd_se_mac(srv, false, line),
        Some(b"hmac") => cmd_se_mac(srv, true, line),
        Some(b"raw") => {
            let cmd = match toks.next().and_then(|t| parse_int(t, 16)) {
                Some(c) => c,
                None => {
                    puts("usage: se raw <cmd_hex> [param_hex ...]\r\n");
                    return;
                }
            };
            let mut params = [0u32; 4];
            let mut np = 0;
            for t in toks {
                if np >= 4 {
                    break;
                }
                if let Some(v) = parse_int(t, 16) {
                    params[np] = v;
                    np += 1;
                }
            }
            let mut out = [0u8; 32];
            let st = crypto::client_se(srv, cmd, &params[..np], &mut out);
            let _ = writeln!(Uart, "se cmd={cmd:#010x} status={st:#x}");
            puts("out: ");
            hexline(&out);
        }
        _ => puts(
            "se subcommands:\r\n  se rand [n]      TRNG random bytes\r\n\
             \x20 se status        SE status (parsed)\r\n  se version       SE FW version\r\n\
             \x20 se otp           OTP version\r\n  se serial        device serial (16B)\r\n\
             \x20 se challenge     secure-debug challenge (16B)\r\n\
             \x20 se rstcause      last reset cause\r\n  se hash <text>   SHA-256 of text\r\n\
             \x20 se cmac <text>   AES-CMAC of text\r\n  se hmac <text>   HMAC-SHA256 of text\r\n\
             \x20 se raw <c> [p..] raw command (hex)\r\n",
        ),
    }
}

/// Display name for crypto-suite benchmark algorithm `id` (see `OP_CBENCH`), and
/// the short token typed on the console to select it.
fn bench_algo(id: u8) -> (&'static [u8], &'static str) {
    match id {
        0 => (b"aes128", "AES-128 ECB"),
        1 => (b"aes256", "AES-256 ECB"),
        2 => (b"gcm", "AES-GCM"),
        3 => (b"cmac", "AES-CMAC"),
        4 => (b"sha256", "SHA-256"),
        5 => (b"hmac", "HMAC-SHA256"),
        6 => (b"ed-sign", "Ed25519 sign"),
        7 => (b"ed-verify", "Ed25519 vrfy"),
        _ => (b"x25519", "X25519 ECDH"),
    }
}

/// Decode a benchmark reply half (`[ops(4), ms(4)]`, little-endian) -> (ops, ms).
fn bench_half(half: &[u8]) -> (u32, u32) {
    (
        u32::from_le_bytes(half[0..4].try_into().unwrap()),
        u32::from_le_bytes(half[4..8].try_into().unwrap()),
    )
}

/// Ops/sec from (ops, ms).
fn bench_rate(ops: u32, ms: u32) -> u32 {
    ops * 1000 / ms.max(1)
}

/// Algorithm `id` reports time-per-op (ms) rather than throughput (the
/// asymmetric ones: Ed25519 sign/verify, X25519 ECDH).
fn bench_timed(id: u8) -> bool {
    id >= 6
}

/// Run one crypto-suite benchmark and print the SE-vs-Oberon result line. Bulk
/// algorithms print throughput (KB/s); asymmetric ones print per-op time (ms).
fn bench_one(srv: TaskId, id: u8) {
    let (_, name) = bench_algo(id);
    let mut r = [0u8; crypto::CBENCH_REPLY];
    crypto::client_cbench(srv, id, &mut r);
    let (se_ops, se_ms) = bench_half(&r[0..8]);
    let (sw_ops, sw_ms) = bench_half(&r[8..16]);
    let se = bench_rate(se_ops, se_ms);
    let sw = bench_rate(sw_ops, sw_ms);
    let (lead, fast, slow) =
        if se >= sw { ("SE", se, sw) } else { ("SW", sw, se) };
    let ratio = if slow > 0 { fast * 10 / slow } else { 0 };
    if bench_timed(id) {
        let st = se_ms * 10 / se_ops.max(1); // tenths of a ms per op
        let wt = sw_ms * 10 / sw_ops.max(1);
        let _ = writeln!(
            Uart,
            "{name:<13} SE {}.{} ms  SW {}.{} ms  {lead} {}.{}x",
            st / 10, st % 10, wt / 10, wt % 10, ratio / 10, ratio % 10
        );
    } else {
        let _ = writeln!(
            Uart,
            "{name:<13} SE {se:>6} KB/s  SW {sw:>6} KB/s  {lead} {}.{}x",
            ratio / 10, ratio % 10
        );
    }
}

/// `bench [algo]`: race the Secure Engine hardware against the Oberon software
/// library. With no argument, runs every algorithm both engines support.
fn cmd_bench(line: &[u8]) {
    let srv = CRYPTOSRV.get_task_id();
    let mut toks = line.split(|&b| b == b' ').filter(|t| !t.is_empty());
    let _ = toks.next(); // "bench"
    match toks.next() {
        None => {
            puts("crypto benchmark (SE hardware vs Oberon software):\r\n");
            for id in 0..crypto::CBENCH_NALGO {
                bench_one(srv, id);
            }
        }
        Some(b"toml") | Some(b"report") => cmd_bench_report(srv),
        Some(b"list") | Some(b"help") => {
            puts("bench [algo|toml] -- algos:\r\n");
            for id in 0..crypto::CBENCH_NALGO {
                let (tok, name) = bench_algo(id);
                let _ = writeln!(
                    Uart,
                    "  {:<10} {name}",
                    core::str::from_utf8(tok).unwrap_or("?")
                );
            }
        }
        Some(sel) => {
            match (0..crypto::CBENCH_NALGO).find(|&id| bench_algo(id).0 == sel) {
                Some(id) => bench_one(srv, id),
                None => puts("unknown algo (try 'bench list')\r\n"),
            }
        }
    }
}

/// `bench toml`: run the full crypto suite and print the SE-vs-Oberon comparison
/// as a TOML document (machine-parseable; pipe the UART capture into any TOML
/// reader). Rates are SE-hardware vs Oberon-software ops/sec (KB/s for the bulk
/// algorithms, op/s for the asymmetric ones).
fn cmd_bench_report(srv: TaskId) {
    puts("# crypto benchmark: SE hardware vs Oberon software\r\n");
    puts("[benchmark]\r\n");
    let _ = writeln!(Uart, "buffer_bytes = {}", crypto::CBENCH_BUF);
    puts("engines = [\"se-hardware\", \"oberon-software\"]\r\n");
    for id in 0..crypto::CBENCH_NALGO {
        let (_, name) = bench_algo(id);
        let mut r = [0u8; crypto::CBENCH_REPLY];
        crypto::client_cbench(srv, id, &mut r);
        let (se_ops, se_ms) = bench_half(&r[0..8]);
        let (sw_ops, sw_ms) = bench_half(&r[8..16]);
        let se = bench_rate(se_ops, se_ms);
        let sw = bench_rate(sw_ops, sw_ms);
        let (winner, fast, slow) =
            if se >= sw { ("se", se, sw) } else { ("oberon", sw, se) };
        let ratio = if slow > 0 { fast * 10 / slow } else { 0 };
        puts("\r\n[[result]]\r\n");
        let _ = writeln!(Uart, "algo = \"{name}\"");
        if bench_timed(id) {
            // Asymmetric: report per-op time (ms). Lower is better, so the TOML
            // value is time and `winner`/`speedup` still mark the faster engine.
            let st = se_ms * 10 / se_ops.max(1);
            let wt = sw_ms * 10 / sw_ops.max(1);
            let _ = writeln!(Uart, "unit = \"ms\"");
            let _ = writeln!(Uart, "se = {}.{}", st / 10, st % 10);
            let _ = writeln!(Uart, "oberon = {}.{}", wt / 10, wt % 10);
        } else {
            let _ = writeln!(Uart, "unit = \"KB/s\"");
            let _ = writeln!(Uart, "se = {se}");
            let _ = writeln!(Uart, "oberon = {sw}");
        }
        let _ = writeln!(Uart, "winner = \"{winner}\"");
        let _ = writeln!(Uart, "speedup = {}.{}", ratio / 10, ratio % 10);
    }
}

/// Demo key for `se cmac`/`se hmac` (so the tag is reproducible/verifiable):
/// the FIPS-197 key `000102...0f`.
const MAC_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f,
];

/// `se cmac <text>` / `se hmac <text>`: keyed MAC of text under [`MAC_KEY`].
fn cmd_se_mac(srv: TaskId, hmac: bool, line: &[u8]) {
    let msg = word_rest(line, 2);
    let mut out = [0u8; 32];
    let n = if hmac { 32 } else { 16 };
    let st = crypto::client_mac(srv, hmac, &MAC_KEY, msg, &mut out[..n]);
    if st == 0 {
        puts(if hmac { "hmac: " } else { "cmac: " });
        hexline(&out[..n]);
    } else {
        let _ = writeln!(Uart, "mac: SE status {st:#x}");
    }
}

/// Return the slice of `line` after skipping `skip` whitespace-delimited tokens,
/// preserving any spaces within the remainder (for free-text args like `hash`).
fn word_rest(line: &[u8], skip: usize) -> &[u8] {
    let mut i = 0;
    for _ in 0..skip {
        while i < line.len() && line[i] == b' ' {
            i += 1;
        }
        while i < line.len() && line[i] != b' ' {
            i += 1;
        }
    }
    while i < line.len() && line[i] == b' ' {
        i += 1;
    }
    &line[i..]
}

/// Run a no-parameter SE command that returns `n` bytes, and hex-dump them.
fn se_read_hex(srv: TaskId, cmd: u32, n: usize, label: &str) {
    let mut out = [0u8; crypto::SE_MAX_OUT];
    let n = n.min(crypto::SE_MAX_OUT);
    let st = crypto::client_se(srv, cmd, &[], &mut out[..n]);
    if st == 0 {
        let _ = write!(Uart, "{label}: ");
        hexline(&out[..n]);
    } else {
        let _ = writeln!(Uart, "{label}: SE status {st:#x}");
    }
}

/// `se rstcause`: last reset cause (EMU_RSTCAUSE bits), decoded. May return an SE
/// error on parts where the mailbox doesn't expose it (it's an EMU register here).
fn cmd_se_rstcause(srv: TaskId) {
    let mut out = [0u8; 4];
    let st = crypto::client_se(srv, crypto::SE_CMD_READ_RSTCAUSE, &[], &mut out);
    if st != 0 {
        let _ = writeln!(Uart, "rstcause: SE status {st:#x} (may be unsupported)");
        return;
    }
    let rc = u32::from_le_bytes(out);
    let _ = writeln!(Uart, "reset cause {rc:#010x}:");
    for (bit, name) in [
        (0, "POR"),
        (1, "PIN"),
        (2, "EM4 wakeup"),
        (3, "WDOG0"),
        (5, "CPU lockup"),
        (6, "SYSREQ (soft)"),
        (7, "DVDD BOD"),
        (9, "DECouple BOD"),
        (10, "AVDD BOD"),
    ] {
        if rc & (1 << bit) != 0 {
            let _ = writeln!(Uart, "  {name}");
        }
    }
}

/// `se status`: GET_STATUS (0xFE010000) -> the SE's status struct. On Series 2
/// (our MG24) this is a **9-word** payload (Series 3 adds a 10th ROM-version
/// word). Mirrors the SDK's `se_get_status.py` raw dump (one labeled line per
/// word) plus a short decode. Field order/meaning from `sl_se_get_status`.
fn cmd_se_status(srv: TaskId) {
    let mut out = [0u8; 36]; // 9 words on Series 2 (over-asking -> SE BUS_ERROR)
    let st = crypto::client_se(srv, crypto::SE_CMD_GET_STATUS, &[], &mut out);
    if st != 0 {
        let _ = writeln!(Uart, "status: SE status {st:#x}");
        return;
    }
    let w = |i: usize| u32::from_le_bytes(out[i * 4..i * 4 + 4].try_into().unwrap());

    // Raw 9-word response, labeled (matches the Python tool's "Response:" dump).
    puts("SE status (GET_STATUS 0xfe010000):\r\n");
    let labels = [
        "tamper status ", // sources latched at the last tamper event
        "tamper time   ", // SE-time of that last tamper event
        "tamper raw    ", // sources currently asserting
        "timestamp     ", // SE current time (0xffffffff = not available)
        "boot status   ",
        "SE FW version ",
        "host FW ver   ",
        "debug status  ",
        "secure boot   ",
    ];
    for (i, label) in labels.iter().enumerate() {
        let _ = writeln!(Uart, "  [{i}] {label} {:#010x}", w(i));
    }

    // Friendly decode of the interesting fields.
    let (tamp, tamp_t, tamp_raw, ts, se_fw, host_fw, boot, dbg, sb) =
        (w(0), w(1), w(2), w(3), w(5), w(6), w(4), w(7), w(8));
    puts("decoded:\r\n");
    let _ = writeln!(
        Uart,
        "  SE FW       {}.{}.{}",
        (se_fw >> 16) & 0xff,
        (se_fw >> 8) & 0xff,
        se_fw & 0xff
    );
    let _ = writeln!(Uart, "  host FW     {host_fw:#010x}");
    let _ = writeln!(Uart, "  boot status {boot:#010x}");
    // SDK: secure boot enabled only if the word is exactly 1.
    let _ = writeln!(
        Uart,
        "  secure boot {}",
        if sb == 1 { "enabled" } else { "disabled" }
    );

    // SE current time. The SE reports 0xffffffff when it doesn't track uptime.
    if ts == 0xffff_ffff {
        puts("  SE time     not available\r\n");
    } else {
        let _ = writeln!(Uart, "  SE time     {ts}");
    }

    // Tamper: latched = sources that tripped at the last event, raw = sources
    // active now. Each bit is one tamper source (channel). 0 = clean.
    if tamp == 0 && tamp_raw == 0 {
        puts("  tamper      none\r\n");
    } else {
        let _ = writeln!(
            Uart,
            "  tamper      latched {tamp:#010x} @ {tamp_t:#x}  raw {tamp_raw:#010x}"
        );
    }

    // Debug port status (bit fields per `decode_debug_status`). Bits 0/1/2/5 are
    // direct; "yes"/"no" reads the asserted sense.
    puts("  debug:\r\n");
    let yn = |b: bool| if b { "yes" } else { "no" };
    let _ = writeln!(Uart, "    lock applied {}", yn(dbg & (1 << 0) != 0));
    let _ = writeln!(
        Uart,
        "    lock state   {}",
        if dbg & (1 << 5) != 0 { "locked" } else { "unlocked" }
    );
    let _ = writeln!(Uart, "    device erase {}", yn(dbg & (1 << 1) != 0));
    let _ = writeln!(Uart, "    secure debug {}", yn(dbg & (1 << 2) != 0));
}

fn dispatch(line: &[u8]) {
    if line == b"se" || line.starts_with(b"se ") {
        cmd_se(line);
        return;
    }
    if line == b"bench" || line.starts_with(b"bench ") {
        cmd_bench(line);
        return;
    }
    match line {
        b"" => {}
        b"help" => puts(
            "commands:\r\n  help    this list\r\n  ps      task table + cpu\r\n\
             \x20 tasks   alias of ps\r\n  uptime  kernel uptime\r\n\
             \x20 load    start the CPU-hog task\r\n  stop    stop the CPU-hog task\r\n\
             \x20 se ...  Secure Engine (se status|rand|version|raw)\r\n\
             \x20 bench [algo|toml]  SE-vs-Oberon crypto benchmark\r\n",
        ),
        b"ps" | b"tasks" => cmd_ps(),
        b"uptime" => cmd_uptime(),
        b"load" => {
            kipc::reinit_task(LOAD_INDEX, true);
            puts("load task started\r\n");
        }
        b"stop" => {
            kipc::reinit_task(LOAD_INDEX, false);
            puts("load task stopped\r\n");
        }
        _ => {
            puts("unknown command: ");
            let _ = Uart.write_str(core::str::from_utf8(line).unwrap_or("?"));
            puts("\r\n");
        }
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    uart_init();
    puts("\r\nHubris EFR32MG24\r\nconsole\r\ntype 'help'\r\n> ");

    let display = DISPLAY.get_task_id();
    let mut fb: gfx::Frame = [0xff; FB_LEN];

    let mut line = [0u8; LINE_MAX];
    let mut len = 0usize;

    // RX is polled every POLL_MS; the LCD mirror is refreshed less often (and
    // even less when it isn't the active mode -- the server's reply tells us).
    let mut tick = 0u32;
    let mut send_every = IDLE_TICKS;
    let mut active = false;

    loop {
        while let Some(b) = rx_byte() {
            match b {
                b'\r' | b'\n' => {
                    puts("\r\n");
                    dispatch(&line[..len]);
                    len = 0;
                    puts("> ");
                }
                0x08 | 0x7f => {
                    // backspace
                    if len > 0 {
                        len -= 1;
                        puts("\x08 \x08");
                    }
                }
                0x20..=0x7e => {
                    if len < LINE_MAX {
                        line[len] = b;
                        len += 1;
                        tx_byte(b); // echo
                    }
                }
                _ => {}
            }
        }

        tick += 1;
        if tick >= send_every {
            tick = 0;
            // Only re-render the mirror when we're the shown mode; otherwise we
            // just send (a cheap poll) to learn when we become active again.
            if active {
                render_screen(&mut fb);
            }
            let (rc, _) = sys_send(
                display,
                gfx::OP_DRAW,
                &[],
                &mut [],
                &[Lease::read_only(&fb[..])],
            );
            active = rc & 1 != 0;
            send_every = if active { ACTIVE_TICKS } else { IDLE_TICKS };
        }

        hl::sleep_for(POLL_MS);
    }
}
