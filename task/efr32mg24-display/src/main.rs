// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! On-device system monitor on the WSTK Sharp Memory LCD (LS013B7DH03,
//! 128x128, 1bpp).
//!
//! Renders a Hubris banner and a live `humility tasks`-style list -- task
//! index, name, and scheduling state -- refreshed about once a second, so you
//! can read system status off the panel without a debugger attached.
//!
//! SPI is bit-banged over GPIO Port C (unprivileged tasks can drive GPIO now
//! that `main()` opened the SMU/PPU). Pins (BRD4187C+BRD4001A board config):
//!   MOSI=PC01  SCLK=PC03  EXTCOMIN=PC06  CS=PC08  DISP_EN=PC09
//! CS active-HIGH; data LSB-first, latched on the rising SCLK edge; pixel bit
//! 1 = white, so black text clears bits over a white (0xff) background.

#![no_std]
#![no_main]

use efr32mg24_gfx::{self as gfx, FB_LEN, HEIGHT, ROW_BYTES};
use userlib::*;

// Port C GPIO (secure alias). MOSI(PC01)/SCLK(PC03) are driven by USART0; the
// control lines CS(PC08), EXTCOMIN(PC06), DISP_EN(PC09) stay plain GPIO.
const C_MODEL: *mut u32 = 0x4003_c094 as *mut u32;
const C_MODEH: *mut u32 = 0x4003_c09c as *mut u32;
const C_DOUT: *mut u32 = 0x4003_c0a0 as *mut u32;

const MOSI: u32 = 1; // PC01 = USART0 TX
const SCLK: u32 = 3; // PC03 = USART0 CLK
const EXTCOMIN: u32 = 6;
const CS: u32 = 8;
const DISP_EN: u32 = 9;
const MODE_PUSHPULL: u32 = 0x4;

// USART0 SPI master + its bus clock + GPIO routing (secure aliases).
const CMU_CLKEN0: *mut u32 = 0x4000_8064 as *mut u32;
const CMU_CLKEN0_USART0: u32 = 1 << 9;
const USART0_EN: *mut u32 = 0x4005_c004 as *mut u32;
const USART0_CTRL: *mut u32 = 0x4005_c008 as *mut u32;
const USART0_FRAME: *mut u32 = 0x4005_c00c as *mut u32;
const USART0_CMD: *mut u32 = 0x4005_c014 as *mut u32;
const USART0_STATUS: *const u32 = 0x4005_c018 as *const u32;
const USART0_CLKDIV: *mut u32 = 0x4005_c01c as *mut u32;
const USART0_TXDATA: *mut u32 = 0x4005_c03c as *mut u32;
const GPIO_USART0_ROUTEEN: *mut u32 = 0x4003_c720 as *mut u32;
const GPIO_USART0_CLKROUTE: *mut u32 = 0x4003_c734 as *mut u32;
const GPIO_USART0_TXROUTE: *mut u32 = 0x4003_c738 as *mut u32;

const CTRL_SYNC: u32 = 1 << 0; // SPI mode; MSBF=0 => LSB-first; CPOL/CPHA = 0
const FRAME_8BIT: u32 = 0x5; // DATABITS = EIGHT
// SPI clock = PCLK / (2 * (1 + (CLKDIV>>8))). 8 -> 19 MHz / 18 ~= 1.06 MHz, just
// under the LS013's ~1.1 MHz limit -- roughly halves the per-frame transfer time.
const CLKDIV_VAL: u32 = 8 << 8;
const CMD_MASTEREN: u32 = 1 << 4;
const CMD_TXEN: u32 = 1 << 2;
const STATUS_TXC: u32 = 1 << 5;
const STATUS_TXBL: u32 = 1 << 6;
const ROUTEEN_CLKPEN: u32 = 1 << 3;
const ROUTEEN_TXPEN: u32 = 1 << 4;
const ROUTE_PIN_SHIFT: u32 = 16;
const PORT_C: u32 = 2;

// LDMA: stream the framebuffer to USART0 without the CPU babysitting each byte.
// A channel is started by pointing CH.LINK at a RAM descriptor and writing
// LINKLOAD (not by writing CHEN).
const CMU_CLKEN0_LDMA: u32 = 1 << 0;
const CMU_CLKEN0_LDMAXBAR: u32 = 1 << 1;
const LDMA_EN: *mut u32 = 0x4004_0004 as *mut u32;
const LDMA_IEN: *mut u32 = 0x4004_0054 as *mut u32; // ch-done interrupt enable
const LDMA_IF_CLR: *mut u32 = 0x4004_2050 as *mut u32; // IF CLR alias (base+0x2000)
// On this silicon these peripheral-paced transfers complete by raising the LDMA
// ERROR flag (IF bit31), with the channel-0 DONE flag (bit0) only sometimes
// also set -- so an IRQ waiting on DONE alone is unreliable. The transfer data
// is correct regardless (the older CHDONE-polling driver never saw corruption),
// so we enable *both* the done and error interrupts and treat either as "the
// transfer finished", clearing both flags. Bit0 = DONE0, bit31 = ERROR.
const LDMA_IF_DONE0_ERR: u32 = (1 << 31) | (1 << 0);
const LDMA_LINKLOAD: *mut u32 = 0x4004_0048 as *mut u32;
const LDMA_CH0_CFG: *mut u32 = 0x4004_005c as *mut u32;
const LDMA_CH0_LINK: *mut u32 = 0x4004_0070 as *mut u32;
// CHDONE CLR alias (base+0x2000+0x34). Writing bit0 clears channel-0's "done"
// latch, which must happen before each LINKLOAD or the channel won't re-arm.
const LDMA_CHDONE_CLR: *mut u32 = 0x4004_2034 as *mut u32;
// CH[0].REQSEL is at LDMAXBAR+0x04 (offset 0 is the read-only IPVERSION).
const LDMAXBAR_CH0_REQSEL: *mut u32 = 0x4004_4004 as *mut u32;
// USART0 TXBL request: SOURCESEL=USART0(4)<<16 | SIGSEL=TXBL(2).
const REQSEL_USART0_TXBL: u32 = (4 << 16) | 2;
// Descriptor CTRL word for memory->peripheral: DSTINC_NONE (3<<28) | XFERCNT
// (<<4). The zero fields select byte size, src-increment-one, absolute addrs,
// block request mode, blocksize 1, and -- crucially -- structReq=0 so each byte
// waits for a USART0 TXBL request (peripheral-paced). structReq=1 would be the
// mem-to-mem "fire it all at once" mode, which overruns the TX FIFO.
const CTRL_DSTINC_NONE: u32 = 3 << 28;
// DONEIEN (CH_CTRL bit 20): set the channel-done interrupt flag (IF.DONE0) when
// the descriptor completes. Without it the transfer still finishes and CHDONE
// goes high, but IF never asserts -- so the LDMA IRQ never fires and the task
// waiting on the done notification would block forever.
const CTRL_DONEIEN: u32 = 1 << 20;

// Buttons: BTN0=PB01, BTN1=PB03 (active-low, internal pull-up). Each routes to
// an EXTI line (1 and 3 -- both odd -> GPIO_ODD / IRQ 25); falling edge = press.
// Line number == pin number here, so the same constant indexes both.
const GPIO_B_MODEL: *mut u32 = 0x4003_c064 as *mut u32;
const GPIO_B_DOUT: *mut u32 = 0x4003_c070 as *mut u32;
const GPIO_EXTIPSELL: *mut u32 = 0x4003_c400 as *mut u32;
const GPIO_EXTIPINSELL: *mut u32 = 0x4003_c408 as *mut u32;
const GPIO_EXTIFALL: *mut u32 = 0x4003_c414 as *mut u32;
const GPIO_IF: *const u32 = 0x4003_c420 as *const u32;
const GPIO_IEN: *mut u32 = 0x4003_c424 as *mut u32;
const GPIO_IF_CLR: *mut u32 = 0x4003_e420 as *mut u32; // IF CLR alias (+0x2000)
const GPIO_B_DIN: *const u32 = 0x4003_c074 as *const u32; // port B data-in

/// Current pressed state of (BTN0, BTN1) read from the live pin levels
/// (active-low). Used for the both-buttons gesture and player steering.
fn buttons_pressed() -> (bool, bool) {
    let din = unsafe { GPIO_B_DIN.read_volatile() };
    (din & (1 << BTN0_LINE) == 0, din & (1 << BTN1_LINE) == 0)
}

/// Modes that support player-vs-AI (both-buttons toggles it): pong and snake.
fn is_game(mode: u8) -> bool {
    mode == 4 || mode == 5
}
const MODE_INPUTPULL: u32 = 2;
const BTN0_LINE: u32 = 1; // EXTI line 1 <- PB01
const BTN1_LINE: u32 = 3; // EXTI line 3 <- PB03

// Display modes, cycled by the buttons. Each is owned by a source task; the
// server maps a source's task index to its mode in `mode_of`.
const NUM_MODES: u8 = 23;
const MIN_GAP_MS: u64 = 150; // button debounce

// Panel geometry (WIDTH/HEIGHT/ROW_BYTES/FB_LEN) comes from `efr32mg24_gfx` so
// the server and the source tasks agree on the framebuffer layout.
// Update stream: cmd + per line (addr + row + dummy) + 16-bit trailer.
const TX_LEN: usize = 1 + HEIGHT * (1 + ROW_BYTES + 1) + 1;

const CMD_UPDATE: u8 = 0x01;
const CMD_CLEAR: u8 = 0x04;

// --- USART0 hardware SPI + LS013 protocol ----------------------------------

fn pin_set(pin: u32, high: bool) {
    unsafe {
        let d = C_DOUT.read_volatile();
        C_DOUT.write_volatile(if high { d | (1 << pin) } else { d & !(1 << pin) });
    }
}

fn delay(loops: u32) {
    for _ in 0..loops {
        unsafe { core::arch::asm!("nop") };
    }
}

fn spi_byte(byte: u8) {
    unsafe {
        for _ in 0..100_000 {
            if USART0_STATUS.read_volatile() & STATUS_TXBL != 0 {
                break;
            }
        }
        USART0_TXDATA.write_volatile(byte as u32);
    }
}

/// Wait until the last byte has fully shifted out, before dropping CS.
fn spi_flush() {
    unsafe {
        for _ in 0..100_000 {
            if USART0_STATUS.read_volatile() & STATUS_TXC != 0 {
                break;
            }
        }
    }
}

fn usart_spi_init() {
    unsafe {
        CMU_CLKEN0
            .write_volatile(CMU_CLKEN0.read_volatile() | CMU_CLKEN0_USART0);
        USART0_EN.write_volatile(1);
        USART0_CTRL.write_volatile(CTRL_SYNC);
        USART0_FRAME.write_volatile(FRAME_8BIT);
        USART0_CLKDIV.write_volatile(CLKDIV_VAL);
        // Route MOSI->PC01, SCLK->PC03 and enable the pins.
        GPIO_USART0_TXROUTE.write_volatile(PORT_C | (1 << ROUTE_PIN_SHIFT));
        GPIO_USART0_CLKROUTE.write_volatile(PORT_C | (3 << ROUTE_PIN_SHIFT));
        GPIO_USART0_ROUTEEN.write_volatile(ROUTEEN_TXPEN | ROUTEEN_CLKPEN);
        USART0_CMD.write_volatile(CMD_MASTEREN | CMD_TXEN);
    }
}

fn ldma_init() {
    unsafe {
        CMU_CLKEN0.write_volatile(
            CMU_CLKEN0.read_volatile() | CMU_CLKEN0_LDMA | CMU_CLKEN0_LDMAXBAR,
        );
        LDMA_EN.write_volatile(1);
        // Channel 0 is paced by USART0's TX-buffer-empty request.
        LDMAXBAR_CH0_REQSEL.write_volatile(REQSEL_USART0_TXBL);
        // Enable both the channel-0 done and the error interrupt (see
        // LDMA_IF_DONE0_ERR) so completion wakes us regardless of which fires.
        LDMA_IEN.write_volatile(LDMA_IF_DONE0_ERR);
    }
    // The NVIC line is enabled per-transfer in `dma_send`, right before the
    // wait, so each wakeup provably belongs to that transfer.
}

/// Stream `buf` (<=2048 bytes -- XFERCNT is 11 bits) to USART0 via LDMA channel
/// 0 as a single descriptor, blocking on the channel-done interrupt so the CPU
/// is free during the transfer. Callers keep each transfer under one CS frame.
fn dma_send(buf: &[u8]) {
    // 4-word descriptor in RAM: CTRL, SRC, DST, LINK(=0, no next). Loaded by an
    // explicit LINKLOAD -- the proven-reliable path on this silicon (hardware
    // auto-link completes with an error flag instead of DONE, see git history).
    let desc: [u32; 4] = [
        CTRL_DSTINC_NONE | CTRL_DONEIEN | (((buf.len() - 1) as u32) << 4),
        buf.as_ptr() as u32,
        USART0_TXDATA as u32,
        0,
    ];
    unsafe {
        // Clear any leftover done/error flag *before* arming, so the interrupt
        // that wakes us can only be this transfer's completion.
        LDMA_IF_CLR.write_volatile(LDMA_IF_DONE0_ERR);
        LDMA_CH0_CFG.write_volatile(0);
        // Clear channel-0's done latch so this LINKLOAD actually re-arms it.
        LDMA_CHDONE_CLR.write_volatile(1);
        LDMA_CH0_LINK.write_volatile((&desc as *const _ as u32) & !0x3);
        // Make sure the descriptor is in RAM before the DMA fetches it.
        core::arch::asm!("dsb sy");
        LDMA_LINKLOAD.write_volatile(1);
    }
    // Enable the NVIC line, then block until the channel-0 done interrupt fires.
    // The kernel auto-disables the line on delivery; we ack the LDMA flag after.
    sys_irq_control(notifications::DMA_IRQ_MASK, true);
    sys_recv_notification(notifications::DMA_IRQ_MASK);
    unsafe { LDMA_IF_CLR.write_volatile(LDMA_IF_DONE0_ERR) };
}

fn lcd_init() {
    unsafe {
        // PC01/PC03 push-pull (USART0 drives them); PC06 EXTCOMIN push-pull.
        C_MODEL.write_volatile(
            C_MODEL.read_volatile()
                | (MODE_PUSHPULL << (MOSI * 4))
                | (MODE_PUSHPULL << (SCLK * 4))
                | (MODE_PUSHPULL << (EXTCOMIN * 4)),
        );
        // PC08 CS, PC09 DISP_EN push-pull.
        C_MODEH.write_volatile(
            C_MODEH.read_volatile()
                | (MODE_PUSHPULL << ((CS - 8) * 4))
                | (MODE_PUSHPULL << ((DISP_EN - 8) * 4)),
        );
    }
    pin_set(CS, false);
    pin_set(EXTCOMIN, false);
    pin_set(DISP_EN, true);
    usart_spi_init();
    ldma_init();
}

fn lcd_clear() {
    pin_set(CS, true);
    delay(200);
    spi_byte(CMD_CLEAR);
    spi_byte(0x00);
    spi_flush();
    delay(50);
    pin_set(CS, false);
}

fn lcd_update(fb: &[u8; FB_LEN], txbuf: &mut [u8; TX_LEN], vcom: bool) {
    // The Memory LCD's multi-line write updates any subset of lines, so we send
    // the frame as two halves. Each half is < 2048 bytes -> a single LDMA
    // descriptor in its own CS frame: no mid-frame pause (which garbles the
    // panel) and no multi-descriptor chaining (which errors on this silicon).
    lcd_send_lines(fb, txbuf, vcom, 0, HEIGHT / 2);
    lcd_send_lines(fb, txbuf, vcom, HEIGHT / 2, HEIGHT);
}

/// Send framebuffer lines `start..end` as one Memory-LCD multi-line write.
fn lcd_send_lines(
    fb: &[u8; FB_LEN],
    txbuf: &mut [u8; TX_LEN],
    vcom: bool,
    start: usize,
    end: usize,
) {
    let mut n = 0;
    txbuf[n] = CMD_UPDATE | ((vcom as u8) << 1);
    n += 1;
    for line in start..end {
        txbuf[n] = (line + 1) as u8; // 1-based line address
        n += 1;
        let base = line * ROW_BYTES;
        txbuf[n..n + ROW_BYTES].copy_from_slice(&fb[base..base + ROW_BYTES]);
        n += ROW_BYTES;
        txbuf[n] = 0xff; // per-line dummy
        n += 1;
    }
    txbuf[n] = 0xff; // trailer
    n += 1;

    pin_set(CS, true);
    delay(200);
    dma_send(&txbuf[..n]);
    spi_flush(); // let the last byte finish shifting out before dropping CS
    delay(50);
    pin_set(CS, false);
}

/// Configure BTN0/BTN1 as pulled-up inputs wired to EXTI lines 1 & 3 (falling
/// edge -> GPIO_ODD), and enable the NVIC line for our button notification.
fn buttons_init() {
    unsafe {
        // PB01 / PB03: input with pull-up (DOUT bit selects the up direction).
        GPIO_B_MODEL.write_volatile(
            GPIO_B_MODEL.read_volatile()
                | (MODE_INPUTPULL << (BTN0_LINE * 4))
                | (MODE_INPUTPULL << (BTN1_LINE * 4)),
        );
        GPIO_B_DOUT.write_volatile(
            GPIO_B_DOUT.read_volatile() | (1 << BTN0_LINE) | (1 << BTN1_LINE),
        );
        // EXTI line N <- PortB (EXTIPSEL=1), pin N (EXTIPINSEL = pin % 4); each
        // field is 4 bits wide, indexed by the line number.
        GPIO_EXTIPSELL.write_volatile(
            GPIO_EXTIPSELL.read_volatile()
                | (1 << (BTN0_LINE * 4))
                | (1 << (BTN1_LINE * 4)),
        );
        GPIO_EXTIPINSELL.write_volatile(
            GPIO_EXTIPINSELL.read_volatile()
                | (1 << (BTN0_LINE * 4))
                | (3 << (BTN1_LINE * 4)),
        );
        // Falling-edge trigger + interrupt-enable for both lines.
        GPIO_EXTIFALL.write_volatile(
            GPIO_EXTIFALL.read_volatile() | (1 << BTN0_LINE) | (1 << BTN1_LINE),
        );
        GPIO_IEN.write_volatile(
            GPIO_IEN.read_volatile() | (1 << BTN0_LINE) | (1 << BTN1_LINE),
        );
    }
    sys_irq_control(notifications::BUTTON_IRQ_MASK, true);
}

/// Map a source task index to its display mode, or `None` if it isn't a source.
/// Hardcoded to the `app.toml` order -- keep in sync.
fn mode_of(index: usize) -> Option<u8> {
    // Grouped: system, games, visual/math, crypto. Keep in sync with source_index.
    match index {
        3 => Some(0),   // viewer    (system)
        2 => Some(1),   // console   (system)
        6 => Some(2),   // cpugraph  (system)
        17 => Some(3),  // temp      (system)
        4 => Some(4),   // pong      (games)
        18 => Some(5),  // snake     (games)
        5 => Some(6),   // life      (visual/math)
        8 => Some(7),   // stars     (visual/math)
        19 => Some(8),  // fractal   (visual/math)
        7 => Some(9),   // logo      (visual/math)
        23 => Some(10), // matrix    (visual/math)
        24 => Some(11), // plasma    (visual/math)
        9 => Some(12),  // crypto    (crypto)
        13 => Some(13), // shaviz    (crypto)
        14 => Some(14), // mactamper (crypto)
        15 => Some(15), // trngrain  (crypto)
        16 => Some(16), // ecdsa     (crypto)
        20 => Some(17), // hashchain (crypto)
        21 => Some(18), // aesava    (crypto)
        22 => Some(19), // gcm       (crypto)
        25 => Some(20), // aesbench  (crypto)
        26 => Some(21), // ecdh      (crypto)
        27 => Some(22), // cryptobench (crypto)
        _ => None,
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    // The frame a source task leases to us (filled by `sys_borrow_read`) and the
    // LCD update stream we assemble from it. Geometry comes from `efr32mg24_gfx`.
    let mut fb: gfx::Frame = [0xff; FB_LEN];
    let mut txbuf = [0u8; TX_LEN];

    lcd_init();
    lcd_clear();
    buttons_init();
    kipc::log(b"display: server ready (LDMA + buttons)\r\n");

    // Server loop. Sources send OP_DRAW with a read-only lease on their frame;
    // only the active mode's source reaches the panel, and each is told (via the
    // reply code) whether it's active so it can throttle when it isn't. The
    // buttons arrive as a kernel notification and cycle the mode.
    let mut vcom = false;
    let mut mode: u8 = 0;
    let mut last_btn: u64 = 0; // debounce timestamp
    let mut player = false; // player-vs-AI mode (pong/snake), toggled by both buttons

    // Only the active mode's source runs; the rest are `start = false` and
    // started on demand (the console is the exception -- it's also the serial
    // shell, so it always runs). Start mode 0's source now.
    if let Some(i) = source_index(mode) {
        kipc::reinit_task(i, true);
    }

    loop {
        let msg = sys_recv_open(&mut [], notifications::BUTTON_IRQ_MASK);
        if msg.sender == TaskId::KERNEL {
            // Button EXTI. Both buttons together toggles player-vs-AI in a game
            // mode; otherwise BTN0 = next mode, BTN1 = previous mode. In player
            // mode single presses don't cycle -- they steer (polled in OP_DRAW).
            let flags = unsafe { GPIO_IF.read_volatile() };
            let now = sys_get_timer().now;
            if now.wrapping_sub(last_btn) >= MIN_GAP_MS {
                let (b0, b1) = buttons_pressed();
                if b0 && b1 && is_game(mode) {
                    player = !player;
                    last_btn = now;
                } else if player && is_game(mode) {
                    last_btn = now; // steering input; consume, don't cycle
                } else {
                    let next = if flags & (1 << BTN0_LINE) != 0 {
                        Some((mode + 1) % NUM_MODES)
                    } else if flags & (1 << BTN1_LINE) != 0 {
                        Some((mode + NUM_MODES - 1) % NUM_MODES)
                    } else {
                        None
                    };
                    if let Some(next) = next {
                        // Swap the running source: stop the old, start the new.
                        if let Some(i) = source_index(mode) {
                            kipc::reinit_task(i, false);
                        }
                        if let Some(i) = source_index(next) {
                            kipc::reinit_task(i, true);
                        }
                        mode = next;
                        player = false; // back to self-play on mode change
                        last_btn = now;
                    }
                }
            }
            unsafe {
                GPIO_IF_CLR
                    .write_volatile((1 << BTN0_LINE) | (1 << BTN1_LINE));
            }
            sys_irq_control(notifications::BUTTON_IRQ_MASK, true);
            continue;
        }

        let active = mode_of(msg.sender.index()) == Some(mode);
        if active && msg.operation == gfx::OP_DRAW as u32 && msg.lease_count >= 1
        {
            let (_rc, _len) = sys_borrow_read(msg.sender, 0, 0, &mut fb);
            lcd_update(&fb, &mut txbuf, vcom);
            vcom = !vcom;
            pin_set(EXTCOMIN, vcom);
        }
        // Reply code: bit0 active, bit1 player-mode, bits[3:2] held steering
        // (1 = BTN0, 2 = BTN1) when this source is the active game in player mode.
        let mut steer = 0u32;
        if active && player && is_game(mode) {
            let (b0, b1) = buttons_pressed();
            steer = b0 as u32 | (b1 as u32) << 1;
        }
        let rc = active as u32 | (player as u32) << 1 | steer << 2;
        sys_reply(msg.sender, rc, &[]);
    }
}

/// Task-table index of the source that owns `mode`, or `None` for the console
/// mode (the console always runs, so it's never stopped/started). Mirrors
/// `mode_of` + the `app.toml` order.
fn source_index(mode: u8) -> Option<usize> {
    // Grouped: system, games, visual/math, crypto. Keep in sync with mode_of.
    match mode {
        0 => Some(3),   // viewer    (system)
        1 => None,      // console   (system, always running)
        2 => Some(6),   // cpugraph  (system)
        3 => Some(17),  // temp      (system)
        4 => Some(4),   // pong      (games)
        5 => Some(18),  // snake     (games)
        6 => Some(5),   // life      (visual/math)
        7 => Some(8),   // stars     (visual/math)
        8 => Some(19),  // fractal   (visual/math)
        9 => Some(7),   // logo      (visual/math)
        10 => Some(23), // matrix    (visual/math)
        11 => Some(24), // plasma    (visual/math)
        12 => Some(9),  // crypto    (crypto)
        13 => Some(13), // shaviz    (crypto)
        14 => Some(14), // mactamper (crypto)
        15 => Some(15), // trngrain  (crypto)
        16 => Some(16), // ecdsa     (crypto)
        17 => Some(20), // hashchain (crypto)
        18 => Some(21), // aesava    (crypto)
        19 => Some(22), // gcm       (crypto)
        20 => Some(25), // aesbench  (crypto)
        21 => Some(26), // ecdh      (crypto)
        22 => Some(27), // cryptobench (crypto)
        _ => None,
    }
}

// Generated notification masks (from app.toml `notifications`).
include!(concat!(env!("OUT_DIR"), "/notifications.rs"));
