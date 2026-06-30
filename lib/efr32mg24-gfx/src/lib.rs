// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Shared 1bpp framebuffer + 5x7 text rendering for the EFR32MG24 Memory-LCD
//! demo (Sharp LS013B7DH03, 128x128).
//!
//! The `display` server owns the panel and the LDMA. "Source" tasks (task
//! viewer, console mirror, pong, ...) render a [`Frame`] with these helpers and
//! send it to the server with operation [`OP_DRAW`] and one read-only lease on
//! the frame. Pixel convention matches the panel: bit 1 = white, 0 = black.

#![no_std]

use core::fmt::Write;

/// Panel geometry.
pub const WIDTH: usize = 128;
pub const HEIGHT: usize = 128;
pub const ROW_BYTES: usize = WIDTH / 8;
pub const FB_LEN: usize = ROW_BYTES * HEIGHT;

/// A 1bpp framebuffer, row-major, LSB = leftmost pixel. Bit 1 = white.
pub type Frame = [u8; FB_LEN];

/// An [`embedded_graphics`](https://docs.rs/embedded-graphics) `DrawTarget` over
/// a [`Frame`], so source tasks can render with that library and still hand the
/// raw bytes to the display server. `BinaryColor::On` = white (foreground, bit
/// set); `Off` = black (background, bit cleared) -- white-on-black.
pub struct FrameBuf<'a> {
    fb: &'a mut Frame,
}

impl<'a> FrameBuf<'a> {
    pub fn new(fb: &'a mut Frame) -> Self {
        Self { fb }
    }
}

impl embedded_graphics_core::geometry::OriginDimensions for FrameBuf<'_> {
    fn size(&self) -> embedded_graphics_core::geometry::Size {
        embedded_graphics_core::geometry::Size::new(WIDTH as u32, HEIGHT as u32)
    }
}

impl embedded_graphics_core::draw_target::DrawTarget for FrameBuf<'_> {
    type Color = embedded_graphics_core::pixelcolor::BinaryColor;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = embedded_graphics_core::Pixel<Self::Color>>,
    {
        use embedded_graphics_core::pixelcolor::BinaryColor;
        for embedded_graphics_core::Pixel(coord, color) in pixels {
            if coord.x < 0
                || coord.y < 0
                || coord.x as usize >= WIDTH
                || coord.y as usize >= HEIGHT
            {
                continue;
            }
            let (x, y) = (coord.x as usize, coord.y as usize);
            let bit = 1 << (x % 8);
            let cell = &mut self.fb[y * ROW_BYTES + x / 8];
            match color {
                BinaryColor::On => *cell |= bit, // white foreground: set bit
                BinaryColor::Off => *cell &= !bit, // black background: clear bit
            }
        }
        Ok(())
    }
}

/// Display-server IPC operation: "render this leased frame". The message body
/// is empty; the frame travels as a single read-only lease (index 0); the reply
/// is empty.
pub const OP_DRAW: u16 = 1;

/// Reset a frame to the background (all-black: every bit 0).
pub fn clear(fb: &mut Frame) {
    fb.fill(0x00);
}

fn set_px(fb: &mut Frame, x: usize, y: usize) {
    if x < WIDTH && y < HEIGHT {
        // Foreground = white: set the bit (panel convention is bit 1 = white).
        fb[y * ROW_BYTES + x / 8] |= 1 << (x % 8);
    }
}

/// Draw `text` (5x7 font) at (x, y); returns the x just past the text.
pub fn draw_text(fb: &mut Frame, x: usize, y: usize, text: &[u8]) -> usize {
    let mut cx = x;
    for &c in text {
        let g = glyph(c);
        for (col, bits) in g.iter().enumerate() {
            for row in 0..7 {
                if (bits >> row) & 1 != 0 {
                    set_px(fb, cx + col, y + row);
                }
            }
        }
        cx += 6; // 5px glyph + 1px space
    }
    cx
}

/// Like [`draw_text`] but each font pixel becomes a `scale`x`scale` block, for
/// big text. Returns the x just past the text.
pub fn draw_text_scaled(
    fb: &mut Frame,
    x: usize,
    y: usize,
    text: &[u8],
    scale: usize,
) -> usize {
    let mut cx = x;
    for &c in text {
        let g = glyph(c);
        for (col, bits) in g.iter().enumerate() {
            for row in 0..7 {
                if (bits >> row) & 1 != 0 {
                    let px = cx + col * scale;
                    let py = y + row * scale;
                    fill_rect(fb, px, py, px + scale - 1, py + scale - 1);
                }
            }
        }
        cx += 6 * scale; // (5px glyph + 1px space) * scale
    }
    cx
}

/// Horizontal line across the full width at row `y`.
pub fn draw_hline(fb: &mut Frame, y: usize) {
    for x in 0..WIDTH {
        set_px(fb, x, y);
    }
}

/// Outline rectangle (inclusive corners).
pub fn draw_rect(fb: &mut Frame, x0: usize, y0: usize, x1: usize, y1: usize) {
    for x in x0..=x1 {
        set_px(fb, x, y0);
        set_px(fb, x, y1);
    }
    for y in y0..=y1 {
        set_px(fb, x0, y);
        set_px(fb, x1, y);
    }
}

/// Filled rectangle (inclusive corners).
pub fn fill_rect(fb: &mut Frame, x0: usize, y0: usize, x1: usize, y1: usize) {
    for y in y0..=y1 {
        for x in x0..=x1 {
            set_px(fb, x, y);
        }
    }
}

/// Blit a packed 1bpp bitmap (`w` px wide, `h` tall, LSB-first within each byte,
/// `(w+7)/8` bytes per row) at `(x, y)`. Set bits draw white; clear bits are
/// transparent (background shows through). Clipped to the frame.
pub fn blit(fb: &mut Frame, x: usize, y: usize, bmp: &[u8], w: usize, h: usize) {
    let rowbytes = w.div_ceil(8);
    for ly in 0..h {
        let sy = y + ly;
        if sy >= HEIGHT {
            break;
        }
        for lx in 0..w {
            let sx = x + lx;
            if sx < WIDTH && bmp[ly * rowbytes + lx / 8] & (1 << (lx % 8)) != 0 {
                set_px(fb, sx, sy);
            }
        }
    }
}

/// A tiny `core::fmt::Write` sink for formatting small numbers into a frame
/// without an allocator, e.g. `let mut n = Num::new(); write!(n, "{i}").ok();`
/// then `draw_text(fb, x, y, n.as_bytes())`.
pub struct Num {
    pub buf: [u8; 8],
    pub len: usize,
}

impl Num {
    pub fn new() -> Self {
        Self { buf: [0; 8], len: 0 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Default for Num {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for Num {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        Ok(())
    }
}

/// Small xorshift32 PRNG for the animated demo source tasks.
pub struct Rng(u32);

impl Rng {
    /// Seed (mixed and forced non-zero -- xorshift can't start from 0).
    pub fn new(seed: u32) -> Self {
        Self(seed.wrapping_mul(2654435761) | 1)
    }

    pub fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }

    /// Uniform in `0..n` (n must be > 0).
    pub fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
}

/// 5-column bitmap for an ASCII character (uppercased); each byte is a column,
/// bit `row` = pixel at that row. Unknown characters render blank.
fn glyph(c: u8) -> [u8; 5] {
    match c.to_ascii_uppercase() {
        b' ' => [0x00, 0x00, 0x00, 0x00, 0x00],
        b'-' => [0x08, 0x08, 0x08, 0x08, 0x08],
        b':' => [0x00, 0x36, 0x36, 0x00, 0x00],
        b'.' => [0x00, 0x60, 0x60, 0x00, 0x00],
        b'!' => [0x00, 0x00, 0x5F, 0x00, 0x00],
        b'"' => [0x00, 0x07, 0x00, 0x07, 0x00],
        b'#' => [0x14, 0x7F, 0x14, 0x7F, 0x14],
        b'%' => [0x23, 0x13, 0x08, 0x64, 0x62],
        b'\'' => [0x00, 0x05, 0x03, 0x00, 0x00],
        b'(' => [0x00, 0x1C, 0x22, 0x41, 0x00],
        b')' => [0x00, 0x41, 0x22, 0x1C, 0x00],
        b'*' => [0x14, 0x08, 0x3E, 0x08, 0x14],
        b'+' => [0x08, 0x08, 0x3E, 0x08, 0x08],
        b',' => [0x00, 0x50, 0x30, 0x00, 0x00],
        b'/' => [0x20, 0x10, 0x08, 0x04, 0x02],
        b'<' => [0x08, 0x14, 0x22, 0x41, 0x00],
        b'=' => [0x14, 0x14, 0x14, 0x14, 0x14],
        b'>' => [0x00, 0x41, 0x22, 0x14, 0x08],
        b'?' => [0x02, 0x01, 0x51, 0x09, 0x06],
        b'0' => [0x3E, 0x51, 0x49, 0x45, 0x3E],
        b'1' => [0x00, 0x42, 0x7F, 0x40, 0x00],
        b'2' => [0x42, 0x61, 0x51, 0x49, 0x46],
        b'3' => [0x21, 0x41, 0x45, 0x4B, 0x31],
        b'4' => [0x18, 0x14, 0x12, 0x7F, 0x10],
        b'5' => [0x27, 0x45, 0x45, 0x45, 0x39],
        b'6' => [0x3C, 0x4A, 0x49, 0x49, 0x30],
        b'7' => [0x01, 0x71, 0x09, 0x05, 0x03],
        b'8' => [0x36, 0x49, 0x49, 0x49, 0x36],
        b'9' => [0x06, 0x49, 0x49, 0x29, 0x1E],
        b'A' => [0x7E, 0x11, 0x11, 0x11, 0x7E],
        b'B' => [0x7F, 0x49, 0x49, 0x49, 0x36],
        b'C' => [0x3E, 0x41, 0x41, 0x41, 0x22],
        b'D' => [0x7F, 0x41, 0x41, 0x22, 0x1C],
        b'E' => [0x7F, 0x49, 0x49, 0x49, 0x41],
        b'F' => [0x7F, 0x09, 0x09, 0x09, 0x01],
        b'G' => [0x3E, 0x41, 0x49, 0x49, 0x7A],
        b'H' => [0x7F, 0x08, 0x08, 0x08, 0x7F],
        b'I' => [0x00, 0x41, 0x7F, 0x41, 0x00],
        b'J' => [0x20, 0x40, 0x41, 0x3F, 0x01],
        b'K' => [0x7F, 0x08, 0x14, 0x22, 0x41],
        b'L' => [0x7F, 0x40, 0x40, 0x40, 0x40],
        b'M' => [0x7F, 0x02, 0x0C, 0x02, 0x7F],
        b'N' => [0x7F, 0x04, 0x08, 0x10, 0x7F],
        b'O' => [0x3E, 0x41, 0x41, 0x41, 0x3E],
        b'P' => [0x7F, 0x09, 0x09, 0x09, 0x06],
        b'Q' => [0x3E, 0x41, 0x51, 0x21, 0x5E],
        b'R' => [0x7F, 0x09, 0x19, 0x29, 0x46],
        b'S' => [0x46, 0x49, 0x49, 0x49, 0x31],
        b'T' => [0x01, 0x01, 0x7F, 0x01, 0x01],
        b'U' => [0x3F, 0x40, 0x40, 0x40, 0x3F],
        b'V' => [0x1F, 0x20, 0x40, 0x20, 0x1F],
        b'W' => [0x3F, 0x40, 0x38, 0x40, 0x3F],
        b'X' => [0x63, 0x14, 0x08, 0x14, 0x63],
        b'Y' => [0x07, 0x08, 0x70, 0x08, 0x07],
        b'Z' => [0x61, 0x51, 0x49, 0x45, 0x43],
        _ => [0x00, 0x00, 0x00, 0x00, 0x00],
    }
}
