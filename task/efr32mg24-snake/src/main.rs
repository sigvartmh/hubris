// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Self-playing Snake (display mode). A greedy AI heads for the food but scores
//! each candidate move by a flood-fill of the free space it would leave, so it
//! avoids trapping itself; it also allows chasing its own tail. When it does get
//! boxed in (or fills the board) it restarts. A display "source" task.

#![no_std]
#![no_main]

use core::fmt::Write as _;

use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 90;
const IDLE_MS: u64 = 200;

const GW: usize = 16; // grid cells across
const GH: usize = 16; // grid cells down
const N: usize = GW * GH;
const CELL: usize = 7; // px per cell
const OX: usize = 8; // grid origin
const OY: usize = 14;

const DIRS: [(i32, i32); 4] = [(1, 0), (-1, 0), (0, 1), (0, -1)]; // R, L, D, U
// Relative 90-degree turns (never a reversal), indexed by current direction.
const TURN_LEFT: [usize; 4] = [3, 2, 0, 1];
const TURN_RIGHT: [usize; 4] = [2, 3, 1, 0];

static mut BUF: [u8; FB_LEN] = [0; FB_LEN];

fn idx(x: i32, y: i32) -> usize {
    y as usize * GW + x as usize
}

/// Count free cells reachable from `start` (occupied cells are walls).
fn reachable(occ: &[bool; N], start: usize) -> u32 {
    if occ[start] {
        return 0;
    }
    let mut seen = [false; N];
    let mut stack = [0u16; N];
    let mut sp = 0;
    stack[sp] = start as u16;
    sp += 1;
    seen[start] = true;
    let mut count = 0;
    while sp > 0 {
        sp -= 1;
        let c = stack[sp] as usize;
        count += 1;
        let (x, y) = ((c % GW) as i32, (c / GW) as i32);
        for (dx, dy) in DIRS {
            let (nx, ny) = (x + dx, y + dy);
            if nx >= 0 && nx < GW as i32 && ny >= 0 && ny < GH as i32 {
                let ni = idx(nx, ny);
                if !occ[ni] && !seen[ni] {
                    seen[ni] = true;
                    stack[sp] = ni as u16;
                    sp += 1;
                }
            }
        }
    }
    count
}

struct Snake {
    body: [u16; N], // ring buffer of cell indices, tail..=head
    head: usize,
    tail: usize,
    len: usize,
    dir: usize, // index into DIRS
    occ: [bool; N],
    food: usize,
}

impl Snake {
    fn new(rng: &mut gfx::Rng) -> Self {
        let mut s = Snake {
            body: [0; N],
            head: 0,
            tail: 0,
            len: 1,
            dir: 0,
            occ: [false; N],
            food: 0,
        };
        let start = idx((GW / 2) as i32, (GH / 2) as i32);
        s.body[0] = start as u16;
        s.occ[start] = true;
        s.spawn_food(rng);
        s
    }

    fn head_xy(&self) -> (i32, i32) {
        let c = self.body[self.head] as usize;
        ((c % GW) as i32, (c / GW) as i32)
    }

    fn spawn_food(&mut self, rng: &mut gfx::Rng) -> bool {
        if self.len >= N {
            return false;
        }
        loop {
            let c = rng.below(N as u32) as usize;
            if !self.occ[c] {
                self.food = c;
                return true;
            }
        }
    }

    /// Pick the next direction: among non-reversing, non-fatal moves, maximize
    /// the free space left behind, tie-breaking toward the food.
    fn choose_dir(&self) -> Option<usize> {
        let (hx, hy) = self.head_xy();
        let (fx, fy) = ((self.food % GW) as i32, (self.food / GW) as i32);
        let tail_cell = self.body[self.tail] as usize;
        let mut best: Option<(usize, u32, i32)> = None;
        for (di, (dx, dy)) in DIRS.iter().enumerate() {
            // Don't reverse into our own neck (only matters once len > 1).
            if self.len > 1 && di ^ 1 == self.dir {
                continue;
            }
            let (nx, ny) = (hx + dx, hy + dy);
            if nx < 0 || nx >= GW as i32 || ny < 0 || ny >= GH as i32 {
                continue;
            }
            let ni = idx(nx, ny);
            // The tail cell vacates this step, so moving onto it is allowed.
            if self.occ[ni] && ni != tail_cell {
                continue;
            }
            // Score: free space reachable after the move (tail treated as free).
            let mut occ = self.occ;
            occ[tail_cell] = false;
            occ[ni] = true;
            let space = reachable(&occ, ni);
            let dist = (nx - fx).abs() + (ny - fy).abs();
            // Prefer more space; for equal space, prefer closer to food.
            let better = match best {
                None => true,
                Some((_, bs, bd)) => space > bs || (space == bs && dist < bd),
            };
            if better {
                best = Some((di, space, dist));
            }
        }
        best.map(|(d, _, _)| d)
    }

    /// Advance one step using the AI's chosen direction. False = died.
    fn step(&mut self, rng: &mut gfx::Rng) -> bool {
        match self.choose_dir() {
            Some(d) => self.advance(d, rng),
            None => false,
        }
    }

    /// Move one cell in `dir`. Returns false if the snake hit a wall or itself
    /// (the caller restarts). Used directly in player mode; via `step` for AI.
    fn advance(&mut self, dir: usize, rng: &mut gfx::Rng) -> bool {
        self.dir = dir;
        let (hx, hy) = self.head_xy();
        let (nx, ny) = (hx + DIRS[dir].0, hy + DIRS[dir].1);
        if nx < 0 || nx >= GW as i32 || ny < 0 || ny >= GH as i32 {
            return false; // hit a wall
        }
        let ncell = idx(nx, ny);
        let eating = ncell == self.food;
        let tail_cell = self.body[self.tail] as usize;

        if !eating {
            // Tail vacates first (so moving onto it is safe).
            self.occ[tail_cell] = false;
            self.tail = (self.tail + 1) % N;
            self.len -= 1;
        }
        if self.occ[ncell] {
            return false; // ran into the body
        }
        self.head = (self.head + 1) % N;
        self.body[self.head] = ncell as u16;
        self.occ[ncell] = true;
        self.len += 1;
        if eating && !self.spawn_food(rng) {
            return false; // board full -> restart
        }
        true
    }

    fn render(&self, buf: &mut [u8; FB_LEN]) {
        gfx::clear(buf);
        let mut num = gfx::Num::new();
        let _ = write!(num, "{}", self.len);
        gfx::draw_text(buf, 2, 1, b"SNAKE  len:");
        gfx::draw_text(buf, 70, 1, num.as_bytes());
        gfx::draw_rect(buf, OX - 1, OY - 1, OX + GW * CELL, OY + GH * CELL);

        // Body cells.
        let mut i = self.tail;
        loop {
            let c = self.body[i] as usize;
            let (x, y) = (c % GW, c / GW);
            let px = OX + x * CELL;
            let py = OY + y * CELL;
            gfx::fill_rect(buf, px, py, px + CELL - 2, py + CELL - 2);
            if i == self.head {
                break;
            }
            i = (i + 1) % N;
        }

        // Food (hollow box).
        let (fx, fy) = (self.food % GW, self.food / GW);
        let px = OX + fx * CELL;
        let py = OY + fy * CELL;
        gfx::draw_rect(buf, px, py, px + CELL - 2, py + CELL - 2);
    }
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut rng = gfx::Rng::new(sys_get_timer().now as u32);
    let mut snake = Snake::new(&mut rng);

    // Player-vs-AI: when set, the human steers with relative turns (BTN0 = left,
    // BTN1 = right) instead of the AI driving. `pdir` is the player's heading.
    let mut player = false;
    let mut pdir = snake.dir;
    let mut prev_steer = 0u32;

    loop {
        let alive = if player {
            snake.advance(pdir, &mut rng)
        } else {
            snake.step(&mut rng)
        };
        if !alive {
            snake = Snake::new(&mut rng);
            pdir = snake.dir;
        }

        let buf: &mut [u8; FB_LEN] = unsafe { &mut *(&raw mut BUF) };
        snake.render(buf);
        if player {
            gfx::draw_text(buf, 104, 1, b"P1");
        }

        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&buf[..])]);

        // Decode player mode + a one-shot turn on each button's rising edge.
        let now_player = rc & 2 != 0;
        let steer = (rc >> 2) & 3;
        if now_player && !player {
            pdir = snake.dir; // keep heading when taking control
        }
        player = now_player;
        if player {
            if steer & 1 != 0 && prev_steer & 1 == 0 {
                pdir = TURN_LEFT[pdir];
            }
            if steer & 2 != 0 && prev_steer & 2 == 0 {
                pdir = TURN_RIGHT[pdir];
            }
        }
        prev_steer = steer;

        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
