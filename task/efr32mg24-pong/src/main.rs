// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Pong that plays itself: two paddles auto-track the ball, which bounces off
//! the walls and paddles with an angle that depends on where it hits. A
//! "source" task in the display-server architecture -- it renders a frame and
//! sends it to `display` (mode 1).

#![no_std]
#![no_main]

use core::fmt::Write as _;

use efr32mg24_gfx::{self as gfx, FB_LEN};
use userlib::*;

task_slot!(DISPLAY, display);

const ACTIVE_MS: u64 = 50; // ~20 fps when shown
const IDLE_MS: u64 = 150; // keep polling so we reappear quickly on a switch

// Playfield is the panel inside its 1px border.
const MIN: i32 = 1;
const MAX: i32 = 126;
const BALL: i32 = 3;
const PADDLE_HALF: i32 = 11; // half-height
const PADDLE_SPEED: i32 = 3; // max paddle move/frame (< MAX_VY -> steep shots win)
const LX: i32 = 4; // left paddle columns LX..=LX+2
const RX: i32 = 121; // right paddle columns RX..=RX+2
const VX: i32 = 5; // horizontal ball speed (fast enough that the AI can't always react)
const MAX_VY: i32 = 5; // max vertical speed (> PADDLE_SPEED so a steep shot can score)
const AIM_ERR: i32 = 6; // +/- pixels the AI can misjudge the ball's target row

/// xorshift32 PRNG -- enough randomness to keep the rally from settling.
struct Rng(u32);

impl Rng {
    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
}

/// New vertical velocity when the ball hits a paddle: the angle from the contact
/// offset, plus a small random kick (-2..=2), never 0. The kick stops the auto
/// game from settling into a flat horizontal rally and varies the trajectories.
fn bounce_vy(by: i32, paddle_center: i32, rng: &mut Rng) -> i32 {
    let base = (by + BALL / 2 - paddle_center) / 3;
    let kick = (rng.next() % 7) as i32 - 3; // -3..=3
    let vy = (base + kick).clamp(-MAX_VY, MAX_VY);
    if vy != 0 {
        vy
    } else if rng.next() & 1 == 0 {
        1
    } else {
        -1
    }
}

/// A random aim offset (-AIM_ERR..=AIM_ERR) the AI applies to the ball's row,
/// re-rolled per rally so a paddle occasionally misjudges a fast shot.
fn aim_err(rng: &mut Rng) -> i32 {
    (rng.next() % (2 * AIM_ERR as u32 + 1)) as i32 - AIM_ERR
}

#[unsafe(export_name = "main")]
fn main() -> ! {
    let display = DISPLAY.get_task_id();
    let mut fb: gfx::Frame = [0xff; FB_LEN];

    // Seed from the boot time (mixed, forced non-zero for xorshift).
    let mut rng = Rng((sys_get_timer().now as u32).wrapping_mul(2654435761) | 1);

    let (mut bx, mut by) = (63i32, 63i32);
    let (mut vx, mut vy) = (VX, 2i32);
    let (mut ly, mut ry) = (63i32, 63i32);
    let (mut l_err, mut r_err) = (0i32, 0i32); // AI aim offsets, re-rolled per rally
    let (mut l_score, mut r_score) = (0u32, 0u32);
    // Player-vs-AI: when set (both-buttons in the display server), the human
    // drives the LEFT paddle via held buttons; the right paddle stays AI.
    let mut player = false;
    let mut steer = 0u32; // 1 = BTN0 (up), 2 = BTN1 (down)

    loop {
        // --- physics ---
        bx += vx;
        by += vy;

        // Top/bottom walls.
        if by <= MIN {
            by = MIN;
            vy = -vy;
        }
        if by + BALL >= MAX {
            by = MAX - BALL;
            vy = -vy;
        }

        // Paddle hits: reflect, and set the vertical angle from the contact
        // offset (hit high -> ball goes up, low -> down). Keeps rallies lively.
        // A paddle hit reflects the ball, picks a new angle, and re-rolls both
        // AI aim errors so the next rally is judged afresh (and sometimes badly).
        if vx < 0 && bx <= LX + 2 && by + BALL >= ly - PADDLE_HALF && by <= ly + PADDLE_HALF {
            bx = LX + 2;
            vx = -vx;
            vy = bounce_vy(by, ly, &mut rng);
            l_err = aim_err(&mut rng);
            r_err = aim_err(&mut rng);
        }
        if vx > 0 && bx + BALL >= RX && by + BALL >= ry - PADDLE_HALF && by <= ry + PADDLE_HALF {
            bx = RX - BALL;
            vx = -vx;
            vy = bounce_vy(by, ry, &mut rng);
            l_err = aim_err(&mut rng);
            r_err = aim_err(&mut rng);
        }

        // Missed the paddle and reached a side wall: the other player scores.
        // Re-serve from the center with a random direction and angle.
        if bx <= MIN || bx + BALL >= MAX {
            if bx <= MIN {
                r_score = r_score.wrapping_add(1);
            } else {
                l_score = l_score.wrapping_add(1);
            }
            bx = 63;
            by = 63;
            vx = if rng.next() & 1 == 0 { VX } else { -VX };
            vy = (rng.next() % (2 * MAX_VY as u32 + 1)) as i32 - MAX_VY;
            if vy == 0 {
                vy = 1;
            }
        }

        // Left paddle: human-driven in player mode (held buttons), else AI.
        // Right paddle is always the AI, chasing the ball plus its aim error.
        if player {
            if steer & 1 != 0 {
                ly -= PADDLE_SPEED;
            }
            if steer & 2 != 0 {
                ly += PADDLE_SPEED;
            }
        } else {
            ly += ((by + l_err) - ly).clamp(-PADDLE_SPEED, PADDLE_SPEED);
        }
        ry += ((by + r_err) - ry).clamp(-PADDLE_SPEED, PADDLE_SPEED);
        ly = ly.clamp(MIN + PADDLE_HALF, MAX - PADDLE_HALF);
        ry = ry.clamp(MIN + PADDLE_HALF, MAX - PADDLE_HALF);

        // --- render ---
        gfx::clear(&mut fb);
        gfx::draw_rect(&mut fb, 0, 0, 127, 127);

        // Center net (dashed) + scoreboard (left | right).
        let mut ny = MIN;
        while ny < MAX {
            gfx::fill_rect(&mut fb, 63, ny as usize, 64, (ny + 3) as usize);
            ny += 7;
        }
        let mut ln = gfx::Num::new();
        let _ = write!(ln, "{l_score}");
        let mut rn = gfx::Num::new();
        let _ = write!(rn, "{r_score}");
        gfx::draw_text(&mut fb, 44, 3, ln.as_bytes());
        gfx::draw_text(&mut fb, 78, 3, rn.as_bytes());
        if player {
            gfx::draw_text(&mut fb, 2, 3, b"YOU");
            gfx::draw_text(&mut fb, 110, 3, b"AI");
        }

        gfx::fill_rect(
            &mut fb,
            LX as usize,
            (ly - PADDLE_HALF) as usize,
            (LX + 2) as usize,
            (ly + PADDLE_HALF) as usize,
        );
        gfx::fill_rect(
            &mut fb,
            RX as usize,
            (ry - PADDLE_HALF) as usize,
            (RX + 2) as usize,
            (ry + PADDLE_HALF) as usize,
        );
        gfx::fill_rect(
            &mut fb,
            bx as usize,
            by as usize,
            (bx + BALL) as usize,
            (by + BALL) as usize,
        );

        let (rc, _) =
            sys_send(display, gfx::OP_DRAW, &[], &mut [], &[Lease::read_only(&fb[..])]);
        player = rc & 2 != 0;
        steer = (rc >> 2) & 3;
        hl::sleep_for(if rc & 1 != 0 { ACTIVE_MS } else { IDLE_MS });
    }
}
