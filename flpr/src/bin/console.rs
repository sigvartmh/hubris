// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Program 4: an interactive shell run by the FLPR on UART30 (P0.00 TX /
//! P0.01 RX, the DK's second VCOM port). It line-edits input (echo + backspace,
//! up to 64 bytes) and on Enter ships the command to the M33, which executes it
//! and replies; the reply is printed back on this console. Type `help`.

#![no_std]
#![no_main]

use flpr::*;

#[no_mangle]
extern "C" fn rust_main() -> ! {
    led_init();
    mailbox_init();
    uart_init();

    uart_puts(b"\r\nFLPR shell on UART30. Type 'help'.\r\nFLPR> ");

    let mut buf = [0u8; LINE_MAX];
    let mut len = 0usize;
    let mut last_was_cr = false;

    loop {
        let c = uart_getc();

        // Swallow the LF that some terminals send right after CR.
        if c == b'\n' && last_was_cr {
            last_was_cr = false;
            continue;
        }
        last_was_cr = c == b'\r';

        match c {
            b'\r' | b'\n' => {
                uart_puts(b"\r\n");
                if len > 0 {
                    // `help` is a static list -> print it locally (no M33
                    // round-trip, and not bound by the 140-byte reply limit).
                    if &buf[..len] == b"help" {
                        print_help();
                    } else {
                        send_command(&buf[..len]); // run on the M33, print reply
                    }
                    blip();
                    len = 0;
                }
                uart_puts(b"FLPR> ");
            }
            0x08 | 0x7f => {
                if len > 0 {
                    len -= 1;
                    uart_puts(b"\x08 \x08");
                }
            }
            0x20..=0x7e => {
                // printable
                if len < LINE_MAX {
                    buf[len] = c;
                    len += 1;
                    uart_putc(c); // echo
                }
            }
            _ => {} // ignore other control bytes
        }
    }
}

/// Print the command list locally on this console.
fn print_help() {
    uart_puts(
        b"commands:\r\n\
          \x20 help                this list\r\n\
          \x20 led <n> on/off/tog  drive LED n (0-3)\r\n\
          \x20 blink <n>           blink LED n\r\n\
          \x20 print on/off        M33 periodic print task\r\n\
          \x20 breathe <n>         breathe LED3 (smaller n = faster)\r\n\
          \x20 run <prog>          run an FLPR program\r\n\
          \x20 stop                stop the running program\r\n\
          \x20 time                kernel uptime\r\n\
          \x20 echo <text>         echo text back\r\n\
          \x20 bench [alg]         crypto bench on M33 (alg: aes aes256\r\n\
          \x20                     ctr cbc ccm sha sha512 sha384 hmac cmac\r\n\
          \x20                     gcm chacha ecdh ed25519 p256; def all)\r\n\
          \x20 rng [n]             CRACEN TRNG random bytes (n<=32)\r\n\
          progs: blink breathe compute benchmark console\r\n\
          (BTN1 returns to this shell)\r\n",
    );
}

/// Brief LED3 pulse to show a command was shipped.
fn blip() {
    led_on();
    delay(120_000);
    led_off();
}
