// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::path::PathBuf;

fn main() {
    build_util::expose_target_board();

    // Hubris's `kernel-link.x` ends with `INCLUDE device.x`. That file is
    // normally supplied by a device PAC (with PROVIDE() aliases for each named
    // IRQ handler). This image uses no PAC -- cortex-m-rt's default
    // `__INTERRUPTS` already binds every vector to the kernel's
    // `DefaultHandler` -- so an empty `device.x` is all the linker needs.
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out.join("device.x"), "").unwrap();
    println!("cargo:rustc-link-search={}", out.display());
}
