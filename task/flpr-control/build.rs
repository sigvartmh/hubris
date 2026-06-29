// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Stages the prebuilt FLPR (RISC-V) firmware for `include_bytes!` and
//! generates this task's notification masks.

use std::env;
use std::fs;
use std::path::PathBuf;

/// FLPR programs, in program-id order (must match `cargo xtask flpr`).
const PROGRAMS: &[&str] =
    &["blink", "breathe", "compute", "benchmark", "console"];

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    for prog in PROGRAMS {
        // repo root is two levels up from task/flpr-control.
        let bin = manifest.join(format!("../../flpr/{prog}.bin"));
        if !bin.exists() {
            panic!(
                "FLPR program image not found at {}.\n\
                 Build it first with: cargo xtask flpr",
                bin.display()
            );
        }
        fs::copy(&bin, out_dir.join(format!("{prog}.bin"))).unwrap();
        println!("cargo:rerun-if-changed={}", bin.display());
    }

    build_util::build_notifications()?;
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
