// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Builds the nRF54L15 FLPR (RISC-V) firmware.
//!
//! The FLPR core is a RISC-V (rv32emc) coprocessor, so its firmware is a
//! separate, standalone crate (`flpr/blink`) that is *not* part of the ARM
//! workspace. It is built with a nightly toolchain + `-Zbuild-std` (the target
//! is tier-3, configured in `flpr/blink/.cargo/config.toml`), then converted to
//! a raw binary that the `flpr-control` Hubris task embeds via `include_bytes!`.
//!
//! Run `cargo xtask flpr` before `cargo xtask dist` for any app that includes
//! the `flpr-control` task.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Path to the FLPR firmware crate, relative to this xtask crate.
const FLPR_CRATE: &str = "../../flpr";
const FLPR_TARGET_DIR: &str = "target/riscv32emc-unknown-none-elf/release";
/// One binary per demo program (src/bin/<name>.rs). Order = program id.
const FLPR_PROGRAMS: &[&str] =
    &["blink", "breathe", "compute", "benchmark", "console"];

pub fn run(verbose: bool) -> Result<()> {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(FLPR_CRATE)
        .canonicalize()
        .context("FLPR firmware crate not found")?;

    // Build the firmware. The target, -Zbuild-std and linker script all come
    // from flpr/.cargo/config.toml, so we just need the nightly channel.
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&crate_dir)
        .args(["+nightly", "build", "--release"]);
    if verbose {
        cmd.arg("--verbose");
    }
    println!("Building FLPR (RISC-V) programs in {}", crate_dir.display());
    let status = cmd.status().context(
        "failed to run `cargo +nightly` — is the nightly toolchain installed \
         with the rust-src component? (rustup toolchain install nightly; \
         rustup component add rust-src --toolchain nightly)",
    )?;
    if !status.success() {
        bail!("FLPR firmware build failed");
    }

    // Convert each program's ELF to a raw binary the launcher can copy into
    // FLPR SRAM (flpr/<name>.bin).
    let objcopy = llvm_objcopy()?;
    for prog in FLPR_PROGRAMS {
        let elf = crate_dir.join(FLPR_TARGET_DIR).join(prog);
        let bin = crate_dir.join(format!("{prog}.bin"));
        let status = Command::new(&objcopy)
            .args(["-O", "binary"])
            .arg(&elf)
            .arg(&bin)
            .status()
            .with_context(|| format!("failed to run {}", objcopy.display()))?;
        if !status.success() {
            bail!("llvm-objcopy of FLPR program '{prog}' failed");
        }
        let size = std::fs::metadata(&bin)?.len();
        println!("  {prog}: {} ({size} bytes)", bin.display());
    }
    Ok(())
}

/// Locate `llvm-objcopy` from the toolchain's `llvm-tools` component. Tries the
/// active toolchain first, then falls back to any installed toolchain that has
/// it (it's commonly present on stable/nightly but not on a pinned channel).
fn llvm_objcopy() -> Result<PathBuf> {
    let sysroot = PathBuf::from(run_rustc(&["--print", "sysroot"])?.trim());
    let host = run_rustc(&["-vV"])?
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(|h| h.trim().to_string())
        .context("could not determine host triple from `rustc -vV`")?;

    let active = sysroot
        .join("lib/rustlib")
        .join(&host)
        .join("bin/llvm-objcopy");
    if active.exists() {
        return Ok(active);
    }

    // Fall back: scan all installed toolchains for an llvm-objcopy.
    if let Some(rustup_home) = rustup_home() {
        let toolchains = rustup_home.join("toolchains");
        if let Ok(entries) = std::fs::read_dir(&toolchains) {
            for entry in entries.flatten() {
                let cand = entry
                    .path()
                    .join("lib/rustlib")
                    .join(&host)
                    .join("bin/llvm-objcopy");
                if cand.exists() {
                    return Ok(cand);
                }
            }
        }
    }

    bail!(
        "llvm-objcopy not found (checked {}). Install it with:\n    \
         rustup component add llvm-tools",
        active.display()
    )
}

fn rustup_home() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("RUSTUP_HOME") {
        return Some(PathBuf::from(h));
    }
    std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".rustup"))
}

fn run_rustc(args: &[&str]) -> Result<String> {
    let out = Command::new("rustc")
        .args(args)
        .output()
        .context("failed to run rustc")?;
    if !out.status.success() {
        bail!("rustc {:?} failed", args);
    }
    Ok(String::from_utf8(out.stdout)?)
}
