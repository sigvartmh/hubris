# demo-efr32mg24

A minimal Hubris bring-up image for the Silicon Labs **EFR32MG24**
(EFR32MG24B220F1536IM48, Cortex-M33 / ARMv8-M), targeting the **xG24-RB4187C**
radio board on a WSTK mainboard.

## What it does

| Task    | Purpose                                                                          |
|---------|----------------------------------------------------------------------------------|
| `jefe`  | Standard supervisor.                                                              |
| `hello` | Blinks **LED0 (PB02)**, records a `ringbuf`, and logs to SWO via the `Log` kipc. |
| `idle`  | Spins the core (insomniac, to keep SysTick alive).                               |

`main()` runs privileged before the kernel starts: it points `VTOR` at main
flash, sets up SWO/ITM trace on **PA3**, and logs a boot banner. Hubris has no
built-in SWO console, so this image provides the whole path itself.

The `hello` task proves the kernel is scheduling in three ways: a blinking LED
(GPIO, MPU-granted via `uses`), a `ringbuf` (read with `humility ringbuf`), and
**live SWO text**. That last one is notable: an unprivileged task can't reach
the ITM stimulus port directly on this core (writes are silently dropped even
with `ITM_TPR` set), so the task hands its log bytes to the kernel via a small
`Log` kipc and the kernel -- privileged -- does the ITM write. See
`sys/kern/src/kipc.rs` (`log`), `sys/kern/src/arch/arm_m.rs` (`log_bytes`), and
`userlib::kipc::log`.

The memory map (`../../chips/efr32mg24`) is main flash @ `0x0800_0000`
(1536 KiB) and SRAM @ `0x2000_0000` (256 KiB). Peripheral/trace register
addresses come from the device headers under `ref/simplicity_sdk`.

## Build, flash & read SWO (Simplicity Commander)

```sh
cargo xtask dist app/demo-efr32mg24/app.toml

# flash the image (ELF carries its own load addresses)
commander-cli flash target/demo-efr32mg24/dist/default/final.elf \
  --device EFR32MG24B220F1536IM48

# read the SWO log (resets the device first). The SWO speed MUST match the
# firmware's SWO_BAUD; commander does NOT configure the target's SWO, it only
# captures it. Default is 875000, which will NOT decode our 1.000 MHz stream.
commander-cli swo read --swospeed 1000000 --timeout 5
```

Expected output -- the boot banner, then the task heartbeat attributed by the
kernel as `kernel<-t<task-index>`:

```
[efr32mg24] hubris kernel booting
kernel<-t1: heartbeat #0
kernel<-t1: heartbeat #1
...
```

The `kernel<-t1:` lines come from the unprivileged `hello` task (index 1) via the
`Log` kipc. You can also read the task's ring buffer over SWD:

```sh
cargo xtask humility app/demo-efr32mg24/app.toml -- ringbuf
cargo xtask humility app/demo-efr32mg24/app.toml -- tasks
```

`humility` (over the same J-Link, via the `[probe-rs]` board config) is still
useful for state -- e.g. `cargo xtask humility app/demo-efr32mg24/app.toml -- tasks`.

## Notes / things to verify on hardware

- **`CYCLES_PER_MS`** (`src/main.rs`) and **`swo::TRACE_CLK_HZ`** are both 19 MHz:
  the Secure Element leaves SYSCLK on HFRCODPLL at its 19 MHz startup frequency
  (confirmed via `CMU_SYSCLKCTRL.CLKSEL == HFRCODPLL`), not the raw-reset FSRCO
  20 MHz. If a later stage raises the core clock, update both, or kernel time and
  the SWO baud scale proportionally.
- **SWO baud** (`swo::SWO_BAUD`, 1.000 MHz) is set entirely by the firmware --
  Simplicity Commander only captures, so pass the matching `--swospeed 1000000`.
  If you change `SWO_BAUD`, keep it an exact divisor of `TRACE_CLK_HZ` (the
  TPIU prescaler is integer) and update the `--swospeed` you pass.
- **LED0 = PB02** on the BRD4187x radio board (same pin on a BRD4001A or BRD4002A
  WSTK, per the Silicon Labs `sl_simple_led_led0` board config). On a different
  mainboard, adjust the port/pin in `task/efr32mg24-hello/src/main.rs`.
- **Per-task SWO** goes through the kernel (`Log` kipc) because unprivileged ITM
  stimulus writes are silently dropped on this core under Hubris's MPU even with
  `ITM_TPR = 1` (verified: `TPR` reads back `0x1`, task runs at GEN 0 without
  faulting). The kipc touches shared code (`sys/abi`, `sys/kern`, `sys/userlib`);
  it's additive and a no-op on images that haven't brought up trace.
