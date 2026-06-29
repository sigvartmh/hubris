# demo-nrf54l15-dk

A minimal Hubris bring-up image for the Nordic **nRF54L15-DK** (PCA10156),
application core (Cortex-M33, ARMv8-M).

## What it does

| Task        | Purpose                                                        |
|-------------|---------------------------------------------------------------|
| `jefe`      | Standard supervisor.                                          |
| `user_leds` | Blinks **LED0** (P2.09) at ~1 Hz, via the `nrf54l15` backend. |
| `uart`      | `drv-nrf54l15-uart`: prints a banner + 1 Hz heartbeat on UARTE20 (P1.04 TX, 115200 8N1). |
| `idle`      | Idles the core (WFI).                                          |

This runs from the **secure** address map; peripheral registers come from the
`nrf-pac` crate (`nrf54l15-app` feature, secure `_S` constants). The memory map
(`../../chips/nrf54l15`) is RRAM @ `0x0` (1524 KiB) and SRAM @ `0x2000_0000`
(256 KiB), taken from the Zephyr devicetree.

## Build & flash

```sh
cargo xtask dist app/demo-nrf54l15-dk/app.toml
# flash with a probe-rs / humility new enough to know nRF54L15
```

## Notes / things to verify on hardware

- **`CYCLES_PER_MS`** in `src/main.rs` assumes the reset-default core clock; if
  the boot frequency differs, kernel time (and the LED/heartbeat rate) scales
  proportionally. Adjust the constant once measured.
- The UART driver is TX-only (polled EasyDMA) and prints directly; it does not
  yet expose an IPC `write` server for other tasks.
