/* Linker script for the nRF54L15 FLPR (RISC-V) blink firmware.
 *
 * The firmware is linked to run from the FLPR execution SRAM as it appears in
 * the global address map (0x2002_7c00, 96 KiB). The M33 copies the raw image
 * there and sets VPR.INITPC to ORIGIN(RAM) before releasing the core.
 *
 * NOTE: this assumes the FLPR fetches using global addresses. If the core
 * instead sees its execution memory at a local (0-based) address, change
 * ORIGIN below and INITPC in the launcher to match.
 */

MEMORY
{
  RAM (rwx) : ORIGIN = 0x20027c00, LENGTH = 96K
}

ENTRY(_start)

SECTIONS
{
  .text :
  {
    KEEP(*(.text.init));   /* _start must be first, at ORIGIN(RAM) */
    *(.text .text.*);
    *(.rodata .rodata.*);
    *(.srodata .srodata.*);
  } > RAM

  .data :
  {
    *(.data .data.*);
    *(.sdata .sdata.*);
  } > RAM

  .bss (NOLOAD) :
  {
    *(.bss .bss.*);
    *(.sbss .sbss.*);
    *(COMMON);
  } > RAM

  /* Reserve the top 256 bytes of the region as a fixed-address mailbox shared
   * with the M33 (0x2003_fb00). The stack grows down from just below it. */
  _mailbox = ORIGIN(RAM) + LENGTH(RAM) - 0x100;
  . = ALIGN(16);
  _stack_top = _mailbox;

  /DISCARD/ :
  {
    *(.eh_frame .eh_frame_hdr);
    *(.comment);
  }
}
