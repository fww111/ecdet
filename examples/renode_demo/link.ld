ENTRY(Reset_Handler)
MEMORY {
    FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 2M
    RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 256K
}
SECTIONS {
    .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
    .text : { *(.text*) *(.rodata*) } > FLASH
    .ARM.exidx : { *(.ARM.exidx*) } > FLASH
    .data : { *(.data*) } > RAM AT > FLASH
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
}
