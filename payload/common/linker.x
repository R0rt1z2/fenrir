OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(main)

SECTIONS
{
  . = BASE_ADDRESS;
  
  .text : {
    *(.text.main)
    *(.text*)
  }
  
  .rodata : {
    *(.rodata*)
  }
  
  .data : {
    *(.data*)
  }
  
  .bss : {
    *(.bss*)
    . = ALIGN(8);
  }
  
  /DISCARD/ : { 
    *(.comment*) *(.note*) *(.eh_frame*) *(.ARM*) *(.plt*) *(.got*)
  }
}