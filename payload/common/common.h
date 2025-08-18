#pragma once

#include "types.h"
#include "arm64.h"

#define PAGE_SIZE 0x1000

#define MB (1024UL*1024UL)
#define BM(base, count, val) (((val) & ((1UL << (count)) - 1)) << (base))

#define BOOT_STATE_GREEN   (0)
#define BOOT_STATE_YELLOW  (1)
#define BOOT_STATE_ORANGE  (2)
#define BOOT_STATE_RED     (3)

#define TIMER_FREQ_MHZ 13

#define WRITE32NC(addr, val) do { \
   __asm__ volatile("str %w0, [%1]" : : "r"(val), "r"(addr) : "memory"); \
} while(0)

#define READ32NC(addr) ({ \
   uint32_t val; \
   __asm__ volatile("ldr %w0, [%1]" : "=r"(val) : "r"(addr) : "memory"); \
   val; \
})

#define WRITE32(addr, val) do { \
   *(volatile uint32_t*)(addr) = (val); \
   __asm__ volatile("dc cvac, %0; dsb sy" : : "r"(addr) : "memory"); \
} while(0)

#define READ32(addr) ({ \
   __asm__ volatile("dc civac, %0; dsb sy" : : "r"(addr) : "memory"); \
   *(volatile uint32_t*)(addr); \
})

#define PATCH32(addr, val) do { \
   *(volatile uint32_t*)(addr) = (val); \
   __asm__ volatile( \
       "dc cvac, %0; dsb sy; ic ivau, %0; dsb sy; isb" \
       : : "r"(addr) : "memory" \
   ); \
} while(0)

void platform_init(void);
void notify_enter_fastboot(void);
void notify_boot_linux(void);
void udelay(uint32_t us);