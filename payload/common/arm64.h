#pragma once

#include <stdint.h>
#include <stddef.h>

#define ISB __asm__ volatile("isb" ::: "memory")
#define DSB __asm__ volatile("dsb sy" ::: "memory")
#define DSB_ISH __asm__ volatile("dsb ish" ::: "memory")
#define DSB_ISHST __asm__ volatile("dsb ishst" ::: "memory")

#define ARM64_TLBI(op, val) \
({ \
	__asm__ volatile("tlbi " #op ", %0" :: "r" (val)); \
	ISB; \
})

#define ARM64_TLBI_NOADDR(op) \
({ \
	__asm__ volatile("tlbi " #op::); \
	ISB; \
})

#define ARM64_DC(op, val) \
({ \
	__asm__ volatile("dc " #op ", %0" :: "r" (val) : "memory"); \
})

#define ARM64_IC(op, val) \
({ \
	__asm__ volatile("ic " #op ", %0" :: "r" (val) : "memory"); \
})

#define ARM64_IC_NOADDR(op) \
({ \
	__asm__ volatile("ic " #op ::: "memory"); \
})

static inline uint32_t arm64_get_current_el(void) {
    uint64_t el;
    __asm__ volatile("mrs %0, CurrentEL" : "=r" (el));
    return (uint32_t)((el >> 2) & 0x3);
}

static inline void arm64_sync_caches_range(uint64_t vaddr, size_t size) {
    uint64_t start = vaddr & ~0x3fUL;
    uint64_t end = vaddr + size;
    for (uint64_t p = start; p < end; p += 64) {
        ARM64_DC(cvau, p);
    }
    DSB_ISH;
    for (uint64_t p = start; p < end; p += 64) {
        ARM64_IC(ivau, p);
    }
    DSB_ISH;
    ISB;
}