#pragma once

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

#define ARM64_IC(op, val) \
({ \
	__asm__ volatile("ic " #op ", %0" :: "r" (val) : "memory"); \
})

#define ARM64_IC_NOADDR(op) \
({ \
	__asm__ volatile("ic " #op ::: "memory"); \
})

#define ISB __asm__ volatile("isb" ::: "memory")
#define DSB __asm__ volatile("dsb sy" ::: "memory")