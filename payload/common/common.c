#include "common.h"
#include "device_config.h"

void platform_init(void) {
    ((void (*)(void))PLATFORM_INIT_ADDR)();
}

void notify_enter_fastboot(void) {
    ((void (*)(void))NOTIFY_ENTER_FASTBOOT_ADDR)();
}

void notify_boot_linux(void) {
    ((void (*)(void))NOTIFY_BOOT_LINUX_ADDR)();
}

void udelay(uint32_t us) {
    uint64_t start, now;
    asm volatile("mrs %0, cntpct_el0" : "=r" (start));
    do {
        asm volatile("mrs %0, cntpct_el0" : "=r" (now));
    } while ((now - start) < (TIMER_FREQ_MHZ * us));
}