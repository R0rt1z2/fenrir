#include "common.h"
#include "debug.h"

__attribute__((section(".text.main"))) int main(void) {
    // This payload executes before LK calls platform_init(), which handles
    // the initialization of platform-specific hardware components. This is
    // one of the earliest points where we can execute custom code during
    // the boot process.
    printf("Entered pre-platform_init() stage1 payload!\n");
    platform_init();

    // The caller expects this function to return an integer value.
    return 0;
}