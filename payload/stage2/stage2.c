#include "fastboot.h"
#include "debug.h"

void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
    video_printf("r0rt1z2 was here...\n");
    fastboot_info("pwned by r0rt1z2");
    fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
    // This payload executes right before LK notifies the system to enter
    // fastboot mode. This is the perfect spot to register custom fastboot
    // commands that will be available during the fastboot session.
    printf("Entered pre-notify_enter_fastboot() stage2 payload!\n");
    fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
    notify_enter_fastboot();
}