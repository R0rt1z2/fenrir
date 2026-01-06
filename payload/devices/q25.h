#pragma once

#define DEVICE_NAME "Q25"

#define STAGE1_BASE 0xffff000050f23670
#define STAGE2_BASE 0xffff000050f1f690
#define STAGE3_BASE 0xffff000050f209e0

#define PLATFORM_INIT_ADDR           0xffff000050f024d0
#define NOTIFY_ENTER_FASTBOOT_ADDR   0xffff000050f056f0
#define NOTIFY_BOOT_LINUX_ADDR       0xffff000050f0c734

#define PRINTF_ADDR                  0xffff000050f57fe0
#define VIDEO_PRINTF_ADDR            0xffff000050f33854

#define FASTBOOT_OKAY_ADDR           0xffff000050f05008
#define FASTBOOT_FAIL_ADDR           0xffff000050f04fd0
#define FASTBOOT_INFO_ADDR           0xffff000050f04f30
#define FASTBOOT_REGISTER_ADDR       0xffff000050f04c5c
#define FASTBOOT_PUBLISH_ADDR        0xffff000050f04d20

#define PADDR_TO_KVADDR_ADDR         0xffff000050f54e34
#define KERNEL_ASPACE_ADDR           0xffff000050fea6b8
