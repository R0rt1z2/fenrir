#include "fastboot.h"
#include "device_config.h"

void fastboot_okay(char *msg) {
    ((void (*)(char *))FASTBOOT_OKAY_ADDR)(msg);
}

void fastboot_fail(char *msg) {
    ((void (*)(char *))FASTBOOT_FAIL_ADDR)(msg);
}

void fastboot_info(char *msg) {
    ((void (*)(char *))FASTBOOT_INFO_ADDR)(msg);
}

void fastboot_register(char *prefix, void *handle, int allowed_when_security_on, int forbidden_when_lock_on) {
    ((void (*)(char *, void *, int, int))FASTBOOT_REGISTER_ADDR)(prefix, handle, allowed_when_security_on, forbidden_when_lock_on);
}

void fastboot_publish(char *name, char *value) {
    ((void (*)(const char *, const char *))FASTBOOT_PUBLISH_ADDR)(name, value);
}