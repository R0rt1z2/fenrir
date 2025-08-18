#pragma once

#include "common.h"

void fastboot_okay(char *msg);
void fastboot_fail(char *msg);
void fastboot_info(char *msg);
void fastboot_register(char *prefix, void *handle, int allowed_when_security_on, int
    forbidden_when_lock_on);
void fastboot_publish(char *name, char *value);