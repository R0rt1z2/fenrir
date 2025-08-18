#include "debug.h"
#include "device_config.h"

int printf(const char *format, ...) {
    return ((int (*)(const char *, ...))PRINTF_ADDR)(format);
}

int video_printf(const char *format, ...) {
    return ((int (*)(const char *, ...))VIDEO_PRINTF_ADDR)(format);
}