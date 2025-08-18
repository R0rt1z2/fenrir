#include "string.h"

char* strcpy(char* dest, const char* src) {
    char* original_dest = dest;
    while ((*dest++ = *src++));
    return original_dest;
}

size_t strlen(const char* str) {
    const char* s;

    for (s = str; *s; ++s)
        ;
    return (s - str);
}