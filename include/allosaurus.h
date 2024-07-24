#ifndef __allosaurus__included__
#define __allosaurus__included__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct ByteBuffer {
    int64_t len;
    uint8_t *data;
} ByteBuffer;

typedef struct ByteArray {
    uintptr_t length;
    const uint8_t *data;
} ByteArray;

typedef struct ExternError {
    int32_t code;
    char* message;
} ExternError;

void* allosaurus_new_server();


#endif