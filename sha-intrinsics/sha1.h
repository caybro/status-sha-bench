#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define LENGTH_SIZE 8  // In bytes
#define BLOCK_LEN 64  // In bytes
#define STATE_LEN 5  // In words

void intrinsics_sha1_process(uint32_t state[STATE_LEN], const uint8_t data[], uint32_t length);

#ifdef  __cplusplus
}
#endif
