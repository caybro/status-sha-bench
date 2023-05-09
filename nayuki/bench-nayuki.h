#pragma once

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef  __cplusplus
extern "C" {
#endif

// Link this program with an external C or x86 compression function
#define BLOCK_LEN 64  // In bytes
#define STATE_LEN 5  // In words
extern void sha1_compress(uint32_t state[STATE_LEN], const uint8_t block[BLOCK_LEN]);

void sha1_hash(const uint8_t message[], size_t len, uint32_t hash[STATE_LEN]);

#ifdef  __cplusplus
}
#endif
