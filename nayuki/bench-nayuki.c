#include "bench-nayuki.h"

/* Full message hasher */
void sha1_hash(const uint8_t message[], size_t len, uint32_t hash[static STATE_LEN]) {
	hash[0] = UINT32_C(0x67452301);
	hash[1] = UINT32_C(0xEFCDAB89);
	hash[2] = UINT32_C(0x98BADCFE);
	hash[3] = UINT32_C(0x10325476);
	hash[4] = UINT32_C(0xC3D2E1F0);
	
	#define LENGTH_SIZE 8  // In bytes
	
	size_t off;
	for (off = 0; len - off >= BLOCK_LEN; off += BLOCK_LEN)
		sha1_compress(hash, &message[off]);
	
	uint8_t block[BLOCK_LEN] = {0};
	size_t rem = len - off;
	memcpy(block, &message[off], rem);
	
	block[rem] = 0x80;
	rem++;
	if (BLOCK_LEN - rem < LENGTH_SIZE) {
		sha1_compress(hash, block);
		memset(block, 0, sizeof(block));
	}
	
	block[BLOCK_LEN - 1] = (uint8_t)((len & 0x1FU) << 3);
	len >>= 5;
	for (int i = 1; i < LENGTH_SIZE; i++, len >>= 8)
		block[BLOCK_LEN - 1 - i] = (uint8_t)(len & 0xFFU);
	sha1_compress(hash, block);
}
