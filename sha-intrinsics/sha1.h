#pragma once

#if defined(__GNUC__)
# include <stdint.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

void sha1_process_x86(uint32_t state[5], const uint8_t data[], uint32_t length);

#ifdef  __cplusplus
}
#endif
