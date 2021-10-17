#if !defined(KECCAK_8WAY) && !defined(KECCAK_4WAY)

#include "sph_keccak.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void sha3d_hash(void *state, const void *input) {
  uint32_t buffer[16];
  sph_keccak256_context ctx_keccak;

  sph_keccak256_init(&ctx_keccak);
  sph_keccak256(&ctx_keccak, input, 80);
  sph_keccak256_close(&ctx_keccak, buffer);
  sph_keccak256_init(&ctx_keccak);
  sph_keccak256(&ctx_keccak, buffer, 32);
  sph_keccak256_close(&ctx_keccak, state);
}

#endif
