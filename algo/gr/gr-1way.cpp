#include "gr.h"

#define CRYPTONIGHT_HASH(variant, way)                                         \
  cryptonight_hash<variant, true>(hash0, hash0);

#define CORE_HASH(hash, input, output, size)                                   \
  sph_##hash##512_init(&ctx.hash);                                             \
  sph_##hash##512(&ctx.hash, input, size);                                     \
  sph_##hash##512_close(&ctx.hash, output);

void gr_hash_1way(void *output0, const void *input0) {
  uint64_t hash0[10] __attribute__((aligned(64)));

  // Copy from input0 to hash0 to make sure that input data for hashing
  // algorighms is properly aligned.
  memcpy(hash0, input0, 80);

  const uint32_t *edata = (const uint32_t *)hash0;
  // Do not get algo hash order each time!
  // Check if time of the block and 2 first words are the same.
  static __thread uint32_t s_ntime = UINT32_MAX;
  static __thread uint32_t prev_b1 = UINT32_MAX;
  static __thread uint32_t prev_b2 = UINT32_MAX;
  if (s_ntime != edata[17] && prev_b1 != edata[1] && prev_b2 != edata[2]) {
    s_ntime = edata[17];
    prev_b1 = edata[1];
    prev_b2 = edata[2];
    gr_getAlgoString((const uint8_t *)(&edata[1]), gr_hash_order);
    gr_rotation = get_config_id(gr_hash_order);
    gr_rotation = (gr_rotation == -1) ? 0 : gr_rotation;
  }

  // Allocate needed memory (only as much as is needed).
  AllocateNeededMemory();
  gr_context_overlay ctx;
  memcpy(&ctx, &gr_ctx, sizeof(ctx));
  size_t size = 80;

  for (int i = 0; i < 15 + 3; i++) {
    const uint8_t algo = gr_hash_order[i];
    switch (algo) {
    case BLAKE:
      CORE_HASH(blake, hash0, hash0, size);
      break;
    case BMW:
      CORE_HASH(bmw, hash0, hash0, size);
      break;
    case GROESTL:
#if defined(__AES__)
      groestl512_full(&ctx.groestl, (void *)hash0, (const void *)hash0,
                      size << 3);
#else
      CORE_HASH(groestl, hash0, hash0, size);
#endif
      break;
    case SKEIN:
      CORE_HASH(skein, hash0, hash0, size);
      break;
    case JH:
      CORE_HASH(jh, hash0, hash0, size);
      break;
    case KECCAK:
      CORE_HASH(keccak, hash0, hash0, size);
      break;
    case LUFFA:
      luffa_full(&ctx.luffa, (BitSequence *)hash0, 512,
                 (const BitSequence *)hash0, size);
      break;
    case CUBEHASH:
      cubehash_full(&ctx.cube, (byte *)hash0, 512, (byte *)hash0, size);
      break;
    case SHAVITE:
      shavite512_full(&ctx.shavite, hash0, hash0, size);
      break;
    case SIMD:
      simd_full(&ctx.simd, (BitSequence *)hash0, (const BitSequence *)hash0,
                size << 3);
      break;
    case ECHO:
#if defined(__AES__)
      echo_full(&ctx.echo, (BitSequence *)hash0, 512,
                (const BitSequence *)hash0, size);
#else
      CORE_HASH(echo, hash0, hash0, size);
#endif
      break;
    case HAMSI:
      CORE_HASH(hamsi, hash0, hash0, size);
      break;
    case FUGUE:
#if defined(__AES__)
      fugue512_full(&ctx.fugue, hash0, hash0, size);
#else
      sph_fugue512_full(&ctx.fugue, hash0, hash0, size);
#endif
      break;
    case SHABAL:
      CORE_HASH(shabal, hash0, hash0, size);
      break;
    case WHIRLPOOL:
      sph_whirlpool512_full(&ctx.whirlpool, hash0, hash0, size);
      break;
    case CNTurtlelite:
      CRYPTONIGHT_HASH(TURTLELITE, 1);
      break;
    case CNTurtle:
      CRYPTONIGHT_HASH(TURTLE, 1);
      break;
    case CNDarklite:
      CRYPTONIGHT_HASH(DARKLITE, 1);
      break;
    case CNDark:
      CRYPTONIGHT_HASH(DARK, 1);
      break;
    case CNLite:
      CRYPTONIGHT_HASH(LITE, 1);
      break;
    case CNFast:
      CRYPTONIGHT_HASH(FAST, 1);
      break;
    }
    size = 64;
  }
  memcpy(output0, hash0, 32);
}
