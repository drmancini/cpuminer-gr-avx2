#include "gr.h"

#define CRYPTONIGHT_HASH(variant, way)                                         \
  if (gr_tune_4way[gr_rotation][6]) {                                          \
    if (way == CN_4WAY) {                                                      \
      cryptonight_4way_hash<variant, true>(hash0, hash1, hash2, hash3, hash0,  \
                                           hash1, hash2, hash3);               \
    } else if (way == CN_3WAY) {                                               \
      cryptonight_3way_hash<variant, true>(hash0, hash1, hash2, hash0, hash1,  \
                                           hash2);                             \
      cryptonight_hash<variant, true>(hash3, hash3);                           \
    } else if (way == CN_2WAY) {                                               \
      cryptonight_2way_hash<variant, true>(hash0, hash1, hash0, hash1);        \
      cryptonight_2way_hash<variant, true>(hash2, hash3, hash2, hash3);        \
    } else {                                                                   \
      cryptonight_hash<variant, true>(hash0, hash0);                           \
      cryptonight_hash<variant, true>(hash1, hash1);                           \
      cryptonight_hash<variant, true>(hash2, hash2);                           \
      cryptonight_hash<variant, true>(hash3, hash3);                           \
    }                                                                          \
  } else {                                                                     \
    if (way == CN_4WAY) {                                                      \
      cryptonight_4way_hash<variant, false>(hash0, hash1, hash2, hash3, hash0, \
                                            hash1, hash2, hash3);              \
    } else if (way == CN_3WAY) {                                               \
      cryptonight_3way_hash<variant, false>(hash0, hash1, hash2, hash0, hash1, \
                                            hash2);                            \
      cryptonight_hash<variant, false>(hash3, hash3);                          \
    } else if (way == CN_2WAY) {                                               \
      cryptonight_2way_hash<variant, false>(hash0, hash1, hash0, hash1);       \
      cryptonight_2way_hash<variant, false>(hash2, hash3, hash2, hash3);       \
    } else {                                                                   \
      cryptonight_hash<variant, false>(hash0, hash0);                          \
      cryptonight_hash<variant, false>(hash1, hash1);                          \
      cryptonight_hash<variant, false>(hash2, hash2);                          \
      cryptonight_hash<variant, false>(hash3, hash3);                          \
    }                                                                          \
  }

#define CORE_HASH(hash, input, output, size)                                   \
  sph_##hash##512_init(&ctx.hash);                                             \
  sph_##hash##512(&ctx.hash, input, size);                                     \
  sph_##hash##512_close(&ctx.hash, output);

void gr_hash_4way(void *output0, void *output1, void *output2, void *output3,
                  const void *input0, const void *input1, const void *input2,
                  const void *input3) {
  uint64_t hash0[10] __attribute__((aligned(64)));
  uint64_t hash1[10] __attribute__((aligned(64)));
  uint64_t hash2[10] __attribute__((aligned(64)));
  uint64_t hash3[10] __attribute__((aligned(64)));

  // Copy from input0 to hash0 to make sure that input data for hashing
  // algorighms is properly aligned.
  memcpy(hash0, input0, 80);
  memcpy(hash1, input1, 80);
  memcpy(hash2, input2, 80);
  memcpy(hash3, input3, 80);

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
      CORE_HASH(blake, hash1, hash1, size);
      CORE_HASH(blake, hash2, hash2, size);
      CORE_HASH(blake, hash3, hash3, size);
      break;
    case BMW:
      CORE_HASH(bmw, hash0, hash0, size);
      CORE_HASH(bmw, hash1, hash1, size);
      CORE_HASH(bmw, hash2, hash2, size);
      CORE_HASH(bmw, hash3, hash3, size);
      break;
    case GROESTL:
#if defined(__AES__)
      groestl512_full(&ctx.groestl, (void *)hash0, (const void *)hash0,
                      size << 3);
      groestl512_full(&ctx.groestl, (void *)hash1, (const void *)hash1,
                      size << 3);
      groestl512_full(&ctx.groestl, (void *)hash2, (const void *)hash2,
                      size << 3);
      groestl512_full(&ctx.groestl, (void *)hash3, (const void *)hash3,
                      size << 3);
#else
      CORE_HASH(groestl, hash0, hash0, size);
      CORE_HASH(groestl, hash1, hash1, size);
      CORE_HASH(groestl, hash2, hash2, size);
      CORE_HASH(groestl, hash3, hash3, size);
#endif
      break;
    case SKEIN:
      CORE_HASH(skein, hash0, hash0, size);
      CORE_HASH(skein, hash1, hash1, size);
      CORE_HASH(skein, hash2, hash2, size);
      CORE_HASH(skein, hash3, hash3, size);
      break;
    case JH:
      CORE_HASH(jh, hash0, hash0, size);
      CORE_HASH(jh, hash1, hash1, size);
      CORE_HASH(jh, hash2, hash2, size);
      CORE_HASH(jh, hash3, hash3, size);
      break;
    case KECCAK:
      CORE_HASH(keccak, hash0, hash0, size);
      CORE_HASH(keccak, hash1, hash1, size);
      CORE_HASH(keccak, hash2, hash2, size);
      CORE_HASH(keccak, hash3, hash3, size);
      break;
    case LUFFA:
      luffa_full(&ctx.luffa, (BitSequence *)hash0, 512,
                 (const BitSequence *)hash0, size);
      luffa_full(&ctx.luffa, (BitSequence *)hash1, 512,
                 (const BitSequence *)hash1, size);
      luffa_full(&ctx.luffa, (BitSequence *)hash2, 512,
                 (const BitSequence *)hash2, size);
      luffa_full(&ctx.luffa, (BitSequence *)hash3, 512,
                 (const BitSequence *)hash3, size);
      break;
    case CUBEHASH:
      cubehash_full(&ctx.cube, (byte *)hash0, 512, (byte *)hash0, size);
      cubehash_full(&ctx.cube, (byte *)hash1, 512, (byte *)hash1, size);
      cubehash_full(&ctx.cube, (byte *)hash2, 512, (byte *)hash2, size);
      cubehash_full(&ctx.cube, (byte *)hash3, 512, (byte *)hash3, size);
      break;
    case SHAVITE:
      shavite512_full(&ctx.shavite, hash0, hash0, size);
      shavite512_full(&ctx.shavite, hash1, hash1, size);
      shavite512_full(&ctx.shavite, hash2, hash2, size);
      shavite512_full(&ctx.shavite, hash3, hash3, size);
      break;
    case SIMD:
      simd_full(&ctx.simd, (BitSequence *)hash0, (const BitSequence *)hash0,
                size << 3);
      simd_full(&ctx.simd, (BitSequence *)hash1, (const BitSequence *)hash1,
                size << 3);
      simd_full(&ctx.simd, (BitSequence *)hash2, (const BitSequence *)hash2,
                size << 3);
      simd_full(&ctx.simd, (BitSequence *)hash3, (const BitSequence *)hash3,
                size << 3);
      break;
    case ECHO:
#if defined(__AES__)
      echo_full(&ctx.echo, (BitSequence *)hash0, 512,
                (const BitSequence *)hash0, size);
      echo_full(&ctx.echo, (BitSequence *)hash1, 512,
                (const BitSequence *)hash1, size);
      echo_full(&ctx.echo, (BitSequence *)hash2, 512,
                (const BitSequence *)hash2, size);
      echo_full(&ctx.echo, (BitSequence *)hash3, 512,
                (const BitSequence *)hash3, size);
#else
      CORE_HASH(echo, hash0, hash0, size);
      CORE_HASH(echo, hash1, hash1, size);
      CORE_HASH(echo, hash2, hash2, size);
      CORE_HASH(echo, hash3, hash3, size);
#endif
      break;
    case HAMSI:
      CORE_HASH(hamsi, hash0, hash0, size);
      CORE_HASH(hamsi, hash1, hash1, size);
      CORE_HASH(hamsi, hash2, hash2, size);
      CORE_HASH(hamsi, hash3, hash3, size);
      break;
    case FUGUE:
#if defined(__AES__)
      fugue512_full(&ctx.fugue, hash0, hash0, size);
      fugue512_full(&ctx.fugue, hash1, hash1, size);
      fugue512_full(&ctx.fugue, hash2, hash2, size);
      fugue512_full(&ctx.fugue, hash3, hash3, size);
#else
      sph_fugue512_full(&ctx.fugue, hash0, hash0, size);
      sph_fugue512_full(&ctx.fugue, hash1, hash1, size);
      sph_fugue512_full(&ctx.fugue, hash2, hash2, size);
      sph_fugue512_full(&ctx.fugue, hash3, hash3, size);
#endif
      break;
    case SHABAL:
      CORE_HASH(shabal, hash0, hash0, size);
      CORE_HASH(shabal, hash1, hash1, size);
      CORE_HASH(shabal, hash2, hash2, size);
      CORE_HASH(shabal, hash3, hash3, size);
      break;
    case WHIRLPOOL:
      sph_whirlpool512_full(&ctx.whirlpool, hash0, hash0, size);
      sph_whirlpool512_full(&ctx.whirlpool, hash1, hash1, size);
      sph_whirlpool512_full(&ctx.whirlpool, hash2, hash2, size);
      sph_whirlpool512_full(&ctx.whirlpool, hash3, hash3, size);
      break;
    case CNTurtlelite:
      CRYPTONIGHT_HASH(TURTLELITE, gr_tune_4way[gr_rotation][Turtlelite]);
      break;
    case CNTurtle:
      CRYPTONIGHT_HASH(TURTLE, gr_tune_4way[gr_rotation][Turtle]);
      break;
    case CNDarklite:
      CRYPTONIGHT_HASH(DARKLITE, gr_tune_4way[gr_rotation][Darklite]);
      break;
    case CNDark:
      CRYPTONIGHT_HASH(DARK, gr_tune_4way[gr_rotation][Dark]);
      break;
    case CNLite:
      CRYPTONIGHT_HASH(LITE, gr_tune_4way[gr_rotation][Lite]);
      break;
    case CNFast:
      CRYPTONIGHT_HASH(FAST, gr_tune_4way[gr_rotation][Fast]);
      break;
    }
    size = 64;
  }
  memcpy(output0, hash0, 32);
  memcpy(output1, hash1, 32);
  memcpy(output2, hash2, 32);
  memcpy(output3, hash3, 32);
}
