#include "gr.h"
#include "virtual_memory.h" // Memory allocation.
#include <stdio.h>
#include <string.h>
#include <unistd.h> // usleep

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/echo/sph_echo.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/nist.h"
#include "algo/skein/sph_skein.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "cryptonote/cryptonight.h"

#if defined(__AES__)
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/fugue/fugue-aesni.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#endif

union _gr_context_overlay {
#if defined(__AES__)
  hashState_echo echo;
  hashState_groestl groestl;
  hashState_fugue fugue;
#else
  sph_groestl512_context groestl;
  sph_echo512_context echo;
  sph_fugue512_context fugue;
#endif
  sph_blake512_context blake;
  sph_bmw512_context bmw;
  sph_skein512_context skein;
  sph_jh512_context jh;
  sph_keccak512_context keccak;
  hashState_luffa luffa;
  cubehashParam cube;
  shavite512_context shavite;
  hashState_sd simd;
  sph_hamsi512_context hamsi;
  sph_shabal512_context shabal;
  sph_whirlpool_context whirlpool;
} __attribute__((aligned(64)));

typedef union _gr_context_overlay gr_context_overlay;

// Only 3 CN algos are selected from available 6.
__thread uint8_t gr_hash_order[GR_HASH_FUNC_COUNT - 3 + 1];

__thread gr_context_overlay gr_ctx;

__thread uint8_t *__restrict__ hp_state = NULL;

static void selectAlgo(const uint8_t nibble, bool *selectedAlgos,
                       uint8_t *selectedIndex, int algoCount,
                       int *currentCount) {
  uint8_t algoDigit = (nibble & 0x0F) % algoCount;
  if (!selectedAlgos[algoDigit]) {
    selectedAlgos[algoDigit] = true;
    selectedIndex[currentCount[0]] = algoDigit;
    currentCount[0] = currentCount[0] + 1;
  }
  algoDigit = (nibble >> 4) % algoCount;
  if (!selectedAlgos[algoDigit]) {
    selectedAlgos[algoDigit] = true;
    selectedIndex[currentCount[0]] = algoDigit;
    currentCount[0] = currentCount[0] + 1;
  }
}

void gr_getAlgoString(const uint8_t *block, uint8_t *selectedAlgoOutput) {
  // Select Core algos.
  bool selectedCoreAlgo[15];

  for (int i = 0; i < 15; i++) {
    selectedCoreAlgo[i] = false;
  }

  uint8_t core_algos[15];
  int selectedCoreCount = 0;
  for (int i = 0; i < 32; i++) {
    selectAlgo(block[i], selectedCoreAlgo, core_algos, 15, &selectedCoreCount);
    if (selectedCoreCount == 15) {
      break;
    }
  }
  if (selectedCoreCount < 15) {
    for (int i = 0; i < 15; i++) {
      if (!selectedCoreAlgo[i]) {
        core_algos[selectedCoreCount] = i;
        selectedCoreCount++;
      }
    }
  }

  // Select Core algos.
  bool selectedCNAlgo[6];

  for (int i = 0; i < 6; i++) {
    selectedCNAlgo[i] = false;
  }

  uint8_t cn_algos[6];
  int selectedCNCount = 0;
  for (int i = 0; i < 32; i++) {
    selectAlgo(block[i], selectedCNAlgo, cn_algos, 6, &selectedCNCount);
    if (selectedCNCount == 6) {
      break;
    }
  }
  if (selectedCNCount < 6) {
    for (int i = 0; i < 6; i++) {
      if (!selectedCNAlgo[i]) {
        cn_algos[selectedCNCount] = i;
        selectedCNCount++;
      }
    }
  }

  selectedCNCount = 0;
  selectedCoreCount = 0;
  // Create proper algo order.
  for (int i = 0; i < 15 + 3; i++) {
    if (i % 6 == 5) {
      // Add CN algo.
      selectedAlgoOutput[i] = cn_algos[selectedCNCount++] + 15;
      i++;
      if (i == 18) {
        break;
      }
    }
    selectedAlgoOutput[i] = core_algos[selectedCoreCount++];
  }
}

static size_t GetMaxTuneSize() {
  const size_t max = 2097152;

  return max;
}

static const uint8_t cn[20][3] = {
    {0, 1, 2}, {0, 1, 3}, {0, 1, 4}, {0, 1, 5}, {0, 2, 3},  // 05
    {0, 2, 4}, {0, 2, 5}, {0, 3, 4}, {0, 3, 5}, {0, 4, 5},  // 10
    {1, 2, 3}, {1, 2, 4}, {1, 2, 5}, {1, 3, 4}, {1, 3, 5},  // 15
    {1, 4, 5}, {2, 3, 4}, {2, 3, 5}, {2, 4, 5}, {3, 4, 5}}; // 20

int get_gr_rotation(void *block_data) {
  uint8_t hash_order[GR_HASH_FUNC_COUNT - 3 + 1];
  gr_getAlgoString((const uint8_t *)&(((const uint32_t *)block_data)[1]),
                   hash_order);

  for (int i = 0; i < 20; i++) {
    if (cn[i][0] + 15 == hash_order[5] || cn[i][0] + 15 == hash_order[11] ||
        cn[i][0] + 15 == hash_order[17]) {
      if (cn[i][1] + 15 == hash_order[5] || cn[i][1] + 15 == hash_order[11] ||
          cn[i][1] + 15 == hash_order[17]) {
        if (cn[i][2] + 15 == hash_order[5] || cn[i][2] + 15 == hash_order[11] ||
            cn[i][2] + 15 == hash_order[17]) {
          return i;
        }
      }
    }
  }
  return -1;
}

void AllocateNeededMemory() {
  size_t size = GetMaxTuneSize();

  // Purges previous memory allocation and creates new one.
  PrepareMemory((void **)&hp_state, size);
}

#define CRYPTONIGHT_HASH(variant) cryptonight_##variant##_hash(hash0, hash0);

#define CORE_HASH(hash, input, output, size)                                   \
  sph_##hash##512_init(&ctx.hash);                                             \
  sph_##hash##512(&ctx.hash, input, size);                                     \
  sph_##hash##512_close(&ctx.hash, output);

void gr_hash(void *output0, const void *input0) {
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
  }

  // Allocate needed memory (only as much as is needed.
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
      cryptonight_hash<TURTLELITE, true>(hash0, hash0);
      break;
    case CNTurtle:
      cryptonight_hash<TURTLE, true>(hash0, hash0);
      break;
    case CNDarklite:
      cryptonight_hash<DARKLITE, true>(hash0, hash0);
      break;
    case CNDark:
      cryptonight_hash<DARK, true>(hash0, hash0);
      break;
    case CNLite:
      cryptonight_hash<LITE, true>(hash0, hash0);
      break;
    case CNFast:
      cryptonight_hash<FAST, true>(hash0, hash0);
      break;
    }
    size = 64;
  }
  memcpy(output0, hash0, 32);
}
