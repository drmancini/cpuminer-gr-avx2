#ifndef GR_GATE_H_
#define GR_GATE_H_

#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

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

#define CN_2WAY 2
#define CN_3WAY 3
#define CN_4WAY 4

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

enum Algo {
  BLAKE = 0,         // 0
  BMW,               // 1
  GROESTL,           // 2
  JH,                // 3
  KECCAK,            // 4
  SKEIN,             // 5
  LUFFA,             // 6
  CUBEHASH,          // 7
  SHAVITE,           // 8
  SIMD,              // 9
  ECHO,              // 10
  HAMSI,             // 11
  FUGUE,             // 12
  SHABAL,            // 13
  WHIRLPOOL,         // 14
  CNDark,            // 15
  CNDarklite,        // 16
  CNFast,            // 17
  CNLite,            // 18
  CNTurtle,          // 19
  CNTurtlelite,      // 20
  GR_HASH_FUNC_COUNT // 21
};

// Only 3 CN algos are selected from available 6.
__thread uint8_t gr_hash_order[GR_HASH_FUNC_COUNT - 3 + 1];
__thread uint8_t gr_rotation = 0;

__thread gr_context_overlay gr_ctx;

enum CryptonightConfig { Turtlelite = 0, Turtle, Darklite, Dark, Lite, Fast };

constexpr __thread uint8_t gr_tune_2way[40][7] = {
    {0, 0, 2, 2, 0, 0, 0}, {0, 0, 2, 2, 0, 0, 0}, {0, 0, 2, 2, 2, 0, 0},
    {0, 0, 2, 2, 2, 0, 0}, {0, 2, 2, 2, 0, 0, 1}, {0, 2, 2, 2, 0, 0, 1},
    {2, 0, 2, 2, 0, 0, 1}, {2, 0, 2, 2, 0, 0, 1}, {0, 0, 0, 2, 2, 0, 0},
    {0, 0, 0, 2, 2, 0, 0}, {0, 2, 0, 2, 0, 0, 0}, {0, 2, 0, 2, 0, 0, 0},
    {2, 0, 0, 2, 0, 0, 0}, {2, 0, 0, 2, 0, 0, 0}, {0, 2, 0, 2, 2, 0, 0},
    {0, 2, 0, 2, 2, 0, 0}, {2, 0, 0, 2, 2, 0, 0}, {2, 0, 0, 2, 2, 0, 0},
    {2, 2, 0, 2, 0, 0, 1}, {2, 2, 0, 2, 0, 0, 1}, {0, 0, 2, 0, 2, 0, 0},
    {0, 0, 2, 0, 2, 0, 0}, {0, 2, 2, 0, 0, 0, 0}, {0, 2, 2, 0, 0, 0, 0},
    {2, 0, 2, 0, 0, 0, 0}, {2, 0, 2, 0, 0, 0, 0}, {0, 2, 2, 0, 2, 0, 0},
    {0, 2, 2, 0, 2, 0, 0}, {2, 0, 2, 0, 2, 0, 0}, {2, 0, 2, 0, 2, 0, 0},
    {2, 2, 2, 0, 0, 0, 1}, {2, 2, 2, 0, 0, 0, 1}, {0, 2, 0, 0, 2, 0, 0},
    {0, 2, 0, 0, 2, 0, 0}, {2, 0, 0, 0, 2, 0, 0}, {2, 0, 0, 0, 2, 0, 0},
    {2, 2, 0, 0, 0, 0, 0}, {2, 2, 0, 0, 0, 0, 0}, {2, 2, 0, 0, 2, 0, 0},
    {2, 2, 0, 0, 2, 0, 0}};

constexpr __thread uint8_t gr_tune_3way[40][7] = {
    {0, 0, 3, 3, 0, 0, 0}, {0, 0, 3, 3, 0, 0, 0}, {0, 0, 3, 3, 3, 0, 0},
    {0, 0, 3, 3, 3, 0, 0}, {0, 3, 3, 3, 0, 0, 1}, {0, 3, 3, 3, 0, 0, 1},
    {3, 0, 3, 3, 0, 0, 1}, {3, 0, 3, 3, 0, 0, 1}, {0, 0, 0, 3, 3, 0, 0},
    {0, 0, 0, 3, 3, 0, 0}, {0, 3, 0, 3, 0, 0, 0}, {0, 3, 0, 3, 0, 0, 0},
    {3, 0, 0, 3, 0, 0, 0}, {3, 0, 0, 3, 0, 0, 0}, {0, 3, 0, 3, 3, 0, 0},
    {0, 3, 0, 3, 3, 0, 0}, {3, 0, 0, 3, 3, 0, 0}, {3, 0, 0, 3, 3, 0, 0},
    {3, 3, 0, 3, 0, 0, 1}, {3, 3, 0, 3, 0, 0, 1}, {0, 0, 3, 0, 3, 0, 0},
    {0, 0, 3, 0, 3, 0, 0}, {0, 3, 3, 0, 0, 0, 0}, {0, 3, 3, 0, 0, 0, 0},
    {3, 0, 3, 0, 0, 0, 0}, {3, 0, 3, 0, 0, 0, 0}, {0, 3, 3, 0, 3, 0, 0},
    {0, 3, 3, 0, 3, 0, 0}, {3, 0, 3, 0, 3, 0, 0}, {3, 0, 3, 0, 3, 0, 0},
    {3, 3, 3, 0, 0, 0, 1}, {3, 3, 3, 0, 0, 0, 1}, {0, 3, 0, 0, 3, 0, 0},
    {0, 3, 0, 0, 3, 0, 0}, {3, 0, 0, 0, 3, 0, 0}, {3, 0, 0, 0, 3, 0, 0},
    {3, 3, 0, 0, 0, 0, 0}, {3, 3, 0, 0, 0, 0, 0}, {3, 3, 0, 0, 3, 0, 0},
    {3, 3, 0, 0, 3, 0, 0}};

constexpr __thread uint8_t gr_tune_4way[40][7] = {
    {0, 0, 4, 4, 0, 0, 0}, {0, 0, 4, 4, 0, 0, 0}, {0, 0, 4, 4, 2, 0, 0},
    {0, 0, 4, 4, 2, 0, 0}, {0, 4, 4, 4, 0, 0, 1}, {0, 4, 4, 4, 0, 0, 1},
    {4, 0, 4, 4, 0, 0, 1}, {4, 0, 4, 4, 0, 0, 1}, {0, 0, 0, 4, 2, 0, 0},
    {0, 0, 0, 4, 2, 0, 0}, {0, 4, 0, 4, 0, 0, 0}, {0, 4, 0, 4, 0, 0, 0},
    {4, 0, 0, 4, 0, 0, 0}, {4, 0, 0, 4, 0, 0, 0}, {0, 4, 0, 4, 2, 0, 0},
    {0, 4, 0, 4, 2, 0, 0}, {4, 0, 0, 4, 2, 0, 0}, {4, 0, 0, 4, 2, 0, 0},
    {4, 4, 0, 4, 0, 0, 1}, {4, 4, 0, 4, 0, 0, 1}, {0, 0, 4, 0, 2, 0, 0},
    {0, 0, 4, 0, 2, 0, 0}, {0, 4, 4, 0, 0, 0, 0}, {0, 4, 4, 0, 0, 0, 0},
    {4, 0, 4, 0, 0, 0, 0}, {4, 0, 4, 0, 0, 0, 0}, {0, 4, 4, 0, 2, 0, 0},
    {0, 4, 4, 0, 2, 0, 0}, {4, 0, 4, 0, 2, 0, 0}, {4, 0, 4, 0, 2, 0, 0},
    {4, 4, 4, 0, 0, 0, 1}, {4, 4, 4, 0, 0, 0, 1}, {0, 4, 0, 0, 2, 0, 0},
    {0, 4, 0, 0, 2, 0, 0}, {4, 0, 0, 0, 2, 0, 0}, {4, 0, 0, 0, 2, 0, 0},
    {4, 4, 0, 0, 0, 0, 0}, {4, 4, 0, 0, 0, 0, 0}, {4, 4, 0, 0, 2, 0, 0},
    {4, 4, 0, 0, 2, 0, 0}};

// Values for 20 CN rotations with subrotation.
constexpr uint8_t cn[40][3] = {
    {0, 1, 2}, {0, 2, 1}, {0, 1, 3}, {0, 3, 1}, {0, 1, 4},
    {0, 4, 1}, {0, 1, 5}, {0, 5, 1}, {0, 2, 3}, {0, 3, 2}, // 05
    {0, 2, 4}, {0, 4, 2}, {0, 2, 5}, {0, 5, 2}, {0, 3, 4},
    {0, 4, 3}, {0, 3, 5}, {0, 5, 3}, {0, 4, 5}, {0, 5, 4}, // 10
    {1, 2, 3}, {1, 3, 2}, {1, 2, 4}, {1, 4, 2}, {1, 2, 5},
    {1, 5, 2}, {1, 3, 4}, {1, 4, 3}, {1, 3, 5}, {1, 5, 3}, // 15
    {1, 4, 5}, {1, 5, 4}, {2, 3, 4}, {2, 4, 3}, {2, 3, 5},
    {2, 5, 3}, {2, 4, 5}, {2, 5, 4}, {3, 4, 5}, {3, 5, 4}}; // 20

void gr_hash_1way(void *output0, const void *input0);
void gr_hash_2way(void *output0, void *output1, const void *input0,
                  const void *input1);
void gr_hash_3way(void *output0, void *output1, void *output2,
                  const void *input0, const void *input1, const void *input2);
void gr_hash_4way(void *output0, void *output1, void *output2, void *output3,
                  const void *input0, const void *input1, const void *input2,
                  const void *input3);

void gr_getAlgoString(const uint8_t *block, uint8_t *selectedAlgoOutput);
int get_config_id(void *hash_order);
int get_gr_rotation_header(void *header);
int get_gr_rotation_block(void *block_hash);

// Memory state
__thread uint8_t *__restrict__ hp_state;

// Uses hp_state as memory.
void AllocateNeededMemory();

#endif // GR_GATE_H_
