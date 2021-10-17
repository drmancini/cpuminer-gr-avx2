#ifndef GR_GATE_H_
#define GR_GATE_H_

#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

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

enum CryptonightConfig { Turtlelite = 0, Turtle, Darklite, Dark, Lite, Fast };

// Only 3 CN algos are selected from available 6.
extern __thread uint8_t gr_hash_order[GR_HASH_FUNC_COUNT - 3 + 1];

void gr_getAlgoString(const uint8_t *block, uint8_t *selectedAlgoOutput);

void gr_hash(void *hash, const void *input0);
int get_gr_rotation(void *input0);

// Memory state
extern __thread uint8_t *hp_state;

// Uses hp_state as memory.
void AllocateNeededMemory();

#endif // GR_GATE_H_
