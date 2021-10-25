#include "gr.h"
#include "virtual_memory.h" // Memory allocation.

__thread uint8_t *__restrict__ hp_state = NULL;
__thread uint8_t gr_hash_order[GR_HASH_FUNC_COUNT - 3 + 1] = {0};
__thread uint8_t gr_rotation = 0;

__thread gr_context_overlay gr_ctx;

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

// Mapping of gr_harh_order CN to cn-config - lightest to heaviest order.
// Config:  Turtlelite, Turtle, Darklite, Dark, Lite, Fast.
// Gr_Hash: Dark, Darklite, Fast, Lite, Turtle, Turtlelite
static uint8_t cn_map[6] = {3, 2, 5, 4, 1, 0};

static size_t GetMaxTuneSize() {
  size_t max = 2097152;
  constexpr size_t max_2pages = 2097152 * 2;
  constexpr size_t max_3pages = 2097152 * 3;
  constexpr size_t max_4pages = 2097152 * 4;
  for (size_t i = 0; i < 40; ++i) {
    if (gr_tune_2way[i][4] == 4 || gr_tune_2way[i][4] == 3 ||
        gr_tune_2way[i][5] == 2) {
      max = max < max_2pages ? max_2pages : max;
    }
    if (gr_tune_2way[i][5] == 3) {
      max = max < max_3pages ? max_3pages : max;
    }
    if (gr_tune_2way[i][5] == 4) {
      max = max < max_4pages ? max_4pages : max;
    }
  }
  for (size_t i = 0; i < 40; ++i) {
    if (gr_tune_3way[i][4] == 4 || gr_tune_3way[i][4] == 3 ||
        gr_tune_3way[i][5] == 2) {
      max = max < max_2pages ? max_2pages : max;
    }
    if (gr_tune_3way[i][5] == 3) {
      max = max < max_3pages ? max_3pages : max;
    }
    if (gr_tune_3way[i][5] == 4) {
      max = max < max_4pages ? max_4pages : max;
    }
  }
  for (size_t i = 0; i < 40; ++i) {
    if (gr_tune_4way[i][4] == 4 || gr_tune_4way[i][4] == 3 ||
        gr_tune_4way[i][5] == 2) {
      max = max < max_2pages ? max_2pages : max;
    }
    if (gr_tune_4way[i][5] == 3) {
      max = max < max_3pages ? max_3pages : max;
    }
    if (gr_tune_4way[i][5] == 4) {
      max = max < max_4pages ? max_4pages : max;
    }
  }

  return max;
}

void AllocateNeededMemory() {
  size_t size = GetMaxTuneSize();

  // Purges previous memory allocation and creates new one.
  PrepareMemory((void **)&hp_state, size);
}

int get_config_id(uint8_t *hash_order) {
  for (size_t i = 0; i < 40; i++) {
    size_t cn0 = cn[i][0] + 15;
    size_t cn1 = cn[i][1] + 15;
    size_t cn2 = cn[i][2] + 15;
    size_t order0 = hash_order[5];
    size_t order1 = hash_order[11];
    size_t order2 = hash_order[17];
    if ((cn0 == order0 && cn1 == order1 && cn2 == order2) ||
        (cn0 == order1 && cn1 == order2 && cn2 == order0) ||
        (cn0 == order2 && cn1 == order0 && cn2 == order1)) {
      return i;
    }
  }

  return -1;
}

int get_gr_rotation_header(void *header) {
  uint8_t hash_order[GR_HASH_FUNC_COUNT - 3 + 1];
  gr_getAlgoString((const uint8_t *)&(((const uint32_t *)header)[1]),
                   hash_order);

  const int rotation = get_config_id(hash_order);
  if (rotation == -1) {
    return -1;
  }
  return rotation / 2;
}

int get_gr_rotation_block(void *block_hash) {
  uint8_t hash_order[GR_HASH_FUNC_COUNT - 3 + 1];

  gr_getAlgoString((const uint8_t *)&(((const uint32_t *)block_hash)[0]),
                   hash_order);

  const int rotation = get_config_id(hash_order);
  if (rotation == -1) {
    return -1;
  }
  return rotation / 2;
}
