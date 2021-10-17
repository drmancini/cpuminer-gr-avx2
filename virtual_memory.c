#include "virtual_memory.h"
#include <math.h> // ceil
#include <stdio.h>
#include <unistd.h> // usleep

static bool huge_pages = false;
__thread bool allocated_hp = false;
__thread size_t currently_allocated = 0;

// Large Page size should be a multiple of 2MiB.
static inline size_t GetProperSize(size_t size) {
  return (size_t)ceil((double)size / 2097152.) * 2097152;
}

// Linux
#include <sys/mman.h>

static inline int read_hp(const char *path) {
  FILE *fd;
  fd = fopen(path, "r");
  if (fd == NULL) {
    return -1;
  }

  uint64_t value = 0;
  int read = fscanf(fd, "%lu", &value);
  if (ferror(fd) != 0 || read != 1) {
    fclose(fd);
    return -2;
  }
  fclose(fd);
  return (int)value;
}

static inline bool write_hp(const char *path, uint64_t value) {
  FILE *fd;
  fd = fopen(path, "w");
  if (fd == NULL) {
    return false;
  }

  int wrote = fprintf(fd, "%lu", value);
  if (ferror(fd) != 0 && wrote != 1) {
    fclose(fd);
    return false;
  }
  fclose(fd);
  return true;
}

static bool InitNodeHugePages(size_t threads, size_t node) {
  char free_path[256];
  sprintf(free_path,
          "/sys/devices/system/node/node%lu/hugepages/"
          "hugepages-2048kB/free_hugepages",
          node);
  int available_pages = read_hp(free_path);
  if (available_pages < 0) {
    huge_pages = false;
    return huge_pages;
  }
  if (available_pages >= (int)threads) {
    huge_pages = true;
    return huge_pages;
  }
  char nr_path[256];
  sprintf(nr_path,
          "/sys/devices/system/node/node%lu/hugepages/"
          "hugepages-2048kB/nr_hugepages",
          node);
  int set_pages = read_hp(nr_path);
  set_pages = set_pages < 0 ? 0 : set_pages + threads - available_pages;
  huge_pages = write_hp(nr_path, set_pages);

  // Check if the value was really written.
  if (huge_pages) {
    int nr_hugepages = read_hp(nr_path);
    // Failed to write values properly?
    if (nr_hugepages < set_pages) {
      huge_pages = false;
    }
  }

  return huge_pages;
}

// One thread should allocate 2 MiB of Large Pages.
bool InitHugePages(size_t threads, size_t max_large_pages) {
  huge_pages = InitNodeHugePages(threads * max_large_pages, 0);
  return huge_pages;
}

#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
void *AllocateLargePagesMemory(size_t size) {
  // Needs to be multiple of Large Pages (2 MiB).
#if defined(__FreeBSD__)
  void *mem =
      mmap(0, size, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_ALIGNED_SUPER | MAP_PREFAULT_READ,
           -1, 0);
#else
  void *mem = mmap(0, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE |
                       MAP_HUGE_2MB,
                   0, 0);
#endif

  if (mem == MAP_FAILED) {
    // Retry without huge pages.
#if defined(__FreeBSD__)
    mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
               0);
#else
    mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
               0);
#endif
  }

  return mem == MAP_FAILED ? NULL : mem;
}

void DeallocateLargePagesMemory(void **memory) {
  // Needs to be multiple of Large Pages (2 MiB).
  munmap(*memory, GetProperSize(currently_allocated));
  *memory = NULL;
  allocated_hp = false;
}

void *AllocateMemory(size_t size) {
  void *mem = AllocateLargePagesMemory(size);
  if (mem == NULL) {
    mem = malloc(size);
    allocated_hp = false;
    if (mem == NULL) {
      exit(1);
    }
  } else {
    allocated_hp = true;
  }
  currently_allocated = size;
  return mem;
}

void DeallocateMemory(void **memory) {
  if (allocated_hp) {
    DeallocateLargePagesMemory(memory);
    // Wait a while (25ms) after deallocation. Should help with
    // fast allocation afterwards.
    usleep(25000);
  } else if (*memory != NULL) {
    // No special method of allocation was used.
    free(*memory);
  }
}

void PrepareMemory(void **memory, size_t size) {
  if (GetProperSize(currently_allocated) < GetProperSize(size)) {
    if (*memory != NULL) {
      DeallocateMemory(memory);
    }
    *memory = (void *)AllocateMemory(GetProperSize(size));
  }
}
