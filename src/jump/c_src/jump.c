#include "jump.h"

int64_t JumpConsistentHash(uint64_t key, int64_t num) {
  int64_t b = -1, j = 0;
  while (j < num) {
    b = j;
    key = key * 2862933555777941757ULL + 1;
    j = (b + 1) * ((double)(1LL << 31) / (double)((key >> 33) + 1));
  }
  return b;
}