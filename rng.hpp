// rng.hpp — randomness for masking.
// xoshiro256** seeded from getrandom(): fast and adequate for benchmarking and
// simulation.  A deployed implementation must draw masks from a TRNG or a
// cryptographic DRBG; the cost of that is not included in cycle counts.
#pragma once
#include <cstdint>
#include <sys/random.h>

namespace mk {

struct Xoshiro {
  uint64_t s[4];
  Xoshiro() { reseed(); }
  void reseed() { if (getrandom(s, sizeof s, 0) != sizeof s) __builtin_trap(); }
  static inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
  inline uint64_t next() {
    uint64_t r = rotl(s[1] * 5, 7) * 9, t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t; s[3] = rotl(s[3], 45);
    return r;
  }
};
inline Xoshiro& rng() { static thread_local Xoshiro g; return g; }

inline uint32_t rand32() { return (uint32_t)(rng().next() >> 32); }

// Uniform in [0, q) by rejection on 16 bits (accept < 19*q = 63251).
inline uint32_t rand_q() {
  for (;;) {
    uint32_t r = rand32() & 0xFFFF;
    if (r < 63251u) return r % 3329u;
  }
}

}  // namespace mk
