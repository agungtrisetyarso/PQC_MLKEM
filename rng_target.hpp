// rng_target.hpp — randomness on the Cortex-M4 target.
// The emulator (or, on a real board, a TRNG driver) fills a buffer of fresh
// random words before each call; gadgets consume it in order.  Keeping the
// randomness external makes every emulated execution reproducible from its
// inputs, which the TVLA harness relies on.
#pragma once
#include <stdint.h>

extern "C" const uint32_t* volatile mk_rnd_ptr;

namespace mk {
static inline uint32_t rand32() { return *mk_rnd_ptr++; }
// Uniform in [0, q) without a data-dependent loop: floor(r q / 2^32) for a
// uniform 32-bit r is within statistical distance q / 2^32 < 2^-20 of uniform
// per value, and keeps the instruction sequence of the Decaps independent of
// the random words (instruction-level traces stay aligned).  MK_RAND_Q_REJECT
// restores rejection sampling as on the host.
static inline uint32_t rand_q() {
#ifdef MK_RAND_Q_REJECT
  for (;;) { uint32_t r = rand32() & 0xFFFF; if (r < 63251u) return r % 3329u; }
#else
  return (uint32_t)(((uint64_t)rand32() * 3329u) >> 32);
#endif
}
}  // namespace mk
