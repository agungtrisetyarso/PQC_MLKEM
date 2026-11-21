// leak.hpp — the LK(v) hook placed on every share-dependent intermediate.
//
//   -DLEAKSIM        (host)  record v into mk::g_trace, in source order.
//   -DMK_NO_BARRIER          identity.  The compiler may then reassociate
//                            share expressions; on Cortex-M4 clang rewrites
//                            ISW's (r ^ a_i b_j) ^ a_j b_i as
//                            (a_i b_j ^ a_j b_i) ^ r, which unmasks.  Kept
//                            only to demonstrate that failure.
//   default                  optimisation barrier: an empty asm that takes v
//                            as "+r", so the compiler cannot see through v and
//                            cannot reassociate across it.  No instructions.
//   -DMK_PRECHARGE   (Thumb) barrier, then drive zero through the result bus
//                            and both operand buses:
//                                mov.w r12, #0 ; eor.w r12, r12, r12
//                            r12 is clobbered, so v never lives there.
// Whether a schedule produced by the compiler keeps these effective is what
// the instruction-level TVLA (target/) checks.
#pragma once
#include <stdint.h>

#ifdef LEAKSIM
#include <vector>
namespace mk {
inline std::vector<uint32_t> g_trace;
inline bool g_rec = false;
inline uint32_t LK(uint32_t v) { if (g_rec) g_trace.push_back(v); return v; }
}  // namespace mk
#elif defined(MK_NO_BARRIER)
namespace mk {
inline constexpr uint32_t LK(uint32_t v) { return v; }
}  // namespace mk
#elif defined(MK_PRECHARGE)
namespace mk {
static inline __attribute__((always_inline)) uint32_t LK(uint32_t v) {
  __asm__ volatile("mov.w r12, #0\n\teor.w r12, r12, r12" : "+r"(v) : : "r12");
  return v;
}
}  // namespace mk
#else
namespace mk {
static inline __attribute__((always_inline)) uint32_t LK(uint32_t v) {
  __asm__("" : "+r"(v));
  return v;
}
}  // namespace mk
#endif
