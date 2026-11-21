// masking.hpp — arbitrary-order masking gadgets for ML-KEM (q = 3329).
//
// Order d, N = d + 1 shares.  All gadgets are templated on N so the compiler
// sees fixed loop bounds.
//
//   Arithmetic sharing : x = sum_i a[i] mod q
//   Boolean sharing    : x = XOR_i b[i]   (16-bit lanes held in uint32_t)
//
// Leakage instrumentation: every share-dependent intermediate passes through
// LK(v).  In benchmark builds LK is a no-op; in leakage builds it appends v to
// the global trace in source execution order (see leak.hpp).
//
// The header is freestanding: it needs only <stdint.h>/<stddef.h>, so the same
// gadget code is compiled for the host and for the Cortex-M4 target.  Define
// MK_TARGET to take randomness from rng_target.hpp instead of rng.hpp.
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef MK_TARGET
#include "rng_target.hpp"
#else
#include "rng.hpp"
#endif
#include "leak.hpp"
#include "ops.hpp"

namespace mk {

constexpr uint32_t Q = 3329;
constexpr uint32_t KMASK = 0xFFFFu;   // Boolean arithmetic is mod 2^16
constexpr int KBITS = 16;

// Minimal fixed-size share vector (std::array is unavailable freestanding).
template <size_t N> struct Shares {
  uint32_t s[N];
  uint32_t& operator[](int i) { return s[i]; }
  // Reads through a const view go through x_ld, so under -DMK_PRECHARGE every
  // share read is a cleared, precharged load rather than a compiler reload.
  uint32_t operator[](int i) const { return x_ld(&s[i]); }
  uint32_t* data() { return s; }
  const uint32_t* data() const { return s; }
};
template <size_t N> using Arith = Shares<N>;   // shares in [0,q)
template <size_t N> using Bool  = Shares<N>;   // 16-bit lanes

// ---------------------------------------------------------------- mod q ----
// Constant-time reduction of r < 2^32 / ... (we only use r < q^2 * 4).
static inline uint32_t barrett(uint32_t r) {
  uint32_t t = (uint32_t)(((uint64_t)r * 1290167u) >> 32);  // floor(2^32/q)
  int32_t  x = (int32_t)(r - t * Q);                          // in [0, 2q)
  x -= (int32_t)Q;
  x += (int32_t)Q & -(int32_t)((uint32_t)x >> 31);
  return (uint32_t)x;
}
static inline uint32_t addq(uint32_t a, uint32_t b) { return barrett(a + b); }
static inline uint32_t subq(uint32_t a, uint32_t b) { return barrett(a + Q - b); }
static inline uint32_t mulq(uint32_t a, uint32_t b) { return barrett(a * b); }

// ------------------------------------------------------------- sharings ----
template <size_t N> Arith<N> arith_share(uint32_t x) {
  Arith<N> a; uint32_t acc = 0;
  for (int i = 1; i < (int)N; i++) { a[i] = rand_q(); acc = addq(acc, a[i]); }
  a[0] = subq(x % Q, acc);
  return a;
}
template <size_t N> uint32_t arith_unshare(const Arith<N>& a) {
  uint32_t acc = 0; for (int i = 0; i < (int)N; i++) acc = addq(acc, a[i]); return acc;
}
template <size_t N> Bool<N> bool_share(uint32_t x) {
  Bool<N> b; uint32_t acc = 0;
  for (int i = 1; i < (int)N; i++) { b[i] = rand32() & KMASK; acc ^= b[i]; }
  b[0] = (x & KMASK) ^ acc;
  return b;
}
template <size_t N> uint32_t bool_unshare(const Bool<N>& b) {
  uint32_t acc = 0; for (int i = 0; i < (int)N; i++) acc ^= b[i]; return acc;
}
// Public constant as a Boolean sharing (c, 0, ..., 0).
template <size_t N> Bool<N> bool_const(uint32_t c) {
  Bool<N> b{}; b[0] = c & KMASK; return b;
}

// ------------------------------------------------------- refresh (SNI) ----
// ISW refresh over all pairs: N(N-1)/2 random words.  t-SNI
// (Barthe et al., CCS 2016).
template <size_t N> void refresh(Bool<N>& x) {
  for (int i = 0; i < (int)N; i++)
    for (int j = i + 1; j < (int)N; j++) {
      uint32_t r = rand16();
      x[i] = x_xor(x[i], r);
      x[j] = x_xor(x[j], r);
    }
}

// --------------------------------------------------------- SecAnd (SNI) ----
// ISW multiplication over GF(2)^16, bit-sliced.  t-SNI.  The bracketing
// r_ji = (r_ij ^ a_i b_j) ^ a_j b_i is required for security.
template <size_t N> Bool<N> sec_and(const Bool<N>& a, const Bool<N>& b) {
  Bool<N> c;
  for (int i = 0; i < (int)N; i++) c[i] = x_and(a[i], b[i]);
  for (int i = 0; i < (int)N; i++)
    for (int j = i + 1; j < (int)N; j++) {
      uint32_t rij = rand16();
      uint32_t t   = x_xor(rij, x_and(a[i], b[j]));
      uint32_t rji = x_xor(t, x_and(a[j], b[i]));
      c[i] = x_xor(c[i], rij);
      c[j] = x_xor(c[j], rji);
    }
  return c;
}

// Share-wise linear helpers (d-NI).
template <size_t N> Bool<N> bxor(const Bool<N>& a, const Bool<N>& b) {
  Bool<N> c; for (int i = 0; i < (int)N; i++) c[i] = x_xor(a[i], b[i]); return c;
}
template <size_t N> Bool<N> bshl(const Bool<N>& a, int s) {
  Bool<N> c; for (int i = 0; i < (int)N; i++) c[i] = x_shl16(a[i], (uint32_t)s); return c;
}

// ------------------------------------------------- SecAdd mod 2^16 --------
// Kogge–Stone adder of Coron–Großschädl–Tibouchi–Vadnala (FSE 2015).
// Every SecAnd whose operands derive from a common variable gets its second
// operand refreshed, so each SecAnd sees independent sharings (composition
// argument in proofs.tex).
template <size_t N> Bool<N> sec_add(const Bool<N>& x, const Bool<N>& y) {
  Bool<N> P = bxor(x, y);
  Bool<N> G = sec_and(x, y);
  for (int i = 0; i < 3; i++) {                 // log2(16) - 1 rounds
    int s = 1 << i;
    Bool<N> H = bshl(G, s); refresh(H);
    G = bxor(G, sec_and(P, H));
    H = bshl(P, s); refresh(H);
    P = sec_and(P, H);
  }
  Bool<N> H = bshl(G, 8); refresh(H);
  G = bxor(G, sec_and(P, H));
  Bool<N> z = bxor(bxor(x, y), bshl(G, 1));
  return z;
}

// --------------------------------------------- SecAdd mod q (Bool in) -----
// x, y Boolean-shared values in [0, q).  Returns Boolean sharing of x+y mod q.
template <size_t N> Bool<N> sec_add_modq(const Bool<N>& x, const Bool<N>& y) {
  Bool<N> s = sec_add(x, y);                                   // s < 2q
  Bool<N> t = sec_add(s, bool_const<N>((1u << 16) - Q));       // s - q mod 2^16
  // Broadcast sign bit of t: m = 0xFFFF iff s < q.  Share-wise, hence linear.
  Bool<N> m;
  for (int i = 0; i < (int)N; i++) m[i] = x_bcast15(t[i]);
  Bool<N> diff = bxor(s, t); refresh(diff);
  Bool<N> sel = sec_and(diff, m);
  return bxor(t, sel);                                         // s if s<q else t
}

// ---------------------------------------------- A2B mod q (recursive) -----
// Coron–Großschädl–Vadnala-style recursion: convert each half, expand to N
// shares with an SNI refresh, combine with one SecAddModq.  T(N) = O(N^2).
template <size_t M, size_t N> Bool<N> expand(const Bool<M>& b) {
  Bool<N> e{};
  for (int i = 0; i < (int)M; i++) e[i] = b[i];
  refresh(e);
  return e;
}

template <size_t N> Bool<N> a2b(const uint32_t* a) {
  if constexpr (N == 1) {
    Bool<1> b; b[0] = x_mov(a[0]); return b;
  } else {
    constexpr size_t N1 = N / 2, N2 = N - N1;
    Bool<N1> y = a2b<N1>(a);
    Bool<N2> z = a2b<N2>(a + N1);
    // Named temporaries: argument evaluation order is unspecified in C++, and
    // both expands consume randomness.  This fixes the order on every compiler.
    Bool<N> ey = expand<N1, N>(y);
    Bool<N> ez = expand<N2, N>(z);
    return sec_add_modq(ey, ez);
  }
}

// ---------------------------------------------------- masked Compress_1 ---
// Compress_1(x) = 1 iff 833 <= x <= 2496.  With b1 = [x < 833] and
// b2 = [x < 2497] (sign bits of x - c mod 2^16), and b1 => b2, we get
// Compress_1(x) = b1 XOR b2: one linear XOR after two comparisons.
// Output: Boolean sharing of one bit (bit 0 of each share).
template <size_t N> Bool<N> compress1(const Arith<N>& w) {
  Bool<N> x = a2b<N>(w.data());
  Bool<N> t1 = sec_add(x, bool_const<N>((1u << 16) - 833));
  Bool<N> x2 = x; refresh(x2);                 // x feeds two gadgets
  Bool<N> t2 = sec_add(x2, bool_const<N>((1u << 16) - 2497));
  Bool<N> m;
  for (int i = 0; i < (int)N; i++) m[i] = x_bit15(x_xor(t1[i], t2[i]));
  refresh(m);
  for (int i = 0; i < (int)N; i++) m[i] = x_and1(m[i]);   // refresh adds 16-bit noise; keep bit 0
  return m;
}

}  // namespace mk
