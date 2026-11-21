// mlkem.hpp — ML-KEM (FIPS 203) ring arithmetic and the masked decryption core.
//
// Linear layer (share-wise, d-NI, O(N)):
//   w = v - NTT^{-1}( s_hat^T o u_hat )
// with s_hat secret and arithmetic-shared, u_hat and v public.  Every
// multiplication is secret x public, so no masked multiplier is needed.
//
// Nonlinear layer (O(N^2) per coefficient):
//   m_c = Compress_1(w_c)   via A2B mod q and two masked comparisons.
#pragma once
#include <array>
#include <cstdint>
#include "masking.hpp"

namespace mk {

constexpr int NCOEF = 256;
constexpr int K = 3;                      // ML-KEM-768
using Poly = std::array<uint32_t, NCOEF>;

// ----------------------------------------------------------------- NTT ----
struct Zetas {
  uint32_t z[128], g[128];
  static uint32_t bitrev7(uint32_t i) { uint32_t r = 0; for (int b = 0; b < 7; b++) r |= ((i >> b) & 1) << (6 - b); return r; }
  static uint32_t pw(uint32_t b, uint32_t e) { uint32_t r = 1; while (e) { if (e & 1) r = r * b % Q; b = b * b % Q; e >>= 1; } return r; }
  Zetas() { for (uint32_t i = 0; i < 128; i++) { z[i] = pw(17, bitrev7(i)); g[i] = pw(17, 2 * bitrev7(i) + 1); } }
};
inline const Zetas& zetas() { static const Zetas Z; return Z; }

inline void ntt(Poly& f) {                // FIPS 203 Algorithm 9
  const auto& Z = zetas(); int i = 1;
  for (int len = 128; len >= 2; len >>= 1)
    for (int start = 0; start < 256; start += 2 * len) {
      uint32_t zeta = Z.z[i++];
      for (int j = start; j < start + len; j++) {
        uint32_t t = mulq(zeta, f[j + len]);
        f[j + len] = subq(f[j], t);
        f[j] = addq(f[j], t);
      }
    }
}
inline void intt(Poly& f) {               // FIPS 203 Algorithm 10
  const auto& Z = zetas(); int i = 127;
  for (int len = 2; len <= 128; len <<= 1)
    for (int start = 0; start < 256; start += 2 * len) {
      uint32_t zeta = Z.z[i--];
      for (int j = start; j < start + len; j++) {
        uint32_t t = f[j];
        f[j] = addq(t, f[j + len]);
        f[j + len] = mulq(zeta, subq(f[j + len], t));
      }
    }
  for (auto& c : f) c = mulq(c, 3303);    // 128^{-1} mod q
}
// acc += a o b in the NTT domain (FIPS 203 Algorithms 11-12).
inline void basemul_acc(Poly& acc, const Poly& a, const Poly& b) {
  const auto& Z = zetas();
  for (int i = 0; i < 128; i++) {
    uint32_t a0 = a[2 * i], a1 = a[2 * i + 1], b0 = b[2 * i], b1 = b[2 * i + 1];
    uint32_t c0 = addq(mulq(a0, b0), mulq(mulq(a1, b1), Z.g[i]));
    uint32_t c1 = addq(mulq(a0, b1), mulq(a1, b0));
    acc[2 * i] = addq(acc[2 * i], c0);
    acc[2 * i + 1] = addq(acc[2 * i + 1], c1);
  }
}

// --------------------------------------------------- unmasked reference ---
inline uint32_t compress_d(uint32_t x, int d) {
  return (uint32_t)((((uint64_t)x << d) + Q / 2) / Q) & ((1u << d) - 1);
}
inline uint32_t decompress_d(uint32_t y, int d) {
  return (uint32_t)(((uint64_t)y * Q + (1u << (d - 1))) >> d);
}

// m'[c] = Compress_1( v - NTT^{-1}(s_hat^T o u_hat) )_c
inline void decrypt_core_ref(const Poly s_hat[K], const Poly u_hat[K], const Poly& v,
                             uint8_t m[NCOEF]) {
  Poly acc{}; for (int j = 0; j < K; j++) basemul_acc(acc, s_hat[j], u_hat[j]);
  intt(acc);
  for (int c = 0; c < NCOEF; c++) m[c] = (uint8_t)compress_d(subq(v[c], acc[c]), 1);
}

// ------------------------------------------------------- masked core ------
template <std::size_t N> struct MaskedSK { Poly s_hat[K][N]; };   // [poly][share]

template <std::size_t N> MaskedSK<N> mask_sk(const Poly s_hat[K]) {
  MaskedSK<N> sk;
  for (int j = 0; j < K; j++)
    for (int c = 0; c < NCOEF; c++) {
      Arith<N> a = arith_share<N>(s_hat[j][c]);
      for (int i = 0; i < (int)N; i++) sk.s_hat[j][i][c] = a[i];
    }
  return sk;
}

// Linear layer: share-wise.  Output w[i] is share i of w (arithmetic).
template <std::size_t N> void masked_linear(const MaskedSK<N>& sk, const Poly u_hat[K],
                                            const Poly& v, Poly w[N]) {
  for (int i = 0; i < (int)N; i++) {
    Poly acc{};
    for (int j = 0; j < K; j++) basemul_acc(acc, sk.s_hat[j][i], u_hat[j]);
    intt(acc);
    // w = v - acc: the public v enters share 0 only.
    for (int c = 0; c < NCOEF; c++) w[i][c] = (i == 0) ? subq(v[c], acc[c]) : subq(0, acc[c]);
  }
}

// Nonlinear layer: Boolean-masked message bits, m[c][i] = share i of bit c.
template <std::size_t N> void masked_nonlinear(const Poly w[N], Bool<N> m[NCOEF]) {
  for (int c = 0; c < NCOEF; c++) {
    Arith<N> a; for (int i = 0; i < (int)N; i++) a[i] = w[i][c];
    m[c] = compress1<N>(a);
  }
}

template <std::size_t N> void masked_decrypt_core(const MaskedSK<N>& sk, const Poly u_hat[K],
                                                  const Poly& v, Bool<N> m[NCOEF]) {
  Poly w[N];
  masked_linear<N>(sk, u_hat, v, w);
  masked_nonlinear<N>(w, m);
}

}  // namespace mk
