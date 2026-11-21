// End-to-end check of the masked ML-KEM-768 decryption core.
//  1. NTT-domain multiplication equals schoolbook multiplication mod X^256+1.
//  2. K-PKE round trip with ML-KEM-768 noise and ciphertext compression
//     (du = 10, dv = 4): unmasked and masked decryption both recover m,
//     and the masked core equals the unmasked core bit for bit.
#include <cstdio>
#include "mlkem.hpp"
using namespace mk;

static Poly rand_poly() { Poly p; for (auto& c : p) c = rand_q(); return p; }
static Poly small_poly() {                        // CBD_2: sum of 2 bits - sum of 2 bits
  Poly p; for (auto& c : p) { uint32_t r = rand32(); int v = (int)(__builtin_popcount(r & 3)) - (int)__builtin_popcount((r >> 2) & 3); c = (uint32_t)((v + (int)Q) % (int)Q); }
  return p;
}
static Poly schoolbook(const Poly& a, const Poly& b) {
  int64_t r[512] = {0};
  for (int i = 0; i < 256; i++) for (int j = 0; j < 256; j++) r[i + j] += (int64_t)a[i] * b[j];
  Poly c; for (int i = 0; i < 256; i++) c[i] = (uint32_t)((((r[i] - r[i + 256]) % Q) + Q) % Q);
  return c;
}

template <std::size_t N> int roundtrip(int trials) {
  int bad = 0, mism = 0;
  for (int t = 0; t < trials; t++) {
    Poly A[K][K]; for (auto& row : A) for (auto& p : row) p = rand_poly();   // A_hat
    Poly s_hat[K], e[K], t_hat[K];
    for (int j = 0; j < K; j++) { s_hat[j] = small_poly(); ntt(s_hat[j]); e[j] = small_poly(); }
    for (int i = 0; i < K; i++) {
      t_hat[i] = Poly{}; for (int j = 0; j < K; j++) basemul_acc(t_hat[i], A[i][j], s_hat[j]);
      Poly ee = e[i]; ntt(ee); for (int c = 0; c < NCOEF; c++) t_hat[i][c] = addq(t_hat[i][c], ee[c]);
    }
    uint8_t msg[NCOEF]; for (auto& b : msg) b = rand32() & 1;
    Poly r_hat[K]; for (auto& p : r_hat) { p = small_poly(); ntt(p); }
    Poly u[K], v{};
    for (int i = 0; i < K; i++) {                                     // u = A^T r + e1
      u[i] = Poly{}; for (int j = 0; j < K; j++) basemul_acc(u[i], A[j][i], r_hat[j]);
      intt(u[i]); Poly e1 = small_poly(); for (int c = 0; c < NCOEF; c++) u[i][c] = addq(u[i][c], e1[c]);
    }
    for (int j = 0; j < K; j++) basemul_acc(v, t_hat[j], r_hat[j]);  // v = t^T r + e2 + Dec1(m)
    intt(v); Poly e2 = small_poly();
    for (int c = 0; c < NCOEF; c++) v[c] = addq(addq(v[c], e2[c]), msg[c] ? 1665 : 0);
    // Compress / decompress the ciphertext as ML-KEM does.
    Poly u_hat[K], v2;
    for (int i = 0; i < K; i++) { for (int c = 0; c < NCOEF; c++) u_hat[i][c] = decompress_d(compress_d(u[i][c], 10), 10); ntt(u_hat[i]); }
    for (int c = 0; c < NCOEF; c++) v2[c] = decompress_d(compress_d(v[c], 4), 4);

    uint8_t ref[NCOEF]; decrypt_core_ref(s_hat, u_hat, v2, ref);
    MaskedSK<N> sk = mask_sk<N>(s_hat);
    Bool<N> mm[NCOEF]; masked_decrypt_core<N>(sk, u_hat, v2, mm);
    for (int c = 0; c < NCOEF; c++) {
      uint32_t bit = bool_unshare(mm[c]) & 1;
      bad += (ref[c] != msg[c]);
      mism += (bit != ref[c]);
    }
  }
  printf("N=%d (d=%d): %d trials, ref-vs-msg errors=%d, masked-vs-ref mismatches=%d\n",
         (int)N, (int)N - 1, trials, bad, mism);
  return bad + mism;
}

int main() {
  int fails = 0;
  for (int t = 0; t < 200; t++) {
    Poly a = rand_poly(), b = rand_poly(), ah = a, bh = b, c{};
    ntt(ah); ntt(bh); basemul_acc(c, ah, bh); intt(c);
    if (c != schoolbook(a, b)) fails++;
    Poly x = a; ntt(x); intt(x); if (x != a) fails++;
  }
  printf("NTT vs schoolbook (200 trials): %s\n", fails ? "FAIL" : "ok");
  fails += roundtrip<1>(50) + roundtrip<2>(50) + roundtrip<3>(30) + roundtrip<4>(20)
         + roundtrip<6>(10) + roundtrip<8>(10);
  printf(fails ? "DECRYPTION TESTS FAILED\n" : "ALL DECRYPTION TESTS PASSED\n");
  return fails != 0;
}
