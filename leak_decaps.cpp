// leak_decaps.cpp — source-level TVLA (value model: HW + N(0,1) noise per
// recorded intermediate) of the masked decapsulation gadgets.
//
//   leak_decaps <target> <N> <traces> <window> [null]
//     target: keccak2   two rounds of masked Keccak-f (secret: the state)
//             keccak    all 24 rounds, first order only (window ignored)
//             b2a       1-bit B2A mod q (secret: the bit)
//             cbd       masked CBD_2 of one coefficient (secret: its 4 bits)
//             compress  masked Compress_10 (secret: x in Z_q)
//             cmp       masked Compress_10 + comparison with a public value +
//                       final fold (secret: whether x matches)
//             decaps    complete masked ML-KEM-768 Decaps, first order only
//                       (fixed vs random valid ciphertext, fixed key re-masked
//                       per run)
//     window: bivariate pairs at distance <= window (0 = all pairs, -1 = none)
//     null:   1 = both classes random (calibration)
//   LEAK_EXCLUDE=<file>: one byte per position, 1 = a function of public
//     data only (diag_decaps_public); maxima are then reported separately for
//     included and excluded positions.
// Prints one CSV line: target,N,len,traces,window,max_t1,n_t1,max_t2,n_t2,
//                      pairs,max_tb,n_tb,null
#define LEAKSIM
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>
#include "decaps.hpp"
using namespace mk; using namespace mk::dc; using fips203::Bytes;

static std::mt19937_64 gen(std::random_device{}());
static std::normal_distribution<double> noise(0.0, 1.0);

template <size_t N> static void run_target(const std::string& tg, int cls, bool nullm) {
  const bool fixed = (cls == 0) && !nullm;
  if (tg == "keccak2" || tg == "keccak") {
    std::array<W64<N>, 25> A;
    for (int i = 0; i < 25; i++) {
      uint64_t v = fixed ? 0x0123456789ABCDEFull * (i + 1) : rnd<uint64_t>(), acc = 0;
      for (size_t s = 1; s < N; s++) { A[i][s] = rnd<uint64_t>(); acc ^= A[i][s]; }
      A[i][0] = v ^ acc;
    }
    g_trace.clear(); g_rec = true;
    if (tg == "keccak") keccak_f<N>(A);
    else {                                         // two rounds, same code path
      using fips203::rol64;
      for (int round = 0; round < 2; round++) {
        std::array<W64<N>, 25> B;
        for (size_t s = 0; s < N; s++) {
          uint64_t C[5], D[5];
          for (int x = 0; x < 5; x++) C[x] = LK64(A[x][s] ^ A[x + 5][s] ^ A[x + 10][s] ^ A[x + 15][s] ^ A[x + 20][s]);
          for (int x = 0; x < 5; x++) D[x] = LK64(C[(x + 4) % 5] ^ rol64(C[(x + 1) % 5], 1));
          for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++)
            B[y + 5 * ((2 * x + 3 * y) % 5)][s] = LK64(rol64(LK64(A[x + 5 * y][s] ^ D[x]), fips203::KECCAK_RHO[x + 5 * y]));
        }
        for (int y = 0; y < 5; y++) for (int x = 0; x < 5; x++)
          A[x + 5 * y] = bxor(B[x + 5 * y], band_r(bnot(B[(x + 1) % 5 + 5 * y]), B[(x + 2) % 5 + 5 * y]));
        A[0][0] = LK64(A[0][0] ^ fips203::KECCAK_RC[round]);
      }
    }
    g_rec = false;
  } else if (tg == "b2a") {
    uint32_t bit = fixed ? 1 : (rand32() & 1); W32<N> b; uint32_t acc = 0;
    for (size_t i = 1; i < N; i++) { b[i] = rand32() & 1; acc ^= b[i]; }
    b[0] = bit ^ acc;
    g_trace.clear(); g_rec = true; for (size_t i = 0; i < N; i++) LK(b[i]); b2a_bit<N>(b); g_rec = false;
  } else if (tg == "cbd") {
    uint8_t byte = fixed ? 0x0F : (uint8_t)(rand32() & 0x0F);        // one coefficient: 4 bits
    SB<N> B; for (auto& v : B) v.assign(128, 0);
    uint8_t acc = 0; for (size_t i = 1; i < N; i++) { B[i][0] = (uint8_t)(rand32() & 0x0F); acc ^= B[i][0]; }
    B[0][0] = byte ^ acc;
    // only coefficient 0 depends on the secret; record its conversion
    g_trace.clear(); g_rec = true;
    Arith<N> x{}, y{};
    for (int j = 0; j < 2; j++) {
      W32<N> bx, by;
      for (size_t s = 0; s < N; s++) { bx[s] = LK((B[s][0] >> j) & 1); by[s] = LK((B[s][0] >> (2 + j)) & 1); }
      Arith<N> ax = b2a_bit<N>(bx), ay = b2a_bit<N>(by);
      for (size_t i = 0; i < N; i++) { x[i] = LK(addq(x[i], ax[i])); y[i] = LK(addq(y[i], ay[i])); }
    }
    for (size_t i = 0; i < N; i++) LK(subq(x[i], y[i]));
    g_rec = false;
  } else if (tg == "compress" || tg == "cmp") {
    uint32_t x = fixed ? 1000 : rand_q();
    Arith<N> a = arith_share<N>(x);
    g_trace.clear(); g_rec = true;
    for (size_t i = 0; i < N; i++) LK(a[i]);
    W32<N> c = compress_d<N>(a, 10);
    if (tg == "cmp") {                              // public value: Compress_10(1000)
      W32<N> eq = bconst<N, uint32_t>(0xFFFFFFFFu);
      c[0] = LK(c[0] ^ fips203::compress(1000, 10) ^ 0xFFFFFFFFu);
      eq = band_r(eq, c);
      for (int sh = 16; sh >= 1; sh >>= 1) { W32<N> t; for (size_t i = 0; i < N; i++) t[i] = LK(eq[i] >> sh); eq = band_r(eq, t); }
      W32<N> sel; for (size_t i = 0; i < N; i++) sel[i] = LK(0u - (eq[i] & 1));
    }
    g_rec = false;
  } else if (tg == "decaps") {
    static fips203::KeyPair kp; static Bytes c0; static bool init = false;
    const fips203::Params& P = fips203::P768;
    if (!init) {
      uint8_t d[32], z[32], m[32]; for (int i = 0; i < 32; i++) { d[i] = (uint8_t)i; z[i] = (uint8_t)(100 + i); m[i] = (uint8_t)(200 + i); }
      kp = fips203::keygen(P, d, z); Bytes K; fips203::encaps(P, kp.ek, m, K, c0); init = true;
    }
    Bytes c = c0;
    if (!fixed) { uint8_t m[32]; for (auto& b : m) b = (uint8_t)rand32(); Bytes K; fips203::encaps(P, kp.ek, m, K, c); }
    MaskedDK<N> K = mask_dk<N>(P, kp.dk);
    g_trace.clear(); g_rec = true; decaps<N>(K, c); g_rec = false;
  } else { fprintf(stderr, "unknown target\n"); exit(2); }
}

template <size_t N> static void run(const std::string& tg, long T, int W, bool nullm) {
  run_target<N>(tg, 1, nullm); const size_t L = g_trace.size();
  const bool biv = W >= 0; if (W == 0) W = (int)L - 1; if (!biv) W = 0;
  std::vector<double> mu[2], s1[2], q1[2], s2[2], q2[2], b1[2], b2[2]; long n[2] = {0, 0};
  for (int c = 0; c < 2; c++) {
    mu[c].assign(L, 0); s1[c].assign(L, 0); q1[c].assign(L, 0); s2[c].assign(L, 0); q2[c].assign(L, 0);
    if (biv) { b1[c].assign(L * W, 0); b2[c].assign(L * W, 0); }
  }
  std::vector<double> x(L + W + 1, 0.0), z(L + W + 1, 0.0);
  long T1 = std::max(2000L, T / 10);
  for (long k = 0; k < T1; k++) {                  // class means for centring
    int c = k & 1; run_target<N>(tg, c, nullm); n[c]++;
    for (size_t i = 0; i < L; i++) mu[c][i] += __builtin_popcount(g_trace[i]) + noise(gen);
  }
  for (int c = 0; c < 2; c++) { for (auto& v : mu[c]) v /= n[c]; n[c] = 0; }
  for (long k = 0; k < T; k++) {
    int c = k & 1; run_target<N>(tg, c, nullm);
    if (g_trace.size() != L) { fprintf(stderr, "non-constant trace length\n"); exit(3); }
    n[c]++;
    for (size_t i = 0; i < L; i++) { x[i] = __builtin_popcount(g_trace[i]) + noise(gen); z[i] = x[i] - mu[c][i]; }
    for (size_t i = 0; i < L; i++) { s1[c][i] += x[i]; q1[c][i] += x[i] * x[i]; double z2 = z[i] * z[i]; s2[c][i] += z2; q2[c][i] += z2 * z2; }
    if (biv) {
      double* p1 = b1[c].data(); double* p2 = b2[c].data();
      for (size_t i = 0; i < L; i++) {
        const double zi = z[i]; const double* zz = &z[i + 1]; double* a = p1 + i * W; double* b = p2 + i * W;
        for (int w = 0; w < W; w++) { double p = zi * zz[w]; a[w] += p; b[w] += p * p; }
      }
    }
  }
  auto welch = [&](double S0, double Q0, double S1, double Q1) {
    double m0 = S0 / n[0], m1 = S1 / n[1], v0 = Q0 / n[0] - m0 * m0, v1 = Q1 / n[1] - m1 * m1;
    double d = std::sqrt(v0 / n[0] + v1 / n[1]); return d > 1e-12 ? (m0 - m1) / d : 0.0; };
  std::vector<uint8_t> excl(L, 0);
  if (getenv("LEAK_EXCLUDE")) {
    FILE* f = fopen(getenv("LEAK_EXCLUDE"), "rb");
    if (!f || fread(excl.data(), 1, L, f) != L) { fprintf(stderr, "bad LEAK_EXCLUDE\n"); exit(4); }
    fclose(f);
  }
  double mx1 = 0, mx2 = 0, mxb = 0, ex1 = 0, ex2 = 0; long c1 = 0, c2 = 0, cb = 0, pairs = 0, ne = 0, ec1 = 0;
  for (size_t i = 0; i < L; i++) {
    double t1 = std::fabs(welch(s1[0][i], q1[0][i], s1[1][i], q1[1][i]));
    double t2 = std::fabs(welch(s2[0][i], q2[0][i], s2[1][i], q2[1][i]));
    if (excl[i]) { ne++; ex1 = std::max(ex1, t1); ex2 = std::max(ex2, t2); ec1 += t1 > 4.5; continue; }
    mx1 = std::max(mx1, t1); mx2 = std::max(mx2, t2); c1 += t1 > 4.5; c2 += t2 > 4.5;
    if (biv) for (int w = 0; w < W; w++) {
      if (i + 1 + w >= L) break;
      pairs++;
      double tb = std::fabs(welch(b1[0][i * W + w], b2[0][i * W + w], b1[1][i * W + w], b2[1][i * W + w]));
      mxb = std::max(mxb, tb); cb += tb > 4.5;
    }
  }
  printf("%s,%d,%zu,%ld,%d,%.2f,%ld,%.2f,%ld,%ld,%.2f,%ld,%d", tg.c_str(), (int)N, L, n[0] + n[1],
         biv ? W : -1, mx1, c1, mx2, c2, pairs, mxb, cb, (int)nullm);
  if (getenv("LEAK_EXCLUDE")) printf(",excluded=%ld,excl_max_t1=%.2f,excl_n_t1=%ld,excl_max_t2=%.2f", ne, ex1, ec1, ex2);
  printf("\n");
  fflush(stdout);
}

int main(int argc, char** argv) {
  if (argc < 5) { fprintf(stderr, "usage: leak_decaps <target> <N> <traces> <window> [null]\n"); return 2; }
  std::string tg = argv[1]; int N = atoi(argv[2]); long T = atol(argv[3]); int W = atoi(argv[4]);
  bool nullm = argc > 5 && atoi(argv[5]);
  if (argc > 6) { run_target<3>(tg, 1, false); printf("%zu\n", g_trace.size()); return 0; }
  switch (N) { case 2: run<2>(tg, T, W, nullm); break; case 3: run<3>(tg, T, W, nullm); break;
               case 4: run<4>(tg, T, W, nullm); break; default: return 2; }
}
