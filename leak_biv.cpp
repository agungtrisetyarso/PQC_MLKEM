// Bivariate second-order TVLA (centred product) over all sample pairs within
// distance W, for the nonlinear pipeline of one coefficient.  Shows whether
// two samples jointly reveal the secret, i.e. whether a d = 2 implementation
// keeps order 2 under each leakage model.
//
// Usage: leak_biv <d> <model 0|1|2> <traces> <window>
//   window 0 = every pair of samples (exhaustive second-order test).
//   LEAKBIV_NULL=1: both classes random (null calibration).
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>
#include "masking.hpp"
using namespace mk;

static std::mt19937_64 gen(std::random_device{}());
static std::normal_distribution<double> noise(0.0, 1.0);

template <std::size_t N> static void trace(uint32_t w, int model, std::vector<double>& s) {
  Arith<N> a = arith_share<N>(w);
  g_trace.clear(); g_rec = true;
  for (int i = 0; i < (int)N; i++) LK(a[i]);
  Bool<N> out = compress1<N>(a); (void)out;
  g_rec = false;
  s.resize(g_trace.size()); uint32_t prev = 0;
  for (size_t t = 0; t < g_trace.size(); t++) {
    uint32_t v = g_trace[t]; double l = __builtin_popcount(v);
    if (model == 1) l += __builtin_popcount(v ^ prev);
    if (model == 2) l += __builtin_popcount(v);
    s[t] = l + noise(gen); prev = v;
  }
}

template <std::size_t N> static void run(int model, long T, int W) {
  const uint32_t FIXED = 1665;
  std::vector<double> s; trace<N>(0, model, s); const size_t L = s.size();
  std::vector<double> mu[2]; mu[0].assign(L, 0); mu[1].assign(L, 0); long cnt[2] = {0, 0};
  const bool null_mode = getenv("LEAKBIV_NULL") && atoi(getenv("LEAKBIV_NULL"));
  if (W <= 0) W = (int)L - 1;
  for (long k = 0; k < T; k++) { int c = k & 1; trace<N>((c || null_mode) ? rand_q() : FIXED, model, s); cnt[c]++; for (size_t i = 0; i < L; i++) mu[c][i] += s[i]; }
  for (int c = 0; c < 2; c++) for (auto& x : mu[c]) x /= cnt[c];
  const size_t P = L * W;
  std::vector<double> S1[2], S2[2]; for (int c = 0; c < 2; c++) { S1[c].assign(P, 0); S2[c].assign(P, 0); }
  long n[2] = {0, 0}; std::vector<double> z(L + W, 0.0);
  for (long k = 0; k < T; k++) {
    int c = k & 1; trace<N>((c || null_mode) ? rand_q() : FIXED, model, s); n[c]++;
    for (size_t i = 0; i < L; i++) z[i] = s[i] - mu[c][i];
    double* a1 = S1[c].data(); double* a2 = S2[c].data();
    for (size_t i = 0; i < L; i++) {
      const double zi = z[i]; double* p1 = a1 + i * W; double* p2 = a2 + i * W; const double* zz = &z[i + 1];
      for (int w = 0; w < W; w++) { double p = zi * zz[w]; p1[w] += p; p2[w] += p * p; }
    }
  }
  double maxt = 0; size_t arg = 0; long over = 0, tested = 0;
  for (size_t i = 0; i < L; i++) for (int w = 0; w < W; w++) {
    if (i + 1 + w >= L) continue;
    size_t q = i * W + w; tested++;
    double m0 = S1[0][q] / n[0], m1 = S1[1][q] / n[1];
    double v0 = S2[0][q] / n[0] - m0 * m0, v1 = S2[1][q] / n[1] - m1 * m1;
    double t = (m0 - m1) / std::sqrt(v0 / n[0] + v1 / n[1]);
    if (std::fabs(t) > maxt) { maxt = std::fabs(t); arg = q; }
    over += std::fabs(t) > 4.5;
  }
  const char* mn[] = {"value", "transition", "precharge"};
  printf("%d,%s,%zu,%ld,%d,%ld,%.1f,%ld,(%zu;%zu)\n", (int)N - 1, mn[model], L, T, W, tested, maxt, over,
         arg / W, arg / W + 1 + arg % W);
  fflush(stdout);
}

int main(int argc, char** argv) {
  int d = atoi(argv[1]), model = atoi(argv[2]); long T = atol(argv[3]); int W = atoi(argv[4]);
  if (d == 1) run<2>(model, T, W); else if (d == 2) run<3>(model, T, W); else if (d == 3) run<4>(model, T, W);
}
