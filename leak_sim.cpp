// Simulated leakage assessment (TVLA, fixed-vs-random Welch t-test) of the
// masked nonlinear pipeline for one coefficient: w -> A2B -> Compress_1.
//
// The intermediates recorded by LK() in source execution order form a
// "register stream" v_0, v_1, ...  Three leakage models:
//   value      : l_t = HW(v_t)                          (probing model)
//   transition : l_t = HW(v_t) + HD(v_{t-1}, v_t)       (one shared register,
//                                                        source order)
//   precharge  : transition model, but the register is cleared to 0 between
//                consecutive writes (countermeasure)  => l_t = 2 HW(v_t), and
//                the clearing step leaks HW(v_t).
// Gaussian noise sigma = 1 is added to every sample.
//
// Tests: first-order univariate t on every sample; second-order univariate
// (centred square); and a bivariate centred-product test on chosen sample
// pairs.  Threshold |t| > 4.5.
#include <cmath>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>
#include "masking.hpp"
using namespace mk;

enum Model { VALUE, TRANSITION, PRECHARGE };
static const char* mname[] = {"value", "transition", "precharge"};

struct Welch {                                   // online mean/variance per class
  std::vector<double> n[2], mu[2], m2[2];
  void init(size_t L) { for (int c = 0; c < 2; c++) { n[c].assign(L, 0); mu[c].assign(L, 0); m2[c].assign(L, 0); } }
  void add(int c, size_t i, double x) { n[c][i]++; double dlt = x - mu[c][i]; mu[c][i] += dlt / n[c][i]; m2[c][i] += dlt * (x - mu[c][i]); }
  double t(size_t i) const {
    double v0 = m2[0][i] / (n[0][i] - 1), v1 = m2[1][i] / (n[1][i] - 1);
    double den = std::sqrt(v0 / n[0][i] + v1 / n[1][i]);
    return den > 0 ? (mu[0][i] - mu[1][i]) / den : 0.0;
  }
};

static std::mt19937_64 gen(std::random_device{}());
static std::normal_distribution<double> noise(0.0, 1.0);

template <std::size_t N> static std::vector<double> one_trace(uint32_t w, Model m) {
  Arith<N> a = arith_share<N>(w);
  g_trace.clear(); g_rec = true;
  for (int i = 0; i < (int)N; i++) LK(a[i]);           // shares loaded into the register
  Bool<N> out = compress1<N>(a);
  g_rec = false; (void)out;
  std::vector<double> s(g_trace.size());
  uint32_t prev = 0;
  for (size_t t = 0; t < g_trace.size(); t++) {
    uint32_t v = g_trace[t];
    double l = __builtin_popcount(v);
    if (m == TRANSITION) l += __builtin_popcount(v ^ prev);
    if (m == PRECHARGE)  l += __builtin_popcount(v);   // HD(0, v)
    s[t] = l + noise(gen);
    prev = v;
  }
  return s;
}

struct Result { size_t L; double max1, max2, maxbi; int n1, n2; size_t argmax1; };

// pairs: sample-index pairs for the bivariate test (indices into the trace).
template <std::size_t N> static Result tvla(Model m, int traces, const std::vector<std::pair<size_t,size_t>>& pairs) {
  // Pass 1: means per class (needed to centre for higher-order tests).
  size_t L = one_trace<N>(0, m).size();
  std::vector<double> mean[2]; mean[0].assign(L, 0); mean[1].assign(L, 0);
  int cnt[2] = {0, 0};
  const uint32_t FIXED = 1665;
  for (int k = 0; k < traces; k++) {
    int c = k & 1; uint32_t w = c ? rand_q() : FIXED;
    auto s = one_trace<N>(w, m); cnt[c]++;
    for (size_t i = 0; i < L; i++) mean[c][i] += s[i];
  }
  for (int c = 0; c < 2; c++) for (auto& x : mean[c]) x /= cnt[c];
  // Pass 2: fresh traces; first-order, centred-square and bivariate statistics.
  Welch W1, W2, WB; W1.init(L); W2.init(L); WB.init(pairs.size());
  for (int k = 0; k < traces; k++) {
    int c = k & 1; uint32_t w = c ? rand_q() : FIXED;
    auto s = one_trace<N>(w, m);
    for (size_t i = 0; i < L; i++) { W1.add(c, i, s[i]); double z = s[i] - mean[c][i]; W2.add(c, i, z * z); }
    for (size_t p = 0; p < pairs.size(); p++)
      WB.add(c, p, (s[pairs[p].first] - mean[c][pairs[p].first]) * (s[pairs[p].second] - mean[c][pairs[p].second]));
  }
  Result r{L, 0, 0, 0, 0, 0, 0};
  for (size_t i = 0; i < L; i++) {
    double a = std::fabs(W1.t(i)), b = std::fabs(W2.t(i));
    if (a > r.max1) { r.max1 = a; r.argmax1 = i; }
    r.max2 = std::max(r.max2, b); r.n1 += a > 4.5; r.n2 += b > 4.5;
  }
  for (size_t p = 0; p < pairs.size(); p++) r.maxbi = std::max(r.maxbi, std::fabs(WB.t(p)));
  return r;
}

template <std::size_t N> static void run(int traces) {
  // Bivariate pairs: the N arithmetic shares are the first N samples; pair
  // share 0 with share 1 (for N = 2 this pair jointly determines w).
  std::vector<std::pair<size_t,size_t>> pairs = {{0, 1}};
  for (Model m : {VALUE, TRANSITION, PRECHARGE}) {
    Result r = tvla<N>(m, traces, pairs);
    printf("%d,%s,%zu,%d,%.1f,%d,%zu,%.1f,%d,%.1f\n", (int)N - 1, mname[m], r.L, traces,
           r.max1, r.n1, r.argmax1, r.max2, r.n2, r.maxbi);
    fflush(stdout);
  }
}

int main(int argc, char** argv) {
  int traces = argc > 1 ? atoi(argv[1]) : 20000;
  printf("d,model,trace_len,traces,max_t1,n_t1_over_4.5,argmax_t1,max_t2,n_t2_over_4.5,max_t_bivariate_s0s1\n");
  run<1>(traces); run<2>(traces); run<3>(traces); run<4>(traces);
}
