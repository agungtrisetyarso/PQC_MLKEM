// Correctness of every gadget at N = 1..8 shares against unmasked arithmetic.
#include <cstdio>
#include "masking.hpp"
using namespace mk;

static int fails = 0;
#define CHECK(c) do { if (!(c)) { if (fails++ < 10) printf("FAIL N=%d line %d\n", (int)N, __LINE__); } } while (0)

static uint32_t compress1_ref(uint32_t x) {           // FIPS 203 rounding
  return ((2 * x + Q / 2) / Q) & 1;                     // round(2x/q) mod 2
}

template <std::size_t N> void run(int iters) {
  for (int it = 0; it < iters; it++) {
    uint32_t x = rand32() & KMASK, y = rand32() & KMASK;
    CHECK(bool_unshare(sec_and(bool_share<N>(x), bool_share<N>(y))) == (x & y));
    CHECK(bool_unshare(sec_add(bool_share<N>(x), bool_share<N>(y))) == ((x + y) & KMASK));
    uint32_t a = rand_q(), b = rand_q();
    CHECK(bool_unshare(sec_add_modq(bool_share<N>(a), bool_share<N>(b))) == (a + b) % Q);
    Arith<N> A = arith_share<N>(a);
    CHECK(arith_unshare(A) == a);
    CHECK(bool_unshare(a2b<N>(A.data())) == a);
    CHECK(bool_unshare(compress1(A)) == compress1_ref(a));
  }
  // Exhaustive Compress_1 over all of Z_q.
  for (uint32_t v = 0; v < Q; v++) CHECK(bool_unshare(compress1(arith_share<N>(v))) == compress1_ref(v));
  printf("N=%d (d=%d): ok so far, fails=%d\n", (int)N, (int)N - 1, fails);
}

int main() {
  run<1>(20000); run<2>(20000); run<3>(20000); run<4>(10000);
  run<5>(5000);  run<6>(5000);  run<7>(3000);  run<8>(3000);
  printf(fails ? "GADGET TESTS FAILED (%d)\n" : "ALL GADGET TESTS PASSED\n", fails);
  return fails != 0;
}
