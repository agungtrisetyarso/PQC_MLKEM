// gen_dag.cpp — record the per-coefficient pipeline (A2B mod q + masked
// Compress_1) for N shares as a straight-line DAG (see record.hpp).
//   ./gen_dag <N> > dag_N<N>.txt          (N = 2..8)
#define MK_RECORD
#include <cstdio>
#include <cstdlib>
#include "masking.hpp"
using namespace mk;

template <size_t N> static void run() {
  rec::reset();
  Arith<N> w;
  for (int i = 0; i < (int)N; i++) w[i] = rec::input(i);
  Bool<N> m = compress1<N>(w);
  uint32_t out[N];
  for (int i = 0; i < (int)N; i++) out[i] = m[i];
  rec::dump(stdout, (int)N, out);
}

int main(int argc, char** argv) {
  int n = argc > 1 ? std::atoi(argv[1]) : 2;
  switch (n) {
    case 2: run<2>(); break; case 3: run<3>(); break; case 4: run<4>(); break;
    case 5: run<5>(); break; case 6: run<6>(); break; case 7: run<7>(); break;
    case 8: run<8>(); break;
    default: std::fprintf(stderr, "N must be 2..8\n"); return 1;
  }
}
