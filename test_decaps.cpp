// test_decaps.cpp — masked decapsulation gadgets against the unmasked FIPS 203
// reference, and the complete masked Decaps against NIST ACVP vectors.
//   ./test_decaps kat/acvp_mlkem.txt
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include "decaps.hpp"
using namespace mk;
using namespace mk::dc;
using fips203::Bytes;

static int fails = 0;
#define CHECK(c, what) do { if (!(c)) { if (fails++ < 12) printf("FAIL N=%d %s\n", (int)N, what); } } while (0)

template <size_t N> SB<N> share_bytes(const Bytes& b) {
  SB<N> s; for (auto& v : s) v.assign(b.size(), 0);
  for (size_t k = 0; k < b.size(); k++) { uint8_t acc = 0; for (size_t i = 1; i < N; i++) { s[i][k] = (uint8_t)rand32(); acc ^= s[i][k]; } s[0][k] = b[k] ^ acc; }
  return s;
}
template <size_t N> Bytes open_bytes(const SB<N>& s) {
  Bytes b(s[0].size(), 0); for (size_t i = 0; i < N; i++) for (size_t k = 0; k < b.size(); k++) b[k] ^= s[i][k]; return b;
}
static Bytes rbytes(size_t n) { Bytes b(n); for (auto& x : b) x = (uint8_t)rand32(); return b; }

template <size_t N> void gadgets() {
  // Keccak-f[1600]
  for (int t = 0; t < 20; t++) {
    uint64_t A[25]; std::array<W64<N>, 25> M;
    for (int i = 0; i < 25; i++) { A[i] = rnd<uint64_t>(); uint64_t acc = 0; for (size_t s = 1; s < N; s++) { M[i][s] = rnd<uint64_t>(); acc ^= M[i][s]; } M[i][0] = A[i] ^ acc; }
    fips203::keccak_f(A); keccak_f<N>(M);
    bool ok = true; for (int i = 0; i < 25; i++) ok &= bopen(M[i]) == A[i];
    CHECK(ok, "keccak_f");
  }
  // SHA3-512 (shared || public) and SHAKE256 (shared || public), several lengths
  for (size_t ls : {32u, 64u, 100u}) for (size_t lp : {0u, 32u, 1088u}) {
    Bytes a = rbytes(ls), b = rbytes(lp), ab = a; ab.insert(ab.end(), b.begin(), b.end());
    MSponge<N> g(72, 0x06); g.absorb_shared(share_bytes<N>(a)); g.absorb_public(b.data(), b.size()); g.finish();
    CHECK(open_bytes<N>(g.squeeze(64)) == fips203::sha3_512(ab), "sha3_512");
    MSponge<N> s(136, 0x1F); s.absorb_shared(share_bytes<N>(a)); s.absorb_public(b.data(), b.size()); s.finish();
    CHECK(open_bytes<N>(s.squeeze(300)) == fips203::shake256(ab, 300), "shake256");
  }
  // 1-bit B2A, both values, fresh sharings
  for (int t = 0; t < 400; t++) {
    uint32_t bit = t & 1; W32<N> b; uint32_t acc = 0;
    for (size_t i = 1; i < N; i++) { b[i] = rand32() & 1; acc ^= b[i]; }
    b[0] = bit ^ acc;
    CHECK(arith_unshare(b2a_bit<N>(b)) == bit, "b2a_bit");
    CHECK(arith_unshare(b2a_bit_cubic<N>(b)) == bit, "b2a_bit_cubic");
  }
  // CBD_eta
  for (int eta : {2, 3}) for (int t = 0; t < 4; t++) {
    Bytes B = rbytes(64 * eta); Poly ref = fips203::sample_cbd(B, eta);
    auto f = cbd<N>(share_bytes<N>(B), eta);
    bool ok = true; for (int c = 0; c < 256; c++) ok &= arith_unshare(f[c]) == ref[c];
    CHECK(ok, "cbd");
  }
  // SecAdd mod 2^K
  for (int K : {17, 20, 26, 27, 32}) for (int t = 0; t < 300; t++) {
    uint32_t M = K == 32 ? 0xFFFFFFFFu : (1u << K) - 1, x = rand32() & M, y = rand32() & M;
    W32<N> X{}, Y{}; uint32_t ax = 0, ay = 0;
    for (size_t i = 1; i < N; i++) { X[i] = rand32() & M; Y[i] = rand32() & M; ax ^= X[i]; ay ^= Y[i]; }
    X[0] = x ^ ax; Y[0] = y ^ ay;
    CHECK(bopen(sec_add_k<N>(X, Y, K)) == ((x + y) & M), "sec_add_k");
  }
  // Compress_d, exhaustive over Z_q, fresh sharing per value
  for (int d : {1, 4, 5, 10, 11}) {
    int bad = 0;
    for (uint32_t x = 0; x < Q; x++) bad += bopen(compress_d<N>(arith_share<N>(x), d)) != fips203::compress(x, d);
    CHECK(bad == 0, "compress_d");
  }
  printf("N=%d gadgets: %s\n", (int)N, fails ? "FAILURES" : "ok");
}

template <size_t N> int decaps_kat(const char* path, int& total) {
  std::ifstream in(path); std::string line; int bad = 0;
  while (std::getline(in, line)) {
    std::istringstream ss(line); std::string kind, param, tc, kv; ss >> kind >> param >> tc;
    if (kind != "decaps") continue;
    std::map<std::string, std::string> f;
    while (ss >> kv) { auto e = kv.find('='); f[kv.substr(0, e)] = kv.substr(e + 1); }
    const fips203::Params* P = fips203::params_by_name(param);
    MaskedDK<N> K = mask_dk<N>(*P, fips203::from_hex(f["dk"]));
    Bytes k = open_bytes<N>(decaps<N>(K, fips203::from_hex(f["c"])));
    bool ok = k == fips203::from_hex(f["k"]);
    bad += !ok; total++;
    if (!ok && bad < 4) printf("  FAIL N=%d %s tc %s (%s)\n", (int)N, param.c_str(), tc.c_str(), f["reason"].c_str());
  }
  return bad;
}

int main(int argc, char** argv) {
  const char* kat = argc > 1 ? argv[1] : "kat/acvp_mlkem.txt";
  gadgets<1>(); gadgets<2>(); gadgets<3>(); gadgets<4>(); gadgets<5>(); gadgets<6>();
  int total = 0, bad = 0;
  bad += decaps_kat<1>(kat, total); bad += decaps_kat<2>(kat, total); bad += decaps_kat<3>(kat, total);
  bad += decaps_kat<4>(kat, total); bad += decaps_kat<5>(kat, total); bad += decaps_kat<6>(kat, total);
  printf("masked Decaps vs ACVP (ML-KEM-512/768/1024, valid + modified ciphertexts), N = 1..6: %d / %d passed\n",
         total - bad, total);
  fails += bad;
  printf(fails ? "MASKED DECAPS TESTS FAILED (%d)\n" : "ALL MASKED DECAPS TESTS PASSED\n", fails);
  return fails != 0;
}
