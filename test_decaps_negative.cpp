// test_decaps_negative.cpp — negative controls for the KAT harness: each
// corruption must break exactly one path of Decaps.
//   z share bit flipped   -> rejection path wrong: valid pass, modified fail
//   s_hat share changed   -> decryption wrong, every ciphertext is rejected:
//                            valid fail, modified pass (K_bar still correct)
//   ek byte flipped       -> re-encryption never matches: valid fail,
//                            modified pass
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include "decaps.hpp"
using namespace mk; using namespace mk::dc; using fips203::Bytes;

template <size_t N> Bytes open_bytes(const SB<N>& s) {
  Bytes b(s[0].size(), 0); for (size_t i = 0; i < N; i++) for (size_t k = 0; k < b.size(); k++) b[k] ^= s[i][k]; return b;
}

int main(int argc, char** argv) {
  constexpr size_t N = 3;
  const char* kat = argc > 1 ? argv[1] : "kat/acvp_mlkem.txt";
  int res[3][2][2] = {};       // [control][reason valid/modified][pass/fail]
  std::ifstream in(kat); std::string line;
  while (std::getline(in, line)) {
    std::istringstream ss(line); std::string kind, param, tc, kv; ss >> kind >> param >> tc;
    if (kind != "decaps") continue;
    std::map<std::string, std::string> f;
    while (ss >> kv) { auto e = kv.find('='); f[kv.substr(0, e)] = kv.substr(e + 1); }
    const fips203::Params* P = fips203::params_by_name(param);
    Bytes dk = fips203::from_hex(f["dk"]), c = fips203::from_hex(f["c"]), k = fips203::from_hex(f["k"]);
    int r = f["reason"] == "valid" ? 0 : 1;
    for (int ctl = 0; ctl < 3; ctl++) {
      MaskedDK<N> K = mask_dk<N>(*P, dk);
      if (ctl == 0) K.z[1][5] ^= 0x10;
      if (ctl == 1) K.s_hat[0][2][17] = addq(K.s_hat[0][2][17], 1000);
      if (ctl == 2) K.ek[3] ^= 0x01;
      bool ok = open_bytes<N>(decaps<N>(K, c)) == k;
      res[ctl][r][ok ? 0 : 1]++;
    }
  }
  const char* name[3] = {"z share bit flipped", "s_hat share +1000", "ek byte flipped"};
  for (int ctl = 0; ctl < 3; ctl++)
    printf("%-22s valid: %2d pass %2d fail | modified: %2d pass %2d fail\n", name[ctl],
           res[ctl][0][0], res[ctl][0][1], res[ctl][1][0], res[ctl][1][1]);
  bool expected = res[0][0][1] == 0 && res[0][1][0] == 0 &&   // z: valid pass, modified fail
                  res[1][0][0] == 0 &&                        // s_hat: valid fail
                  res[2][0][0] == 0;                          // ek: valid fail
  printf(expected ? "NEGATIVE CONTROLS BEHAVE AS EXPECTED\n" : "NEGATIVE CONTROLS UNEXPECTED\n");
  return !expected;
}
