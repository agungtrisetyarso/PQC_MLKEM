// test_fips203.cpp — the unmasked reference against every NIST ACVP ML-KEM
// vector (key generation, encapsulation, decapsulation incl. modified
// ciphertexts), plus SHA-3 / SHAKE known answers.
//   ./test_fips203 kat/acvp_mlkem.txt
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include "fips203.hpp"
using namespace fips203;

static std::string hex(const Bytes& b) { static const char* h = "0123456789ABCDEF"; std::string s;
  for (uint8_t x : b) { s += h[x >> 4]; s += h[x & 15]; } return s; }

int main(int argc, char** argv) {
  int fails = 0;
  // SHA-3 known answers (FIPS 202 examples): empty input.
  if (hex(sha3_256({})) != "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A") { puts("SHA3-256 KAT FAIL"); fails++; }
  if (hex(sha3_512({})).substr(0, 32) != "A69F73CCA23A9AC5C8B567DC185A756E") { puts("SHA3-512 KAT FAIL"); fails++; }
  if (hex(shake256({}, 32)) != "46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762F") { puts("SHAKE256 KAT FAIL"); fails++; }
  std::ifstream in(argc > 1 ? argv[1] : "kat/acvp_mlkem.txt");
  std::string line; std::map<std::string, std::pair<int, int>> tally;   // kind/param -> (pass, total)
  while (std::getline(in, line)) {
    std::istringstream ss(line); std::string kind, param, tc, kv; ss >> kind >> param >> tc;
    std::map<std::string, std::string> f;
    while (ss >> kv) { auto e = kv.find('='); f[kv.substr(0, e)] = kv.substr(e + 1); }
    const Params* P = params_by_name(param); bool ok = false;
    if (kind == "keygen") {
      KeyPair kp = keygen(*P, from_hex(f["d"]).data(), from_hex(f["z"]).data());
      ok = kp.ek == from_hex(f["ek"]) && kp.dk == from_hex(f["dk"]);
    } else if (kind == "encaps") {
      Bytes K, c; encaps(*P, from_hex(f["ek"]), from_hex(f["m"]).data(), K, c);
      ok = K == from_hex(f["k"]) && c == from_hex(f["c"]);
    } else if (kind == "decaps") {
      ok = decaps(*P, from_hex(f["dk"]), from_hex(f["c"])) == from_hex(f["k"]);
      kind += "/" + f["reason"];
    }
    auto& t = tally[kind + " " + param]; t.second++; t.first += ok;
    if (!ok && fails++ < 5) printf("FAIL %s %s tc %s\n", kind.c_str(), param.c_str(), tc.c_str());
  }
  int total = 0;
  for (auto& [k, v] : tally) { printf("  %-28s %3d / %3d\n", k.c_str(), v.first, v.second); total += v.second; }
  printf(fails ? "FIPS 203 REFERENCE: %d FAILURES\n" : "FIPS 203 REFERENCE: ALL %d ACVP VECTORS PASSED\n", fails ? fails : total);
  return fails != 0;
}
