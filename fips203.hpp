// fips203.hpp — unmasked ML-KEM (FIPS 203) reference: Keccak / SHA-3 / SHAKE,
// K-PKE and ML-KEM key generation, encapsulation and decapsulation for
// ML-KEM-512, -768 and -1024.  Checked against NIST ACVP vectors
// (test_fips203.cpp).  It is the ground truth for the masked decapsulation;
// it is not hardened and must not process secrets in a deployment.
#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "mlkem.hpp"

namespace fips203 {

using Bytes = std::vector<uint8_t>;
using mk::Poly;
using mk::Q;

// ------------------------------------------------------------- Keccak ----
inline const uint64_t KECCAK_RC[24] = {
  0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808Aull, 0x8000000080008000ull,
  0x000000000000808Bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
  0x000000000000008Aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000Aull,
  0x000000008000808Bull, 0x800000000000008Bull, 0x8000000000008089ull, 0x8000000000008003ull,
  0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800Aull, 0x800000008000000Aull,
  0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull};
// rho offsets r[x][y], lane index x + 5y
inline const int KECCAK_RHO[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
                                   41, 45, 15, 21, 8, 18, 2, 61, 56, 14};
inline uint64_t rol64(uint64_t v, int r) { return r ? (v << r) | (v >> (64 - r)) : v; }

inline void keccak_f(uint64_t A[25]) {
  for (int round = 0; round < 24; round++) {
    uint64_t C[5], D[5], B[25];
    for (int x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (int x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rol64(C[(x + 1) % 5], 1);
    for (int i = 0; i < 25; i++) A[i] ^= D[i % 5];
    for (int x = 0; x < 5; x++)
      for (int y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rol64(A[x + 5 * y], KECCAK_RHO[x + 5 * y]);
    for (int x = 0; x < 5; x++)
      for (int y = 0; y < 5; y++) A[x + 5 * y] = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
    A[0] ^= KECCAK_RC[round];
  }
}

// Sponge with domain byte (0x06 for SHA-3, 0x1F for SHAKE).
struct Sponge {
  uint64_t A[25]; size_t rate, pos; bool squeezing; uint8_t dom;
  Sponge(size_t rate_bytes, uint8_t domain) : rate(rate_bytes), pos(0), squeezing(false), dom(domain) { std::memset(A, 0, sizeof A); }
  void xor_byte(size_t i, uint8_t b) { A[i / 8] ^= (uint64_t)b << (8 * (i % 8)); }
  uint8_t get_byte(size_t i) const { return (uint8_t)(A[i / 8] >> (8 * (i % 8))); }
  void absorb(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i++) { xor_byte(pos++, p[i]); if (pos == rate) { keccak_f(A); pos = 0; } }
  }
  void finish() { xor_byte(pos, dom); xor_byte(rate - 1, 0x80); keccak_f(A); pos = 0; squeezing = true; }
  void squeeze(uint8_t* out, size_t n) {
    if (!squeezing) finish();
    for (size_t i = 0; i < n; i++) { if (pos == rate) { keccak_f(A); pos = 0; } out[i] = get_byte(pos++); }
  }
};
inline Bytes sha3_256(const Bytes& m) { Sponge s(136, 0x06); s.absorb(m.data(), m.size()); Bytes o(32); s.squeeze(o.data(), 32); return o; }
inline Bytes sha3_512(const Bytes& m) { Sponge s(72, 0x06); s.absorb(m.data(), m.size()); Bytes o(64); s.squeeze(o.data(), 64); return o; }
inline Bytes shake256(const Bytes& m, size_t n) { Sponge s(136, 0x1F); s.absorb(m.data(), m.size()); Bytes o(n); s.squeeze(o.data(), n); return o; }

// ------------------------------------------------------------- params ----
struct Params { const char* name; int k, eta1, eta2, du, dv; };
inline const Params P512 = {"ML-KEM-512", 2, 3, 2, 10, 4};
inline const Params P768 = {"ML-KEM-768", 3, 2, 2, 10, 4};
inline const Params P1024 = {"ML-KEM-1024", 4, 2, 2, 11, 5};
inline const Params* params_by_name(const std::string& n) {
  for (const Params* p : {&P512, &P768, &P1024}) if (n == p->name) return p;
  return nullptr;
}

// ------------------------------------------------------ encode/decode ----
inline uint32_t compress(uint32_t x, int d) { return (uint32_t)((((uint64_t)x << d) + Q / 2) / Q) & ((1u << d) - 1); }
inline uint32_t decompress(uint32_t y, int d) { return (uint32_t)(((uint64_t)y * Q + (1u << (d - 1))) >> d); }

inline void byte_encode(const Poly& f, int d, uint8_t* out) {          // 32 d bytes
  std::memset(out, 0, 32 * d);
  for (int i = 0; i < 256; i++)
    for (int j = 0; j < d; j++) { int b = i * d + j; out[b / 8] |= ((f[i] >> j) & 1) << (b % 8); }
}
inline Poly byte_decode(const uint8_t* in, int d) {
  Poly f{};
  for (int i = 0; i < 256; i++) {
    uint32_t v = 0;
    for (int j = 0; j < d; j++) { int b = i * d + j; v |= (uint32_t)((in[b / 8] >> (b % 8)) & 1) << j; }
    f[i] = d == 12 ? v % Q : v;
  }
  return f;
}

// --------------------------------------------------------------- sampling --
inline Poly sample_ntt(const uint8_t rho[32], uint8_t j, uint8_t i) {
  Sponge s(168, 0x1F); uint8_t b[34]; std::memcpy(b, rho, 32); b[32] = j; b[33] = i; s.absorb(b, 34);
  Poly a{}; int n = 0; uint8_t c[3];
  while (n < 256) {
    s.squeeze(c, 3);
    uint32_t d1 = c[0] + 256u * (c[1] & 15), d2 = (c[1] >> 4) + 16u * c[2];
    if (d1 < Q) a[n++] = d1;
    if (d2 < Q && n < 256) a[n++] = d2;
  }
  return a;
}
inline Poly sample_cbd(const Bytes& B, int eta) {
  Poly f{};
  auto bit = [&](int i) { return (B[i / 8] >> (i % 8)) & 1; };
  for (int i = 0; i < 256; i++) {
    int x = 0, y = 0;
    for (int j = 0; j < eta; j++) { x += bit(2 * i * eta + j); y += bit(2 * i * eta + eta + j); }
    f[i] = (uint32_t)((x - y + (int)Q) % (int)Q);
  }
  return f;
}
inline Bytes prf(const uint8_t s[32], uint8_t b, int eta) {
  Bytes in(s, s + 32); in.push_back(b); return shake256(in, 64 * eta);
}

// ------------------------------------------------------------------ K-PKE --
struct KeyPair { Bytes ek, dk; };

inline KeyPair kpke_keygen(const Params& P, const uint8_t d[32]) {
  Bytes in(d, d + 32); in.push_back((uint8_t)P.k);
  Bytes g = sha3_512(in); const uint8_t *rho = g.data(), *sigma = g.data() + 32;
  int k = P.k; uint8_t N = 0;
  std::vector<Poly> s(k), e(k), t(k);
  for (int i = 0; i < k; i++) { s[i] = sample_cbd(prf(sigma, N++, P.eta1), P.eta1); }
  for (int i = 0; i < k; i++) { e[i] = sample_cbd(prf(sigma, N++, P.eta1), P.eta1); }
  for (int i = 0; i < k; i++) { mk::ntt(s[i]); mk::ntt(e[i]); }
  for (int i = 0; i < k; i++) {
    t[i] = Poly{};
    for (int j = 0; j < k; j++) mk::basemul_acc(t[i], sample_ntt(rho, (uint8_t)j, (uint8_t)i), s[j]);
    for (int c = 0; c < 256; c++) t[i][c] = mk::addq(t[i][c], e[i][c]);
  }
  KeyPair kp; kp.ek.resize(384 * k + 32); kp.dk.resize(384 * k);
  for (int i = 0; i < k; i++) { byte_encode(t[i], 12, &kp.ek[384 * i]); byte_encode(s[i], 12, &kp.dk[384 * i]); }
  std::memcpy(&kp.ek[384 * k], rho, 32);
  return kp;
}

inline Bytes kpke_encrypt(const Params& P, const Bytes& ek, const uint8_t m[32], const uint8_t r[32]) {
  int k = P.k; uint8_t N = 0; const uint8_t* rho = &ek[384 * k];
  std::vector<Poly> t(k), y(k), e1(k), u(k);
  for (int i = 0; i < k; i++) t[i] = byte_decode(&ek[384 * i], 12);
  for (int i = 0; i < k; i++) y[i] = sample_cbd(prf(r, N++, P.eta1), P.eta1);
  for (int i = 0; i < k; i++) e1[i] = sample_cbd(prf(r, N++, P.eta2), P.eta2);
  Poly e2 = sample_cbd(prf(r, N++, P.eta2), P.eta2);
  for (int i = 0; i < k; i++) mk::ntt(y[i]);
  for (int i = 0; i < k; i++) {
    u[i] = Poly{};
    for (int j = 0; j < k; j++) mk::basemul_acc(u[i], sample_ntt(rho, (uint8_t)i, (uint8_t)j), y[j]);   // A^T
    mk::intt(u[i]);
    for (int c = 0; c < 256; c++) u[i][c] = mk::addq(u[i][c], e1[i][c]);
  }
  Poly v{};
  for (int j = 0; j < k; j++) mk::basemul_acc(v, t[j], y[j]);
  mk::intt(v);
  for (int c = 0; c < 256; c++) {
    uint32_t mu = decompress((m[c / 8] >> (c % 8)) & 1, 1);
    v[c] = mk::addq(mk::addq(v[c], e2[c]), mu);
  }
  Bytes c(32 * (P.du * k + P.dv));
  for (int i = 0; i < k; i++) {
    Poly cu; for (int j = 0; j < 256; j++) cu[j] = compress(u[i][j], P.du);
    byte_encode(cu, P.du, &c[32 * P.du * i]);
  }
  Poly cv; for (int j = 0; j < 256; j++) cv[j] = compress(v[j], P.dv);
  byte_encode(cv, P.dv, &c[32 * P.du * k]);
  return c;
}

// Ciphertext -> (u_hat, v) as used by the decryption core.
inline void kpke_decode_ct(const Params& P, const Bytes& c, std::vector<Poly>& u_hat, Poly& v) {
  int k = P.k; u_hat.resize(k);
  for (int i = 0; i < k; i++) {
    Poly cu = byte_decode(&c[32 * P.du * i], P.du);
    for (int j = 0; j < 256; j++) u_hat[i][j] = decompress(cu[j], P.du);
    mk::ntt(u_hat[i]);
  }
  Poly cv = byte_decode(&c[32 * P.du * k], P.dv);
  for (int j = 0; j < 256; j++) v[j] = decompress(cv[j], P.dv);
}

inline void kpke_decrypt(const Params& P, const Bytes& dk, const Bytes& c, uint8_t m[32]) {
  int k = P.k; std::vector<Poly> u_hat; Poly v; kpke_decode_ct(P, c, u_hat, v);
  Poly w{};
  for (int i = 0; i < k; i++) mk::basemul_acc(w, byte_decode(&dk[384 * i], 12), u_hat[i]);
  mk::intt(w);
  std::memset(m, 0, 32);
  for (int j = 0; j < 256; j++) m[j / 8] |= compress(mk::subq(v[j], w[j]), 1) << (j % 8);
}

// ----------------------------------------------------------------- ML-KEM --
inline KeyPair keygen(const Params& P, const uint8_t d[32], const uint8_t z[32]) {
  KeyPair p = kpke_keygen(P, d);
  Bytes h = sha3_256(p.ek);
  KeyPair out; out.ek = p.ek;
  out.dk = p.dk; out.dk.insert(out.dk.end(), p.ek.begin(), p.ek.end());
  out.dk.insert(out.dk.end(), h.begin(), h.end()); out.dk.insert(out.dk.end(), z, z + 32);
  return out;
}
inline void encaps(const Params& P, const Bytes& ek, const uint8_t m[32], Bytes& K, Bytes& c) {
  Bytes in(m, m + 32); Bytes h = sha3_256(ek); in.insert(in.end(), h.begin(), h.end());
  Bytes g = sha3_512(in);
  K.assign(g.begin(), g.begin() + 32);
  c = kpke_encrypt(P, ek, m, g.data() + 32);
}
inline Bytes decaps(const Params& P, const Bytes& dk, const Bytes& c) {
  int k = P.k;
  Bytes dkp(dk.begin(), dk.begin() + 384 * k), ek(dk.begin() + 384 * k, dk.begin() + 768 * k + 32);
  const uint8_t* h = &dk[768 * k + 32]; const uint8_t* z = &dk[768 * k + 64];
  uint8_t m[32]; kpke_decrypt(P, dkp, c, m);
  Bytes in(m, m + 32); in.insert(in.end(), h, h + 32);
  Bytes g = sha3_512(in);
  Bytes jin(z, z + 32); jin.insert(jin.end(), c.begin(), c.end());
  Bytes Kbar = shake256(jin, 32);
  Bytes c2 = kpke_encrypt(P, ek, m, g.data() + 32);
  return c2 == c ? Bytes(g.begin(), g.begin() + 32) : Kbar;
}

inline Bytes from_hex(const std::string& s) {
  Bytes b(s.size() / 2);
  for (size_t i = 0; i < b.size(); i++) b[i] = (uint8_t)std::stoul(s.substr(2 * i, 2), nullptr, 16);
  return b;
}

}  // namespace fips203
