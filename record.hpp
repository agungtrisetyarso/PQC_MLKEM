// record.hpp — symbolic execution of the gadgets (-DMK_RECORD, host only).
//
// Every value is a uint32_t that is either a public constant (< 2^31) or a
// node handle (bit 31 set).  Running a gadget in this mode records its exact
// straight-line program, in source order, as a DAG over the eight share
// primitives plus RAND16 and INPUT.  target/shgen.py turns that DAG into
// Cortex-M4 assembly, so the gadget source stays the single definition of
// the computation and clang never schedules or spills a share.
#pragma once
#include <stdint.h>
#include <cstdio>
#include <vector>

namespace mk::rec {

enum Op : int { INPUT, RAND16, AND, XOR, SHL16, BCAST15, BIT15, AND1, MOV };
inline const char* op_name[] = {"INPUT", "RAND16", "AND", "XOR", "SHL16", "BCAST15", "BIT15", "AND1", "MOV"};

struct Node { Op op; uint32_t a, b; uint32_t param; };   // a, b: operand handles or constants
inline std::vector<Node> nodes;
inline uint32_t n_rand = 0;

constexpr uint32_t TAG = 0x80000000u;
inline bool is_node(uint32_t v) { return (v & TAG) != 0; }
inline uint32_t mk_node(Op op, uint32_t a, uint32_t b, uint32_t param) {
  nodes.push_back({op, a, b, param});
  return TAG | (uint32_t)(nodes.size() - 1);
}

inline void reset() { nodes.clear(); n_rand = 0; }
inline uint32_t input(uint32_t i) { return mk_node(INPUT, 0, 0, i); }
inline uint32_t rand16() { return mk_node(RAND16, 0, 0, n_rand++); }

// Binary op with folding only when both operands are public constants, or
// when an operand is the constant 0 and the result is trivially known.
inline uint32_t bin(Op op, uint32_t a, uint32_t b) {
  if (!is_node(a) && !is_node(b)) return op == AND ? (a & b) : (a ^ b);
  if (op == XOR) { if (a == 0) return b; if (b == 0) return a; }
  if (op == AND && (a == 0 || b == 0)) return 0;
  return mk_node(op, a, b, 0);
}
inline uint32_t un(Op op, uint32_t a, uint32_t param = 0) {
  if (!is_node(a)) {
    switch (op) {
      case SHL16:   return (a << param) & 0xFFFFu;
      case BCAST15: return (0u - ((a >> 15) & 1u)) & 0xFFFFu;
      case BIT15:   return (a >> 15) & 1u;
      case AND1:    return a & 1u;
      default:      return a;
    }
  }
  return mk_node(op, a, 0, param);
}

inline void dump(FILE* f, int N, const uint32_t* out) {
  std::fprintf(f, "# shares %d nodes %zu rand %u\n", N, nodes.size(), n_rand);
  auto opnd = [&](uint32_t v) { static char buf[2][24]; static int k; k ^= 1;
    if (is_node(v)) std::snprintf(buf[k], 24, "n%u", v & ~TAG); else std::snprintf(buf[k], 24, "c%u", v);
    return buf[k]; };
  for (size_t i = 0; i < nodes.size(); i++) {
    const Node& n = nodes[i];
    std::fprintf(f, "%zu %s %s %s %u\n", i, op_name[n.op], opnd(n.a), opnd(n.b), n.param);
  }
  std::fprintf(f, "out");
  for (int i = 0; i < N; i++) std::fprintf(f, " %s", opnd(out[i]));
  std::fprintf(f, "\n");
}

}  // namespace mk::rec
