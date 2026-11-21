// ops.hpp — the share-level operations every gadget is written in.
//
// Host and default target builds: plain C++ through the LK() hook (a compiler
// barrier, or a recorder under -DLEAKSIM).
//
// -DMK_PRECHARGE (Cortex-M4): each operation is one volatile inline-asm block
// that clears its destination register, performs the operation, and then
// precharges the result bus, both operand buses and both memory buses:
//     mov %0,#0 ; <op> ; mov r12,#0 ; eor r12,r12,r12 ; str r12,[sp,#-4] ; ldr r12,[sp,#-4]
// Volatile asm blocks keep their program order, so the compiler cannot
// schedule two share operations next to each other without the precharge
// between them, which it did when precharge was attached to values instead
// of operations.  Compiler-generated moves, spills and reloads are outside
// these blocks; the instruction-level TVLA measures what they still leak.
#pragma once
#include <stdint.h>
#include "leak.hpp"

namespace mk {

#if defined(MK_RECORD)
}  // namespace mk
#include "record.hpp"
namespace mk {
inline uint32_t x_and(uint32_t a, uint32_t b) { return rec::bin(rec::AND, a, b); }
inline uint32_t x_xor(uint32_t a, uint32_t b) { return rec::bin(rec::XOR, a, b); }
inline uint32_t x_shl16(uint32_t a, uint32_t s) { return rec::un(rec::SHL16, a, s); }
inline uint32_t x_bcast15(uint32_t a) { return rec::un(rec::BCAST15, a); }
inline uint32_t x_bit15(uint32_t a) { return rec::un(rec::BIT15, a); }
inline uint32_t x_and1(uint32_t a) { return rec::un(rec::AND1, a); }
inline uint32_t x_mov(uint32_t a) { return rec::un(rec::MOV, a); }
inline uint32_t x_ld(const uint32_t* p) { return *p; }
inline uint32_t rand16() { return rec::rand16(); }
#elif defined(MK_PRECHARGE)
// After the operation: zero the result bus and both operand buses, then the
// memory write and read buses through a dead word just below SP.
#define MK_PC "\n\tmov.w r12, #0\n\teor.w r12, r12, r12" \
              "\n\tstr r12, [sp, #-4]\n\tldr r12, [sp, #-4]"
// Before the operation: clear the destination register, so the write does
// not overwrite another share (register-overwrite transition).
#define MK_Z "mov.w %0, #0\n\t"
#define MK_INL static inline __attribute__((always_inline))
MK_INL uint32_t x_and(uint32_t a, uint32_t b) {
  uint32_t r; __asm__ volatile(MK_Z "and.w %0, %1, %2" MK_PC : "=&r"(r) : "r"(a), "r"(b) : "r12"); return r;
}
MK_INL uint32_t x_xor(uint32_t a, uint32_t b) {
  uint32_t r; __asm__ volatile(MK_Z "eor.w %0, %1, %2" MK_PC : "=&r"(r) : "r"(a), "r"(b) : "r12"); return r;
}
MK_INL uint32_t x_shl16(uint32_t a, uint32_t s) {          // (a << s) mod 2^16
  uint32_t r; __asm__ volatile(MK_Z "lsl.w %0, %1, %2\n\tuxth %0, %0" MK_PC : "=&r"(r) : "r"(a), "r"(s) : "r12"); return r;
}
MK_INL uint32_t x_bcast15(uint32_t a) {                     // bit 15 broadcast to 16 bits
  uint32_t r; __asm__ volatile(MK_Z "sbfx %0, %1, #15, #1\n\tuxth %0, %0" MK_PC : "=&r"(r) : "r"(a) : "r12"); return r;
}
MK_INL uint32_t x_bit15(uint32_t a) {                       // bit 15 to bit 0
  uint32_t r; __asm__ volatile(MK_Z "ubfx %0, %1, #15, #1" MK_PC : "=&r"(r) : "r"(a) : "r12"); return r;
}
MK_INL uint32_t x_and1(uint32_t a) {
  uint32_t r; __asm__ volatile(MK_Z "and.w %0, %1, #1" MK_PC : "=&r"(r) : "r"(a) : "r12"); return r;
}
// Load of a share: clear the destination, load, precharge.
MK_INL uint32_t x_ld(const uint32_t* p) {
  uint32_t r; __asm__ volatile(MK_Z "ldr %0, [%1]" MK_PC : "=&r"(r) : "r"(p), "m"(*p) : "r12"); return r;
}
MK_INL uint32_t x_mov(uint32_t a) {
  uint32_t r; __asm__ volatile(MK_Z "mov %0, %1" MK_PC : "=&r"(r) : "r"(a) : "r12"); return r;
}
#undef MK_INL
#endif
#if !defined(MK_RECORD) && !defined(MK_PRECHARGE)
inline uint32_t x_and(uint32_t a, uint32_t b) { return LK(a & b); }
inline uint32_t x_xor(uint32_t a, uint32_t b) { return LK(a ^ b); }
inline uint32_t x_shl16(uint32_t a, uint32_t s) { return LK((a << s) & 0xFFFFu); }
inline uint32_t x_bcast15(uint32_t a) { return LK((0u - ((a >> 15) & 1u)) & 0xFFFFu); }
inline uint32_t x_bit15(uint32_t a) { return LK((a >> 15) & 1u); }
inline uint32_t x_and1(uint32_t a) { return LK(a & 1u); }
inline uint32_t x_mov(uint32_t a) { return LK(a); }
inline uint32_t x_ld(const uint32_t* p) { return *p; }
#endif
#if !defined(MK_RECORD)
// Fresh 16-bit mask word.  Defined here so every build consumes randomness
// through one call, in the same order (the generated assembly relies on it).
inline uint32_t rand16() { return rand32() & 0xFFFFu; }
#endif

}  // namespace mk
