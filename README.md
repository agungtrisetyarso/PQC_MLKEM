# Compiler-aware certification of higher-order masked ML-KEM decapsulation

Research artifact for the manuscript `paper/manuscript.tex`:
"Compiler-Aware Certification of Higher-Order Masked Post-Quantum
Cryptography: A Binary-Level Security Analysis of ML-KEM Decapsulation".

Everything here concerns an **emulated Cortex-M4 and an instruction-level
leakage model. No physical measurement has been made.**
`review/physical_validation_protocol.md` says what a measurement campaign
should do and what the emulator predicts.

## What is in the archive

1. **The source** (`decaps.hpp`): a complete arbitrary-order masked ML-KEM
   decapsulation in C++, built from share-wise code, the PINI AND of Cassiers
   and Standaert, and the 1-bit B2A of Schneider et al. A2B is index-aligned
   (the structure of Bronchain and Cassiers), so the whole decapsulation is a
   PINI composition with no refresh placed for composition (Theorem 1).
2. **Source-level checks** (`verify/`): the gadget templates are recorded
   symbolically and checked exhaustively for NI, SNI and PINI.
3. **The binary-level certificate** (`target/`): for one compiled Cortex-M4
   image,
   - `shareflow.c` traces every executed instruction and evaluates the glue
     hypotheses H0 and H1 (public control flow, no index mixing, aligned
     gadget calls, fresh randomness, contracts);
   - `symlift.py` lifts every gadget function by symbolic execution of its
     machine code into the program it computes over GF(2) or GF(q), with all
     its leakage observations and boundary values;
   - `verify/probe_exact.py` checks the lifted programs exhaustively
     (value-PINI and unit-PINI, hypothesis H2);
   - `certify.py` evaluates the hypotheses of Theorem 2 and prints the
     certified orders.
4. **Leakage tests** (`shareflow tvla`): instruction-level fixed-versus-random
   tests of the complete decapsulation, with ten random-versus-random splits.
5. **The earlier study** of the decryption core (share-aware code generation,
   `target/shgen.py`, `target/ctrace.c`, technical note
   `paper/masked_mlkem_note.tex`).

## Claims and evidence

| Claim | Evidence | Command |
|---|---|---|
| Masked Decaps is correct | NIST ACVP vectors, host N = 1..6 and emulated Cortex-M4 | `make test`; every `shareflow flow` run |
| Source is d-PINI for every d | proof (manuscript, Theorem 1) | |
| Gadget code meets its specification | exhaustive NI/SNI/PINI matrix | `verify/run_matrix.sh` |
| Binary is d-probing secure for value probes | certificate: H0, H1, H2v (Theorem 2a) | `target/run_all.sh`, `target/certify.py` |
| Binary has transition order floor(d/2) | certificate: H0, H1, H2t (Theorem 2b) | same |
| The order floor(d/2) is exact | floor(d/2)+1 observations determine an operand of the compiled PINI AND | `TSTAR` lines of `lift/*.checks.log` |
| Compiler configurations | nine configurations, d = 1 and 2 | `target/run_compilers.sh` |
| Broken hypotheses are reported | four negative controls | `target/run_negative.sh` |
| Certificates hold on valid and modified ciphertexts | ten ACVP vectors | `target/run_vectors.sh` |
| Leakage tests agree | TVLA with ten null splits | `target/run_tvla_decaps.sh`, `target/tvla_vs_flow.py` |
| Cost | emulated instruction counts, calibrated on PQClean against pqm4 | `target/run_cost.sh` |
| Physical leakage | **not tested** | `review/physical_validation_protocol.md` |

## Reproducing

    pip install numpy unicorn==2.1.4 capstone pyelftools
    apt install gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib clang
    target/verify_shipped.sh            # one minute: manifest and all 32 shipped certificates
    ./reproduce_manuscript.sh quick     # about 5 minutes with the shipped cache: build, ACVP, certificate at d = 1, 2
    ./reproduce_manuscript.sh full      # several hours on two cores: everything in the manuscript

`ARTIFACT.md` maps every table and claim of the manuscript to a command and
an output file, lists the tool versions, and states the known gaps.
`MANIFEST.sha256` has the digest of every file. `reproduce.sh` reproduces the
earlier decryption-core study.

The results behind the manuscript are included: `target/flow/` (traces and
TVLA), `target/lift/` (lifted programs, observations, check logs),
`target/cmp/` (compiler study), `verify/verify.log` (matrix; a job that did
not finish has a TIMEOUT line with the limit that applied, between 600 and
2400 s).

## Layout

| Path | Contents |
|---|---|
| `decaps.hpp` | masked Decaps. `MK_GADGET_BOUNDARIES` keeps gadgets out of line; `MK_FLUSH` clears registers and latches at gadget exit; `MK_A2B_CGV` and `MK_COMPRESS_DIV` restore two earlier variants, and `MK_MUT_REUSE` weakens the PINI AND, as negative controls (never use) |
| `fips203.hpp`, `mlkem.hpp`, `masking.hpp` | unmasked FIPS 203 reference; NTT; gadgets of the earlier study |
| `test_decaps.cpp`, `test_decaps_negative.cpp` | gadget tests, masked Decaps against ACVP, negative controls |
| `verify/sym.hpp`, `verify/export.cpp` | symbolic share types; export of the gadget templates as programs |
| `verify/probe_exact.py` | exact checker: NI, SNI, PINI; `--obs` with `--units` (unit-PINI), value probes, `--budget` (t*) |
| `verify/run_matrix.sh` | the gadget x order x property matrix |
| `target/m4_decaps.cpp`, `build_decaps.sh`, `link_decaps.ld` | Cortex-M4 image of the Decaps (GCC or Clang) |
| `target/shareflow.c` | tracer: `pcs`, `flow`, `cost`, `tvla` |
| `target/decode_m4.py` | decoding of the executed instructions |
| `target/symlift.py` | symbolic lifting of gadget functions |
| `target/lift_check.sh`, `certify.py` | exact checks of the lifted gadgets; the certificate |
| `target/run_all.sh`, `run_compilers.sh`, `run_vectors.sh`, `run_negative.sh`, `run_cost.sh`, `run_tvla_decaps.sh` | the experiments of the manuscript |
| `target/tables.py`, `flow_causes.py`, `tvla_vs_flow.py`, `predictions.py` | tables, attribution, comparison with TVLA, predictions for a physical campaign |
| `target/calib/` | PQClean builds used to calibrate instruction counts |
| `target/legacy/` | superseded tools (the sampling-based lifter of the previous version) and, in `results_v1/`, their results |
| `firmware/` | ChipWhisperer capture path of the earlier decryption-core study |
| `review/` | responses to the reviews; physical validation protocol |

## Trusted base and limits

- The emulator (Unicorn 2.1.4), the decoder (Capstone), the instruction
  semantics written in `symlift.py` and the label propagation of
  `shareflow.c` are trusted. The lifter re-evaluates every symbolic value on
  the concrete run; the tracer's predictions are compared with leakage tests.
- The certificate holds for the public inputs that were traced. Gadget
  input domains are checked at every call of the traced runs, not derived
  statically.
- The exact checks are exhaustive and complete only for small share counts;
  the tables state where they stop.
- The sampler mod q uses 32 random bits per element; Corollary 1 of the
  manuscript bounds its effect.
- Instruction counts are not cycle measurements of this code.

## History of the tools

Cross-checks have found defects in earlier versions of the tools, all fixed
before the numbers of the manuscript were produced: link-register overwrites
not checked; nested sub-gadgets relabelling saved registers; wire
identification by sampling (replaced by symbolic lifting); predicated
instructions skipped by the emulator not seen by the tracer or the lifter; a
decoder that reports a flag update for `adc rd, rn, #imm`.

Found when the archive was rebuilt from a clean copy: the lifter's `.obs`
files depended on Python's set order (which component label a wire set
carried), and its count of derived values was too low because object ids
were reused. Both are fixed; the files are now identical from run to run.
`target/relift.sh` regenerated them for every binary after checking that the
lifted programs (`.dag`), the value files (`.val`) and the sets of observed
wire tuples were unchanged, so the existing check logs remain valid. Only
the "derived" column of the certificate table changed (55, 157, 300, 486
for the B2A, previously 48, 132, 246, 403).
