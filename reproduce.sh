#!/bin/sh
# reproduce.sh — rebuild everything and re-run the checks in dependency order.
#
#   ./reproduce.sh quick     builds, correctness, equivalence and validation
#                            checks (minutes)
#   ./reproduce.sh full      quick + every TVLA campaign in the note (hours)
#
# Needs: g++, clang++, python3 with numpy, unicorn, capstone, pyelftools,
# ziglang (pip); gcc to build ctrace.  Firmware additionally needs
# arm-none-eabi-gcc + newlib and a ChipWhisperer checkout (firmware/README).
set -e
cd "$(dirname "$0")"
MODE=${1:-quick}
U=$(python3 -c "import unicorn,os; print(os.path.dirname(unicorn.__file__))")

echo "== host build and correctness"
make all
make test

echo "== FIPS 203 reference and masked decapsulation vs NIST ACVP vectors"
./test_fips203 kat/acvp_mlkem.txt
./test_decaps kat/acvp_mlkem.txt
./test_decaps_negative kat/acvp_mlkem.txt

echo "== mechanised verification, quick part (d <= 2; ./verify/run_verify.sh for all)"
( cd verify && g++ -std=c++17 -O1 -I.. -o export export.cpp && ./export . > export.log &&
  for g in band bref band_r amul aref mux chi_row b2a; do for p in NI SNI; do
    python3 probe_exact.py dag/${g}_N3.dag $p 2; done; done &&
  ! python3 probe_exact.py dag/round_noref_N2.dag NI 1 --first > /dev/null &&
  echo "mutant without the chi refresh fails 1-NI, as expected" )

echo "== record gadget DAGs and generate share-aware assembly"
for N in 2 3 4; do ./gen_dag $N > target/gen/dag_N$N.txt; done
cd target
for N in 2 3 4; do for M in full noclear nopc; do
  python3 shgen.py gen/dag_N$N.txt gen/sh_N${N}_$M.S --mode $M
  python3 -m ziglang cc -target thumb-freestanding-eabi -mcpu=cortex_m4 -nostdlib \
    -Wl,-T,link.ld -o m4_N${N}_sh$M.elf gen/sh_N${N}_$M.S
done; done
./build.sh

echo "== equivalence: all builds give identical output shares"
python3 equivalence.py

echo "== C tracer: build and validate against the Python tracer"
gcc -O3 -march=native -Wall -Wextra -o ctrace ctrace.c -I"$U/include" -L"$U/lib" \
    -l:libunicorn.so.2 -Wl,-rpath,"$U/lib" -lpthread -lm
mkdir -p prog
for N in 2 3 4; do for v in naive base pre shfull shnoclear shnopc; do
  python3 export_prog.py m4_N${N}_${v}.elf $N prog/m4_N${N}_${v}.prog
done; done
python3 validate_ctrace.py m4_N2_shfull.elf prog/m4_N2_shfull.prog 2 4
python3 validate_ctrace.py m4_N3_pre.elf prog/m4_N3_pre.prog 3 4

echo "== model fitting: recovery of known weights"
python3 fit_model.py synth ./ctrace prog/m4_N2_shfull.prog 2 120 1.0 results_c/fitted_weights_synth.txt

echo "== complete masked Decaps on an emulated Cortex-M4 (manuscript)"
( cd target &&
  gcc -O3 -march=native -o shareflow shareflow.c -I"$U/include" -L"$U/lib" \
      -l:libunicorn.so.2 -Wl,-rpath,"$U/lib" -lpthread -lm &&
  cp shareflow shareflow_v2 &&
  python3 mkinputs.py ../kat/acvp_mlkem.txt in768.bin 768 &&
  python3 mkinputs.py ../kat/acvp_mlkem.txt in768_3.bin 768 3 &&
  python3 mkkeys.py ../kat/acvp_mlkem.txt keys_fr200.bin 200 &&
  for N in 2 3 4 5; do ./build_decaps.sh $N gcc_O2 -O2 -DMK_GADGET_BOUNDARIES; done &&
  for N in 2 3; do ./build_decaps.sh $N gcc_O2f -O2 -DMK_GADGET_BOUNDARIES -DMK_FLUSH; done &&
  for N in 2 3 4 5; do ./analyze_decaps.sh $N gcc_O2 3; done &&      # share-flow (Sec. 5-6)
  for N in 2 3; do ./analyze_decaps.sh $N gcc_O2f 3; done &&         # with the gadget-exit flush
  for N in 1 2 3 4 5 6 7 8; do ./build_decaps.sh $N perfO2 -O2 &&
    ./shareflow pcs m4d_N${N}_perfO2.elf $N in768.bin > flow/pcs_N${N}_perfO2.txt &&
    python3 decode_m4.py m4d_N${N}_perfO2.elf flow/pcs_N${N}_perfO2.txt flow/N${N}_perfO2.tab flow/N${N}_perfO2.sym &&
    ./shareflow cost m4d_N${N}_perfO2.elf flow/N${N}_perfO2.tab $N in768.bin | tail -1; done &&   # cost (Sec. 9)
  mkdir -p frozen && for N in 2 3; do cp m4d_N${N}_gcc_O2.elf frozen/ &&
    cp flow/N${N}_gcc_O2.tab frozen/N${N}_gcc_O2_v2.tab && cp flow/N${N}_gcc_O2.sym frozen/N${N}_gcc_O2.sym &&
    cp flow/N${N}_gcc_O2.json frozen/flow_N${N}.json; done )

if [ "$MODE" = full ]; then
  echo "== instruction-level campaign (hours)"
  rm -f results_c/tab_* results_c/main_* results_c/null_*
  ./run_campaign.sh
  cd ..
  ./run_exhaustive.sh
  ./diag_decaps_public
  rm -f results_decaps_leak.csv && ./run_decaps_leak.sh
  ./run_decaps_excl.sh
  ./run_b2a_leak.sh
  ./run_bench.sh
  ( cd verify && rm -f verify*.log && ./run_verify.sh verify.log 1/2 & cd verify && ./run_verify.sh verify2.log 2/2; wait )
  ( cd verify && cat verify*.log | python3 log2csv.py /dev/stdin > results_verify.csv )
  [ -n "$IRONMASK" ] && ( cd verify && ./run_ironmask.sh )
  ( cd target && python3 summarize.py > ../paper/tables_generated.tex )
  ( cd target && ./run_lift_checks.sh &&                       # Table: lifted gadgets, t*, weighted PINI
    ./run_compilers.sh && python3 compilers_table.py > ../paper/tables_compilers.tex &&
    ./run_tvla_decaps_v2.sh 2 1000 && ./run_tvla_decaps_v2.sh 3 600 &&
    python3 tvla_vs_flow.py flow/tvla_N2_gcc_O2.csv flow/tvla_N2_gcc_O2_null.csv frozen/flow_N2.json frozen/N2_gcc_O2.sym &&
    python3 tvla_vs_flow.py flow/tvla_N3_gcc_O2.csv flow/tvla_N3_gcc_O2_null.csv frozen/flow_N3.json frozen/N3_gcc_O2.sym &&
    python3 summarize.py > /dev/null )
fi
echo REPRODUCE_DONE
