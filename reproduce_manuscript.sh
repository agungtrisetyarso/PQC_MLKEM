#!/bin/sh
# reproduce_manuscript.sh — reproduce the results of paper/manuscript.tex.
#
#   ./reproduce_manuscript.sh quick   build, ACVP, certificate of the GCC -O2
#                                     binaries at d = 1, 2 (about 5 minutes
#                                     with the shipped cache)
#   ./reproduce_manuscript.sh full    everything: certificates d = 1..4, the
#                                     nine compiler configurations, cost, the
#                                     verification matrix, both TVLA campaigns
#                                     (several hours on two cores, 8 GB RAM)
#
# Needs: g++, clang++, arm-none-eabi-gcc with newlib and libstdc++,
# python3 with numpy, unicorn 2.1.4, capstone, pyelftools.
# The first lifting of a mod-q gadget of a new compiler configuration
# enumerates all 2^32 values of a random word (minutes); results are cached
# in target/lift/rawcache.json, which is shipped.
set -e
cd "$(dirname "$0")"
MODE=${1:-quick}
U=$(python3 -c "import unicorn,os; print(os.path.dirname(unicorn.__file__))")

echo "== host: masked Decaps against the NIST ACVP vectors (N = 1..6)"
make test_decaps test_fips203 > /dev/null
./test_fips203 kat/acvp_mlkem.txt | tail -1
./test_decaps kat/acvp_mlkem.txt | tail -2

echo "== tools"
cd target
gcc -O3 -march=native -o shareflow shareflow.c -I"$U/include" -L"$U/lib" \
    -l:libunicorn.so.2 -Wl,-rpath,"$U/lib" -lpthread -lm
[ -f in768.bin ] || python3 mkinputs.py ../kat/acvp_mlkem.txt in768.bin 768
[ -f in768_3.bin ] || python3 mkinputs.py ../kat/acvp_mlkem.txt in768_3.bin 768 3
[ -f keys_fr200.bin ] || python3 mkkeys.py ../kat/acvp_mlkem.txt keys_fr200.bin 200
mkdir -p flow lift cmp frozen

if [ "$MODE" = quick ]; then
  for N in 2 3; do
    ./build_decaps.sh $N gcc_O2 -O2 -DMK_GADGET_BOUNDARIES > /dev/null 2>&1
    ./analyze_decaps.sh $N gcc_O2 3 | tail -1                      # trace: H0, H1
    ./lift_check.sh m4d_N${N}_gcc_O2.elf flow/N${N}_gcc_O2.tab lift/gcc_O2_N$N   # lift and check: H2
    python3 certify.py flow/N${N}_gcc_O2.json lift/gcc_O2_N$N      # the certificate (Table IV)
  done
  ./build_decaps.sh 2 perfO2 -O2 > /dev/null 2>&1; ./analyze_decaps.sh 2 perfO2 3 | tail -1
  python3 certify.py flow/N2_perfO2.json lift/none | tail -3       # negative control: must fail H1
  echo REPRODUCE_QUICK_DONE
  exit 0
fi

echo "== certificates (Table IV), flush variant, compiler study (Table VI)"
./run_all.sh | tee all.log
python3 tables.py cert > ../paper/tables_cert.tex
python3 tables.py compilers > ../paper/tables_compilers.tex
python3 flow_causes.py flow/N3_gcc_O2.json flow/N3_gcc_O2.tab flow/N3_gcc_O2.sym     # Table V

echo "== all ten ACVP vectors, valid and modified ciphertexts (Section V-A)"
./run_vectors.sh | tee vectors.log
echo "== negative controls (Table VII)"
./run_negative.sh | tee negative.log

echo "== cost (Tables IX, X) and calibration against pqm4"
./run_cost.sh
python3 tables.py cost > ../paper/tables_cost.tex
( cd calib && ./run_calib.sh ) 2>/dev/null || echo "(calibration: see target/calib/README)"

echo "== TVLA of the complete Decaps with ten null splits (Section VI)"
for N in 2 3; do cp m4d_N${N}_gcc_O2.elf frozen/; cp flow/N${N}_gcc_O2.tab flow/N${N}_gcc_O2.sym frozen/
  cp flow/N${N}_gcc_O2.json frozen/flow_N$N.json; done
./run_tvla_decaps.sh 2 1000 6 2
./run_tvla_decaps.sh 3 600 6 4
for N in 2 3; do python3 tvla_vs_flow.py flow/tvla_N${N}_gcc_O2.csv flow/tvla_N${N}_gcc_O2_null.csv frozen/flow_N$N.json frozen/N${N}_gcc_O2.sym; done
for N in 2 3; do python3 predictions.py flow/N${N}_gcc_O2.json flow/N${N}_gcc_O2.tab flow/N${N}_gcc_O2.sym flow/predictions_N${N}_gcc_O2.csv; done

echo "== source-level verification matrix (Table III)"
( cd ../verify && rm -f export.log.v5 && : > verify.log && ./run_matrix.sh &&
  python3 log2csv.py verify.log > results_verify.csv )
python3 tables.py verify > ../paper/tables_verify.tex
echo REPRODUCE_FULL_DONE
