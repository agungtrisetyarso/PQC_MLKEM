#!/bin/sh
# Exhaustive second-order (all pairs) source-level test of the gadget
# composition, value model, 1e5 traces; each with a null calibration run.
cd "$(dirname "$0")"
OUT=results_exhaustive.csv
echo "d,model,trace_len,traces,window,pairs_tested,max_t,pairs_over_4.5,argmax_pair,null" > $OUT
for d in 2 3; do
  ./leak_biv $d 0 100000 0 | sed 's/$/,0/' >> $OUT
  LEAKBIV_NULL=1 ./leak_biv $d 0 100000 0 | sed 's/$/,1/' >> $OUT
  echo "done d=$d $(date +%H:%M:%S)"
done
echo EXHAUSTIVE_COMPLETE
