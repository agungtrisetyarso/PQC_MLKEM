#!/bin/sh
# Source-level TVLA of the masked decapsulation gadgets (value model).
# d = 2 (N = 3) real + null; d = 1 (N = 2) positive control.
cd "$(dirname "$0")"
OUT=results_decaps_leak.csv
[ -f $OUT ] || echo "target,N,len,traces,window,max_t1,n_t1,max_t2,n_t2,pairs,max_tb,n_tb,null" > $OUT
lane_a() {
  for t in b2a cbd compress cmp; do
    ./leak_decaps $t 3 100000 0 0 >> $OUT; ./leak_decaps $t 3 100000 0 1 >> $OUT; ./leak_decaps $t 2 20000 0 0 >> $OUT
  done
  ./leak_decaps keccak2 3 100000 256 0 >> $OUT; ./leak_decaps keccak2 3 100000 256 1 >> $OUT; ./leak_decaps keccak2 2 20000 256 0 >> $OUT
  ./leak_decaps keccak 3 100000 -1 0 >> $OUT; ./leak_decaps keccak 3 100000 -1 1 >> $OUT
  echo "lane A done $(date +%H:%M:%S)"
}
lane_b() {
  ./leak_decaps decaps 3 20000 -1 0 >> $OUT; ./leak_decaps decaps 3 20000 -1 1 >> $OUT
  ./leak_decaps decaps 2 20000 -1 0 >> $OUT
  echo "lane B done $(date +%H:%M:%S)"
}
lane_a & lane_b & wait
echo DECAPS_LEAK_COMPLETE
