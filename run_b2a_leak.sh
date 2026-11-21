#!/bin/sh
# Source-level TVLA of the SPOG19 B2A and CBD built on it (value model).
cd "$(dirname "$0")"
OUT=results_b2a_leak.csv
echo "target,N,len,traces,window,max_t1,n_t1,max_t2,n_t2,pairs,max_tb,n_tb,null" > $OUT
( for t in b2a cbd; do ./leak_decaps $t 3 100000 0 0 >> $OUT; ./leak_decaps $t 3 100000 0 1 >> $OUT; done ) &
( for t in b2a cbd; do ./leak_decaps $t 2 20000 0 0 >> $OUT; ./leak_decaps $t 4 100000 0 0 >> $OUT; ./leak_decaps $t 4 100000 0 1 >> $OUT; done ) &
wait
echo B2A_LEAK_COMPLETE
