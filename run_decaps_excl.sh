#!/bin/sh
# Masked Decaps, first- and second-order univariate, fixed vs random valid
# ciphertext, with public-only positions reported separately.
cd "$(dirname "$0")"
OUT=results_decaps_excl.csv
echo "target,N,len,traces,window,max_t1,n_t1,max_t2,n_t2,pairs,max_tb,n_tb,null,excluded,excl_max_t1,excl_n_t1,excl_max_t2" > $OUT
( LEAK_EXCLUDE=decaps_public_mask_N3.bin ./leak_decaps decaps 3 20000 -1 0 >> $OUT
  LEAK_EXCLUDE=decaps_public_mask_N3.bin ./leak_decaps decaps 3 20000 -1 1 >> $OUT ) &
( LEAK_EXCLUDE=decaps_public_mask_N2.bin ./leak_decaps decaps 2 20000 -1 0 >> $OUT
  LEAK_EXCLUDE=decaps_public_mask_N2.bin ./leak_decaps decaps 2 20000 -1 1 >> $OUT ) &
wait
echo EXCL_COMPLETE
