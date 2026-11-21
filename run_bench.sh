#!/bin/sh
# five pinned runs of bench_decaps; writes the per-column median to results_bench_decaps.csv
for i in 1 2 3 4 5; do taskset -c 1 ./bench_decaps > bench_run$i.txt; done
python3 - <<'PY'
import statistics
runs=[open(f"bench_run{i}.txt").read().splitlines() for i in (1,2,3,4,5)]
unm=statistics.median(int(r[0].split(":")[1].split()[0]) for r in runs)
out=[f"# unmasked reference Decaps (ML-KEM-768), median of 5 x 21: {int(unm)} cycles", runs[0][1]]
for k in range(2,len(runs[0])):
    rows=[r[k].split(",") for r in runs]
    med=[]
    for j in range(len(rows[0])):
        vals=[float(x[j]) for x in rows]; m=statistics.median(vals)
        med.append(f"{m:.3f}" if "." in rows[0][j] else str(int(m)))
    out.append(",".join(med))
open("results_bench_decaps.csv","w").write("\n".join(out)+"\n")
PY
echo BENCH_DONE
