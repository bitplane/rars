# Exact encoder results

Candidate `a34ab21c` with `experimental-ring-state` passes all five bounds and
writes byte-identical archives to current rars on all seven inputs. The native
RAR smoke passes 12/12. Run on arm64 macOS, Rust 1.97.1, 2026-10-21.

Settings: RAR 5, level 3, 4 MiB dictionary, no filters, one thread, 256 MiB
memory limit, 2,806,768 bytes of input. Ratios are candidate over control,
paired medians with 95% bootstrap intervals. Raw data is in
[results/qualification.json](results/qualification.json) and the verdict in
[results/assessment.json](results/assessment.json).

## The five bounds

| Criterion | Ratio [95% interval] | Verdict |
|---|---:|---|
| dictionary-distance / current CPU | 0.880 [0.818, 0.920] | PASS |
| hot-prefix-pressure / current CPU | 0.811 [0.771, 0.828] | PASS |
| source-tree-2m / wide wall | 0.949 [0.943, 0.965] | PASS |
| source-tree-2m / wide CPU | 0.947 [0.943, 0.965] | PASS |
| source-tree-2m / cyclic RSS | 0.942 [0.940, 0.946] | PASS |

## Against current rars

| Workload | Archive bytes | Wall | CPU | RSS |
|---|---:|---:|---:|---:|
| dictionary-distance | 172,331 | 1.019 [0.912, 1.058] | 0.880 [0.818, 0.920] | 0.889 [0.888, 0.891] |
| hot-prefix-pressure | 192,801 | 0.993 [0.889, 1.053] | 0.811 [0.771, 0.828] | 0.894 [0.891, 0.895] |
| related-releases | 1,403 | 0.994 [0.964, 1.070] | 0.975 [0.887, 0.997] | 0.829 [0.825, 0.831] |
| shifted-repeat | 8,650 | 0.991 [0.900, 1.032] | 0.927 [0.889, 0.997] | 0.887 [0.882, 0.891] |
| source-and-logs | 35,101 | 0.901 [0.843, 0.926] | 0.880 [0.874, 0.899] | 0.862 [0.860, 0.865] |
| source-tree-2m | 316,499 | 0.608 [0.595, 0.645] | 0.598 [0.586, 0.645] | 0.618 [0.606, 0.629] |
| unrelated-data | 24,733 | 1.018 [0.974, 1.720] | 0.927 [0.859, 1.057] | 0.887 [0.885, 0.889] |

Intervals that cross 1 are not wins. Unrelated-data is slower than the wide
control: wall 1.030 [1.004, 1.121].

## 2 MiB source against each control

| Control | Wall | CPU | RSS |
|---|---:|---:|---:|
| Current | 0.608 [0.595, 0.645] | 0.598 [0.586, 0.645] | 0.618 [0.606, 0.629] |
| Wide | 0.949 [0.943, 0.965] | 0.947 [0.943, 0.965] | 0.882 [0.879, 0.884] |
| Cyclic | 0.921 [0.916, 0.947] | 0.921 [0.918, 0.945] | 0.942 [0.940, 0.946] |

Small-input wall times include process start-up and up to 10 ms of polling.
