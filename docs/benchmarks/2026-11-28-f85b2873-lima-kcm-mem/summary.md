# KCM memory A/B (Pss_Anon MiB, medians of 3 R and 3 T runs, interleaved)

| stage | R kcm | T kcm | R - T (kcm) | R apiserver | T apiserver |
|---|---|---|---|---|---|
| burst | 45.99 | 37.71 | 8.28 | 24.00 | 24.41 |
| idle | 42.81 | 33.24 | 9.57 | 20.81 | 20.03 |
| wordpress | 45.22 | 34.76 | 10.46 | 20.98 | 20.93 |

Phase 0 (`median(R) - median(T) >= 5` at every stage): PASS
