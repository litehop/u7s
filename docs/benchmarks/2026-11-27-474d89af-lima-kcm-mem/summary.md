# KCM memory A/B (Pss_Anon MiB, medians of 3 R and 3 T runs, interleaved)

| stage | R kcm | T kcm | R - T (kcm) | R apiserver | T apiserver |
|---|---|---|---|---|---|
| idle | 42.99 | 34.87 | 8.12 | 20.57 | 19.89 |
| wordpress | 45.13 | 35.99 | 9.14 | 22.00 | 20.82 |

Phase 0 (`median(R) - median(T) >= 5` at every stage): PASS
