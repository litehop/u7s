# KCM memory A/B (Pss_Anon MiB, medians of 3 R and 3 T runs, interleaved)

| stage | R kcm | T kcm | R - T (kcm) | R apiserver | T apiserver |
|---|---|---|---|---|---|
| idle | 42.32 | 33.06 | 9.26 | 20.17 | 19.93 |
| wordpress | 47.07 | 35.37 | 11.7 | 20.91 | 20.64 |

Phase 0 (`median(R) - median(T) >= 5` at every stage): PASS
