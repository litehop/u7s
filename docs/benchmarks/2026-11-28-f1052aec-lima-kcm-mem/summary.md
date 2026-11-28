# KCM memory A/B (Pss_Anon MiB, medians of 3 R and 3 T runs, interleaved)

| stage | R kcm | T kcm | R - T (kcm) | R apiserver | T apiserver |
|---|---|---|---|---|---|
| burst | 48.80 | 38.11 | 10.69 | 24.97 | 24.27 |
| idle | 43.96 | 34.23 | 9.73 | 20.75 | 19.71 |
| wordpress | 44.83 | 36.06 | 8.77 | 21.38 | 20.56 |

Phase 0 (`median(R) - median(T) >= 5` at every stage): PASS
