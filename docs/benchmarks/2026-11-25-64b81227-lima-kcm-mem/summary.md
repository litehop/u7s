# KCM memory A/B (Pss_Anon MiB, medians of 3 R and 3 T runs, interleaved)

**Exploratory and non-authoritative** (local Lima, n=3 per mode). T is the unvalidated 11-controller trim and has NOT passed conformance (mayor-rh8y3.3). The tree was dirty (`git_dirty=1`) and the stamped SHA differs from the code that ran: two fixes were made after the run, a lint fix (`head -1` to `sed -n 1p`) and diff rounding.

| stage | R kcm | T kcm | R - T (kcm) | R apiserver | T apiserver |
|---|---|---|---|---|---|
| idle | 42.32 | 33.06 | 9.26 | 20.17 | 19.93 |
| wordpress | 47.07 | 35.37 | 11.70 | 20.91 | 20.64 |

Phase 0 (`median(R) - median(T) >= 5` at every stage): PASS
