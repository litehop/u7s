# Vale trial (report-only)

Bead: mayor-fqktu

**Answer:** Vale is cheap to run (0.5 s over all four key files) but untuned it is noise, mostly style preference (263 alerts on 3.6k words). Tuned down it gives a small, readable list (39 alerts, about 1 per 90 words) whose true-positive rate is roughly one in three. Run it as a non-blocking report, not a gate, and do not block on `ai-tells` yet.

## Setup (committed)

- `.vale.ini`: `Vale` + `Google` v0.7.2 + `tbhb/vale-ai-tells` v1.37.0 (`ai-tells.zip`) + `Microsoft` v0.15.2 (synced; compared, not enabled). All pinned by release-zip URL; `vale sync` fetches them into `.vale/styles/`, which is gitignored (config and `config/vocabularies/` stay tracked).
- `.vale/styles/config/vocabularies/u7s/accept.txt`: 24 project terms. Entries enforce case in `Vale.Terms`, so capitalisable ones are `[Kk]ubelet`-style regexes; plain `openssl` made `OpenSSL` an error.
- Runtime: 0.5 s for README + install + releasing + CHANGELOG (about 3.6k words); no network after sync.

## Counts (untuned: suggestion level, Google + ai-tells + Vale)

| file | words | error | warning | suggestion |
|---|---|---|---|---|
| README.md | 907 | 17 | 5 | 35 |
| docs/install.md | 2289 | 40 | 10 | 114 |
| docs/releasing.md | 242 | 4 | 0 | 12 |
| CHANGELOG.md | 211 | 4 | 1 | 21 |

All `docs/*.md` + README + CHANGELOG: 166 errors, 34 warnings, 479 suggestions. Nearly all errors are `ai-tells` (its default severity) plus a handful of `Vale.Spelling`/`Terms`. Microsoft gave 25 error / 10 warning / 132 suggestion on the same files, mostly duplicating Google (Acronyms, Passive, Semicolon, Contractions); Google picked, Microsoft dropped.

## Top rules (four key files) and signal

Verdicts are my reading of ~3 samples each, not a labelled study.

| rule | hits | verdict | est. signal |
|---|---|---|---|
| Google.Parens | 59 | style preference (parentheticals like `(snapshots)`, `(up to 3 minor versions older)` are fine) | <10% |
| Google.Acronyms | 38 | noise (MTU, VPS, NIC are audience-known) | <10% |
| Google.Passive | 36 | mixed; "are fixed at first install" is deliberate | ~20% |
| Google.Semicolons | 27 | preference | ~0% |
| Google.Contractions | 21 | contradicts project voice ("does not") | 0% |
| ai-tells.SemicolonUsage | 12 | preference; the semicolon clauses read fine | ~10% |
| ai-tells.NounString | 9 | false positive: it fires on `the control plane's release` | ~0% |
| Google.WordListCase | 8 | "above" to "preceding": preference | ~10% |
| ai-tells.NegatedObject | 7 | "needs no token" is clear, idiomatic | ~0% |
| Google.OxfordComma | 5 | real, but project does not use it | convention |
| ai-tells.FigurativeMints | 4 | "mint a token": literal in PKI context | ~10% |
| ai-tells.VerbTricolon, UniversalSubject, ServesAsDodge | 3, 2, 2 | tricolon FP; "Every release is gated" is a real unverifiable blanket claim | ~40% |

Real findings came from the long tail of `ai-tells`: `UniversalSubject` ("Every step below uses", "Every release is gated"), `FigurativeCarries/Lands/Holds/Owns` ("the output holds the token", "changes land in"), `AnthropomorphicCognition` ("the node trusts/learns"), `ShipOveruse`, `LabelAndExplain`. A human reviewer would notice about a third of these, usually as minor wordiness, not defects. It does detect the LLM register in the docs; it does not find factual or structural problems.

## Proposed tuned config

Tested on the four files (with `Google.OxfordComma` still on): 39 alerts (31 error, 8 warning), down from 263. Add to `[*.md]` and set `MinAlertLevel = warning`:

```ini
Google.Parens = NO            # parentheticals are normal in reference docs
Google.Acronyms = NO          # audience knows MTU/NIC/VPS
Google.Passive = NO           # frequent and often right
Google.Semicolons = NO        # preference
Google.Contractions = NO      # house voice uses "does not"
Google.WordListCase = NO      # above/disable preference
Google.EmDash = NO
Google.OxfordComma = NO       # project does not use it (add if it adopts one)
ai-tells.SemicolonUsage = NO  # same as above
ai-tells.NounString = NO      # fires on possessives
ai-tells.NegatedObject = NO   # "needs no token" is fine
ai-tells.EmDashUsage = NO
ai-tells.FigurativeMints = NO # "mint" is literal for tokens/certs
```

The remaining `ai-tells` rules stay at their default `error`; Vale has no wildcard to downgrade a whole style, so a gate would have to filter by check name from the JSON output rather than by level.

## Report vs gate

- Report (recommended): a script, `vale --output=JSON --no-exit`, that prints counts per file and level; optionally a CI job posting the count delta on docs-changing PRs. Cost: about 20 lines, zero blocking.
- Gate on errors only: after tuning, only `Vale.Spelling`/`Terms` errors are mechanical and trustworthy. `ai-tells` rules at ~1 in 3 would block on false positives, and rule-level suppression per file is the machina.js pattern we want to avoid ("do not change levels to pass").
- Vocabulary upkeep: 24 terms covered four files plus the docs; new terms arrive with new components (about one new term per feature PR). Cost is a line in `accept.txt` per false spelling hit, only if spelling is gated.

## Recommendation

Adopt Vale as a non-blocking report on human-facing docs with the tuned config. Keep `ai-tells` as advisory only (reviewer hint for the LLM register), and gate only on `Vale.Spelling`/`Terms` if the operator wants a block. Revisit after ~10 doc PRs to see whether the warning count trends down.
