# Vale rules

Advisory prose lint: `scripts/vale-report.sh` (add `--strict` to fail on
`u7s/` errors; CI does not). Config is `.vale.ini`; `.vale/styles/u7s/`
and `u7s-code/` are ours, the rest is fetched by `vale sync`.

## House rule to Vale rule

| House rule | Vale |
|---|---|
| Docs style guide 10: no minimizing words | `u7s.Minimizing` (warning) |
| CLAUDE.md 16: no narration ("this session") | `u7s.Narration` (warning) |
| Tracked docs never cite `ai/findings/<file>.md` | `u7s.FindingsPath` (error) |
| Worker 10: no bead IDs in code comments | `u7s-code.BeadIDInComment` (error, `.rs` only; `scripts/check-bead-id-refs.sh` stays the gate) |
| Style guide 3: "will" only in ADRs | `Google.Will`, off in `docs/decisions/` |
| CLAUDE.md 11: follow corpus (Oxford comma used in most lists) | `Google.OxfordComma` |
| Concise, no filler (CLAUDE.md 2, 16) | `ai-tells.*` hints, `Vale.Spelling`/`Terms` with `accept.txt` |
| Active voice, second person, fenced code, heading levels, hard-wrap, answer first, one term per concept | Not lintable here (judgment, or markdown structure) |

Disabled because they contradict the corpus or are noise on technical
prose: contractions, em dashes, semicolons, colons, parentheses, acronyms,
passive, `e.g.`, units, headings case, "we"/"I", `ai-tells` rules that fire
on project vocabulary (surface, shape, ship, mint). Each has a one-line
reason in `.vale.ini`.

Vale does not lint `.sh` comments here: no bash grammar is installed. Fix
a false positive by adding the term to
`.vale/styles/config/vocabularies/u7s/accept.txt`, never by weakening a
`u7s/` rule.
