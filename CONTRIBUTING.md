# Contributing

u7s is developed with the [mayor method](docs/the-mayor-method/README.md):
one long-lived AI session (the mayor) coordinates short-lived AI worker
sessions, and a human operator makes the product and policy calls. This is
not a traditional fork-and-PR project with a volunteer contributor base
today. This guide states that plainly and covers what you need if you want
to contribute anyway — as a human, or as an agent operating in this repo.

## How work is tracked

Every unit of work is a bead, tracked with [beads](https://github.com/gastownhall/beads) (`bd`).

1. Run `bd ready` to see unclaimed work.
2. Run `bd show <id>` to read a bead in full before starting.
3. Run `bd update <id> --claim` to claim it.
4. Run `bd close <id> --reason="..."` when the work lands.

Do not track work in a separate TODO list, GitHub Projects board, or issue
labels — beads is the single source of truth. See
[`docs/the-mayor-method/README.md`](docs/the-mayor-method/README.md) for why
the project is organized this way.

## Code and doc conventions

Follow [`CLAUDE.md`](CLAUDE.md) and [`AGENTS.md`](AGENTS.md). These files
are written for AI agents, but they encode the project's actual engineering
conventions — read them even if you're a human contributor, so your changes
match the surrounding code. For user-facing docs specifically, follow
[`docs/style-guide.md`](docs/style-guide.md).

## Opening a pull request

1. Reference the bead ID your PR closes in the PR description.
2. Keep the diff scoped to that bead — do not bundle unrelated changes.
3. Run the project's tests and lints before opening the PR (see `CLAUDE.md`
   for the commands).
4. Open the PR against `main`.

A `critical-reviewer` pass runs against every PR from a worker branch and
posts a verdict. The mayor merges any PR whose latest verdict is `LGTM` or
`LGTM-with-suggestions` and whose checks are green; `needs-changes` blocks
the merge until addressed. A PR from a human contributor goes through the
same CI and review gate — there is no separate human fast path today.

## Licensing

u7s is licensed under [Apache License 2.0](LICENSE). By contributing, you
agree that your contributions will be licensed under the same terms.

## Questions

u7s currently has a single operator and no public discussion forum. Open a
GitHub issue on this repository for questions; for security reports, follow
[`SECURITY.md`](SECURITY.md) instead.
