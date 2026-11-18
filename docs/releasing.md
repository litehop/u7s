# Releasing

Mayor/operator only: a release publishes to GitHub, so confirm with the
operator first. Every release is gated, patch releases included. Whether
`-snapshot.N` prereleases need the gate is undecided.

1. **Finalize the changelog on main.** A PR with a user-visible change
   (install, manifests, API behaviour, flags) appends a line under
   `## [Unreleased]` in `CHANGELOG.md`, in Added / Changed / Fixed / Security,
   with a Breaking subsection when relevant. Internal work gets no entry.
   Before cutting the snapshot, rename `## [Unreleased]` to
   `## [X.Y.Z] - <date>` and add a fresh empty Unreleased, so the gated commit
   already carries the release section.
2. **Cut a snapshot from main**: tag main's commit and push the tag
   (`git tag vX.Y.Z-snapshot.N <sha>`, then
   `git push origin vX.Y.Z-snapshot.N`). A tag containing `-` is a prerelease and gets the one-line notes.
3. **Run the gate against that snapshot** on GCP, on the release-gate shape
   (`n1-custom-1-1024`, 20-pod burst, 3 runs):
   `scripts/release-gate/burst-gate.sh --backend gcp --release <snapshot-tag> --confirm`.
   Flags and exit codes: the script header and
   [dev-setup.md](dev-setup.md#release-gate-1-gib-burst-survival).
4. **Release only on 3/3 PASS.** On a failure, find the root cause; do not
   retry until it passes. INVALID and PREEMPTED runs are not verdicts.
5. **Tag `vX.Y.Z`** on the exact commit whose snapshot passed the gate; the
   release is rebuilt from the tag, not promoted from the snapshot. The
   workflow publishes the changelog section as the release notes and fails the
   build, before compiling, if the section is missing or empty
   (`scripts/changelog-section.sh`).
