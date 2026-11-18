# Releasing

Mayor/operator only: a release publishes to GitHub, so confirm with the
operator first. Every release is gated, patch releases included. Whether
`-snapshot.N` prereleases need the gate is undecided.

1. **Cut a snapshot from main**:
   `gh workflow run release-tarball.yaml -f version=vX.Y.Z-snapshot.N`.
   A tag containing `-` is a prerelease and gets the one-line notes.
2. **Run the gate against that snapshot** on GCP, on the release-gate shape
   (`n1-custom-1-1024`, 20-pod burst, 3 runs):
   `scripts/release-gate/burst-gate.sh --backend gcp --release <snapshot-tag> --confirm`.
   Flags and exit codes: the script header and
   [dev-setup.md](dev-setup.md#release-gate-1-gib-burst-survival).
3. **Release only on 3/3 PASS.** On a failure, find the root cause; do not
   retry until it passes. INVALID and PREEMPTED runs are not verdicts.
4. **Write the changelog section.** A PR with a user-visible change (install,
   manifests, API behaviour, flags) appends a line under `## [Unreleased]` in
   `CHANGELOG.md`, in Added / Changed / Fixed / Security, with a Breaking
   subsection when relevant. Internal work gets no entry. Before tagging
   `vX.Y.Z`, rename `## [Unreleased]` to `## [X.Y.Z] - <date>` and add a fresh
   empty Unreleased.
5. **Tag `vX.Y.Z`.** The workflow publishes that changelog section as the
   release notes. It fails the build, before compiling, if the section is
   missing or empty (`scripts/changelog-section.sh`).
