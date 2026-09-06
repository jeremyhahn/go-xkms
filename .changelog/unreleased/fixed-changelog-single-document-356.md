- **`CHANGELOG.md` is one document again, and every release's notes are now
  bounded by the right heading.** The file held two concatenated changelog
  documents — the go-trusted-ca history imported at the 2026-04-16 merge kept
  its own `# Changelog` H1, "Keep a Changelog" header block and
  `## [Unreleased]` — so `## [Unreleased]` matched twice and every tool that
  splices on it picked a different occurrence. `make release` extracts a
  version's notes as everything between its heading and the next line
  beginning `## [`, and because that `sed` range *restarts*, the duplicate
  `## [0.1.0-alpha]` heading meant `v0.1.0-alpha` published 141 entries: its
  own 97 plus 44 belonging to go-trusted-ca. It now publishes 97.
  The imported sections are retained verbatim under
  `## [go-trusted-ca] - merged 2026-04-16` with their headings demoted one
  level, so they bound the oldest go-xkms release instead of being swept into
  it and can never be read as a go-xkms version. The duplicate header block is
  gone, the surviving one cites Keep a Changelog 1.1.0, and the colliding
  `[0.1.0-alpha]:` link definition is now an inline link. All 734 entries keep
  the exact heading path they had; `scripts/changelog-assemble.sh` now refuses
  a file that does not carry exactly one `## [Unreleased]` heading (#356).
