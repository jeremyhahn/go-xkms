# fd2575g: carry the F4 members' docs/SPEC.md rows into the fold (CA m2575)

- Members, in order: #2000, #1957, #2002, #1974, #2003, #1964, train c #2040.
- Rule: where two members change the same row, #2000 wins over #1957 and #2002 wins over #1958/train c; the #1958 rescope at docs/SPEC.md:168 keeps the fold's text (open owner question).

## Results

- #2000: attestation-verifier row carried (transport appraisal routes). Its device-security-event-evidence row was already in the fold from train c, in the same text.
- #1957: its one row (attestation-verifier) is the same text as #2000's, so #2000's commit carries it; no separate commit.
- #2002: left out. Its only row is phone-verify-user at docs/SPEC.md:168, the #1958 rescope, which this lane must not change; the fold keeps train c's text there. The owner question decides #2002's text (RP name as SHA-256 per WebAuthn L2 §6.1, 1 to 64 bytes, its own line references).
- #1974: left out. Its only row is device-security-event-evidence as "planned" with "Hook: none"; #2000 and train c ship the same row as "shipped" with the `types.SecurityEventAttester` hook, which replaces the sentences #1974 edits (line references `types.go:1953`, `uccs.go:201`).
- #2003: ota-image-keys row carried (`ExportOTAImageKey` SDK export, rulings 210 and 213).
- #1964: authz-admin-routes and authz-method-tables rows carried (`qrdbserver.ModuleHTTPRegistrar`, `qrdbserver.ModuleMCPToolPermissioner`).
- Train c #2040: all four rows (device-security-event-evidence, release-signing-key, trust-roots, phone-verify-user) were already in the fold; nothing to add.
- Line 168 unchanged.
- make lint: passes (0 issues on every module and tag set).
- SPEC check: the Makefile has no SPEC target, so none was run.
