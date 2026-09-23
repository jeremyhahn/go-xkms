- **Headless commands try TPM PCR-policy auto-unseal before falling back to a
  password.** `xkey extension serve`, `xkey fido2` (`fido2 start`), and the
  barrier-backed stores `xkey oath`/`xkey backup`/`xkey device oath-sync` use
  (via `openBarrierBackend`, `xkey/cmd/xkey/cmd/barrier_store.go`) now drive
  the same `services.BarrierAutoUnsealService` the xKey GUI uses at startup:
  when the barrier is sealed with the `tpm2` strategy, they first try the
  auto-unseal policy designated with `xkey policy set-auto-unseal <name>`
  (no password read anywhere), and only fall back to a direct TPM unseal or a
  password when no policy is configured. A policy that exists but no longer
  matches the current PCR values is a logged, typed refusal
  (`services.ErrBarrierAutoUnsealPCRMismatch`), never a silent fall-through.
  Added `xkey barrier unseal --auto`, which runs the auto-unseal once and
  never prompts for or reads a password — the explicit verb for unattended
  startup scripts. New shared helper `tryBarrierPolicyAutoUnseal`
  (`xkey/cmd/xkey/cmd/barrier_auto_unseal.go`) opens the TPM, reads the
  designated policy, and drives the unseal; `probeTPMModule` is factored out
  of the existing `probeTPMSealer` so both share one TPM-opening path.
  **BREAKING**: the default PCR policy store location for `xkey policy ...`
  changes from the CWD-relative `./data/policies` to `<data dir>/pcr_policies`
  (`xkey/cmd/xkey/cmd/policy.go`), matching the location the xKey GUI already
  uses (`pkg/gui/app.go`) — the CLI and GUI now share the same policies by
  default instead of writing to two unrelated locations, and `--store` still
  overrides it. Rewrote `xkey/skills/xkey-agent/SKILL.md`: every command and
  flag re-verified against `xkey --help` output, documents the TPM
  auto-unseal default and agent-safe alternatives (`auth login --piv`,
  `auth register --setup-token`, `oidc login --no-browser`, `device enroll`),
  and is referenced from `xkey/AGENTS.md`/`xkey/CLAUDE.md`. Tests (tag
  `tpm_simulator`): `TestTryBarrierPolicyAutoUnseal_Success` (real simulator
  seal + unseal, no password), `_NoPolicyConfigured` (silent fallback),
  `_PCRMismatch` (typed error), `_PolicyStoreOpenFailedIsTyped`. Files:
  `xkey/cmd/xkey/cmd/barrier_auto_unseal.go`,
  `xkey/cmd/xkey/cmd/barrier_auto_unseal_test.go`,
  `xkey/cmd/xkey/cmd/extension_serve.go`, `xkey/cmd/xkey/cmd/barrier_store.go`,
  `xkey/cmd/xkey/cmd/barrier_unseal.go`, `xkey/cmd/xkey/cmd/policy.go`,
  `xkey/cmd/xkey/cmd/fido2.go`, `xkey/skills/xkey-agent/SKILL.md`,
  `xkey/CLAUDE.md` (`xkey/AGENTS.md` is a symlink to it).
