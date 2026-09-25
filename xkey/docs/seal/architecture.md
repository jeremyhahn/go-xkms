# Seal & Auto-Unseal — Architecture

> **Status: NORMATIVE** · Feature: `seal` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Scope

Everything that keeps xKey's data at rest encrypted, and everything that
unlocks it again without (or with) a human. Two independent layers make up
"seal" in this codebase:

1. **The Barrier** (`sdk/go` `xkms.Barrier`, wrapped by
   `pkg/gui/services.BarrierService`) — AES-256-GCM transparent encryption
   that wraps the xKey data directory's storage backend. Every CLI command
   and the GUI that persists a secret (OATH credentials, FIDO2 keys, the
   OIDC token store, static passwords, PIV keys stored in software) writes
   through it once it is initialized. Sealed with one of seven strategies:
   TPM 2.0, PKCS#11, a software Argon2id-derived key, or one of four cloud
   KMS strategies (AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault
   — go-xkms#757).
2. **The legacy sealed-blob store** (`pkg/gui/services.SealService`,
   `PlatformPolicyService`, `AutoUnsealService`) — a GUI-only, pre-barrier
   mechanism for sealing individual named secrets (a LUKS passphrase, the
   pre-barrier password master key, a user PIN) to a chosen backend, and
   for auto-unsealing a LUKS-encrypted volume at GUI startup. It predates
   the Barrier and is still wired into the first-run setup wizard
   (`xkey/docs/setup-wizard/`) for LUKS-storage installs; it is not the
   mechanism the CLI or headless daemons use.

This document also covers **barrier auto-unseal** — the mechanism this
feature folder was created to document (go-xkms headless-agent work,
2026-09-23): unsealing the Barrier itself without a password, driven by a
named PCR policy, from both the GUI at startup and every headless CLI
command that needs the barrier unsealed.

Out of scope: `xkey platform-store` (a *different* thing with a confusingly
similar name — a key-value secret store served by a remote **xkmsd**
server; see `xkey/docs/architecture/platform-store.md`) and LUKS2 container
management itself (`xkey/docs/luks/`, still unconverted). The setup
wizard's own step ordering is normative in `xkey/docs/setup-wizard/`; this
document does not repeat it.

## The Barrier

`xkms.Barrier` (`sdk/go`) implements `storage.Backend`: `Put`/`Get`/`Delete`
transparently encrypt/decrypt with a data encryption key (DEK) derived from
a root key. The root key is generated once (`xkey barrier init`), sealed
with the chosen strategy, and persisted at `<data dir>/barrier/root_key`.
Unsealing (`xkey barrier unseal`, or a headless command's own unseal path)
loads that blob, unseals the root key via the recorded strategy, and derives
the DEK into memory; sealing (`xkey barrier seal`) zeroes the DEK. The
barrier always wraps *some* base backend — a plain filesystem directory, or
a LUKS-mounted one when LUKS storage is chosen — so "is the barrier
initialized" is the one question `barrier_store.go`'s
`resolveSecretStoreBackend`/`openBarrierBackend` ask on behalf of every
barrier-aware CLI command (`oath`, `backup`, `oath sync`, `fido2
--storage barrier`, the OIDC token store).

## Barrier Auto-Unseal: the decision order

A **tpm2-strategy** barrier can unseal without any password at all, because
the TPM's own PCR policy session authorizes the unseal. Both the GUI
(`pkg/gui/app.go`, at Wails startup) and every headless CLI entry point
(`xkey extension serve`, `xkey fido2` with `--storage barrier`, `xkey oath`/
`xkey backup`/`xkey oath sync` against a tpm2-strategy barrier, and
the explicit `xkey barrier unseal --auto`) drive the same decision, in the
same order:

| Step | Condition | Outcome |
|---|---|---|
| 1. Policy auto-unseal | A policy is designated auto-unseal (`xkey policy set-auto-unseal <name>`) and its recorded PCR values match the TPM's current ones | Barrier unseals with no password; logged as success |
| 2. Direct TPM unseal | No policy is designated at all | Falls back silently (this is the expected state for a barrier that never had a policy set) to a direct TPM unseal — still no password, but without PCR verification |
| 3. Password | The barrier's strategy is not `tpm2` (`software`), or the direct TPM unseal itself fails | Password is required (flag, file, environment, or interactive prompt, depending on the command) |

Step 1 failing for any reason **other** than "no policy configured" — most
importantly a **PCR mismatch** (the platform's measured boot state changed
since the policy was captured) — is always a logged `Warn` naming the cause
before falling through to step 2. It is never silent: a PCR mismatch means
something about the machine changed, and an operator needs to see that even
though the command still proceeds. The typed sentinel is
`services.ErrBarrierAutoUnsealPCRMismatch`
(`xkey/pkg/gui/services/barrier_auto_unseal.go`); see
[engineering.md](engineering.md) for the full error surface.

This auto-unseal is distinct from — and does not touch — the legacy
`AutoUnsealService`'s LUKS-volume and pre-barrier-password auto-unseal
described below.

## Cloud KMS strategies: one composition path, two entry points

`xkmsd` (`pkg/server/seal_strategies.go`) and xkey both build a cloud KMS
seal strategy (`aws_kms`/`gcp_kms`/`azure_kv`/`vault`) through the same
function, `pkg/seal.BuildCloudKMSStrategy` (re-exported as
`sdk/go.BuildCloudKMSStrategy`): given an already-constructed backend
(`AWSKMSBackend`, `GCPKMSBackend`, `AzureKVBackend`, or `VaultBackend`, all
implementing `types.KeyProvider`), it provisions the symmetric wrapping key
the barrier root key is sealed under — a fixed name (`sdk/go.SealKeyCN`),
created on first use and reused thereafter — and returns the matching
`CloudKMSStrategy`. Sharing this one function is what lets a barrier
initialized by `xkmsd` unseal under xkey and vice versa; xkmsd's
`buildHardwareSealStrategy` calls it for the same four strategy IDs xkey
does.

What differs between the two is how the backend itself gets built, because
xkey has no backend/provider registry of its own the way `xkmsd`'s
`s.keyProviders` is:

- `cmd/xkey/cmd/barrier_cloudkms_<provider>.go` (one file per provider,
  gated by that provider's Go build tag — `awskms`, `gcpkms`, `azurekv`,
  `vault`, matching `pkg/backend/<provider>`'s own gating) constructs the
  backend from `xkey/pkg/config.BarrierCloudKMSConfig` (persisted by `xkey
  barrier init --strategy <id> --<provider>-...`, see cli.md) and registers
  itself into a small dispatch map (`cloudKMSStrategyBuilders`,
  `barrier_cloudkms.go`) keyed by `sdk/go.StrategyID`. A binary built
  without a provider's tag has no entry for that ID and reports a typed
  error naming the missing tag rather than a compile error or a silent
  fallback.
- `services.BarrierService` (used by both the GUI and, via
  `cmd/xkey/cmd/extension_serve.go`, the headless daemon) has no cloud
  backend wiring of its own either. `SetCloudKMSStrategyFunc` injects a
  `func(strategyID string) (xkms.SealingStrategy, error)` the same way
  `SetTPMSealerFunc` injects a TPM2 sealer; `extension serve` builds the
  strategy via the dispatch map above and injects it before calling
  `Unseal`. This replaces the flat refusal `extension serve` used to return
  for every cloud KMS strategy (go-xkms#699); `pkcs11` and `shamir` are
  still refused (see cli.md) because unsealing them headlessly needs a
  secret source (a TPM-sealed PIN store, an operator share quorum) that does
  not exist yet — a different problem from "no backend wiring", which cloud
  KMS had until this issue.

Credentials follow the layer that owns the concept: an explicit credential
is a `*xkms.SecretValue` config field (`BarrierAWSKMSConfig.SecretAccessKey`,
`BarrierAzureKVConfig.ClientSecret`, `BarrierVaultConfig.Token`), resolved
through `sdk/go.NewSecretConfigProcessor`/`NewSecretResolverRegistry` — the
same go-qrdb secret-reference contract `xkmsd` resolves its own backend
credentials through (`pkg/server/secret_wiring.go`) — never a plain string.
xkey registers no resolvers of its own (it has no credential store), so a
field left `nil` is skipped (ambient credentials — the AWS SDK default
chain, GCP Application Default Credentials, Azure `DefaultAzureCredential`,
or Vault's `VAULT_TOKEN`, and the documented default for every provider),
while a field naming an explicit reference fails closed with
`sdk/go.ErrUnresolvedSecretURI` until a resolver for a scheme xkey can
serve is registered.

## Named PCR policies: one store, shared by the GUI and every CLI command

A PCR policy (`xkey policy create <name> --pcrs 0,2,4,7 --bank sha256`)
captures a named snapshot of TPM PCR digests. Designating one for
auto-unseal (`xkey policy set-auto-unseal <name>`) is a one-time,
human-run setup step; agents never create or designate a policy, only
benefit from one that already exists. The store —
`pcrpolicy.DAOStore` (`xkey/pkg/pcr_policy`), a go-qrdb `GenericDAO` over a
file-backed `kvstore.KVStore` — lives at exactly one location by default,
**`<data dir>/pcr_policies`**, resolved through the shared
`resolveDataDir`/`featureDataDir` chain (`--data-dir`, `XKEY_DATA_DIR`,
config, then `~/.xkey/data`). The GUI's `initializeDataDir`
(`pkg/gui/app.go`) opens the identical `pcrpolicy.DAOStore` at the identical
path, so a policy created or designated through either surface is visible
to the other and to every headless auto-unseal caller — there is one policy
store, not two that happen to agree by convention. `xkey policy`'s
`--store` flag can still point elsewhere for an isolated profile or test
directory; that default only changed to `<data dir>/pcr_policies` as part
of this work — it was previously the CWD-relative `./data/policies`, which
could not have matched the GUI's location by construction.

## Auto-unseal beyond the barrier: PlatformStore-based backends

The barrier PCR-policy auto-unseal above answers "can the barrier itself
unlock without a human." A broader question — "can *any* named secret
(a LUKS passphrase, a user PIN, an HSM PIN) be retrieved without a human at
boot" — is answered per sealing backend by the PlatformStore/PlatformSealer
machinery (`pkg/seal` in the root module; `xkey/pkg/gui/services.SealService`
for the GUI's local sealed-blob flavor of it, see below). Capability varies
by backend:

| Strategy | Auto-unseal | Password/PIN needed | Hardware-backed |
|---|:---:|:---:|:---:|
| TPM2 (PCR-bound) | Yes, when PCRs match | No (falls through to manual otherwise) | Yes |
| PKCS#11/HSM | Partial — token must be present | PIN, cached in PlatformStore if stored | Yes |
| Cloud KMS (AWS/GCP/Azure/Vault) | Yes, when IAM/identity is configured | No (external auth) | Yes |
| Software (Argon2id/PBKDF2) | No | Always | No |

The static password store additionally has two auto-unseal modes once its
PIN is available: **per-operation** (`pin_per_operation` — the PIN is held
in memory and supplied on every decrypt) and **session** (`session_based` —
`SessionStore.Unlock(pin)` is called once and subsequent operations succeed
until `Lock()`).

## The legacy sealed-blob store (GUI only)

`pkg/gui/services.SealService` seals arbitrary named secrets (a barrier
software-strategy password, a user PIN, a LUKS passphrase) to a chosen
backend via a `map[string]types.Sealer` registry (`RegisterSealer`,
`SetDefaultBackend`), and persists each as an individual
`{id}.sealed.json` file (default `~/.xkey/data/sealed/`, mode `0600`) that
records its own `backend_id` and `policy_type` (`none`, `password`,
`platform_policy`, or `custom_pcr` — the latter two require the `tpm2`
backend). A record predating those two required fields is rejected, never
defaulted (`ErrSealBlobPolicyTypeMissing`/`ErrSealBlobBackendIDMissing`).

`PlatformPolicyService` captures a **single, unnamed** PCR snapshot (default
PCRs `[0, 7, 9]`, bank `sha256`) at `~/.config/xkey/platform.policy` —
deliberately outside any LUKS volume, so it is readable before that volume
is mounted. This is the `policy_type: platform_policy` a `SealService`
request can bind to; it is a different store from the named, multiple-policy
`pcrpolicy.DAOStore` this feature folder otherwise documents, and the two
are not interchangeable.

`AutoUnsealService` uses both to auto-unseal a LUKS-encrypted storage
volume: `Enable(passphrase, pcrs, bank, policyType, policyName, backend)`
seals the volume passphrase; `TryAutoUnseal()` (called at GUI startup)
retrieves and uses it; `Reseal()` re-seals with current PCR values,
typically after a platform update. It also seals a `software`-strategy
barrier's password (a `tpm2`-strategy barrier needs no such thing — it
auto-unseals inherently, via the mechanism this document otherwise
describes). All of this is wired together by the first-run setup wizard;
see [setup-wizard/](../setup-wizard/) for the step-by-step orchestration.

## Rejected alternatives

- **Auto-provisioning an unprovisioned TPM's SRK as a side effect of an
  unseal attempt.** The in-process TPM simulator used in tests starts every
  fresh instance with no Storage Root Key resident at its persistent
  handle; real hardware is provisioned once, out of band, with `xkey tpm
  provision`/`install`, and stays provisioned. Silently provisioning the
  TPM's owner hierarchy from a headless daemon's unseal path would be a
  security-relevant behaviour change (it creates persistent TPM objects) no
  narrower change should make unilaterally, so headless auto-unseal treats
  "no TPM, or an unprovisioned one" as a typed failure and falls back,
  exactly as the direct-unseal path already did.
- **Threading the auto-unseal TPM connection's closer through one-shot CLI
  commands** (`xkey oath`, `xkey backup`, `xkey barrier unseal --auto`).
  These are single, short-lived processes; the connection is deliberately
  left open until the process exits rather than adding an explicit close
  path through several layers of call chain for no observable benefit. A
  long-running daemon (`xkey extension serve`) does thread it, to an
  explicit shutdown defer.
- **Moving `BarrierAutoUnsealService`/`TPMAccessor`/`BarrierService` out of
  `xkey/pkg/gui/services`.** That package already compiled into, and was
  already imported directly by, the plain CLI binary before headless
  auto-unseal existed (no Wails build tag gates the package as a whole) —
  it was already the de facto shared, non-GUI-coupled layer despite its
  path. A real physical move remains open as follow-up work; this feature
  did not force it.

## See also

- [engineering.md](engineering.md) — exported surface, invariants, errors, tests
- [cli.md](cli.md) — every `xkey barrier`/`xkey policy` verb and flag
- [api.md](api.md) — network-transport surface (none)
- [user.md](user.md) — task-oriented usage, including agent auto-unseal setup
- [xkey-agent skill](../../skills/xkey-agent/SKILL.md) — the agent-facing summary of this feature
- [setup-wizard/](../setup-wizard/) — first-run orchestration that wires `PlatformPolicyService`/`AutoUnsealService`/`BarrierService` together
