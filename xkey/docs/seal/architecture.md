# Seal & Auto-Unseal — Architecture

> **Status: NORMATIVE** · Feature: `seal` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

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
2. **The sealed-blob store** (`pkg/gui/services.SealService`,
   `AutoUnsealService`) — a GUI-only, pre-barrier
   mechanism for sealing individual named secrets (a LUKS passphrase, the
   pre-barrier password master key, a user PIN) to a chosen backend, and
   for auto-unsealing a LUKS-encrypted volume at GUI startup. It predates
   the Barrier and is still wired into the first-run setup wizard
   (`xkey/docs/setup-wizard/`) for LUKS-storage installs; it is not the
   mechanism the CLI or headless daemons use.

This document also covers **barrier auto-unseal** — the mechanism this
feature folder was created to document (go-xkms headless-agent work,
2026-09-23): unsealing the Barrier itself without a password, driven by a
named TPM policy the TPM itself enforces, from both the GUI at startup and
every headless CLI command that needs the barrier unsealed. The named
policies themselves are the shared TPM policy service, normative in
[`docs/tpm-policies/`](../../../docs/tpm-policies/).

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

Auto-unseal is an attribute of a **named TPM policy** (at most one per
scope). Enabling it (`xkey tpm policy auto-unseal <name>`, or the GUI) seals
the barrier's password in the TPM as the object `xkey-barrier-auto-unseal`,
in the system scope of xKey's TPM, bound to that policy and to nothing else.
At startup the TPM unseals it through a policy session — `PolicyAuthorizeNV`
over the policy's NV index, satisfied only by the PCR values the scope's
TPM-resident authority approved — so it is the TPM, not xKey, that checks
the platform state. Any barrier strategy that takes a password (`software`,
or `tpm2` with one) can auto-unseal this way.

Both the GUI (`pkg/gui/app.go`, at Wails startup) and every headless CLI
entry point (`xkey extension serve`, `xkey fido2` with `--storage barrier`,
`xkey oath`/`xkey backup`/`xkey oath sync` against a tpm2-strategy barrier,
and the explicit `xkey barrier unseal --auto`) drive the same decision
through `services.BarrierAutoUnsealService`:

| Step | Condition | Outcome |
|---|---|---|
| 1. Policy auto-unseal | A policy carries the auto-unseal mark and the TPM releases the password sealed under it | Barrier unseals with no password; logged as success |
| 2. Direct TPM unseal | A `tpm2` barrier created without a password | The TPM releases the root key on its own |
| 3. Password | Anything else | Password is required (flag, file, environment, or interactive prompt, depending on the command) |

Step 1 failing for any reason **other** than "no policy carries the mark"
is always a logged `Warn` naming the cause before falling through. The
important one is `services.ErrBarrierAutoUnsealRefused`: the TPM refused the
policy session because the PCRs no longer hold the approved values (the
platform's measured boot state changed) or the policy was revoked. The
operator re-approves an intended change with `xkey tpm policy update
<name>`; no re-seal is needed. `ErrBarrierAutoUnsealNotEnrolled` and
`ErrBarrierAutoUnsealPolicyMoved` report a mark with no password sealed
under it (the mark was set on the server API or moved); auto-unseal fails
closed until it is enabled again. See [engineering.md](engineering.md) for
the full error surface.

This auto-unseal is distinct from — and does not touch — the
`AutoUnsealService`'s LUKS-volume auto-unseal described below.

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

## Named TPM policies: one service, shared by the GUI and every CLI command

xKey does not keep a policy store of its own. Locally it runs the shared
TPM policy service (`pkg/tpmpolicy`, reached through `sdk/go`
`BuildTPMPolicyService`) in-process over its own TPM, in the system scope,
exactly as `xkmsd` does over its TPM — `localtpm.Open` (go-xkms
`pkg/localtpm`, the same implementation xkmsctl runs for its TPM vault keys). Its registry lives in
**`<data dir>/tpm-policies`** and tenant object blobs in
`<data dir>/tpm-keys`, opened with the storage engine the unified config
selects; the system scope's own objects (its policy authority, its sealed
scope secrets, the auto-unseal password object) live in the TPM's key store
at `<data dir>/tpm`. The GUI's `ensureLocalTPMPolicies` and the CLI's
`openLocalTPMPolicies` open the same stores, so a policy created through
either surface is visible to the other and to every headless auto-unseal
caller.

The registry is deliberately **outside the barrier**: boot-time auto-unseal
reads it before the barrier is open, and the TPM resolves each policy's NV
index and approval from it when it unseals. Nothing in it is secret — PCR
selections and values, approvals signed by the TPM-resident authority, the
TPM Names of NV indices, and scope secrets sealed by the TPM under the
platform policy — and tampering with it cannot authorize anything the TPM
would not.

When xKey is connected to a server, `services.TPMPolicyService` runs the
same operations on the server through `transport.Client`'s `TPMPolicy*`
methods instead; the server records the objects it creates.

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
| TPM2 (named TPM policy) | Yes, while the TPM accepts the policy | No (falls through to manual otherwise) | Yes |
| PKCS#11/HSM | Partial — token must be present | PIN, cached in PlatformStore if stored | Yes |
| Cloud KMS (AWS/GCP/Azure/Vault) | Yes, when IAM/identity is configured | No (external auth) | Yes |
| Software (Argon2id/PBKDF2) | No | Always | No |

The static password store additionally defines two `AccessMode` values, but
only one is a reachable code path: **session** (`session_based` —
`TenantPasswordStoreManager.UnlockTenant` is called once, on a remote
`xkmsd` server, and subsequent operations for that tenant succeed until
`LockTenant`; go-xkms `pkg/staticpw/access.go`, `tenant_store_manager.go`).
**per-operation** (`pin_per_operation`) is a defined constant with no store
implementation behind it (go-xkms#864) and is not reachable through `xkey`
or `xkmsd` today.

## The sealed-blob store (GUI only)

`pkg/gui/services.SealService` seals arbitrary named secrets (a user PIN, a
LUKS passphrase, a password master key) to a chosen backend through the SDK
client — the connected server's, or the embedded local one — and persists
each as an individual `{id}.sealed.json` file (default
`~/.xkey/data/sealed/`, mode `0600`, or through the barrier once it is
open) that records its own `backend_id`. A blob's protection is:

- a **TPM policy** (tpm2 backend only): none, the built-in `platform`
  policy (the default), or a named policy — the TPM enforces it on every
  unseal; each tpm2 blob is sealed as its own object (`xkey-sealed-<id>`), so
  each keeps its own policy binding, and a blob sealed locally under a named
  policy is recorded against it, so the policy cannot be deleted while the
  blob exists (deleting the blob removes the record);
- plus an optional **password**: on the tpm2 backend the sealed object's
  TPM authorization value (with a policy, the policy's password branch,
  which still unseals after the PCRs change); on other backends a software
  check against an argon2id hash.

A record without a `backend_id` is rejected, never defaulted
(`ErrSealBlobBackendIDMissing`).

`AutoUnsealService` uses it to auto-unseal a LUKS-encrypted storage
volume: `Enable(passphrase, tpmPolicy, backend)` seals the volume
passphrase (the wizard uses the built-in `platform` policy);
`TryAutoUnseal()` (called at GUI startup) retrieves and uses it; `Reseal()`
re-seals under the same policy, which for the platform policy re-binds it to
the current platform PCR. The first-run setup wizard wires all of this
together; see [setup-wizard/](../setup-wizard/).

## Rejected alternatives

- **Comparing PCRs in software before unsealing.** The previous barrier
  auto-unseal read the PCRs, compared them with a stored snapshot, and then
  unsealed with an empty password — the TPM never enforced the policy, and
  a fallback "direct TPM unseal" skipped the check entirely. Auto-unseal now
  has the TPM release the password through the policy's own session.
- **A separate xKey policy store.** xKey used to keep its own PCR policy
  DAO (`pkg/pcr_policy`) and a single unnamed "platform policy" file;
  neither was enforced by the TPM, and both duplicated the shared TPM policy
  model. Both were removed in favour of the shared service.

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
- [cli.md](cli.md) — every `xkey barrier` verb and flag, and `xkey tpm policy auto-unseal`
- [docs/tpm-policies/](../../../docs/tpm-policies/) — the named TPM policy service (normative)
- [api.md](api.md) — network-transport surface (none)
- [user.md](user.md) — task-oriented usage, including agent auto-unseal setup
- [xkey-agent skill](../../skills/xkey-agent/SKILL.md) — the agent-facing summary of this feature
- [setup-wizard/](../setup-wizard/) — first-run orchestration that wires `TPMPolicyService`/`BarrierAutoUnsealService`/`AutoUnsealService`/`BarrierService` together
