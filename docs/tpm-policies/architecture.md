# TPM Policies and TPM Tenancy — Architecture

> **Status: DESIGN (not yet implemented)** · Feature: `tpm-policies` · Repo: `go-xkms` · Last verified: 2026-09-29

This is the design for named TPM policies that many keys and sealed objects
share, for a registry that records which keys use which policy, and for
per-tenant TPM modes. It replaces the PCR snapshot store in `pkg/seal/policy`,
xKey's `pcr_policy` store and xKey's `PlatformPolicyService`.

## The problem

A TPM cannot report which policy an object was created under. It only compares
an object's `authPolicy` digest with the digest a session reaches. Today:

- A key has one policy switch, `KeyAttributes.PlatformPolicy`. Its value is
  the fixed platform policy `PolicyOR(PolicyPCR(PCR 16), PolicyAuthValue)`.
  There is no way to choose another policy.
- A seal request's PCR selection is copied into `TPMAttributes.PCRSelection`
  and never turned into an `authPolicy`. A "PCR-bound" sealed object is not
  bound to those PCRs. REST, gRPC and MCP do not even carry the field.
- `pkg/seal/policy` stores PCR values and compares them. Nothing uses it to
  create or authorize an object.
- A policy digest built directly from PCR values changes whenever those values
  change. Every object created under it must then be re-created, which a
  non-exportable key cannot survive.
- TPM2 key blobs are stored by CN alone. Two tenants that use the same CN
  collide, and a tenant cannot list its own TPM2 keys.

## Object model

| Object | Identity | Contents | Mutability |
|---|---|---|---|
| **Scope** | tenant ID (`system` for the platform) | TPM mode, storage key, policy authority, revocation counter | created once per tenant TPM mode |
| **Policy authority** | one per scope | a TPM-resident, non-exportable ECDSA P-256 signing key | rotated only by re-keying the scope |
| **Revocation counter** | one NV counter index per scope | a monotonically increasing `epoch` | increments on every policy update or revocation |
| **Named policy** | `(scope, name)` | PCR bank, PCR selection, captured PCR values, `policyRef`, the current approval, `auto_unseal` flag | the name and `policyRef` never change; the approval is replaced by an update |
| **Approval** | `(scope, name, epoch)` | `approvedPolicy` digest and the authority's signature over it | immutable; superseded by the next epoch |
| **Assignment** | `(scope, object ID)` | policy name, `policyRef`, authority Name, and the key's `authPolicy` digest at creation | written at creation, removed with the object |

`platform` is a built-in named policy in every scope. It is today's platform
policy (PCR 16 in the platform bank, OR the object's auth value), with no
authority and no approval. It cannot be created, updated or deleted. It is the
default when a caller names no policy. It replaces `KeyAttributes.PlatformPolicy`,
the key backend's `platform_policy` setting and the probe's `PlatformPolicy`.
The platform store's sealer keeps its flag only if something outside key
creation still needs it; otherwise it uses `platform` too.

### What an object is bound to

An object that uses a named policy `P` in scope `S` is created with:

```
authPolicy = PolicyOR(PolicyAuthorizeNV(index(P)), PolicyAuthValue)
index(P)   = PolicyAuthorize(policyRef(P), keySign = Name(authority(S)))   -- as TPMT_HA
```

- `policyRef(P)` is `SHA-256("xkms/tpm-policy/v1" ‖ scope ‖ 0x00 ‖ name)`. The
  authority's signature covers both the approved digest and the reference, so
  an approval for one policy cannot authorize an object bound to another.
- The object's `authPolicy` does not contain PCR values. The PCR values live in
  the approval, and that is why an update needs no re-key.
- `PolicyAuthValue` is the second branch, as in `platform`. The key password
  stays a separate field on the key.
- An object with **no** auth value gets the `PolicyAuthorizeNV` branch alone.
  An OR branch that an empty password satisfies would bypass the policy.
- Named-policy objects are created with `userWithAuth` clear, so the policy is
  the only way to authorize them. The password path is the `PolicyAuthValue`
  branch.
- The TPM refuses a policy whose hash differs from the object's name
  algorithm. That mismatch is refused at creation with `ErrPolicyHashMismatch`.

An approval for `P` at epoch `e` signs:

```
approvedPolicy = PolicyPCR(selection(P), digest(values(P)))
               → PolicyNV(counter(S), operandB = e, offset 0, TPM_EO_EQ)
aHash          = H(approvedPolicy ‖ policyRef(P))
signature      = Sign(authority(S), aHash)
```

### Using an object (sign, decrypt, ECDH, unseal)

The session code (`pkg/tpm2/session.go`, `createKeySession`) chooses a branch
from the assignment:

- **Approved branch, no password:**
  1. `PolicyPCR(selection, values)`
  2. `PolicyNV(counter, e, EQ)`
  3. `PolicyGetDigest`
  4. `VerifySignature(authority, aHash, signature)`, which yields a ticket
  5. `PolicyAuthorize(approvedPolicy, policyRef, Name(authority), ticket)`
  6. `PolicyAuthorizeNV(index(P))`
  7. `PolicyOR`, when the object has an auth-value branch
- **Password branch:** `PolicyAuthValue`, then `PolicyOR`, with the object's
  auth value in an HMAC-bound session. This matches the platform policy's PIN
  branch today.

The TPM enforces both "the live PCRs equal the approved values" and "the
approval is current". The server makes no software comparison.

## Policy-authority lifecycle

1. **Binding record.** Each object stores a binding record beside its blobs
   (`.tpmpolicy`, format `XTPB` v1): scope, policy, index, hash and whether it
   has an auth-value branch. The session code reads this record, not the
   caller's attributes.
2. **Scope creation** runs when a tenant's `tpm.mode` becomes `shared` or
   `vtpm`, and at first boot for `system`. It creates the scope's storage
   key, then the authority under it, then the counter, and writes the scope
   record.
3. **Authority key:**
   - It is an ECDSA P-256 signing child of the scope's storage key, with
     `fixedTPM | fixedParent | sensitiveDataOrigin`, so it is non-exportable.
     It signs only approval digests that xkms computes itself; callers never
     reach it.
   - It is bound to the `platform` policy and has a random 32-byte auth value.
     That value lives in the scope's sealed secrets behind the barrier.
   - Its public area and Name are recorded in the scope record. Every approval
     is verified against that Name.
4. **Signing** happens only inside xkms, on policy create and update. A caller
   never supplies a signature.
5. **Rotation** is required (owner ruling, 2026-09-29). See
   [Authority rotation](#authority-rotation).

## Authority rotation

**Feasibility.** Rotation uses `TPM2_PolicyAuthorizeNV` indirection: an object
binds to an NV index, and the NV index names the current authority, so writing
the index moves every bound object to a new authority without re-keying. This
was verified on 2026-09-29:

| TPM | Revision | PolicyAuthorizeNV |
|---|---|---|
| go-tpm-tools simulator (MSFT) | 1.54 | advertised; runs, and the session digest equals the trial digest |
| swtpm 0.7.3 (libtpms) | 1.64 | advertised; runs, and the session digest equals the trial digest |
| production vTPM host (IBM firmware 2024-01-25) | 1.83 | advertised (capability query only) |

go-tpm v0.9.8 implements `PolicyAuthorizeNV`, including its trial `Update`.

**The gap in one index per tenant.** `PolicyAuthorizeNV` checks that the
session's current digest equals the digest stored in the index, then *resets*
the digest to `H(0 ‖ CC_PolicyAuthorizeNV ‖ Name(index))`. `PolicyAuthorize`
resets it the same way. An object's `authPolicy` therefore records only which
index it follows. If every object of a tenant follows one index, all of them
share one `authPolicy`, and the TPM would accept any current approval of that
tenant for any of its objects. The object-to-policy binding would then be
enforced only in software. Three ways to keep the TPM enforcing it:

| Option | Object binds to | Stored in NV | Update or rotation cost | NV cost on the physical TPM |
|---|---|---|---|---|
| **A** (ruled 2026-09-29, built) | `PolicyAuthorizeNV(index(P))`, one index per named policy | `PolicyAuthorize(authority, policyRef(P))` digest | rotation rewrites each of the tenant's policy indices; an update re-signs the tenant's policies (a few) | one index per named policy, plus one counter per tenant |
| B | `PolicyAuthorizeNV(index(tenant))` | `PolicyAuthorize(authority, tenantRef)` digest | approvals are per object (`PolicyNameHash(object Name)`), so every update or rotation re-signs every object of the tenant | one index plus one counter per tenant |
| C | same as B | same as B | same as A | same as B, but the object-to-policy binding is enforced only by the registry |

Option A keeps the session code simple and updates cheap. Its NV use is bounded
by the number of named policies, not objects, and `vtpm` tenants spend their
own vTPM's NV. The policy indices and the tenant counter are written with an
`AUTHWRITE` secret held in the scope record. The authority never controls its
own replacement.

**Rotation steps (option A):**
1. Create authority `k+1`.
2. For each policy, write the index with `PolicyAuthorize(authority k+1, policyRef(P))`.
3. Sign every policy's current approval with `k+1`.
4. Store the scope record and approvals in one registry batch.
5. Flush and evict authority `k`.

Approvals signed by `k` no longer match any index, so rotation also revokes
them. If the process crashes after the first index write, `k` and `k+1` are
both recorded as `rotating`, and startup finishes the remaining writes.

**Tenant key rotation** (ruled 2026-09-29: a service-layer version model on
every backend, with the version carried in an envelope header). It is
designed in [Key versions](#key-versions). The ruling asks for key versions:
a new version under the tenant's scope, old versions kept for verify and
decrypt until retired, and "rotate all keys in this scope". xkms has no such
model today:
- the gRPC API declares `ListKeyVersions`, `Enable/DisableKeyVersion` and
  `Enable/DisableAllKeyVersions`, but nothing implements them;
- `RotateKey` replaces a software key in place and delegates to the cloud KMS's
  own versioning;
- TPM2 returns `ErrKeyRotationNotSupported`.

The model is therefore a new, cross-backend design. It must decide how a
verify or decrypt call selects a version.

## Key versions

Owner ruling (2026-09-29): a service-layer version model on every backend.

- **A version is its own backend key.** Key `K` version `n` is the backend key
  `K@v<n>`. `RotateKey(K)` creates `K@v<n+1>` with the same algorithm,
  attributes and, for TPM2, the same scope and policy. It then makes that
  version current. Nothing is re-keyed in place, so a non-exportable TPM2 key
  rotates like any other.
- **The version records live in the registry**
  (`{tenant}/key-versions/<keyID>`). A record holds the current version and,
  per version, its state (`enabled`, `disabled` or `retired`) and creation
  time. The gRPC `ListKeyVersions`, `Enable/DisableKeyVersion` and
  `Enable/DisableAllKeyVersions` RPCs, already declared, are implemented over
  it.
- **Encrypt and sign always use the current version. Decrypt and verify select
  the version from the envelope,** so callers never track versions.
  - A disabled version refuses every operation until it is re-enabled.
  - A retired version is gone: its backend key is deleted, and it can never be
    re-enabled.
  - Older enabled versions keep serving decrypt and verify.
- **Rotate all:** `RotateScopeKeys(tenant)` rotates every key in the tenant's
  scope and reports each result.

### Envelope format (v1)

```
offset  size  field
0       2     magic 0x58 0x4B ("XK")
2       1     format version, 0x01
3       1     kind: 0x01 ciphertext, 0x02 signature
4       4     key version, uint32 big-endian (1-based)
8       n     payload: the backend's ciphertext or signature, unchanged
```

- A header whose magic, format version or kind is unknown is refused with
  `*EnvelopeFormatError`. It is never guessed at.
- A future format bumps byte 2. Decoders keep every format they have ever
  shipped.

**Open question, not yet ruled on:** a signature or an RSA-OAEP ciphertext
often leaves xkms in a standard format that has no room for a header: X.509
and CSR signatures, SSH signatures, JWS, git commit signatures, and ciphertext
a third party produced with the public key. See the report accompanying this
section for the options.

## NV counter and revocation

- Each scope has one NV index of type `TPM_NT_COUNTER`, and each named policy
  has one ordinary NV index holding a `TPMT_HA` digest. Both use the same
  attributes:
  - `AUTHWRITE`, with the index's auth value set to a random write secret held
    (sealed) in the scope record. Only xkms can update, rotate or revoke.
  - `POLICYREAD`, with the read policy
    `PolicyOR(PolicyCommandCode(NV_Read), PolicyCommandCode(X))`. X is
    `PolicyAuthorizeNV` for a policy index and `PolicyNV` for the counter.
    Using an object therefore needs no secret, and the index cannot be read
    for any other purpose.
    `AUTHREAD` would check reads against the write secret. An empty auth value
    would leave the index writable by anyone.
  - `NO_DA`: the secret is random, so dictionary-attack lockout would only
    let one caller lock the TPM for every tenant.
- The first write sets `TPMA_NV_WRITTEN`, which changes the index's Name. An
  object is bound to the Name read after that write, and creating an object
  against an unwritten index is refused.
- Physical-TPM indices come from the owner range `0x01500000–0x015FFFFF` and
  are allocated per scope. A vTPM uses a fixed index in its own TPM.
- **Update of `P`:**
  1. Read the live PCRs over `P`'s selection.
  2. Increment the counter to `e+1`.
  3. Re-sign every policy in the scope at `e+1`. Policies other than `P` keep
     their PCR values.
  4. Store the new approvals in one registry transaction.
- **Revoke** increments the counter and re-signs every policy except the
  revoked one. The revoked policy then has no current approval, so its objects
  answer only to their password branch until the policy is updated again.
- **Replay:** an approval signed at epoch `e` contains `PolicyNV(… = e)`. After
  the increment `PolicyNV` fails, so the old approval cannot be replayed. The
  TPM refuses it, not software.
- **Crash between steps 2 and 4:** the counter is ahead of the stored
  approvals, so every approved branch fails closed. On start, the service finds
  `stored epoch < counter` and re-signs at the counter's value. That is safe
  because the stored PCR values are the ones already approved.
- **Capacity:** each shared-mode tenant costs one physical NV index. The TPM
  reports its NV capacity, scope creation fails with `ErrTPMNVExhausted` when
  it is full, and `vtpm` has no such limit.

## Registry

The registry is stored in the scope's storage, under
`{tenant}/tpm-policies/shared/`. It opens through the same `compose.StorageFactory`
seam every other xkms store uses, so xkmsd gets `createStorage("tpm-policies")`
and an embedding host gets `xkms/tpm-policies/`:

```
scope                               the scope record (mode, handles, authority public, counter index, epoch)
policies/<name>                     the named policy and its current approval
assignments/by-object/<objectID>    object → policy (name, policyRef, authority Name, authPolicy digest)
assignments/by-policy/<name>/<id>   policy → objects
```

- Both assignment directions are written and removed in one batch with the
  object's own blobs.
- `DeletePolicy` refuses with `*PolicyInUseError{Policy, Objects}` while
  `by-policy/<name>/` is non-empty, and lists the object IDs.
- A policy cannot be updated in a way that changes its selection or bank.
  Doing that means creating a new policy and re-keying, because the `policyRef`
  would still match but the meaning would silently change. `update` re-captures
  values only.
- An object ID is `<kind>/<CN>`, where kind is `key` or `sealed`, inside the
  scope. The registry key and the TPM blob path both include the tenant, which
  closes the CN collision.

## Tenancy modes

The physical TPM belongs to the system tenant. `tpm.mode` is kept in the
xkms-owned scope record at `{tenant}/tpm-policies/shared/scope`, and only the
system administrator can set it:

| Mode | Where the tenant's TPM objects live | Isolation |
|---|---|---|
| `none` | nowhere; the tenant cannot create TPM2 keys, sealed objects or policies | n/a |
| `shared` (default) | physical TPM, under a per-tenant storage key that is a child of the Platform SRK | The tenant storage key's auth value is a random secret in the tenant's scope record. Blobs are under the tenant's prefix. One tenant cannot load another's objects, because it cannot authorize the other's parent. |
| `vtpm` | a per-tenant vTPM (swtpm) that the node runs | a separate TPM: its own EK, SRK, authority, counter and NV |

- The system tenant always uses the physical TPM, and its scope's storage key
  is the Platform SRK.
- A mode change is allowed only when the tenant's scope holds no objects and no
  policies other than `platform`. TPM objects cannot move between TPMs, so any
  other transition is refused with `*TPMModeChangeError{Objects}`.
- In `shared` and `vtpm` modes, `platform` means the tenant's own TPM's
  platform policy. For `shared` that is the physical TPM's.
- Scoping follows the plan's model: policies and the registry are
  tenant-shared, at `{tenant}/tpm-policies/shared`. There is no user-personal
  TPM policy, because an authority is per tenant.

### vTPM mode: swtpm management

`swtpm` (0.7.3, libtpms) is installed on the host and in the CI and
devcontainer images (`Dockerfile.ci`). The node runs it as a **managed child
process** rather than a sidecar container, because:

- xkmsd already owns the TPM lifecycle, and a process needs no container
  runtime on bare-metal nodes;
- the state-encryption key reaches swtpm over an inherited file descriptor
  (`--key fd=N,mode=aes-256-cbc`) and never touches disk;
- a sidecar would need the key shipped across a container boundary, and a
  second supervisor to restart it.

An embedding host that runs in containers (quicbaas) still gets a process
inside its own container.

- **Supervisor:** `pkg/tpm2/vtpm`. It exposes `Manager.Start(tenant)`, `Stop`,
  `Status` and `Open(tenant) (TrustedPlatformModule, error)`.
  - It runs `swtpm socket --tpm2 --tpmstate dir=<data>/vtpm/<tenant>
    --server type=unixio,path=<run>/vtpm-<tenant>.sock --ctrl
    type=unixio,path=<run>/vtpm-<tenant>.ctrl --key fd=3,mode=aes-256-cbc
    --flags startup-clear`.
  - It restarts the process with backoff, and reconnects clients by reopening
    the socket.
- **State key:** a random 32 bytes created when the tenant's scope is created,
  and sealed under `vtpm-state`, a named policy in the system scope. It is
  stored in the system scope's storage and unsealed by the node at start. A
  vTPM's state cannot be read on a different platform, and a firmware change is
  handled by updating `vtpm-state` rather than by losing the vTPMs.
- **First start:** `swtpm_setup` with an EK, then xkms provisions the vTPM's
  SRK, the tenant's authority and the counter.
- **Tests:**
  - The in-process go-tpm-tools simulator is a process-wide singleton (one
    instance at a time), so it cannot stand in for a physical TPM and a vTPM
    at the same time.
  - The start and stop test therefore runs real `swtpm` from `make test`,
    because the binary is a declared test dependency.
  - Every policy test runs on the simulator behind the same
    `TrustedPlatformModule` interface.

## xKey parity

xKey uses the same package, `pkg/tpmpolicy`, re-exported through `sdk/go`:

- **Local mode:** the `system` scope over xKey's own TPM. The registry is xKey's
  qrdb KV store under `<dataDir>/tpm-policies`. This replaces
  `xkey/pkg/pcr_policy`, `PlatformPolicyService` and the `platform.policy` file.
- **Connected mode:** the same service calls go through `transport.Client`
  against the server.
- **Barrier auto-unseal:** becomes the named policy's `auto_unseal` attribute.
  At most one policy per scope carries it. `BarrierAutoUnsealService` reads it
  from the registry, and unseals through a real policy session instead of
  comparing PCRs in software.
- **Seal service:** the `none | password | platform_policy | custom_pcr` policy
  types become "no policy" or "a named policy (default `platform`)", with an
  optional password.

## APIs

One service, `tpmpolicy.Service`. It is the only business-logic entry point,
and every transport calls it through `XKMSService`.

| Operation | REST | gRPC | MCP | CLI (`xkmsctl` / `xkey`) |
|---|---|---|---|---|
| Create a policy (captures live PCRs) | `POST /api/v1/tpm/policies` | `TPMPolicyCreate` | `tpm.policy.create` | `tpm policy create <name> --pcrs 0,7 --bank sha256 [--auto-unseal]` |
| List or get | `GET /api/v1/tpm/policies[/{name}]` | `TPMPolicyList/Get` | `tpm.policy.list/get` | `tpm policy list/get` |
| Update (re-capture, re-approve) | `POST …/{name}/update` | `TPMPolicyUpdate` | `tpm.policy.update` | `tpm policy update <name>` |
| Revoke the current approval | `POST …/{name}/revoke` | `TPMPolicyRevoke` | `tpm.policy.revoke` | `tpm policy revoke <name>` |
| Verify live PCRs against a policy | `POST …/{name}/verify` | `TPMPolicyVerify` | `tpm.policy.verify` | `tpm policy verify <name>` |
| Delete (refused while assigned) | `DELETE …/{name}` | `TPMPolicyDelete` | `tpm.policy.delete` | `tpm policy delete <name>` |
| Objects using a policy | `GET …/{name}/objects` | `TPMPolicyObjects` | `tpm.policy.objects` | `tpm policy objects <name>` |
| Policy of an object | `GET /api/v1/keys/{id}/tpm-policy` | `TPMObjectPolicy` | `tpm.object.policy` | `key policy <id>` |
| Create a key with a policy | `POST /api/v1/keys` `{…, "tpm_policy": "<name>"}` | `GenerateKeyRequest.tpm_policy` | `xkms.generateKey{tpm_policy}` | `key generate … --tpm-policy <name>` |
| Seal with a policy | `POST /api/v1/seal` `{…, "tpm_policy": "<name>", "password"}` | `SealRequest.tpm_policy` | `xkms.seal{tpm_policy}` | `seal --tpm-policy <name>` |
| Set a tenant's TPM mode | `PUT /api/v1/tenants/{id}/tpm` `{mode}` | `SetTenantTPMMode` | `xkms.setTenantTPMMode` | `tenant tpm-mode <id> none\|shared\|vtpm` |
| vTPM status, start, stop | `GET/POST /api/v1/tenants/{id}/tpm/{status,start,stop}` | `TenantVTPM*` | `xkms.tenantVTPM*` | `tenant vtpm status\|start\|stop <id>` |

- The old `/api/v1/policies/*`, the `Policy*` RPCs, the `policy.*` MCP tools,
  `xkmsctl policy`, `xkey policy` and `refresh` are deleted.
- Permissions: `tpm_policy:{create,get,list,update,revoke,verify,delete}`,
  scoped to the caller's tenant. `tenant:set_tpm_mode` is system-scope only.
- The SDK exposes the same verbs on `xkms.Client`.

## Rejected alternatives

- **PCR values directly in the object's `authPolicy`.** Every PCR change would
  force a re-key.
- **`PolicyAuthorizeNV`.** It stores the approved digest in NV, so one index per
  policy is needed. A per-scope counter plus signed approvals uses one index per
  tenant.
- **A software PCR comparison before unseal** (xKey auto-unseal today). It is
  advisory, not enforced by the TPM.
- **A sidecar container per vTPM.** It needs a container runtime and a second
  supervisor, and puts the state key across a container boundary.
