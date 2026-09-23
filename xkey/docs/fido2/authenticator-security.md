# Security Considerations

This document outlines security considerations, best practices, and threat mitigations for the native FIDO2 authenticator.

## Overview

The native FIDO2 authenticator is a software-based implementation designed for development, testing, and scenarios where hardware security is not available. Understanding its security characteristics is essential for proper deployment.

## Security Model

### Comparison with Hardware Authenticators

| Property | Hardware Authenticator | Native Authenticator |
|----------|----------------------|---------------------|
| Key Storage | Secure element | Process memory / storage |
| Key Extraction | Physically protected | Software protected |
| Side-channel resistance | Hardware mitigations | Limited |
| Tamper resistance | Physical security | None |
| Attestation | Hardware-rooted | Self-signed |

### Threat Model

The native authenticator provides security against:
- Remote network attacks
- Protocol-level attacks
- Credential phishing (origin binding)
- Replay attacks (signature counters)

The native authenticator does NOT protect against:
- Physical access to the host system
- Privileged malware on the host
- Memory dumping attacks
- Side-channel attacks

## Key Storage Security

### Private Key Protection

Private keys are stored in PKCS#8 format when using the legacy crypto path or the software key backend. Security depends on both the key backend and storage backend:

**Legacy Path / Software Key Backend:**
- Keys are generated in-process using Go's `crypto/rand`
- Private keys can be exported as PKCS#8
- Keys are stored via the credential storage backend

**TPM2 Key Backend:**
- Keys are generated inside the TPM hardware
- Private keys cannot be exported (`ErrExportNotSupported`)
- Hardware isolation protects against software-based extraction
- Signing operations happen within the TPM

**MemoryStorage:**
- Keys exist only in process memory
- Lost on process termination
- No persistence vulnerability
- No encryption at rest

**BackendStorage (Persistent):**
- Keys written to disk or database
- Should use encrypted storage
- Should use proper file permissions
- Consider encryption at rest

### Key Hierarchy in Memory

The `KeyManager` holds four unwrapped keys while unlocked — the Admin Key, the
Credential Master Key, the Storage Master Key and the User Master Key. Each
unwraps something below it, so each is worth more to an attacker than the keys
it protects: reading the CMK is enough to unwrap every credential key, and
reading the AK is enough to unwrap the attestation key.

All four live in memguard-backed protected memory (`secure.Buffer`):

| Property | Effect |
|----------|--------|
| mlocked | The pages cannot be written to swap |
| Canary-guarded | Adjacent overreads are detected |
| Deterministic destroy | Cleared on `Lock()` by release, not by convention |

Consumers borrow the plaintext through `WithBytes`, never `Bytes`. Only
`WithBytes` holds the borrow across the read: a memguard failure anywhere in
the process purges every live enclave, and an accessor that has already
returned cannot keep the pages mapped while the caller reads them.

**Both transits are closed.** `KeyWrapper.UnwrapInto` decrypts into a
caller-supplied destination sized before any protected-key borrow is taken, so
an unlock writes each unwrapped key directly into mlocked memory — the
plaintext never exists on the ordinary Go heap (go-xkms#291). The interface no
longer has a method that can return a plaintext slice the caller does not own.
`KeyWrapper.WrapFrom(src *secure.Buffer)` is the mirror on the way in
(go-xkms#387): the plaintext is read through a borrow on a protected buffer
the caller owns, and Seal streams it straight into the ciphertext, so the
interface cannot express a wrap of heap plaintext. `InitializeSOPIN` generates
the AK and CMK directly into protected memory and adopts them as they are;
`WrapCredentialKey` and `WrapAttestationKey` take a `*secure.Buffer` the
caller destroys afterwards. The one heap copy that remains is the PKCS#8
encoding `x509` can only produce on the heap, and `secure.NewBufferFromBytes`
wipes it as it moves it into protected memory.

Borrows on protected buffers must not nest (go-qrdb `pkg/secure`). Every wrap
of one protected key under another therefore goes through
`wrapFromProtected`, which borrows the wrapping key only long enough to expand
it into the cipher's key schedule, releases that borrow, and only then lets
`WrapFrom` borrow the plaintext. A re-nested borrow deadlocks against a queued
purge-class operation rather than erroring, so the regression test drives
every wrap path under purge-class contention and relies on the test timeout.

`GetCMK` returns a heap copy that is the caller's to wipe. It is not protected
memory and is not documented as though it were. (It currently has no non-test
caller.)

### Key Backend Comparison

| Property | Legacy/Software | TPM2 |
|----------|----------------|------|
| Key Generation | In-process (crypto/rand) | TPM hardware |
| Key Export | Supported (PKCS#8) | Not supported |
| Key Import | Supported (PKCS#8) | Not supported |
| Hardware Isolation | None | Yes |
| Algorithms | ES256, ES384, ES512, EdDSA | ES256, ES384 |
| Attestation | Self-signed | Hardware-rooted |

### Recommendations

1. **Use TPM2 key backend** when hardware security is available
2. **Use encrypted storage** for persistent credentials
3. **Restrict file permissions** (0600 for credential files)
4. **Consider memory encryption** for high-security scenarios
5. **Clear memory** after key operations

```go
// Example: Zeroing sensitive memory via go-enclave.
enclave.Wipe(b)
```

## PIN Protocol Security

### PIN Protocol v1 Implementation

The authenticator implements CTAP2.0 PIN Protocol v1:

```
Platform                    Authenticator
    |                            |
    |  GetKeyAgreement           |
    |--------------------------->|
    |                            | Generate ECDH key pair
    |                            |
    |  authenticator_pub_key     |
    |<---------------------------|
    |                            |
    | SetPIN(platform_pub, enc_pin, auth) |
    |--------------------------->|
    |                            | K = ECDH(authenticator_priv, platform_pub)
    |                            | sharedSecret = SHA-256(K)
    |                            | Verify HMAC auth
    |                            | Decrypt and validate PIN
    |                            | Store SHA-256(PIN)[:16]
```

### PIN Security Properties

| Property | Implementation |
|----------|---------------|
| PIN Transport | AES-256-CBC encrypted |
| PIN Storage | SHA-256 truncated to 16 bytes |
| Key Agreement | ECDH P-256 |
| Auth Verification | HMAC-SHA-256 |
| Brute Force Protection | Retry counter with lockout |

### pinUvAuthToken Authorization

A pinUvAuthToken is not a bearer credential for the whole authenticator. Every
command that consumes one checks four things, in this order, and answers any
failure with the same `CTAP2_ERR_PIN_AUTH_INVALID` so a caller cannot tell which
check refused it:

| Check | Rule |
|-------|------|
| Lifetime | The token was minted by a clientPIN ceremony and both usage timers are still within limits |
| Authenticity | `pinUvAuthParam` is a valid HMAC of the client data hash under the token |
| Permission | The token carries the permission the command needs — `mc` (0x01) for makeCredential, `ga` (0x02) for getAssertion, `cm` (0x04) for credential management, `acfg` (0x20) for authenticator config |
| Permissions RP ID | If the token is bound to an RP ID, it matches the request's RP ID |

A token minted without a permissions RP ID is bound to the RP ID of its first
makeCredential or getAssertion, per CTAP 2.1 §6.1.2 and §6.2.2, and every later
use must present that same RP. So a platform that obtains a token scoped to one
site cannot replay it against another.

The superseded `getPinToken` subcommand carries no permissions parameter; the
token it produces is granted `mc` and `ga` with no RP binding, per CTAP 2.1
§6.5.5.7.1. It never inherits the permissions or RP binding of the token it
replaces.

### pinUvAuthToken Lifetime

Per CTAP 2.1 §6.5.2.1, a token stops being usable when either timer elapses:

| Timer | Limit | Meaning |
|-------|-------|---------|
| Inactivity | 30 seconds | Time since the token last authorized a command |
| Maximum usage period | 10 minutes | Time since the token was minted, however often it is used |

These timers apply to every command a token authorizes — makeCredential,
getAssertion, credential management and authenticator config alike.

A token that has outlived either limit is discarded rather than left in place,
and its bytes are wiped rather than merely dereferenced. Tokens are also cleared
by `authenticatorReset`, and do not survive the process, so a power cycle
invalidates them.

### Clearing the pinUvAuthToken After a Presence-Testing Operation

The timers bound *how long* a token lives; they do not bound *how much* it
authorizes. CTAP 2.1 §6.5.5.7 closes that gap: "when a pinUvAuthToken is used
with an operation that tests user presence, it is updated to remove all
permissions except lbw". §6.1.2 step 14 states this for makeCredential, and
§6.2.2 states the same for getAssertion: call `clearUserVerifiedFlag()` and
`clearPinUvAuthTokenPermissionsExceptLbw()` once the `up` bit is set in the
response. The token is not invalidated and is not made single-use — `lbw`
deliberately survives.

The authenticator does the same, so:

- **One user verification authorizes one credential operation.** After a
  makeCredential, or a getAssertion that collects user presence, the token
  retains only `lbw` and its `userVerified` flag is false. The platform must
  obtain a fresh token for the next operation — which is how conforming
  hardware behaves, and what a platform that requests per-operation scope
  already expects.
- **A silent assertion costs nothing.** A getAssertion with `up=false` sets no
  `up` bit, so it neither collects presence nor spends the token. Conditional
  UI can keep discovering credentials with one token.
- **The non-consuming probe agrees.** `CanAuthorizePinUvAuthToken`, used to
  decide credProtect visibility and excludeList answers before a credential is
  selected, reports a spent token as unauthorized, so a consumed token cannot
  unlock a protected credential.

`clearUserPresentFlag()` has no counterpart here: this authenticator never
caches user presence in the token — every token is minted with
`beginUsingPinUvAuthToken(userIsPresent: false)`, which §6.5.2.1 permits by
allowing a user present time limit of zero.

The superseded `getPinToken` subcommand also rejects the `permissions` and
`rpId` parameters with `CTAP1_ERR_INVALID_PARAMETER` per §6.5.5.7.1, rather
than ignoring a scope the platform believes it requested.

### PIN Attack Mitigations

**Brute Force:**
- Configurable retry limit (default: 8)
- Counter persisted to storage
- Authenticator locks when exhausted
- Requires factory reset to recover

**Eavesdropping:**
- PIN encrypted with ECDH-derived key
- Ephemeral key per session
- HMAC authentication prevents tampering

### Recommendations

1. **Set minimum PIN length** >= 6 characters
2. **Reduce retry count** for high-security (3-5 attempts)
3. **Persist retry counter** atomically with credentials
4. **Regenerate ECDH keys** after PIN operations

```go
config := &authenticator.Config{
    PINMinLength:  6,  // Longer minimum
    PINMaxRetries: 5,  // Fewer attempts
}
```

## hmac-secret Extension Security

### Key Derivation Security

The hmac-secret extension enables deriving symmetric secrets:

```
credential_hmac_key (32 bytes, random)
    |
    v
HMAC-SHA-256(credential_hmac_key, salt)
    |
    v
derived_secret (32 bytes)
```

### Security Properties

| Property | Value |
|----------|-------|
| Secret Key Size | 32 bytes (256 bits) |
| Algorithm | HMAC-SHA-256 |
| Key Isolation | Per-credential key |
| Salt Size | 32 bytes required |

### Protocol Flow Security

```
Platform                    Authenticator
    |                            |
    | GetAssertion with hmac-secret |
    | - keyAgreement (platform_pub) |
    | - saltEnc (encrypted salt)    |
    | - saltAuth (HMAC)             |
    |--------------------------->|
    |                            | K = ECDH(auth_priv, platform_pub)
    |                            | sharedSecret = SHA-256(K)
    |                            | Verify saltAuth
    |                            | salt = decrypt(saltEnc)
    |                            | output = HMAC(cred_key, salt)
    |                            | encOutput = encrypt(output)
    |                            |
    | Encrypted HMAC output      |
    |<---------------------------|
```

### Attack Mitigations

**Salt Manipulation:**
- Salt encrypted in transit
- HMAC verification prevents tampering
- Invalid salts rejected

**Key Extraction:**
- HMAC key never leaves authenticator
- Only derived outputs returned
- Requires valid GetAssertion

### Recommendations

1. **Use random salts** (32 bytes from CSPRNG)
2. **Never reuse salts** across derivations
3. **Bind to credential** - different credential = different derived key
4. **Protect derived secrets** appropriately

## Credential Protection

### credProtect Extension

Per-credential protection levels:

| Level | Name | Protection |
|-------|------|------------|
| 1 | userVerificationOptional | Always visible |
| 2 | userVerificationOptionalWithList | Visible in allowList or with UV |
| 3 | userVerificationRequired | Requires user verification |

These levels are enforced on the assertion path and on the transport's
no-credentials deferral heuristic, per CTAP 2.1 §12.1:

| Level | Usable when |
|-------|-------------|
| 1 / unset | Always |
| 2 | The platform named the credential in an allowList, **or** user verification was performed |
| 3 | User verification was performed, however the credential was named |

A credential the request may not use is treated as **absent**: the operation
ends in `CTAP2_ERR_NO_CREDENTIALS`, which is indistinguishable from the
authenticator not holding it. Reporting "exists but protected" would turn the
protection level into the oracle it exists to prevent.

Level 3 also hides the credential from the makeCredential `excludeList`. Without
user verification in the same transaction, the authenticator answers as though
it does not hold the credential, so the exclude-list response cannot be used to
confirm that a protected credential exists.

Because §12.1 filtering depends on whether the request is user-verified, the
pinUvAuthToken is checked before credentials are located — the order CTAP 2.1
§6.2.2 specifies. That check is read-only
(`CanAuthorizePinUvAuthToken`): it binds no permissions RP ID, refreshes no
timer and discards no expired token, so asking the question does not spend the
use the authoritative `AuthorizePinUvAuthToken` later commits.

The transport's no-credentials deferral heuristic (`HasMatchingCredentials`)
applies the **same** filtering. Whether a getAssertion is answered at once or
deferred to another authenticator is observable on the HID interface, so a
deferral answer that ignored protection levels would be a third existence
oracle beside the assertion and excludeList paths. The heuristic establishes
the request's user-verification state with the same read-only token check,
then reports only credentials the assertion path would return: a level-3
credential is invisible without user verification, and a level-2 credential is
invisible to an RP enumeration without it.

The indexed storage backend keeps this decision free of storage I/O by
recording each credential's protection level in its in-memory index at write
time and rebuilding it from stored credentials on load. An index entry whose
level was never recorded is treated as level 3, so a missing level fails
closed rather than open.

In a multi-authenticator deployment this means a request that this
authenticator could only answer with user verification is deferred exactly as
if it held nothing. A platform that wants the protected credential obtains a
pinUvAuthToken first, which is also what commits it to this authenticator and
ends deferral.

### excludeList and the Credential Oracle

The `excludeList` answer is withheld until after the user presence gate. A match
costs the same gesture as an ordinary registration, and the operation ends in
`CTAP2_ERR_CREDENTIAL_EXCLUDED` whether or not the user approves — the ordering
CTAP 2.1 §6.1.2 requires.

Answering earlier would make the authenticator a silent oracle: any process able
to reach the CTAP interface could test `(credentialID, rpId)` pairs at machine
speed, with no prompt, and learn which sites the user has registered with.

### What the UP and UV Flags Assert

The UV flag tells the relying party that a human verified themselves, and
downstream systems make authorization decisions on it. The authenticator sets it
only when that actually happened in the transaction:

| Flag | Set when |
|------|----------|
| UP | A user presence test ran through the configured handler, the key backend collected presence itself, or the platform completed a PIN entry |
| UV | The platform presented a valid `pinUvAuthParam`, or the key backend performs user verification internally (for example a phone biometric) |

`InternalPINHash`, the Go-API field that lets an in-process caller skip the
clientPIN ECDH ceremony, is not on either list. The caller runs inside the
authenticator's process and can read the expected value back from it, so the
comparison proves nothing about a human. It gets a caller past the "a PIN is
set, so present a pinUvAuthParam" precondition and nothing more: the user
presence gate still runs, and the assertion reports UV as absent.

Consequently the in-process browser-extension autofill ceremony verifies its
assertions with `autofill.VerifierOptions{AllowMissingUV: true}`, which relaxes
the UV check and nothing else. That opt-out is scoped to that one ceremony:
`autofill.NewAssertionVerifier`, which is what the SDK re-exports and what
downstream consumers use against real authenticators, still requires UV.

### Who Answers for the User

A UP flag is only as truthful as the handler that produced it, and the handler
is a deployment choice:

| Handler | Presence source |
|---------|-----------------|
| `SocketHandler` | GUI touch prompt — the user clicks approve or deny |
| `InteractiveHandler` | terminal prompt |
| `AutoGrantHandler` | approves everything — automation and tests only |

`AutoGrantHandler` is what `NewAuthenticator` installs when the configuration
names no handler, so an embedder that forgets one gets a UP flag for every
request without asking anybody.

One authenticator instance is shared by the USB HID bridge, the browser
extension and autofill, so its handler is a property of the whole session, not
of any one transport. The GUI therefore installs its touch prompt at
authenticator initialization (`FIDO2DeviceService.AttachPresenceHandler`) rather
than when the virtual device starts. Starting the device captures that same
handler and stopping it puts that same handler back, so there is no window —
device disabled in settings, `/dev/uhid` unavailable, or the user toggling the
device off — in which the other consumers fall back to auto-approval. The prompt
does not depend on the UHID bridge: it notifies the frontend and waits for
approve, deny or timeout, all of which keep working with the device stopped.

### Recommendations

1. **Use level 3** for high-value credentials
2. **Require PIN** for credential management
3. **Audit credential access** patterns

```go
extensions := map[string]interface{}{
    "credProtect": uint8(3), // Maximum protection
}
```

## Security Officer Role and Token Initialization

### Two specifications, two halves

xKey's Security Officer / User split is the **PKCS#11** role model. CTAP 2.1
defines a single user PIN and has **no** Security Officer, so no single
specification governs this surface:

| Concern | Governing spec |
|---|---|
| When the SO credential is established, and how it changes | PKCS#11 v3.0 §5.6 -- `C_InitToken`, `C_InitPIN`, `C_SetPIN` |
| The trust-on-first-use window on that first establishment | CTAP 2.1 §6.9 -- `authenticatorReset` |
| Retry budget, power-cycle threshold, lockout | CTAP 2.1 §6.5.5.7 -- `authenticatorClientPIN` |
| Role separation and initialization as a distinct act | FIPS 140-3 / ISO-IEC 19790 -- Crypto Officer |

### The token lifecycle

A token is **uninitialized** until it is given an SO PIN. There is exactly one
source of truth for that -- `state.SOPINManager.IsSet` -- because initialization
*is* establishing the SO PIN, and a second flag would only be a second thing to
disagree.

```
uninitialized  --InitializeToken (window + user presence)-->  initialized
initialized    --ChangeSOPIN (current SO PIN)-------------->  initialized
initialized    --authenticatorReset (SO + user presence)--->  uninitialized
```

**An uninitialized token refuses SO-gated operations.** It does not waive them.
`ResetUserPIN`, `ReplaceAttestKey`, `SetRPPolicy`, `DeleteRPPolicy` and
`SetProfile` all return `ErrTokenUninitialized`, which is deliberately distinct
from `ErrKeyManagerLocked`: "there is no Security Officer" and "the Security
Officer has not authenticated" demand different responses, and reporting the
second for the first is how "no SO PIN set" comes to be read as "no SO
required". The two are distinct on the wire as well: `ErrTokenUninitialized`
maps to `CTAP2_ERR_NOT_ALLOWED` (0x30), `ErrKeyManagerLocked` to
`CTAP2_ERR_PIN_REQUIRED` (0x36).

`authenticatorGetInfo` advertises the reachable vendor subcommands in
`vendorPrototypeConfigCommands` (0x15), which CTAP 2.1 §6.4 requires whenever
the `vendorPrototype` subcommand is supported. Without it a client has no way to
discover that initialization exists.

### The trust-on-first-use window

The first SO PIN cannot be authenticated against anything, because nothing
exists yet to authenticate against. That window is real and it is not closed by
omission. CTAP 2.1 §6.9 bounds the equivalent risk on `authenticatorReset` with
two requirements, and first initialization applies both:

1. **A short window after power-up.** `Config.TokenInitWindow`, default 10
   seconds, matching the common hardware implementation. Outside it,
   `ErrTokenInitWindowClosed`.
2. **User presence.** The presence handler must approve, or
   `ErrUserPresenceRequired`.

Together these mean a caller cannot claim the Security Officer role on a device
it did not just power on and physically confirm. That is the spec-sanctioned
answer; xKey does not invent an enrolment token or an out-of-band pairing step
alongside it, because a second mechanism is a second thing to get wrong.

**Refusals are ordered so a doomed request never prompts.** An already-closed
window, a malformed PIN, or an already-initialized token are all rejected before
the user is asked to touch anything.

**Honest limitation.** For a *hardware* token, "power-up" is a physical act an
attacker must be present for. For this **software** authenticator a power cycle
is a **process restart**, which anyone who can start the daemon can perform. The
window therefore raises the bar to "can restart the process and satisfy the
presence handler at that moment" rather than to "is holding the device". Deploy
accordingly: the daemon's ability to be restarted is part of this control's
threat model, and a presence handler that auto-grants (`NewAutoGrantHandler`,
the default) removes the second bound entirely.

Widening `TokenInitWindow` widens exactly this window. It cannot be disabled: a
zero or negative value selects the default rather than meaning "always open".

### Changing the SO PIN

After initialization the SO PIN changes **only** through `ChangeSOPIN`, which
proves the current PIN by AES-GCM authenticated decryption of the wrapped Admin
Key -- possession of the key, not comparison of a hash.

Nothing is mutated before that proof succeeds. Rotating the Argon2id salt on an
unproven PIN would make the real SO PIN underivable and brick the token, so the
unwrap happens first and `SOPINManager.Rekey` is called only after it.

A malformed *new* PIN is rejected before any retry is charged: an operator's
typo in the value they are setting is not a failed authentication attempt.

### Retry budget, power cycle, lockout

Per CTAP 2.1 §6.5.5.7, applied to the SO credential:

| Control | Value | Behaviour |
|---|---|---|
| Total retry budget | 8 (`DefaultSOPINMaxRetries`) | Exhausted -> `ErrSOPINBlocked`, terminal until `authenticatorReset` |
| Consecutive failures per power cycle | 3 (`SOPINMaxConsecutiveFailures`) | Reached -> `ErrSOPINAuthBlocked`; attempts resume only after a restart |
| Persistence | Budget persisted; consecutive counter not | A restart clears the power-cycle block and **never** refunds the budget |

The verification contract is deliberately three calls, not one:

```go
smk, err := manager.BeginVerify(pin)   // spends one retry, up front
if err != nil { return err }
if unwrapOK(smk) { manager.ConfirmVerified() } else { return manager.RecordFailure() }
```

The retry is spent **before** the answer is known, so a caller that crashes, is
killed, or simply never reports back cannot obtain a free attempt. Every spend
is persisted by the token layer -- on failure as well as success -- so a restart
mid-attack cannot reset the counter.

The state is surfaced as the PKCS#11 `CK_TOKEN_INFO` flags a PKCS#11
application would expect, over the `GetTokenInfo` vendor subcommand and through
`Authenticator.TokenFlags()`:

| Flag | PKCS#11 | Meaning |
|---|---|---|
| `TokenFlagInitialized` | `CKF_TOKEN_INITIALIZED` | The token has an SO PIN |
| `TokenFlagSOPINCountLow` | `CKF_SO_PIN_COUNT_LOW` | At least one failure since the last success |
| `TokenFlagSOPINFinalTry` | `CKF_SO_PIN_FINAL_TRY` | One more failure locks the token |
| `TokenFlagSOPINLocked` | `CKF_SO_PIN_LOCKED` | Budget exhausted |

`GetTokenInfo` never fails on an uninitialized token -- it reports flags of
zero, which renders as `uninitialized`. A caller that cannot read the state
cannot recover from it either, and an error saying "SO PIN not set" is precisely
the message that gets read as "no SO PIN needed".

### Reset

`authenticatorReset` is the only path back to uninitialized, and it is
destructive by design.

- On an **initialized** token it requires an authenticated Security Officer
  *and* user presence.
- On an **uninitialized** token user presence alone gates it. That is not a
  waiver: PKCS#11 `C_InitToken` likewise needs no prior authentication on an
  uninitialized token, and demanding a credential that cannot exist would make
  such a token permanently unresettable.

A completed reset **re-arms** the initialization window. The caller has just
proven user presence, and on an initialized token also SO possession, so this
grants nothing they had not already demonstrated -- while without it a reset
would leave the token uninitialized but un-initializable until the next restart.

**Known gap.** CTAP 2.1 §6.9 also requires `authenticatorReset` itself to arrive
within a short time of power-up. That bound is **not** enforced here, because
factory reset is driven from the UI long after startup. This is recorded rather
than implied: reset is gated by SO authentication and user presence, not by
timing.

### What is not covered

No CLI verb reaches these commands yet. `authenticatorConfig` `0x0D` with
`subCommand >= 0x80` is the only transport, and building a host-side CTAP client
for it is tracked separately. Note that `xkey pin set-so` drives an unrelated
subject -- the qrdb PIN service -- and has never touched
`AuthenticatorState.SOPINManager`.

## SO Policy Controls

### Attestation Override

`RPPolicy.AttestationOverride` holds a WebAuthn attestation **conveyance
preference** — `""`, `none`, `indirect`, `direct` or `enterprise`. That is a
different vocabulary from the attestation **statement format** the authenticator
produces (`none`, `packed`, `tpm`), and the two must not be assigned to one
another.

A preference asking for attestation resolves to the authenticator's configured
statement format. If the authenticator is configured to produce no attestation,
or the key backend cannot produce the statement, the registration is **refused**
— `ErrAttestationOverrideUnsupported` (`CTAP2_ERR_UNSUPPORTED_OPTION`) or
`ErrAttestationUnavailable`. It is never downgraded to `fmt: none`: an SO who
mandates attestation must get attestation or an error, never a credential
telling the relying party that none was available.

`enterprise` carries one more requirement, the same one the request path
applies to an RP that asks for enterprise attestation itself: enterprise
attestation must be enabled on the authenticator (`enable-enterprise-attestation`)
**and** the RP must be marked `Enterprise` in its policy. An override that
mandates enterprise attestation for an RP not entitled to it is refused with
`ErrEnterpriseAttestationNotEntitled` (`CTAP2_ERR_OPERATION_DENIED`). It is not
resolved to the ordinary statement under the enterprise label, and the
entitlement is checked before the configured format, so the refusal names the
real reason even on an authenticator that produces no attestation at all.

### Tamper Lock

`Authenticator.TamperDetected` is set when the SO-signed policy HMAC fails
verification at startup. It is enforced, not merely recorded: while it is set,
every user-mode operation is refused with `ErrPolicyTamperLocked`
(`CTAP2_ERR_INTEGRITY_FAILURE`). The gate is one method,
`requirePolicyIntegrity`, and it sits in front of

- the CTAP dispatch (`ProcessCBORWithContext`) for `makeCredential`,
  `getAssertion`, `getNextAssertion`, `clientPIN`, `reset`, `bioEnrollment`,
  `credentialManagement`, `largeBlobs` and `config`, before the request is
  decoded, and
- the Go API `MakeCredential` and `GetAssertion`, which do not pass through
  the CBOR dispatch.

`getInfo` and `selection` remain answerable. Both are read-only discovery, and
refusing them would make a locked device indistinguishable from a dead one.
`getInfo` reports the state truthfully under the vendor option
`policyTamperLocked: true`, present only while locked; a client that does not
know the option ignores it per CTAP 2.1 §6.4.

**What sets the flag.** The authenticator opens with a policy integrity
provider, the stored state carries a policy HMAC tag, and the tag does not
verify over the current signed field set. A schema change (see below) does not
set it, so a routine upgrade never locks a device.

**Cost of a false positive.** The device serves no user until the Security
Officer recovers it. Nothing is lost: credentials and PINs are untouched, and no
reflash or reset is needed.

**Recovery.** The Security Officer re-signs the policy over the configuration
the device actually has (`PolicyManager().Sign` on the current state, then
persist the state) and re-opens the authenticator. Startup verification then
passes, `TamperDetected` is false, and user-mode commands are served again.
Nothing clears the flag at runtime: verification is a startup event, and a flag
that could be toggled in-process would be a flag an attacker with the same
access could toggle.

### Policy Integrity HMAC

The SO-signed policy HMAC covers every setting that changes the authenticator's
security posture, so that an attacker with the filesystem write access the HMAC
exists to detect cannot flip one and still verify:

`minPINLength`, `maxPINRetries`, `soPINMaxRetries`, `alwaysUV`,
`maxCredentials`, `maxResidentCredentials`, `enableCredentialManagement`,
`enableEnterpriseAttestation`, `transports`, `requireUserPresence`,
`enableUserIntentCheck`, `attestationFormat`, `enablePIN`, `enableResidentKey`,
`enableHMACSecret`, `supportedAlgorithms` and `aaguid`.

A mismatch report names the field that moved, not merely that something did.

#### Schema version

The canonical form carries a schema version as its first member (`"v"`), and
`PolicyFieldsSchemaVersion` is bumped whenever the field set changes shape.

A policy signed under a different version reports **`ErrPolicySchemaChanged`**,
never `ErrPolicyTampered`. These are different events demanding opposite
responses — one means the policy must be re-signed, the other means someone
modified the device — and conflating them would make a routine upgrade look
like an attack on every device at once.

A schema change does not raise the tamper flag and does not prevent startup. It
logs that policy integrity is unverified until the Security Officer re-signs.
Field-level diagnostics are suppressed for it: a snapshot stored under another
field set deserializes with zero values for fields it never carried, so a
mismatch list would name settings nobody touched.

`soPINMaxRetries` is a compile-time constant — `Config` carries no field for it
— so it is identical on both sides of every comparison and cannot detect
tampering. It is retained because removing it would change the signed bytes for
the same reason adding a field does.

## Attestation Security

### Self-Attestation

The native authenticator uses self-attestation:

```go
type AuthenticatorState struct {
    AttestationKey  *ecdsa.PrivateKey // Generated on init
    AttestationCert []byte             // Self-signed
}
```

**Implications:**
- No hardware root of trust
- Cannot prove authenticator identity
- Relying parties should accept self-attestation for testing only

### AAGUID Considerations

- Zero AAGUID acceptable for testing
- Custom AAGUID should be registered for production
- AAGUID does not prove authenticator identity without attestation

## Thread Safety

### Concurrency Security

The authenticator uses mutexes for thread safety:

```go
type Authenticator struct {
    mu sync.RWMutex // Protects state
}
```

**Protected Operations:**
- Credential storage access
- PIN state modifications
- Assertion context

**Atomic Operations:**
- Closed flag
- PIN retry counter
- UV retry counter

### Recommendations

1. **Don't share authenticator** across security boundaries
2. **Use separate instances** for isolation
3. **Check IsClosed()** before operations

## Storage Security

### File-Based Storage

For persistent storage:

```go
// Secure file permissions
os.Chmod(credentialPath, 0600)

// Secure directory permissions
os.Chmod(storageDir, 0700)
```

### Database Storage

For database-backed storage:

1. **Encrypt connections** (TLS)
2. **Use parameterized queries** (prevent injection)
3. **Encrypt sensitive columns** (private keys)
4. **Audit access** (logging)

### Memory Clearing

Clear sensitive data when done:

```go
func (a *Authenticator) Close() error {
    a.mu.Lock()
    defer a.mu.Unlock()

    // Clear PIN state
    if a.state != nil {
        enclave.Wipe(a.state.PINHash)
    }

    // Clear PIN protocol state
    if a.pinState.protocol != nil {
        enclave.Wipe(a.pinState.protocol.pinUvAuthToken)
        enclave.Wipe(a.pinState.protocol.sharedSecret)
    }

    return a.storage.Close()
}
```

## Deployment Recommendations

### Development/Testing

```go
config := &authenticator.Config{
    EnablePIN:        true,
    EnableHMACSecret: true,
    Storage:          authenticator.NewMemoryStorage(), // Ephemeral
}
```

### Production (Hardware Unavailable)

```go
config := &authenticator.Config{
    PINMinLength:        8,
    PINMaxRetries:       5,
    EnablePIN:           true,
    EnableHMACSecret:    true,
    KeyBackend:          software.NewSoftwareKeyBackend(),
    UserPresenceHandler: authenticator.NewAutoGrantHandler(),
    Storage:             encryptedPersistentStorage,
}
```

### Production (TPM2 Available)

```go
tpmBackend, err := tpm2.NewTPM2KeyBackend(&tpm2.TPM2Config{
    DevicePath: "/dev/tpmrm0",
})
if err != nil {
    log.Fatal(err)
}

config := &authenticator.Config{
    PINMinLength:        8,
    PINMaxRetries:       5,
    EnablePIN:           true,
    EnableHMACSecret:    true,
    KeyBackend:          tpmBackend,
    AttestationFormat:   "tpm",
    UserPresenceHandler: authenticator.NewAutoGrantHandler(),
    Storage:             encryptedPersistentStorage,
}
```

### High-Security Recommendations

1. **Use TPM2 key backend** when hardware is available
2. **Use hardware authenticators** when possible
3. **If software-only:**
   - Run in isolated environment (VM, container)
   - Use encrypted storage
   - Implement additional access controls
   - Monitor for anomalies
   - Use the software key backend (explicit backend vs legacy path)

## Known Limitations

1. **No hardware protection** - Keys exist in software (unless TPM2 key backend is used)
2. **No side-channel protection** - Timing attacks possible
3. **No physical presence** - UP flag is handled by software, and it is only as meaningful as the configured handler: `InteractiveHandler` prompts via terminal and `SocketHandler` routes to the GUI dialog, but `AutoGrantHandler` approves every request without asking anyone. Deployments that need the UP flag to mean something must not run `AutoGrantHandler`.
6. **No in-process user verification** - There is no path that collects a real PIN entry from a caller inside the process. In-process ceremonies such as browser-extension autofill are gated on user presence, and their assertions report UV as absent.
4. **Self-attestation only** - No hardware root of trust (unless TPM2 key backend with attestation is used)
5. **Memory exposure** - Keys in process memory (software backend); TPM2 backend mitigates this
7. **Software power cycle** - The trust-on-first-use window for the Security Officer PIN is bounded by time since power-up (CTAP 2.1 §6.9), but a "power cycle" here is a process restart. Anyone who can restart the daemon can reopen the window. See [Security Officer Role and Token Initialization](#security-officer-role-and-token-initialization).
8. **Reset is not window-bounded** - CTAP 2.1 §6.9 requires `authenticatorReset` to arrive shortly after power-up; that bound is not enforced. Reset is gated by Security Officer authentication and user presence instead.
9. **No CLI path to token initialization** - The SO PIN commands are reachable only over CTAP `authenticatorConfig` (`0x0D`, `subCommand >= 0x80`). `xkey pin set-so` drives an unrelated subject and does not initialize the virtual authenticator.

## Security Checklist

- [ ] Storage backend configured with encryption
- [ ] File permissions restricted (0600/0700)
- [ ] PIN minimum length >= 6
- [ ] PIN retry limit <= 5
- [ ] Token initialized (SO PIN established) before the authenticator is exposed on a transport
- [ ] `TokenInitWindow` left at its default, or narrowed -- never widened without cause
- [ ] User presence handler is not `AutoGrantHandler` where the initialization window matters
- [ ] AAGUID set appropriately
- [ ] Authenticator closed when done
- [ ] Error handling doesn't leak info
- [ ] Logging doesn't include secrets
- [ ] Deployment environment hardened
