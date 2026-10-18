# Trusted service plane

> **Status: DESIGN** · Approved with corrections 2026-10-15 (DS-1746)
> go-xkms's part of the trusted service plane: rows, seams, moves and lane order. The SPEC rows it names are normative once they land in [SPEC.md](../SPEC.md).

Design page. Approved with corrections by the Company Agent at 00:25Z on 2026-10-15 (DS-1746); this version carries the corrections.
Facts are from go-xkms c9a1cdb25, go-qrdb b65df70 and #722, go-quicbaas 0f45b54 and go-trusted-platform (gtp) a124fe9.

## Rows

| Row | Status | Blocked on |
|---|---|---|
| `attested-caller-gate` | planned | nothing |
| `trust-roots` | planned | nothing |
| `image-signing` | planned | nothing |
| `workload-identity` | planned | go-qrdb accepting `spiffe://<tenant>/...` (ordered 00:32Z) |
| `transparency-log` | planned | go-qrdb's verifiable-log type (#721/#722) |
| `hsm-self-defence` | future | `hsm-device-protocol` (#1521), the HSM node |

## 1. Attested-caller gate (`attested-caller-gate`)

- The gate already exists:
  - `pkg/attestation/peergate` implements go-qrdb's `auth.PeerAttestationVerifier` (`verifier.go:144` VerifyPeer, `collector.go:115,179` Challenge/Submit).
  - go-qrdb provides `node.WithPeerAttestationGate` (`sdk/go/node/node.go:210`, installed in the auth chain at `pkg/auth/wiring/wiring.go:428`).
  - It is not wired: the only caller is the SDK re-export.
- Design:
  - `pkg/server/qrdb_node.go:151` adds the gate when `attestation.peer_gate` is `optional` or `required`.
  - The evidence store moves from `MemoryStore` to a qrdb DAO.
  - Challenge/Submit become xkms module verbs on every transport.
  - `sdk/go` re-exports one option, `WithAttestedCallerGate(policy)`.
  - The PCR policy comes from the embedder (go-quicbaas's reference-values store). xkms ships no golden values.
- Seams:
  - consumes go-qrdb's peer-attestation hook;
  - provides go-quicbaas (gate option);
  - provides gtp (proxy, VPN and admission compose over it).

## 2. Trust roots (`trust-roots`) and image signing (`image-signing`)

**Trust-root service.**
- One persisted, purpose-classified root store: CA, TCG EK, Android, IDevID and image signer.
- It lives on a qrdb DAO and is served as module verbs.
- It is built from xkey's truststore (§5).
- Peergate, image verification, VM attestation and go-quicbaas appraisal all read it.

**Image signing (`pkg/image`).**
- The signer key is a KMS `crypto.Signer` (TPM, PKCS#11 or cloud), never a key file.
- Its certificate comes from `TrustedCA`'s code-signing profile (`profile_codesigning.go:64`).
- Output:
  - a DSSE envelope over an in-toto statement, with the image digest as subject;
  - pushed as an OCI 1.1 referrer, with the `sha256-<hex>.att` tag as fallback (cosign verify-attestation reads both);
  - an optional RFC 3161 timestamp;
  - every signature appended to the transparency log.
- `VerifyImage` checks against the trust-root service and replaces go-quicbaas's Tier 0 `ImageSignature` (`container_trust.go:71`).

**Signature verification in `pkg/signing` (correction 3).**
- `pkg/signing` today is sign-only (`signer.go:36-136`).
- It receives gtp's manifest RSA check as its verify half:
  - PKCS#1 v1.5 over SHA-256, SHA-384 or SHA-512;
  - RSA keys only, anything else refused with a typed error.
- The source is three copies in gtp: `manifest/signer.go:214,430` and `verifier.go:252`, all `rsa.VerifyPKCS1v15`.
- The verify half calls the one existing RSA verify, `types.SimpleVerifier` (`pkg/types/types.go:3574`, PKCS#1 v1.5 at :3585). It adds no second implementation.
- gtp's five tests move with it: `TestManifestSignerVerifySignature`, `TestVerifyManifestSignature`, `TestManifestVerifierVerifySignature`, `TestQuickVerify`, `TestExtractPublicKeyFromManifest`.
- The manifest format and its AK-key extraction (`verifier.go:487`) stay in gtp and call `sdk/go` signing.

## 3. Workload identity (`workload-identity`)

**Owner ruling (00:32Z, 2026-10-15): the tenant is the SPIFFE trust domain** (`spiffe://<tenant>/<kind>/<name>`). go-qrdb has been ordered to accept the form.

**Today.**
- `x509-svid` profile: `profile_ipsec_svid.go:38` (one URI SAN, 1h default, 24h max).
- `SignCSRWithSPIFFE` stamps `spiffe://<td>/tenant/<tenant>/<kind>/<name>` (`service_adapter.go:56`).
- go-qrdb verifies that form against one pinned trust domain (`pkg/auth/spiffe/spiffe.go:170`).

**Design.**
- `SignCSRWithSPIFFE` stamps the tenant as the trust domain.
- The SVID is issued through ACME at deploy, kind `svc`, and also carries the tenant in OU[0].
- Each tenant's trust bundle is its own CA, because strict isolation already gives every tenant one. A compromise stays inside one tenant.
- go-quicbaas verifies against the tenant's bundle. Cross-tenant calls need explicit SPIFFE federation.
- Tenant IDs must be valid trust-domain names (lowercase letters, digits, `.`, `-`, `_`), as go-qrdb's tenant-ID rules guarantee.
- No migration is needed in alpha.
- The tenant key is `Subject.OrganizationalUnit[0]` (DS-1736):
  - go-qrdb sets it at `pkg/cert/default_provider.go:472,574` and reads it at `pkg/auth/mtls.go:233`;
  - go-xkms reads it at `pkg/auth/mtls.go:282`;
  - permanentIdentifier is untouched;
  - the owner confirmed it on 2026-10-15 15:50Z (DS-1898): the X.509 subject OU carries the tenant on every layer.

**Seams.** Consumes go-qrdb's per-tenant trust-domain verification (ordered). Provides go-quicbaas with SVIDs.

## 4. Transparency log (`transparency-log`)

**Built on go-qrdb's verifiable-log type** (#722, `pkg/vlog`, not yet merged). go-xkms ships no log, Merkle-tree or proof code.

**Entry kinds.**
- xkms appends three itself:
  - `cert-issued`: SHA-256 of the certificate, serial, profile, tenant;
  - `image-signed`: image digest, envelope digest, signer;
  - `revoked`: serial, reason.
- A fourth, `external`, is appended by the layers above under the caller's SPIFFE ID. go-quicbaas uses it for admissions, deployments and policy changes.

**API.**
- Verbs: append; read the signed tree head; inclusion proof; consistency proof.
- New permissions follow go-qrdb's built-in role placement.

**Head signing (correction 5).**
- go-xkms implements go-qrdb's `HeadSignerProvider` (#722 §6). For the transparency log it returns a signer over the CA key, the same `crypto.Signer` that `pkg/cakey.Provider` exposes.
- Checkpoint signature type, proposed to the qrdb coordinator through the Department:
  - **ECDSA P-256 with SHA-256 at least**. This is go-xkms's CA default (`pkg/ca/config.go:38-40`).
  - P-384 with SHA-384 is allowed when the CA key is P-384.
  - The checkpoint is #722's C2SP signed note (its open question 2, recommendation (a)), carrying the note signature type for RFC 6962 tree-head signatures.
  - RSA and Ed25519 CA keys are not used to sign checkpoints, and P-224 is refused.
- Recorded on both pages once the qrdb coordinator agrees. Until then it is a proposal.

## 5. Moves

Each move is made with history and tests, wired at the destination, and the copy is removed by the source repository's own lane.

| Source | Destination | Kept | Already at the destination |
|---|---|---|---|
| xkey/pkg/attestation `verifier.go` | pkg/attestation `purpose.go` (moved, #1548) | purpose-pooled checks on the one `Verifier` (`WithTrustStore`), `VerifyPurposeChain`, `BuildTrustPool` | EK `evidence/ekcert.go:87`, Android `android/extension.go:648`, IDevID `peer/devid.go:150` |
| xkey/pkg/attestation `device.go` | pkg/attestation `android_device.go`, pkg/attestation/android `device.go` (moved, #1548) | `VerifyAndroidDeviceKey`, `AndroidDeviceTrust`, `ParseDERChain`, `VerifiedTrustAnchor`, `FormatTrustAnchor`; boot-state, key-origin and application checks | `android.VerifyKeyAttestation` (`android/extension.go:648`) |
| xkey/pkg/truststore | pkg/attestation/truststore (`trust-roots`) | `TrustStore`, `CertPurpose` taxonomy and quarantine, `ClassifyCertificate`, import, `DAOStore` | embedded Google root (`config.go:30`) |
| xkey/pkg/pairing `noise.go` | pkg/trust/bootstrap: interactive Noise XX session over go-truststrap | session and key helpers | static-key helpers (`noise_server.go:57-91`) |
| xkey/pkg/pairing wire protocol | root (ruling below) | the protocol `pkg/backend/phone` and `pkg/api/transport/usb` use | nothing |
| xkey virtual FIDO2 authenticator | pkg/fido2 (ruling below) | the authenticator and virtual device that `pkg/webauthn/client` and `cmd/xkmsctl` use | CTAP2 types in pkg/fido2 |
| gtp pkg/image | pkg/image | reference parsing, registry referrer push, RFC 3161 client, tests | nothing |
| gtp pkg/attestation/vm, **the whole package with its tests** | pkg/attestation/vm | all 9 files; the test table below | quote and AK cert in `pkg/attestation/evidence` |
| gtp manifest RSA verify | pkg/signing (§2) | the check, its 5 tests | `types.SimpleVerifier` |
| go-quicbaas `ca_service_adapter*.go`, `fleet_cert_issuer.go`, `acme_service.go`, `server_cert_sans.go` | pkg/ca, pkg/acme | `CrossSignRoot`, `IssuerChainPEM`, device-identity dispatcher (EK/AK/IDevID), by-serial get/revoke/list, fleet-node issuer and bundle, ACME order facade, server-TLS cert reissue | the rest already re-exports go-xkms |
| go-quicbaas `pkg/certstore` `KVStoreCertStorage` | nothing kept, reasoned below | — | `storage.CertAdapter` |

**Ruling (Company Agent 00:25Z): root stops importing xkey.**
- Today root requires xkey at `go.mod:46` (`replace ./xkey`).
- The pairing wire protocol moves to root and the virtual FIDO2 authenticator to `pkg/fido2`, then the require is dropped.

### pkg/attestation/vm (correction 2)

go-quicbaas has no copy. Where the code is wired:
- The package is wired at the destination to go-xkms's own types:
  - `go-quicbaas/sdk/go/xkms/ca` OIDs → `evidence/akcert.go:31,35`;
  - `xkmssdk.KeyAttributes` → `pkg/types/types.go:1133`.
- `quote.go` and `akcert.go` call `pkg/attestation/evidence`, so quote and AK-certificate verification have one implementation.
- The package keeps what evidence lacks:
  - `akpublic.go`;
  - the attestor and verifier;
  - evidence and types;
  - the declared-scheme check and the IAK scheme names.

Two behaviours differ. go-xkms's fail-closed behaviour wins in both, and the test moves inverted:
- **nil roots:** gtp skips the chain check (`vm/akcert.go:51`); go-xkms refuses (`evidence/akcert.go:104`).
- **declared scheme:** gtp checks only the declared scheme (`vm/quote.go:92`); go-xkms tries PKCS1v15, then PSS (`evidence/quote.go:240-257`). The declared-scheme check is kept as the stricter one and added to evidence.

**Tests, one by one, against go-xkms's coverage.**

`quote_test.go`

| gtp test | go-xkms coverage |
|---|---|
| `_RoundTrips` (:115) | partial: `TestVerifySignature_RawECDSAAndRSA` (evidence/quote_test.go:188), `TestVerifyQuote_ECDSA` (:157). The RSA-SHA384 and PSS max-salt cases move. |
| `_DeclaredSchemeIsTheOneChecked` (:160), `_SchemeKeyMismatch` (:176) | not covered; move |
| `_FailsClosed` (:208) | partial: `TestVerifySignature_Failures` (:225), `TestVerifyQuote_Failures` (:312). The unknown-algorithm case moves. |
| `TestQuoteSignatureAlgorithm_*` (:251, :263, :274) | not covered; move |
| `_UnsupportedKeyType` (:293) | covered: `TestVerifySignature_Failures` (:225) |
| `TestParseQuoteNonce`, `_InvalidData`, `TestVerifyQuoteNonce` (:310, :319, :330) | covered: `TestVerifyQualifyingData` (:300), `TestParseQuote_Failures` (:246) |
| `TestVerifyQuotePCRDigest`, `_Mismatch` (:345, :355) | covered: `TestVerifyPCRValues` (:280) |
| `_UnsupportedBank` (:390), `TestParseQuoteAttest_WrongType` (:418) | covered: `TestParseQuote_Failures` (:246) |
| `TestQuotePCRDigest_*` (:443, :460) | partial: the sorted-index case moves |

`akcert_test.go`

| gtp test | go-xkms coverage |
|---|---|
| `_RestrictedAndChainedPasses` (:107), `_MissingRestrictedIsRefused` (:124), `_UntrustedIssuerIsRefused` (:145) | covered: `TestVerifyAKCertificate` (evidence/cert_test.go:109) |
| `_NoPoliciesAtAllIsRefused` (:137) | covered: `TestCarriesVerifiedTPMRestricted` (:162) |
| `_ExpiredIsRefused` (:156) | not covered; move |
| `_NilRootsSkipsChainButNotTheAttribute` (:164) | not covered; moves inverted (refused) |
| `_GarbageIsRefused` (:178) | covered: `TestParseCertificatesPEM_Failures` (:155) |
| `TestAKCertErrors_Messages` (:193) | moves with the package's error types |

The other test files:
- `akpublic_test.go` (7 tests) moves; evidence has no counterpart.
- `verifier_test.go`:
  - `_VerifyEKCertificate` (:644) is covered by `TestVerifyEKCertificate` (cert_test.go:199).
  - Freshness, host binding (`_HostBindingValidation` :763) and the declared scheme in `_VerifyQuote`/`_VerifyAttestation` (:206, :522) move.
  - The lifecycle and helper tests move.
- `attestor_test.go` (7), `errors_test.go` (27) and `types_test.go` (19) move with their code.

### KVStoreCertStorage: nothing kept (correction 4)

- `go-quicbaas/pkg/certstore/kvstore_storage.go:49` has no callers. Nothing imports the package.
- It is a second certificate datastore over go-quicbaas's KVStore, which the one-datastore ruling removes.
- Every method is already in go-xkms's `storage.CertAdapter` (`pkg/storage/certadapter.go`): `SaveCert` :48, `GetCert` :66, `DeleteCert` :86, `SaveCertChain` :97, `GetCertChain` :122, `ListCerts` :142, `CertExists` :147, `Close` :157.
- The only difference is the chain encoding: length-prefixed DER instead of a PEM blob. That is encoding, not behaviour, so nothing is kept.
- go-quicbaas's lane compares its test cases against `pkg/storage`'s CertAdapter tests and moves any case not covered there before removing the file.

**What stays where it is.**
- In xkey: device binding and pairing policy, SAS, the message loop, transports, OS cert-store install.
- In gtp: workload PCR producers and the manifest format, re-pointed to `sdk/go`.
- go-quicbaas's own: podman, the registry and the container attestor.

## 6. HSM self-defence (`hsm-self-defence`, future)

- Consumes `hsm-device-protocol` (#1521).
- Two predetermined responses:
  - **lockdown**, the default: key operations and unseal are refused until a tenant quorum-signed unlock;
  - **key wipe**: the backend's tenant keys are zeroized. It is refused without a corroborating deterministic signal.
- Responses and the custom script are tenant-signed artefacts, verified against `trust-roots` (signer OU[0] = tenant).
- Every response is logged to `transparency-log`.
- Signal enforcement and policy selection are on the device:
  - the M7, through System Manager/EdgeLock;
  - the A55 NPU, which selects among the signed policies.

## Seams (a row on both sides)

- **go-qrdb provides:** peer-attestation (`attested-caller-gate`) and the verifiable log, with its `HeadSignerProvider` (`transparency-log`).
- **go-quicbaas:**
  - consumes the gate option, SVIDs, `VerifyImage`, tlog append and `trust-roots`;
  - provides the PCR policy.
- **gtp consumes:** the gate, `sdk/go/evidence`, pkg/attestation/vm and `pkg/signing` verify.
- **trusted-imx95 provides:** the HSM device side.

## Lane order after the rows

1. attested-caller-gate
2. trust-roots
3. xkey fold-ins and the root→xkey cut
4. pkg/attestation/vm and the pkg/signing verify
5. image-signing
6. go-quicbaas CA pieces
7. transparency-log, when go-qrdb ships
8. workload-identity, after go-qrdb accepts the tenant trust-domain form

The HSM rows stay future.
