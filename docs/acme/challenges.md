# ACME Challenge Types

Detailed documentation for all supported ACME challenge types, including standard RFC 8555 challenges and TPM-based extensions.

## Challenge Overview

```
+----------------------------------------------------------+
|                  Challenge Types                          |
+----------------------------------------------------------+
|                                                           |
|  Standard ACME (RFC 8555)                                 |
|  +------------------+  +------------------+               |
|  |     http-01      |  |     dns-01       |               |
|  |  HTTP validation |  |  DNS validation  |               |
|  +------------------+  +------------------+               |
|                                                           |
|  TPM Extensions (TCG)                                     |
|  +------------------+  +------------------+               |
|  |   enroll-01      |  |   endorse-01     |               |
|  | TCG-CSR-IDevID   |  |  EK Certificate  |               |
|  +------------------+  +------------------+               |
|                                                           |
|  +------------------+                                     |
|  | device-attest-01 |                                     |
|  | TPM Attestation  |                                     |
|  +------------------+                                     |
+----------------------------------------------------------+
```

## http-01 Challenge

### Overview

The http-01 challenge validates domain control by requiring the client to serve a specific value at a well-known HTTP URL. This is the most common challenge type for web server deployments.

**RFC Reference:** RFC 8555 Section 8.3

### Challenge Flow

```
Client                  ACME Server              Target Domain
   |                         |                        |
   | 1. Create order         |                        |
   |------------------------>|                        |
   |   (identifiers: dns)    |                        |
   |                         |                        |
   |<------------------------|                        |
   |   Challenge(type: http-01, token: xxx)           |
   |                         |                        |
   | 2. Setup HTTP server    |                        |
   |-------------------------------------------->     |
   |   Serve keyAuth at well-known path               |
   |                         |                        |
   | 3. Respond to challenge |                        |
   |------------------------>|                        |
   |                         |                        |
   |                         | 4. HTTP GET            |
   |                         |----------------------->|
   |                         |  /.well-known/acme-challenge/{token}
   |                         |<-----------------------|
   |                         |   Response: keyAuth    |
   |                         |                        |
   |                         | 5. Verify keyAuth      |
   |                         |                        |
   |<------------------------|                        |
   |   Challenge valid       |                        |
```

### Key Authorization

The client must serve the key authorization at:

```
http://{domain}/.well-known/acme-challenge/{token}
```

The key authorization is computed as:

```
keyAuth = token + "." + base64url(SHA256(JWK_Thumbprint))
```

Where JWK_Thumbprint is the SHA-256 hash of the account's public key JSON Web Key thumbprint.

### Implementation Details

**Verify Function:**

```go
func Verify(
    resolver *net.Resolver,
    ca CertificateAuthority,
    domain, port, challengeToken, expectedKeyAuth string) error
```

| Parameter | Description |
|-----------|-------------|
| `resolver` | DNS resolver for domain name resolution |
| `ca` | Certificate Authority (reserved for future use) |
| `domain` | Domain name to verify (e.g., "example.com") |
| `port` | HTTP port number (typically "80") |
| `challengeToken` | Unique token from ACME server |
| `expectedKeyAuth` | Expected key authorization value |

**HTTP Client Configuration:**

- Timeout: 10 seconds
- Dial timeout: 5 seconds
- No redirect following (per RFC 8555)
- TLS verification disabled (HTTP protocol)

### Client Setup

The client half of the challenge is a short-lived HTTP server serving the key
authorization. It is reachable from the SDK, so a consumer that imports only
`sdk/go` can answer an http-01 challenge:

```go
import trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"

responder, err := trustedca.NewHTTP01Responder(trustedca.HTTP01ResponderConfig{
    Addr:    "80",       // a bare port, or any net.Listen address such as "127.0.0.1:8080"
    KeyAuth: keyAuth,
})
if err != nil {
    return err          // nothing is listening; do not accept the challenge
}
defer func() { _ = responder.Close() }()
```

The listener is bound before `NewHTTP01Responder` returns, so:

- A bind failure — no `CAP_NET_BIND_SERVICE` for port 80, or the port already
  held — arrives as a typed `HTTP01ResponderBindError` at the call, not as a
  rejected authorization several round trips later.
- The responder is already answering when the call returns, so the order may be
  accepted immediately without racing the server's validation request.
- Each responder owns its listener, so concurrent orders each take their own on
  their own address and cannot disturb one another.

`Addr()` reports the bound address, which is where a kernel-assigned port shows
up when the configuration asked for port 0. `Shutdown(ctx)` stops the responder
gracefully and `Close()` stops it immediately. Once the responder has stopped,
either call is a no-op returning nil, so the deferred `Close` above stays
correct after an explicit `Shutdown`; a `Shutdown` that misses its deadline
returns `HTTP01ResponderShutdownError` and leaves the responder running, so
`Close` can force the teardown.

Wiring the responder into an order goes through the `ChallengeSetup` and
`ChallengeCleanup` seams of `ACMECertificateRequest`; see
[`sdk/go/acme/http01_responder.go`](../../sdk/go/acme/http01_responder.go) for a
complete example.

### Error Types

| Error | Description |
|-------|-------------|
| `ErrUnexpectedHTTPStatus` | HTTP response status is not 200 OK |
| `ErrKeyAuthorizationMismatch` | Response body doesn't match expected keyAuth |
| `HTTP01ResponderConfigError` | A required `HTTP01ResponderConfig` field is missing |
| `HTTP01ResponderBindError` | The responder could not take the address; unwraps to the `net` error |
| `HTTP01ResponderShutdownError` | A graceful shutdown did not finish before its deadline |

### Wildcard Domains

Per RFC 8555 Section 7.1.4, http-01 challenge is **not allowed** for wildcard domains. Use dns-01 instead.

---

## dns-01 Challenge

### Overview

The dns-01 challenge validates domain control by requiring the client to provision a DNS TXT record containing a specific value. This challenge type supports wildcard certificate issuance.

**RFC Reference:** RFC 8555 Section 8.4

### Challenge Flow

```
Client                  ACME Server              DNS Server
   |                         |                        |
   | 1. Create order         |                        |
   |------------------------>|                        |
   |   (identifiers: dns)    |                        |
   |                         |                        |
   |<------------------------|                        |
   |   Challenge(type: dns-01, token: xxx)            |
   |                         |                        |
   | 2. Compute validation   |                        |
   |    value                |                        |
   |    SHA256(keyAuth)      |                        |
   |    base64url encode     |                        |
   |                         |                        |
   | 3. Add TXT record       |                        |
   |-------------------------------------------->     |
   |   _acme-challenge.{domain} = validation          |
   |                         |                        |
   | 4. Respond to challenge |                        |
   |------------------------>|                        |
   |                         |                        |
   |                         | 5. DNS TXT lookup      |
   |                         |----------------------->|
   |                         |   _acme-challenge.{domain}
   |                         |<-----------------------|
   |                         |   TXT: validation      |
   |                         |                        |
   |                         | 6. Verify value        |
   |                         |                        |
   |<------------------------|                        |
   |   Challenge valid       |                        |
```

### DNS TXT Record

The TXT record must be provisioned at:

```
_acme-challenge.{domain}
```

The record value is computed as:

```
validation = base64url(SHA256(keyAuth))
```

Where `keyAuth = token + "." + base64url(SHA256(JWK_Thumbprint))`.

### Implementation Details

**Verify Function:**

```go
func Verify(
    resolver Resolver,
    ca CertificateAuthority,
    domain, port, challengeToken, expectedKeyAuth string) error
```

**DNS Service Interface:**

```go
type DNSServiceInterface interface {
    // Zone retrieves a DNS zone by domain name
    Zone(domain string) (DNSZone, error)

    // Save persists zone changes to the datastore
    Save(zone DNSZone) error
}
```

The DNS service must be configured before challenge verification:

```go
dns01.SetDNSService(dnsService)
```

### Client Setup

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01"

// Initialize DNS service
dns01.SetDNSService(dnsService)

// Setup provisions the TXT record
err := dns01.Setup(challengeToken, domain)
```

### Error Types

| Error | Description |
|-------|-------------|
| `ErrChallengeFailed` | TXT record doesn't match expected value |
| `ErrDNSServiceNotInitialized` | DNS service not configured |

### Wildcard Support

The dns-01 challenge is the **only** challenge type that supports wildcard domains per RFC 8555. For `*.example.com`, the TXT record is provisioned at `_acme-challenge.example.com`.

---

## device-attest-01 Challenge

### Overview

The device-attest-01 challenge follows [draft-ietf-acme-device-attest](https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest): remote attestation of a device-resident key. The device proves that the key the certificate is issued for lives in its TPM (format `tpm`) or secure element (format `dice`).

**The client answers the challenge; the server never contacts the device.** The client POSTs the challenge URL, as an ordinary authenticated ACME request, with the payload

```json
{"attObj": "<base64url, unpadded, of the CBOR attestation object>"}
```

and the server verifies the attestation from that payload. The device needs no HTTP server, no address and no inbound route. An AVR on a serial port enrolls through a gateway that holds the ACME account and POSTs on its behalf. This is the difference from `enroll-01` and `endorse-01`, whose servers do dial the device.

Freshness is the key authorization, derived from the challenge token and the account key. The attestation must cover it: `TPMExtraData(alg, keyAuth)` in the `certInfo` of a `tpm` statement, `DICENonce(keyAuth)` in the `eat_nonce` of a `dice` leaf. A recording of an earlier answer does not verify against a new token.

The `tpm` evidence is a TPM2_Certify of the certificate key by the device's Initial Attestation Key (IAK), carried as a WebAuthn Level 2 section 8.3 attestation statement. The attestation object is the WebAuthn `{fmt, attStmt}` map. The draft has the key authorization take the place of `authenticatorData || clientDataHash`, and says `authData` SHOULD be omitted: the server ignores it if sent, as it ignores any member of the payload besides `attObj` (the draft requires servers to ignore unrecognized fields). The draft's `hardware-module` identifier type is not supported; devices are identified by `permanent-identifier`.

**References:**
- [draft-ietf-acme-device-attest](https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest)
- [W3C WebAuthn TPM Attestation, section 8.3](https://www.w3.org/TR/webauthn/#sctn-tpm-attestation)

### TPM Requirements

- TPM 2.0 compliant hardware or software TPM
- Initial Attestation Key (IAK) provisioned. Its certificate must be installed in the TPM with `ProvisionIAKCert` (`pkg/tpm2/cert_idevid.go:116`) and is read back with `IAKCertificate` (`cert_idevid.go:141`). enroll-01 issues an IAK certificate and returns it to the caller, but does not install it (see the known limitation under Trust anchors: that certificate does not yet meet section 8.3.1). The certificate must meet WebAuthn Level 2 section 8.3.1 (`checkAIKCertificate`, `pkg/acme/challenges/device-attest-01/tpm.go:155`): X.509 v3, empty Subject, a subjectAltName naming the TPM manufacturer/model/version, `tcg-kp-AIKCertificate` extended key usage, and `CA:FALSE`
- A Platform SRK, the parent of the certificate key
- Support for TPM2_Certify (`CertifyKey`, `pkg/tpm2/attestation.go:76`)

PCR state is not part of the evidence. The statement certifies a key, not the platform's measurements.

### Challenge Flow

```
Client (TPM)                          ACME Server
   |                                       |
   | 1. Create order                       |
   |   (identifier: permanent-identifier)  |
   |-------------------------------------->|
   |   Challenge(device-attest-01, token)  |
   |<--------------------------------------|
   |                                       |
   | 2. Certificate key under the          |
   |    Platform SRK (created once)        |
   | 3. TPM2_Certify(key) by the IAK,      |
   |    qualifyingData =                   |
   |    TPMExtraData(alg, keyAuth)         |
   | 4. Encode the attestation object      |
   |                                       |
   | 5. POST the challenge URL:            |
   |    {"attObj": base64url(CBOR)}       |
   |-------------------------------------->|
   |                   6. VerifyAttestation|
   |                      - anchor x5c     |
   |                      - section 8.3    |
   |                      - identity ==    |
   |                        identifier     |
   |                   (nothing is dialed) |
   |                                       |
   | 7. Finalize: CSR signed by the key,   |
   |    permanentIdentifier otherName      |
   |-------------------------------------->|
   |                   8. BindCSRKey:      |
   |                      CSR key ==       |
   |                      pubArea key      |
```

### Attestation Object Structure

The `attObj` member of the payload is the base64url (unpadded) encoding of this CBOR attestation object:

```
{"attObj": base64url(CBOR of)
  {
    "fmt": "tpm",
    "attStmt": {
      "ver": "2.0",
      "alg": <COSE identifier of the IAK's signature algorithm>,
      "x5c": [<DER IAK certificate>],
      "sig": <the IAK's signature over certInfo>,
      "certInfo": <TPMS_ATTEST from TPM2_Certify>,
      "pubArea": <TPMT_PUBLIC of the certificate key>
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `fmt` | Attestation format (`"tpm"`) |
| `ver` | TPM version (`"2.0"`) |
| `alg` | COSE identifier of the IAK's signature algorithm. The default IAK answers with PS256 (-37). ES256 (-7), RS256 (-257) and the SHA-384/512 variants are also used (`coseAlgorithms`, `pkg/acme/challenges/device-attest-01/setup.go:84`) |
| `x5c` | The IAK certificate. It must meet section 8.3.1: an empty subject, a TCG SAN, not a CA, and EKU `tcg-kp-AIKCertificate` |
| `sig` | The IAK's signature over `certInfo`: DER for ECDSA and the raw value for RSA (WebAuthn L2 section 6.5.6) |
| `certInfo` | The `TPM_ST_ATTEST_CERTIFY` TPMS_ATTEST. Its `extraData` is `TPMExtraData(alg, keyAuthorization)` (`tpm.go:205`) |
| `pubArea` | The TPMT_PUBLIC of the certificate key |

certInfo's `extraData` must equal `TPMExtraData(alg, keyAuth)` (`tpm.go:205`) exactly -- the hash of the ACME key authorization under the hash algorithm `alg` names -- compared in constant time. There is no substring, prefix or containment fallback: a value present anywhere else in `certInfo` does not satisfy the check. This exact-match requirement is enforced by `pkg/attestation.VerifyInvariants` (via `pkg/tpm2.VerifyCertify`'s `subtle.ConstantTimeCompare(attest.ExtraData.Buffer, opts.ExpectedQualifyingData)`), not by this package.

### Client

`deviceattest01.Setup` (`pkg/acme/challenges/device-attest-01/setup.go:115`) builds the response for a key the TPM already holds. `TrustedPlatformModule` (`setup.go:65`) is the `IAKAttributes`/`IAKCertificate`/`CertifyKey` subset of `pkg/tpm2.TrustedPlatformModule`, so a go-xkms TPM is passed as it is:

```go
payload, err := deviceattest01.Setup(keyAuth, tpm, keyAttrs, keyBackend)
```

`keyAttrs` is the certificate key and `keyBackend` the store its blobs live in. Its parent is the Platform SRK, as for every go-xkms key.

The ACME client does all of this through `TPMModule.CreateAttestedKey` (`pkg/acme/client/tpm.go:192`). `XKMSTPMAdapter.CreateAttestedKey` (`tpm.go:477`) creates a P-256 signing key named by the certificate's common name under the Platform SRK on first use and reuses it afterwards. It then calls `Setup` and returns the response and the key's `crypto.Signer`. `NewXKMSTPMAdapter` (`tpm.go:298`) takes the TPM and its key-blob store:

```go
adapter := acmeclient.NewXKMSTPMAdapter(tpm, keyBackend)
cert, err := client.DeviceAttest(ctx, &acmeclient.EnrollmentConfig{
    Challenge:  string(acmeclient.ChallengeTypeDeviceAttest01),
    CommonName: "device-0001.example.com",
    TPMModule:  adapter,
})
```

`DeviceAttest` (`pkg/acme/client/enrollment.go`) sends the response as the challenge's payload (`acme.Challenge.Payload`, which `golang.org/x/crypto/acme` sends in place of `{}`). It opens no listener, so `EnrollmentConfig.IPAddress`, `Port` and `ListenHost` are unused for this challenge and may be left empty. At finalization it signs the CSR with the attested key, not the account key. The order's permanent-identifier is the device's own identity, `TPMModule.DeviceIdentity`: the RFC 4043 `permanentIdentifier` of the IAK certificate, read by `deviceattest01.DeviceIdentityFromCertificate`, the same rule the server applies to the evidence. The server refuses a challenge whose attested identity differs from the order's identifier, so the IP address is never sent. The CSR names the same identity in the `permanentIdentifier` otherName that finalize matches (`deviceAttestCSR`).

### Server

`VerifyAttestation(verifier, payload, keyAuth)` (`pkg/acme/challenges/device-attest-01/deviceattest01.go`) decodes the payload (`ParseAttestationRequest`), asks the verifier to check the object and anchor `x5c` (`AttestationVerifier`), then applies section 8.3 in `verifyTPMEvidence` (`tpm.go:65`) and returns a `VerifiedAttestation`. That record authorizes nothing until `BindCSRKey` (`binding.go:142`) has confirmed that the CSR's key is `pubArea`'s key. For this reason the one-shot `Verify` returns `ErrKeyBindingRequired` for this format.

**AttestationVerifier Interface** (`pkg/acme/challenges/device-attest-01/deviceattest01.go:174`):

```go
type AttestationVerifier interface {
    VerifyAttestationObject(obj *AttestationObject, expectedChallenge []byte) error
    VerifyAKCertificateChain(certs [][]byte) error
}
```

The production implementation is `TrustAnchorVerifier` (`anchors.go`, exposed as `ACMETrustAnchorVerifier` in `sdk/go/acme`). It is passed to the challenge verifier (`handlers.NewDeviceAttestVerifier`, `sdk/go/acme.ACMEAttestingVerifiers`) rather than asserted from the CA handle, because the CA that issues certificates and the roots that vouch for a device are separate configuration. A nil verifier registers nothing and a verifier called with none refuses (`ErrNoAttestationVerifier`).

#### Trust anchors

`TrustAnchorVerifier` is built from two separate root sets. A format with no configured root is refused (`ErrNoTrustAnchors`); it is never verified against the other format's roots.

| Format | Anchoring | Primitive |
|---|---|---|
| `tpm` | the AIK certificate in `x5c[0]`, through the intermediates the device sends after it, must chain to a `tpm_roots` entry | `evidence.VerifyAKCertificate`, after `checkAIKCertificate` reads the critical TCG `subjectAltName` |
| `dice` | the alias chain must descend from a `dice_roots` entry and satisfy the DICE policy, including the `eat_nonce` for this challenge and a `tcg-dice-Ueid` | `dice.Verify` |

`tpm_roots` are the CAs that vouch for AIK certificates: a TPM manufacturer's attestation CA or a privacy CA. A device sends the AIK certificate as `x5c[0]` and any intermediates after it; `Setup` sends only the AIK certificate today, so when the AIK is issued by an intermediate CA, configure that issuing CA itself as the root (a certificate in `tpm_roots` anchors a chain whether or not it is self-signed). A `tpm` statement carries no EK certificate, so the EK-to-manufacturer chain is not re-proven here. It is proven by whoever issued the AIK certificate: for a go-xkms CA, `enroll-01` verifies the EK chain against the configured manufacturer roots (`pkg/ca`, `verifyEKCertificateChain`) before issuing the IAK.

**Known limitation.** The statement's `x5c[0]` must meet WebAuthn Level 2 section 8.3.1, including an empty subject. The IAK certificates a go-xkms CA issues at `enroll-01` carry a subject (`iak-<model>-<serial>`, so the certificate store can key them), so they are not accepted as `x5c[0]` and a device cannot yet enroll with `enroll-01` and then attest with that same certificate. Use AIK certificates from a CA that issues section 8.3.1 conformant ones. Reconciling the two profiles (relaxing the subject requirement for TCG IAK certificates, or issuing the IAK with an empty subject) is an open decision.

`VerifyAKCertificateChain` is the format-blind second check. It requires every certificate to be inside its validity window and signed by the next, and the last to be, or be signed by, a root of either set. It can only remove chains the format-aware check admitted.

#### Configuration

`xkmsd` builds the verifier from `acme.challenges`:

```yaml
acme:
  challenges:
    device_attest01: true
    device_attest:
      tpm_roots:  [/etc/xkms/acme/tpm-aik-root.pem]
      dice_roots: [/etc/xkms/acme/dice-device-id.pem]
      dice_require_device_signed_leaf: true   # secure-element profiles, e.g. AVR + ATECC608A
      dice_require_measurement: true         # DiceTcbInfo must carry an FWID
      dice_require_tcb_info: true            # DiceTcbInfo must be present (operational flags)
```

`device_attest01` with neither `tpm_roots` nor `dice_roots` fails configuration validation (`config.ErrACMEDeviceAttestNoAnchors`), and the daemon independently refuses to start (`ErrACMEDeviceAttestAnchors` wrapping `ACMEErrNoTrustAnchors`) if no anchor loads. A file that is missing or holds no PEM certificate is also a startup error. No operational flag (`notConfigured`, `notSecure`, `recovery`, `debug`) is tolerated.

The issued certificate carries the attested identity as the RFC 4043 `permanentIdentifier` otherName in its subjectAltName. It is the issuer's statement, taken from the verified evidence and passed to the CA in `SignOptions.OtherNames`; the CA copies no otherName a CSR requests.

At finalization the request's key is bound to the attestation recorded for the device the request names (its `permanentIdentifier`), whatever the order's other identifiers are and however many devices it authorizes.

There is no `VerifyQuote` method: the TPM2_Certify binding (Name match, `extraData` match, signature verification) is made statelessly by `pkg/attestation.VerifyInvariants`/`pkg/tpm2.VerifyCertify` against the AIK certificate already anchored by `VerifyAKCertificateChain`, not by a round trip to the CA.

### Error Types

| Error | Description |
|-------|-------------|
| `ErrAttestationKeyUnavailable` | The IAK or its certificate cannot be read (`setup.go:48`) |
| `ErrNoCertificateKey` | `Setup` was given no certificate key (`setup.go:53`) |
| `ErrCertifyFailed` | The TPM refused to certify the certificate key (`setup.go:57`) |
| `ErrInvalidKeyAlgorithm` | The IAK signs with an algorithm that has no COSE identifier |
| `ErrInvalidAttestationFormat` | Unsupported attestation format |
| `ErrInvalidAttestationObject` | Cannot parse attestation object |
| `ErrAttestationPayloadInvalid` | The POSTed payload is not `{"attObj": base64url(CBOR)}`; the detail names the layer that failed |
| `ErrNoAttestationVerifier` | An attestation was verified with no trust policy |
| `ErrNoTrustAnchors` | No root is configured, or none for the attestation's format |
| `ErrTPMAttestationInvalid` | The statement fails section 8.3. The cause is joined, e.g. `pkg/tpm2.ErrCertifyWrongType` for a quote |
| `ErrAIKCertificateInvalid` | `x5c[0]` does not meet section 8.3.1 |
| `ErrCertificateChainInvalid` | `x5c` does not anchor to the configured roots |
| `ErrKeyBindingRequired` | `Verify` was used for a format that binds through the CSR |

---

## enroll-01 Challenge

### Overview

The enroll-01 challenge is a custom ACME extension for OEM enrollment of TPM-equipped devices during manufacturer provisioning. It implements procedures from TCG TPM 2.0 Keys for Device Identity and Attestation specification Section 6.

**Reference:** [TCG TPM 2.0 Keys for Device Identity](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf)

### TCG Procedures Implemented

- **Section 6.2:** OEM Installation of IAK and IDevID in a Single Pass
- **Section 6.1.4:** Included Attestation Variation

### TPM Requirements

- TPM 2.0 compliant hardware or software TPM
- Endorsement Key (EK) certificate provisioned by manufacturer
- Ability to create Attestation Keys (AK/IAK)
- Support for TPM2_MakeCredential and TPM2_ActivateCredential

### Challenge Flow

```
Client (TPM)              ACME Server                CA
   |                           |                      |
   | 1. Create order           |                      |
   |-------------------------->|                      |
   |   (identifiers: ip or permanent-identifier)      |
   |                           |                      |
   |<--------------------------|                      |
   |   Challenge(type: enroll-01, token: xxx)         |
   |                           |                      |
   | 2. Create TCG-CSR-IDEVID  |                      |
   |    - CreateIDevID         |                      |
   |    - Include EK cert      |                      |
   |    - Include AK pub       |                      |
   |                           |                      |
   | 3. Start HTTP server      |                      |
   |    - Challenge endpoint   |                      |
   |    - Activation endpoint  |                      |
   |                           |                      |
   | 4. Respond to challenge   |                      |
   |-------------------------->|                      |
   |                           |                      |
   |                           | 5. GET CSR           |
   |<--------------------------|                      |
   |   TCG-CSR-IDEVID          |                      |
   |-------------------------->|                      |
   |                           |                      |
   |                           | 6. Verify CSR        |
   |                           |--------------------->|
   |                           |   MakeCredential     |
   |                           |<---------------------|
   |                           |   credBlob, secret   |
   |                           |                      |
   |                           | 7. POST activation   |
   |<--------------------------|                      |
   |   credBlob, encSecret     |                      |
   |                           |                      |
   | 8. ActivateCredential     |                      |
   |    (TPM operation)        |                      |
   |                           |                      |
   |-------------------------->|                      |
   |   Decrypted secret        |                      |
   |                           |                      |
   |                           | 9. Verify secret     |
   |                           |                      |
   |<--------------------------|                      |
   |   Challenge valid         |                      |
```

### TCG-CSR-IDevID Structure

The CSR follows TCG specification format containing:

| Field | Description |
|-------|-------------|
| `prodModel` | Product model identifier |
| `prodSerial` | Product serial number |
| `ekCert` | Endorsement Key certificate (DER) |
| `attestPub` | Attestation public key (TPM2B_PUBLIC) |
| `signingPub` | Signing public key (TPM2B_PUBLIC) |
| `bootEvntLog` | Boot event log (optional) |
| `prodCaData` | Production CA data (optional) |

### Implementation Details

**Verify Functions:**

```go
func VerifyActivation(
    client *validation.Client,
    ca TCGCSRVerifier,
    domain, port, token, keyAuth string) (*Activation, error)

// Verify is VerifyActivation for a caller with no use for the result.
func Verify(client *validation.Client, ca TCGCSRVerifier, domain, port, token, keyAuth string) error
```

**CertificateAuthority Interface:**

```go
type CertificateAuthority interface {
    VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg interface{}) (
        credentialBlob []byte,
        encryptedSecret []byte,
        plainSecret []byte,
        err error)
    DefaultSignatureAlgorithm() x509.SignatureAlgorithm
}
```

### Credential Activation

The server uses TPM2_MakeCredential to create an encrypted credential that can only be decrypted by the specific TPM identified by the EK certificate:

```
                 +----------------+
                 |  ACME Server   |
                 +----------------+
                        |
                        | MakeCredential(EK_pub, AK_name, secret)
                        v
                 +----------------+
                 | credentialBlob |
                 | encryptedSecret|
                 +----------------+
                        |
                        | Send to client
                        v
                 +----------------+
                 |  Client TPM    |
                 +----------------+
                        |
                        | ActivateCredential(EK, AK, credBlob, encSecret)
                        v
                 +----------------+
                 |  plain secret  |
                 +----------------+
```

### Binding the finalize request to the activated TPM

Credential activation proves a TPM holding one endorsement key and one activation key (the IAK) answered. The TCG-CSR-IDEVID that finalizes the order arrives one request later, and without a binding a client that passed the challenge once could build one in software around another device's *public* EK certificate and be issued an IDevID carrying that device's identity.

`VerifyActivation` therefore returns the `Activation` it activated, and the server persists it on the challenge as an `entities.DeviceAttestation` (`Format: "enroll-01"`): `LeafDER` is the activated EK certificate, `DeviceIdentityValue` its TCG permanent identifier (`ca.EKCertificatePermanentIdentifier`, the SHA-256 of its DER, the same value the issued IAK and IDevID carry), and `PubArea` the IAK's TPMT_PUBLIC. At finalize the order is refused unless:

- enroll-01 is the only attestation challenge that validated it (an `endorse-01` or `device-attest-01` authorization cannot become an IDevID; neither can an order no attestation challenge validated, such as an `ip` identifier `http-01` validated), and
- the TCG-CSR's EK certificate has the recorded permanent identifier and its IAK public area is the recorded one (`bindEnrollActivation`).

The identifier comparison at the challenge is unchanged and real for enroll-01: the dial that proved a genuine TPM answered reached the address the order's identifier names. The TPM itself is named by the activated EK. Typed errors: `ErrEnrollActivationNotFound`, `ErrEnrollActivationMismatch`, `ErrFinalizeRequestNotPermitted` (all `badCSR` 400).

### Client Setup

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/enroll-01"

// Setup creates TCG-CSR-IDEVID and starts HTTP server
packedCSR, err := enroll01.Setup(port, keyAuth, ca, tpm)
```

### HTTP Endpoints

The client must serve two endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/acme-challenge/{token}` | GET | Returns base64url-encoded TCG-CSR-IDEVID |
| `/.well-known/acme-activation/{token}` | POST | Receives credential, returns decrypted secret |

### Certificate Issuance

Upon successful credential activation, the CA issues:

1. **IAK Certificate:** Certifies the Initial Attestation Key. Subject CN
   `iak-<model>-<serial>` (`ca.IAKCommonName`), applied by the CA when it
   issues.
2. **IDevID Certificate:** Device Identity certificate. Subject CN
   `<model>-<serial>`.

Both certificates are returned concatenated in PEM format, IAK first. Both are
recorded in the CA's certificate store under their own common names, so either
can be listed, revoked, or fetched later; the IAK is read back with
`IAKCertificate(ctx, model, serial)`. The `TCGData.IAKCertificateDER` and
`IDevIDCertificateDER` fields handed to the order-finalize hooks carry the same
DER bytes.

---

## endorse-01 Challenge

### Overview

The endorse-01 challenge is a custom ACME extension for issuing Endorsement Key (EK) certificates to TPMs that do not have manufacturer-issued EK certificates.

### Use Cases

- TPM simulators (swtpm) without manufacturer EK certificates
- Devices from manufacturers that don't provision EK certificates
- Enterprise custom EK certificate enrollment
- Development and testing environments

### Important Distinction

Unlike enroll-01, the endorse-01 challenge does **not** perform TPM2_MakeCredential/TPM2_ActivateCredential because:

1. The TPM doesn't have an EK certificate yet
2. That's exactly what this challenge issues
3. Authorization is handled via EAB and server policy

### Challenge Flow

```
Client                  ACME Server                Admin
   |                         |                      |
   | 0. Create EAB credential|                      |
   |   (out of band)         |<---------------------|
   |                         |   Pre-authorization  |
   |                         |                      |
   | 1. Create account with EAB                     |
   |------------------------->|                     |
   |                         |                      |
   | 2. Create order         |                      |
   |------------------------->|                     |
   |   (identifier: permanent-identifier)           |
   |                         |                      |
   |<-------------------------|                     |
   |   Challenge(type: endorse-01)                  |
   |                         |                      |
   | 3. Generate CSR         |                      |
   |    with EK public key   |                      |
   |                         |                      |
   | 4. Respond to challenge |                      |
   |------------------------->|                     |
   |   (auto-validated)      |                      |
   |                         |                      |
   | 5. Finalize order       |                      |
   |------------------------->|                     |
   |   CSR with EK pub key   |                      |
   |                         |                      |
   |                         | 6. Issue EK cert     |
   |                         |    with TCG          |
   |                         |    extensions        |
   |                         |                      |
   |<-------------------------|                     |
   |   EK Certificate        |                      |
```

### Implementation Details

**Verify Function:**

```go
func Verify(
    resolver *net.Resolver,
    ca CertificateAuthority,
    domain, port, challengeToken, expectedKeyAuth string) error
```

endorse-01 proves **nothing about the key it certifies**. An EK is decrypt-only, so the key cannot sign a proof of possession, and the server holds no exchange with the device to make one (see below). The External Account Binding is therefore the only control, and `endorse01.Verify`, which returns `nil`, is deprecated and is not what authorizes a request.

What the server does:

1. **EAB is required by default.** A server that sets nothing requires it (`Params.EndorseEABOptional` zero value; `acme.endorse_eab_required` unset means true). A request from an account with no EAB of purpose `endorse-01` is `unauthorized`.
2. **The EAB must name the EK it authorizes**, by `deviceInfo.ekPublicKeyHash` (the SHA-256 of the EK's PKIX DER, which is what the order's identifier base64url-encodes, in hex, optionally prefixed `sha256:`) and/or the metadata key `acme.endorse_device_id_meta_key`. A binding that names neither would authorize its account for any key and is refused (`ErrEndorseEABKeyNotBound`). An EK other than the bound one is refused (`ErrEndorseEABKeyMismatch`).
3. **The attested identity is the EAB's**, not the order's. `ChallengeHandler` hands the EAB-authorized identity to the verifier (`AttestationChallenge.AuthorizedIdentity`); `handlers.NewEndorseVerifier` reports it and refuses without one (`ErrEndorseNoAuthorizedIdentity`). The handler then compares it with the order's identifier like every attestation type.
4. **An endorse-01 authorization finalizes only as an EK certificate.** The EK-certificate path requires endorse-01 to be the only attestation challenge that validated the order, and an endorse-01-validated order cannot finalize a TCG-CSR, IDevID, cluster or device-attest-01 certificate request (`ErrFinalizeRequestNotPermitted`).

**Waiving EAB.** Set `endorse_eab_required: false` (or `XKMS_ACME_ENDORSE_EAB_REQUIRED=false`; `Params.EndorseEABOptional` in Go). Then any account can obtain an EK certificate for any public key, the request's own identifier is the "authorized" identity, and the server logs a warning for every challenge. Do this only on a closed lab server.

**Why there is no MakeCredential proof of possession.** A proof needs the server to learn the name of a key resident in the same TPM and have the device activate a credential made for the EK. The existing primitives (`tpm2.NewCredentialChallenge`, `ActivateCredential`) would do the cryptography, but the exchange has no carrier. The order's identifier is the EK, not an address, so there is nothing for the server to dial (the same separation of identifier and address that  leaves open), and a second request on the challenge changes the ACME protocol. Both are architectural, so EAB, bound to the key, is the control.

### Client Setup

```go
import "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/endorse-01"

// Create CSR with EK public key
csr, err := endorse01.Setup(challengeToken, ca, tpm, serializer)
```

### Authorization via EAB

endorse-01 requires External Account Binding unless it is explicitly waived:

```yaml
acme:
  endorse_eab_required: true          # the default when the key is absent
  endorse_device_id_meta_key: ""      # optional: name the EK in EAB metadata instead of deviceInfo.ekPublicKeyHash
```

Register each device (or each device's EK within a batch) with an EAB of purpose `endorse-01` whose `deviceInfo.ekPublicKeyHash` is the SHA-256 of its EK's PKIX DER, hex encoded. This ensures only pre-authorized devices can obtain EK certificates. A binding shared by a batch that names no EK is refused.

### EK Certificate Content

The issued EK certificate includes TCG-compliant extensions:

| Extension | OID | Description |
|-----------|-----|-------------|
| Subject Alternative Name | 2.5.29.17 | TPM serial number as permanentIdentifier |
| Extended Key Usage | 2.5.29.37 | tcg-kp-EKCertificate |
| Certificate Policies | 2.5.29.32 | tcg-ce-TPMPolicies |

---

## Challenge Selection Logic

The ACME server selects challenges based on identifier type:

```go
switch id.Type {
case common.AuthzTypeDNS:
    if isWildcard {
        // Wildcard: only DNS-01 allowed (RFC 8555)
        challengeTypes = append(challengeTypes, "dns-01")
    } else {
        // Non-wildcard: HTTP-01 and DNS-01
        challengeTypes = append(challengeTypes, "http-01", "dns-01")
    }
case common.AuthzTypeIP, common.AuthzTypePermanentIdentifier:
    // TPM challenges
    challengeTypes = append(challengeTypes,
        "enroll-01",
        "endorse-01",
        "device-attest-01")
}
```

## Challenge Configuration Summary

| Challenge | Port | Protocol | Identifier Type | Wildcard |
|-----------|------|----------|-----------------|----------|
| http-01 | 80 | HTTP | dns | No |
| dns-01 | 53 | DNS | dns | Yes |
| device-attest-01 | none (client POSTs the attestation) | none | permanent-identifier | N/A |
| enroll-01 | configurable | HTTP | ip, permanent-identifier | N/A |
| endorse-01 | N/A | N/A | permanent-identifier | N/A |

## See Also

- [README](README.md) - Module overview
- [Architecture](architecture.md) - System architecture
- [Configuration](../acme-issuance/engineering.md) - Server configuration (`acme/configuration.md` was deleted by go-xkms#942)
- [API Reference](api-reference.md) - HTTP API documentation
