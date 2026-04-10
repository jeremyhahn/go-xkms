# Init Ceremony

Step-by-step walkthrough of the `xkmsd init` ceremony, including the challenge-response certificate retrieval protocol and Shamir share claim protocol.

## Prerequisites

Before running `xkmsd init`:

1. A valid `xkmsd.yaml` configuration file exists
2. The PKCS#11 library is accessible (if using HSM backends)
3. Each SO has generated a CSR with their preferred algorithm (M-of-N only)
4. The SO PIN and User PIN have been chosen per organizational policy

## Single Admin Ceremony

### Step 1: Run Init

```bash
xkmsd init --config /etc/xkms/xkmsd.yaml --so-pin <SO_PIN> --user-pin <USER_PIN>
```

### Step 2: What Happens

The server executes the following sequence:

```
1. Load config from xkmsd.yaml
2. C_InitToken(SO PIN)         -- initialize PKCS#11 token
3. C_InitPIN(User PIN)         -- set user PIN on token
4. Initialize barrier           -- create AES-256-GCM root key
5. Seal User PIN               -- via configured credential strategy (skip if "manual")
6. Create CA key pair           -- on selected backend
7. Issue CA self-signed cert
8. Generate server TLS key pair
9. Issue server TLS cert        -- signed by CA
10. Compute SPKI pin
11. Write SO cert to data dir
12. Print SPKI pin to stdout
```

### Step 3: Output

```
Init complete.
  CA Subject:   CN=xkms-ca
  TLS Subject:  CN=xkmsd.example.com
  SPKI Pin:     sha256//e5f6a7b8c9d0e1f2a3b4c5d6e7f8...
  Data Dir:     /var/lib/xkms
  State:        operational
```

The server is now ready for `xkmsd start`.

## M-of-N Ceremony

### Step 1: SOs Generate CSRs

Each Security Officer generates a CSR using their preferred algorithm. The private key stays with the SO and is never shared.

```bash
# RSA
openssl req -new -newkey rsa:4096 -keyout admin1-key.pem -out admin1.csr -nodes \
  -subj "/CN=admin1@example.com"

# ECDSA
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout admin2-key.pem -out admin2.csr -nodes \
  -subj "/CN=admin2@example.com"

# Ed25519
openssl genpkey -algorithm Ed25519 -out admin3-key.pem
openssl req -new -key admin3-key.pem -out admin3.csr -subj "/CN=admin3@example.com"
```

### Step 2: Run Init with Threshold

```bash
xkmsd init --config /etc/xkms/xkmsd.yaml \
  --so-pin <SO_PIN> --user-pin <USER_PIN> \
  --threshold 2 \
  --so admin1@example.com:/path/to/admin1.csr \
  --so admin2@example.com:/path/to/admin2.csr \
  --so admin3@example.com:/path/to/admin3.csr
```

### Step 3: What Happens

```
1-9.  Same as single admin (token init, barrier, CA, TLS)
10.   Shamir-split barrier root key into N shares (threshold=M)
11.   For each SO CSR:
      a. Verify CSR signature
      b. Sign CSR with CA key -> SO certificate
      c. Seal Shamir share with SO public key
      d. Store sealed share + SO certificate for claim
12.   Start temporary TLS listener for claims
13.   Print SPKI pin to stdout
14.   Wait for all SOs to claim certs + shares
15.   Transition to operational state
```

### Step 4: Output

```
Init complete (M-of-N enrollment active).
  CA Subject:     CN=xkms-ca
  TLS Subject:    CN=xkmsd.example.com
  SPKI Pin:       sha256//e5f6a7b8c9d0e1f2a3b4c5d6e7f8...
  Threshold:      2-of-3
  Claim Endpoint: https://xkmsd.example.com:8443
  State:          enrolling

  Pending claims:
    admin1@example.com  [cert: pending] [share: pending]
    admin2@example.com  [cert: pending] [share: pending]
    admin3@example.com  [cert: pending] [share: pending]
```

## Challenge-Response Certificate Claim

SOs retrieve their signed certificates via a challenge-response protocol that proves possession of the CSR private key. This uses SPKI pinning for trust-on-first-use since the SO does not yet have the CA certificate.

### Protocol Flow

```
SO (xkmsctl)                              Server (xkmsd)
    |                                          |
    |-- claim-cert(username, SPKI pin) ------->|
    |                                          |
    |<---- nonce (random 32 bytes) ------------|
    |                                          |
    |   sign(nonce, CSR private key)           |
    |                                          |
    |-- signed_nonce(signature, algorithm) --->|
    |                                          |
    |   verify(signature, CSR public key)      |
    |                                          |
    |<---- SO certificate + CA certificate ----|
    |                                          |
```

### Step-by-Step

1. SO connects with SPKI pin verification (no CA trust needed yet):

```bash
xkmsctl init claim-cert \
  --server https://xkmsd.example.com:8443 \
  --spki-pin sha256//e5f6a7b8c9d0e1f2... \
  --username admin2@example.com \
  --key /path/to/admin2-key.pem
```

2. Server generates a random 32-byte nonce and sends it to the client.

3. Client signs the nonce with the CSR private key (RSA-PSS, ECDSA, or Ed25519 -- algorithm auto-detected from key type).

4. Server verifies the signature against the public key from the stored CSR. If verification succeeds, the server returns the signed SO certificate and the CA certificate.

5. Client saves both certificates to disk.

### Supported Signature Algorithms

| Key Type | Signature Algorithm | Hash |
|----------|-------------------|------|
| RSA | RSA-PSS | SHA-256 |
| ECDSA (P-256) | ECDSA | SHA-256 |
| ECDSA (P-384) | ECDSA | SHA-384 |
| ECDSA (P-521) | ECDSA | SHA-512 |
| Ed25519 | Ed25519 | N/A (intrinsic) |

## Shamir Share Claim Protocol

After claiming their certificate, each SO claims their sealed Shamir share. This step requires mTLS authentication with the newly obtained certificate.

### Protocol Flow

```
SO (xkmsctl)                              Server (xkmsd)
    |                                          |
    |-- claim-share(mTLS cert, username) ----->|
    |                                          |
    |   verify mTLS client cert against CA     |
    |   look up sealed share for username      |
    |                                          |
    |<---- sealed share (encrypted blob) ------|
    |                                          |
    |   unseal with SO private key             |
    |   store share in local secure storage    |
    |   zeroize plaintext share from memory    |
    |                                          |
    |-- ack ---------------------------------->|
    |                                          |
    |   delete sealed share from server        |
    |   zeroize server-side copy               |
    |                                          |
```

### Step-by-Step

1. SO connects with mTLS using their newly claimed certificate:

```bash
xkmsctl init claim-share \
  --server https://xkmsd.example.com:8443 \
  --tls-cert admin2.pem \
  --tls-key admin2-key.pem \
  --tls-ca ca.pem \
  --username admin2@example.com
```

2. Server verifies the client certificate against the CA.

3. Server looks up the sealed share for the authenticated username.

4. Server sends the sealed share (encrypted with the SO's public key).

5. Client decrypts the share with their private key.

6. Client stores the share in local secure storage (e.g., `xkey share store barrier <share>`).

7. Client zeroizes the plaintext share from memory.

8. Client sends acknowledgment to server.

9. Server deletes the sealed share and zeroizes its copy.

### Share Lifecycle

```
seal --> unseal --> deliver --> delete --> zeroize
  |         |          |          |          |
  v         v          v          v          v
 Server    Client    Network    Server     Both
 encrypts  decrypts  transfer   removes   clear
 share     share     complete   share     memory
```

Each share is delivered exactly once. After delivery and acknowledgment, no copy of the share remains on the server.

## State Transitions

```
awaiting_init
      |
      | xkmsd init (begin)
      v
  initializing
      |
      +---- single admin -----> operational
      |
      +---- M-of-N ----------> enrolling
                                    |
                                    | all claims complete
                                    v
                                operational
```

### State Persistence

The current state is persisted to `<data_dir>/init-state.json`:

```json
{
  "state": "enrolling",
  "threshold": 2,
  "total": 3,
  "claims": {
    "admin1@example.com": {"cert": true, "share": false},
    "admin2@example.com": {"cert": false, "share": false},
    "admin3@example.com": {"cert": false, "share": false}
  }
}
```

## Error Handling and Recovery

### Init Failure Mid-Ceremony

If `xkmsd init` fails partway through:

1. **Before barrier creation**: Safe to re-run `xkmsd init` from scratch.
2. **After barrier creation, before TLS cert**: Delete the data directory and re-run.
3. **During M-of-N enrollment**: The enrollment state is persisted. Restart `xkmsd init` with the same parameters to resume.

### Claim Failures

| Failure | Recovery |
|---------|----------|
| Network error during cert claim | Re-run `xkmsctl init claim-cert` (idempotent until success) |
| Wrong private key | Use the correct key that matches the CSR |
| SPKI pin mismatch | Verify the pin from init output; possible MITM |
| Share claim before cert claim | Claim certificate first (mTLS required) |
| Server restart during enrollment | Enrollment state is persisted; resume claims after restart |

### PIN Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `ErrSOPINInvalid` | SO PIN does not meet policy | Choose a stronger PIN |
| `ErrUserPINInvalid` | User PIN does not meet policy | Choose a stronger PIN |
| `ErrTokenAlreadyInitialized` | Token was already initialized | Use `--force` flag or wipe the token |

## Security Considerations

- The SO PIN is verified against the actual PKCS#11 backend. It is never stored by go-xkms.
- The User PIN seal strategy determines how the User PIN is protected at rest (see [credentials.md](credentials.md)).
- SPKI pinning prevents MITM during the initial cert claim when no CA trust is established.
- Shamir shares are sealed with the SO's public key -- only the SO can decrypt their share.
- All plaintext key material is zeroized from memory after use.
- The temporary enrollment TLS listener uses the same server certificate generated during init.

## Related Documentation

- [Init System Overview](README.md)
- [Threshold Architecture](threshold.md)
- [Credential Seal Strategies](credentials.md)
- [FIPS Roles](roles.md)
