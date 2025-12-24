# FROST CLI Documentation

## Overview

The FROST (Flexible Round-Optimized Schnorr Threshold) command group provides threshold signature operations where M-of-N participants can collaboratively sign messages without ever reconstructing the private key. This enables secure, distributed signing with no single point of failure.

FROST signatures are generated through a two-round protocol:
1. **Round 1**: Each participant generates and shares commitments
2. **Round 2**: Participants generate signature shares using collected commitments
3. **Aggregation**: Shares are combined into a final signature

## Build Requirements

The FROST CLI requires the `frost` build tag:

```bash
# Build with FROST support
go build -tags frost ./cmd/keychain

# Or using Make
make build WITH_FROST=1
```

## Supported Algorithms

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| `FROST-Ed25519-SHA512` | Default, recommended for general use | High-performance signing |
| `FROST-ristretto255-SHA512` | Enhanced privacy using ristretto255 | Privacy-focused applications |
| `FROST-Ed448-SHAKE256` | Higher security margin | High-security requirements |
| `FROST-P256-SHA256` | NIST P-256 curve | FIPS compliance |
| `FROST-secp256k1-SHA256` | Bitcoin/Ethereum curve | Blockchain applications |

## Command Reference

### frost keygen

Generate FROST key packages using the trusted dealer model.

**Modes:**
- **Dealer Mode** (`--export-dir` set): Generates all participant packages and exports to files
- **Participant Mode** (`--participant-id` set): Generates and stores only one participant's package

**Syntax:**
```bash
keychain frost keygen [flags]
```

**Flags:**
```
-a, --algorithm string        FROST algorithm (default "FROST-Ed25519-SHA512")
-t, --threshold int          Minimum signers required (M) (default 2)
-n, --total int             Total participants (N) (default 3)
-p, --participants string   Comma-separated participant names
    --key-id string         Custom key identifier (auto-generated if not set)
    --participant-id uint32 This participant's ID (1 to total); 0 = dealer mode
    --export-dir string     Export directory for packages (dealer mode)
```

**Examples:**

Generate and export all packages (dealer mode):
```bash
# Simple 2-of-3 threshold with default algorithm
keychain frost keygen \
  --key-id corp-signing-key \
  --threshold 2 \
  --total 3 \
  --export-dir ./packages

# With named participants
keychain frost keygen \
  --key-id multisig-wallet \
  --algorithm FROST-secp256k1-SHA256 \
  --threshold 3 \
  --total 5 \
  --participants "alice,bob,charlie,dave,eve" \
  --export-dir ./wallet-packages
```

Generate and store locally (participant mode):
```bash
# Participant 1 generates their package
keychain frost keygen \
  --key-id corp-signing-key \
  --threshold 2 \
  --total 3 \
  --participant-id 1

# Participant 2 generates their package
keychain frost keygen \
  --key-id corp-signing-key \
  --threshold 2 \
  --total 3 \
  --participant-id 2
```

**Output (Dealer Mode):**
```json
{
  "key_id": "corp-signing-key",
  "algorithm": "FROST-Ed25519-SHA512",
  "threshold": 2,
  "total": 3,
  "group_public_key": "a7f8e9d6...",
  "exported_files": [
    "./packages/participant_1.json",
    "./packages/participant_2.json",
    "./packages/participant_3.json"
  ],
  "mode": "dealer"
}
```

**Output (Participant Mode):**
```json
{
  "key_id": "corp-signing-key",
  "algorithm": "FROST-Ed25519-SHA512",
  "threshold": 2,
  "total": 3,
  "participant_id": 1,
  "group_public_key": "a7f8e9d6...",
  "mode": "participant"
}
```

### frost import

Import a FROST key package from a file received from the trusted dealer.

**Syntax:**
```bash
keychain frost import --package <file>
```

**Flags:**
```
--package string   Path to key package file (required)
```

**Example:**
```bash
# Import participant package
keychain frost import --package ./alice_participant_1.json
```

**Output:**
```json
{
  "key_id": "corp-signing-key",
  "algorithm": "FROST-Ed25519-SHA512",
  "threshold": 2,
  "total": 3,
  "participant_id": 1,
  "participant_name": "alice",
  "group_public_key": "a7f8e9d6...",
  "imported_from": "./alice_participant_1.json"
}
```

### frost list

List all FROST keys managed by this node.

**Syntax:**
```bash
keychain frost list [flags]
```

**Flags:**
```
-f, --format string   Output format (table, json) (default "table")
```

**Examples:**
```bash
# Table format
keychain frost list

# JSON format
keychain frost list --format json
```

**Output (Table):**
```
KEY ID                         ALGORITHM                  THRESHOLD
----------------------------------------------------------------------
corp-signing-key              FROST-Ed25519-SHA512       2/3
multisig-wallet               FROST-secp256k1-SHA256     3/5
```

**Output (JSON):**
```json
[
  {
    "cn": "corp-signing-key",
    "frost_attributes": {
      "algorithm": "FROST-Ed25519-SHA512",
      "threshold": 2,
      "total": 3,
      "participant_id": 1
    }
  }
]
```

### frost info

Display detailed information about a FROST key.

**Syntax:**
```bash
keychain frost info <key-id> [flags]
```

**Flags:**
```
-f, --format string      Output format (table, json) (default "table")
    --show-public-key    Display group public key
```

**Examples:**
```bash
# Basic info
keychain frost info corp-signing-key

# Include public key
keychain frost info corp-signing-key --show-public-key
```

**Output:**
```json
{
  "key_id": "corp-signing-key",
  "algorithm": "FROST-Ed25519-SHA512",
  "participant_id": 1,
  "group_public_key": "a7f8e9d6c5b4a3..."
}
```

### frost delete

Delete a FROST key and all associated data.

**Syntax:**
```bash
keychain frost delete <key-id> [flags]
```

**Flags:**
```
-f, --force   Skip confirmation prompt
```

**Examples:**
```bash
# Delete with confirmation
keychain frost delete old-key

# Force delete without confirmation
keychain frost delete old-key --force
```

**Output:**
```
Successfully deleted key: old-key
```

### frost round1

Generate nonces and commitments for the first round of FROST signing.

Each participating signer must execute this command to create:
- **Commitments** (public, shared with all signers)
- **Nonces** (secret, kept locally)

**Syntax:**
```bash
keychain frost round1 -k <key-id> -o <output-file>
```

**Flags:**
```
-k, --key-id string   Key identifier (required)
-o, --output string   Output file for commitment (required)
```

**Example:**
```bash
# Participant 1 generates commitments
keychain frost round1 \
  --key-id corp-signing-key \
  --output p1-commitment.json
```

**Output:**
```json
{
  "participant_id": 1,
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "commitment_file": "p1-commitment.json",
  "nonce_file": "p1-commitment.json.nonces"
}
```

**Important:**
- The commitment file (`p1-commitment.json`) must be shared with all other signers
- The nonce file (`p1-commitment.json.nonces`) must be kept **secret** and only used once
- Never reuse nonces across signing sessions

### frost round2

Generate a signature share using collected commitments from all participants.

**Syntax:**
```bash
keychain frost round2 [flags]
```

**Flags:**
```
-k, --key-id string           Key identifier (required)
-m, --message string          Message to sign
    --message-file string     File containing message
    --message-hex string      Message as hex string
    --nonces string          This participant's nonce package file (required)
-c, --commitments string     Comma-separated commitment files (required)
-o, --output string          Output file for signature share (required)
```

**Examples:**

Sign a text message:
```bash
keychain frost round2 \
  --key-id corp-signing-key \
  --message "Approve transaction #12345" \
  --nonces p1-commitment.json.nonces \
  --commitments p1-commitment.json,p2-commitment.json \
  --output p1-share.json
```

Sign a file (hashes the file):
```bash
keychain frost round2 \
  --key-id corp-signing-key \
  --message-file ./contract.pdf \
  --nonces p1-commitment.json.nonces \
  --commitments p1-commitment.json,p2-commitment.json \
  --output p1-share.json
```

Sign a hex-encoded hash:
```bash
keychain frost round2 \
  --key-id corp-signing-key \
  --message-hex "a7f8e9d6c5b4a39287f6e5d4c3b2a19078f6e5d4c3b2a19078f6e5d4c3b2a190" \
  --nonces p1-commitment.json.nonces \
  --commitments p1-commitment.json,p2-commitment.json,p3-commitment.json \
  --output p1-share.json
```

**Output:**
```json
{
  "participant_id": 1,
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "share_file": "p1-share.json"
}
```

**Important:**
- All participants must use the **same message**
- All participants must provide the **same set of commitments** in the same order
- The nonces file is consumed and should not be reused

### frost aggregate

Combine signature shares into a final FROST signature.

**Syntax:**
```bash
keychain frost aggregate [flags]
```

**Flags:**
```
-k, --key-id string           Key identifier (required)
-m, --message string          Message that was signed
    --message-file string     File containing message
    --message-hex string      Message as hex string
-c, --commitments string     Comma-separated commitment files (required)
    --shares string          Comma-separated signature share files (required)
-o, --output string          Output file for signature (required)
    --format string          Signature format (raw, hex, base64) (default "raw")
    --verify                 Verify signature after aggregation (default true)
```

**Examples:**

Aggregate a 2-of-3 threshold signature:
```bash
keychain frost aggregate \
  --key-id corp-signing-key \
  --message "Approve transaction #12345" \
  --commitments p1-commitment.json,p2-commitment.json \
  --shares p1-share.json,p2-share.json \
  --output signature.bin \
  --format hex \
  --verify
```

Aggregate from file signing:
```bash
keychain frost aggregate \
  --key-id corp-signing-key \
  --message-file ./contract.pdf \
  --commitments p1-commitment.json,p2-commitment.json,p3-commitment.json \
  --shares p1-share.json,p2-share.json,p3-share.json \
  --output contract.sig \
  --format base64
```

**Output:**
```json
{
  "signature_file": "signature.bin",
  "format": "hex",
  "verified": true,
  "size_bytes": 64
}
```

**Signature Formats:**
- `raw`: Binary signature bytes (default)
- `hex`: Hexadecimal encoded string
- `base64`: Base64 encoded string

### frost verify

Verify a FROST signature against the group public key.

**Syntax:**
```bash
keychain frost verify [flags]
```

**Flags:**
```
-k, --key-id string           Key identifier
-m, --message string          Original message
    --message-file string     File containing message
    --message-hex string      Message as hex string
    --signature string        Signature file
    --signature-hex string    Signature as hex string
```

**Examples:**

Verify signature from file:
```bash
keychain frost verify \
  --key-id corp-signing-key \
  --message "Approve transaction #12345" \
  --signature signature.bin
```

Verify hex-encoded signature:
```bash
keychain frost verify \
  --key-id corp-signing-key \
  --message "Approve transaction #12345" \
  --signature-hex "a7f8e9d6c5b4a39287f6e5d4c3b2a19078f6e5d4c3b2a19078f6e5d4c3b2a190..."
```

Verify file signature:
```bash
keychain frost verify \
  --key-id corp-signing-key \
  --message-file ./contract.pdf \
  --signature contract.sig
```

**Output (Success):**
```json
{
  "status": "PASSED",
  "key_id": "corp-signing-key",
  "message": "Approve transaction #12345"
}
```

**Output (Failure):**
```
Error: signature verification FAILED: invalid signature
```

## Two-Round Signing Protocol

The FROST signing protocol requires coordination between M participants (where M is the threshold):

### Protocol Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│Participant 1│     │Participant 2│     │Participant 3│
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │ ┌─────────────────────────────────────┐
       │ │ ROUND 1: Generate Nonces/Commitments│
       │ └─────────────────────────────────────┘
       │                   │                   │
       ├──► round1         │                   │
       │   outputs:        │                   │
       │   - commitment    ├──► round1         │
       │   - nonces        │   outputs:        │
       │                   │   - commitment    ├──► round1
       │                   │   - nonces        │   outputs:
       │                   │                   │   - commitment
       │                   │                   │   - nonces
       │                   │                   │
       │◄──────────────────┼───────────────────┤
       │    Share commitments (broadcast)      │
       ├───────────────────┼──────────────────►│
       │                   │                   │
       │ ┌─────────────────────────────────────┐
       │ │ ROUND 2: Generate Signature Shares  │
       │ └─────────────────────────────────────┘
       │                   │                   │
       ├──► round2         │                   │
       │   inputs:         │                   │
       │   - message       ├──► round2         │
       │   - nonces        │   inputs:         │
       │   - all commits   │   - message       │
       │   output:         │   - nonces        │
       │   - share         │   - all commits   │
       │                   │   output:         │
       │                   │   - share         │
       │                   │                   │
       │◄──────────────────┼───────────────────┤
       │    Collect M shares (any M of N)      │
       ├───────────────────┼──────────────────►│
       │                   │                   │
       │ ┌─────────────────────────────────────┐
       │ │ AGGREGATION: Combine Shares         │
       │ └─────────────────────────────────────┘
       │                   │                   │
       ├──► aggregate      │                   │
       │   inputs:         │                   │
       │   - M shares      │                   │
       │   - M commits     │                   │
       │   - message       │                   │
       │   output:         │                   │
       │   - signature     │                   │
       │                   │                   │
       ▼                   ▼                   ▼
```

### Step-by-Step Example: 2-of-3 Multisig

This example demonstrates a complete 2-of-3 threshold signing workflow where Alice, Bob, and Charlie hold key shares, and any 2 can sign.

#### Initial Setup (Trusted Dealer)

```bash
# Dealer generates all key packages
keychain frost keygen \
  --key-id company-multisig \
  --threshold 2 \
  --total 3 \
  --participants "alice,bob,charlie" \
  --export-dir ./packages

# Securely distribute packages to each participant
# - alice receives alice_participant_1.json
# - bob receives bob_participant_2.json
# - charlie receives charlie_participant_3.json
```

#### Participant Import

Each participant imports their package:

```bash
# Alice imports her package
keychain frost import --package alice_participant_1.json

# Bob imports his package
keychain frost import --package bob_participant_2.json

# Charlie imports his package
keychain frost import --package charlie_participant_3.json
```

#### Signing Session (Alice and Bob sign)

**Round 1: Generate Commitments**

```bash
# Alice generates commitments
keychain frost round1 \
  --key-id company-multisig \
  --output alice-commitment.json
# Output: alice-commitment.json (share this)
#         alice-commitment.json.nonces (keep secret!)

# Bob generates commitments
keychain frost round1 \
  --key-id company-multisig \
  --output bob-commitment.json
# Output: bob-commitment.json (share this)
#         bob-commitment.json.nonces (keep secret!)
```

Exchange commitment files (share `alice-commitment.json` and `bob-commitment.json` with each other).

**Round 2: Generate Signature Shares**

Both participants must use the identical message and commitment set:

```bash
# Alice generates her signature share
keychain frost round2 \
  --key-id company-multisig \
  --message "Transfer $10,000 to Account XYZ" \
  --nonces alice-commitment.json.nonces \
  --commitments alice-commitment.json,bob-commitment.json \
  --output alice-share.json

# Bob generates his signature share
keychain frost round2 \
  --key-id company-multisig \
  --message "Transfer $10,000 to Account XYZ" \
  --nonces bob-commitment.json.nonces \
  --commitments alice-commitment.json,bob-commitment.json \
  --output bob-share.json
```

Exchange signature shares.

**Aggregation: Create Final Signature**

Any participant (or even a non-participant with the public key) can aggregate:

```bash
keychain frost aggregate \
  --key-id company-multisig \
  --message "Transfer $10,000 to Account XYZ" \
  --commitments alice-commitment.json,bob-commitment.json \
  --shares alice-share.json,bob-share.json \
  --output transaction.sig \
  --format hex \
  --verify
```

**Verification**

Anyone with the group public key can verify:

```bash
keychain frost verify \
  --key-id company-multisig \
  --message "Transfer $10,000 to Account XYZ" \
  --signature transaction.sig
```

## M-of-N Threshold Examples

### 2-of-2: Two-Person Approval

Simple approval requiring both parties:

```bash
# Setup
keychain frost keygen \
  --key-id dual-approval \
  --threshold 2 \
  --total 2 \
  --participants "ceo,cfo" \
  --export-dir ./dual-approval

# Both CEO and CFO must participate in every signature
```

**Use Cases:**
- Critical financial transactions
- Dual-control requirements
- High-security operations

### 2-of-3: Resilient Multisig

Most common configuration, balances security and availability:

```bash
# Setup
keychain frost keygen \
  --key-id board-signing \
  --threshold 2 \
  --total 3 \
  --participants "alice,bob,charlie" \
  --export-dir ./board-keys

# Any 2 of 3 can sign
# - Alice + Bob
# - Alice + Charlie
# - Bob + Charlie
```

**Use Cases:**
- Business continuity (one person unavailable)
- Cryptocurrency wallets
- Code signing with backup signers

### 3-of-5: Corporate Governance

Requires majority approval:

```bash
# Setup
keychain frost keygen \
  --key-id board-approval \
  --threshold 3 \
  --total 5 \
  --participants "ceo,cfo,cto,coo,general-counsel" \
  --export-dir ./board-approval

# Requires 3 of 5 board members
# - Protects against 2 compromised keys
# - Survives 2 unavailable members
```

**Use Cases:**
- Board resolutions
- Major business decisions
- High-value transactions

### 5-of-7: High-Security Vault

Maximum security with resilience:

```bash
# Setup
keychain frost keygen \
  --key-id vault-key \
  --threshold 5 \
  --total 7 \
  --algorithm FROST-Ed448-SHAKE256 \
  --participants "exec1,exec2,exec3,board1,board2,legal,compliance" \
  --export-dir ./vault

# Requires 5 of 7 keyholders
# - Protects against 4 compromised keys
# - Survives 2 unavailable members
```

**Use Cases:**
- Root CA signing keys
- Disaster recovery keys
- Critical infrastructure

### 1-of-N: Shared Identity

Any member can act on behalf of the group:

```bash
# Setup
keychain frost keygen \
  --key-id support-team \
  --threshold 1 \
  --total 5 \
  --participants "support1,support2,support3,support4,support5" \
  --export-dir ./support-keys

# Any single team member can sign
```

**Use Cases:**
- Shared service accounts
- Team email signatures
- Support ticket systems

## Security Considerations

### Nonce Reuse

**CRITICAL:** Never reuse nonces across signing sessions. Reusing nonces can leak your secret key share.

Each `frost round1` execution generates fresh nonces. Always:
- Generate new nonces for each signing session
- Delete nonce files after use
- Never copy or backup nonce files

### Commitment Distribution

Commitments are public and must be broadcast to all participating signers:
- Share commitment files through any channel
- All signers must receive the same set of commitments
- Order of commitments must match across all participants

### Message Consistency

All participants must sign the **identical message**:
- Use `--message-hex` for hash values to avoid encoding issues
- When signing files, all participants must sign the same file hash
- Verify message consistency before round 2

### Key Package Security

Key packages contain secret shares:
- Protect package files like private keys (0600 permissions)
- Transfer packages through secure channels
- Delete dealer copies after distribution
- Never share your participant package with others

### Threshold Selection

Choose appropriate M-of-N ratios:
- **M = N**: All participants required (no resilience)
- **M = N - 1**: One person can be unavailable
- **M = ceil(N/2)**: Majority required (good default)
- **M < N/2**: Less than majority (lower security)

Security properties:
- System tolerates up to **N - M** compromised shares
- System survives up to **N - M** unavailable members
- Requires **M** shares to sign

## Algorithm Selection Guide

### FROST-Ed25519-SHA512 (Recommended)

**Best for:**
- General-purpose signing
- High-performance applications
- Modern systems

**Properties:**
- Fast signing and verification
- Small signatures (64 bytes)
- Widely supported
- Well-studied security

### FROST-ristretto255-SHA512

**Best for:**
- Privacy-focused applications
- Zero-knowledge proofs
- Advanced cryptographic protocols

**Properties:**
- Prime-order group (simpler security proofs)
- Compatible with ristretto255 ecosystem
- Slightly slower than Ed25519

### FROST-Ed448-SHAKE256

**Best for:**
- High-security requirements
- Long-term secrets
- Paranoid security margins

**Properties:**
- 224-bit security level
- Larger signatures (114 bytes)
- Higher computational cost
- Maximum security

### FROST-P256-SHA256

**Best for:**
- FIPS 140-2/3 compliance
- Regulated industries
- Legacy system compatibility

**Properties:**
- NIST-approved curve
- Hardware acceleration support
- FIPS validated implementations available
- Broader industry acceptance

### FROST-secp256k1-SHA256

**Best for:**
- Bitcoin/Ethereum applications
- Blockchain integration
- Cryptocurrency wallets

**Properties:**
- Compatible with Bitcoin/Ethereum
- Widely used in blockchain
- Extensive tooling support

## Troubleshooting

### Error: "package for participant X not found"

**Cause:** Participant ID doesn't match generated packages.

**Solution:** Ensure `--participant-id` is between 1 and `--total`.

### Error: "session ID mismatch"

**Cause:** Mixing nonces/commitments from different round1 sessions.

**Solution:** All files must be from the same round1 session. Regenerate if needed.

### Error: "insufficient shares"

**Cause:** Not enough signature shares for threshold.

**Solution:** Collect at least M shares where M is the threshold value.

### Error: "invalid signature"

**Cause:** Message mismatch, wrong shares, or corrupted data.

**Solution:**
- Verify all participants signed the same message
- Check that commitments and shares are from the same session
- Ensure files are not corrupted

### Error: "nonce file not found"

**Cause:** Nonce file missing or wrong path.

**Solution:**
- Nonce files are created as `<commitment-file>.nonces`
- Check file permissions and path
- Regenerate round1 if file was deleted

## Best Practices

### Development

1. **Test with small thresholds** (2-of-3) during development
2. **Use consistent key IDs** across all participants
3. **Automate commitment/share exchange** for production
4. **Log all signing sessions** with session IDs
5. **Implement timeout logic** for uncompleted signing rounds

### Production

1. **Secure key package distribution** using encrypted channels
2. **Implement access controls** on FROST operations
3. **Audit all signing operations** with participant tracking
4. **Use hardware backends** for participant secret shares
5. **Rotate keys periodically** based on security policy
6. **Test disaster recovery** procedures regularly

### Operational

1. **Document participant responsibilities** clearly
2. **Maintain participant contact information**
3. **Establish communication protocols** for signing sessions
4. **Define escalation procedures** for unavailable participants
5. **Monitor for suspicious signing patterns**
6. **Keep backup copies** of group public keys

## Integration Examples

### Automated Signing Service

```bash
#!/bin/bash
# Automated FROST signing service for participant 1

KEY_ID="service-key"
MESSAGE="$1"
COMMITMENTS_DIR="/var/frost/commitments"
SHARES_DIR="/var/frost/shares"

# Round 1: Generate commitment
keychain frost round1 \
  --key-id "$KEY_ID" \
  --output "$COMMITMENTS_DIR/p1-$SESSION_ID.json"

# Wait for other commitments (implement your coordination logic)
wait_for_commitments "$COMMITMENTS_DIR" 2  # Wait for threshold

# Round 2: Generate share
keychain frost round2 \
  --key-id "$KEY_ID" \
  --message "$MESSAGE" \
  --nonces "$COMMITMENTS_DIR/p1-$SESSION_ID.json.nonces" \
  --commitments "$COMMITMENTS_DIR/p1-$SESSION_ID.json,$COMMITMENTS_DIR/p2-$SESSION_ID.json" \
  --output "$SHARES_DIR/p1-share.json"
```

### Blockchain Wallet

```bash
#!/bin/bash
# FROST-based cryptocurrency wallet signing

WALLET_KEY="btc-multisig-wallet"
TX_HASH="$1"  # Transaction hash to sign

# Generate commitment for this transaction
keychain frost round1 \
  --key-id "$WALLET_KEY" \
  --output "tx-$TX_HASH-commitment.json"

# Broadcast commitment to other wallet holders
broadcast_commitment "tx-$TX_HASH-commitment.json"

# Collect commitments from threshold participants
collect_commitments "$TX_HASH" 3  # 3-of-5 multisig

# Sign transaction hash
keychain frost round2 \
  --key-id "$WALLET_KEY" \
  --message-hex "$TX_HASH" \
  --nonces "tx-$TX_HASH-commitment.json.nonces" \
  --commitments "$(list_commitments $TX_HASH)" \
  --output "tx-$TX_HASH-share.json"

# Broadcast signature share
broadcast_share "tx-$TX_HASH-share.json"
```

### Document Signing Workflow

```bash
#!/bin/bash
# Multi-party document approval system

DOC_FILE="$1"
KEY_ID="board-approval"
THRESHOLD=3
TOTAL=5

# Hash document
DOC_HASH=$(sha256sum "$DOC_FILE" | cut -d' ' -f1)

# Round 1
keychain frost round1 \
  --key-id "$KEY_ID" \
  --output "doc-$DOC_HASH-commitment.json"

# Email commitment to all board members
send_commitments "doc-$DOC_HASH-commitment.json"

# Wait for threshold commitments
wait_for_approval_threshold "$DOC_HASH" "$THRESHOLD"

# Round 2
keychain frost round2 \
  --key-id "$KEY_ID" \
  --message-file "$DOC_FILE" \
  --nonces "doc-$DOC_HASH-commitment.json.nonces" \
  --commitments "$(get_commitments $DOC_HASH)" \
  --output "doc-$DOC_HASH-share.json"

# Submit share for aggregation
submit_share "doc-$DOC_HASH-share.json"

# Coordinator aggregates when threshold reached
if is_coordinator; then
  keychain frost aggregate \
    --key-id "$KEY_ID" \
    --message-file "$DOC_FILE" \
    --commitments "$(get_all_commitments $DOC_HASH)" \
    --shares "$(get_all_shares $DOC_HASH)" \
    --output "$DOC_FILE.sig" \
    --format base64 \
    --verify
fi
```

## See Also

- [FROST Documentation](../../frost/README.md)
- [FROST Security Guide](../../frost/security.md)
- [Key Management](./key.md)
- [Getting Started](../getting-started.md)
