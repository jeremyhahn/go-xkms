# Boulder CA Comparison: Enhancement Opportunities for go-xkms

## Executive Summary

This document compares go-xkms against Boulder (Let's Encrypt's production CA) to identify security and performance enhancements. Boulder processes 2M+ certificates daily and represents production-grade CA engineering.

**Priority Legend:**
- **P0 (Critical)**: Security-critical, should be implemented ASAP
- **P1 (High)**: Important for production readiness
- **P2 (Medium)**: Nice to have for enterprise deployments
- **P3 (Low)**: Future enhancements

---

## Security Enhancements

### P0-1: Key Validation Framework (goodkey)

**Boulder Implementation:** `github.com/letsencrypt/boulder/goodkey/good_key.go`

**Current State:** go-xkms performs basic key validation but lacks comprehensive checks.

**Missing Features:**

| Feature | Boulder | go-xkms | Risk |
|---------|---------|---------------|------|
| Fermat Factorization Detection | ✅ 110 rounds | ❌ Missing | High - weak RSA keys |
| ROCA Vulnerability Check (CVE-2017-15361) | ✅ rocacheck | ❌ Missing | Critical - Infineon HSM keys |
| Small Prime Divisibility | ✅ 152 primes (2-751) | ❌ Missing | Medium - weak keys |
| NIST SP800-56A ECDSA Validation | ✅ All 4 steps | ❌ Partial | High - invalid EC points |
| Configurable Allowed Key Sizes | ✅ Per-profile | ❌ Hardcoded | Low |

**Implementation Plan:**

```go
// pkg/ca/goodkey/goodkey.go

type KeyPolicy struct {
    AllowedRSASizes   []int  // e.g., 2048, 3072, 4096
    AllowedECDSACurves []string // e.g., P-256, P-384, P-521
    FermatRounds      int    // Default: 110 (CABF minimum: 100)
    CheckBlockedKeys  bool
}

// Validation checks:
// 1. RSA exponent must be 65537
// 2. RSA modulus divisible by small primes → reject
// 3. RSA Fermat factorization check
// 4. RSA ROCA vulnerability check
// 5. ECDSA point not at infinity
// 6. ECDSA point coordinates in valid range
// 7. ECDSA point on curve
// 8. ECDSA n*Q = infinity (cofactor check)
```

**Reference:** Boulder's `goodkey/good_key.go:138-425`

---

### P0-2: Certificate Linting Integration (zlint)

**Boulder Implementation:** `github.com/letsencrypt/boulder/issuance/cert.go:290-373`

**Current State:** go-xkms does not lint certificates before signing.

**Why Critical:** Zlint catches Baseline Requirements violations, encoding errors, and policy violations BEFORE signing. Without linting, invalid certificates can be issued.

**Implementation Plan:**

```go
// pkg/ca/linter/linter.go

import "github.com/zmap/zlint/v3/lint"

type CertLinter struct {
    registry   lint.Registry
    ignoreLints []string  // Per-profile ignored lint rules
}

// Lint certificate template before signing
func (l *CertLinter) LintCertificate(cert *x509.Certificate) (*LintResult, error)

// Lint TBS certificate bytes
func (l *CertLinter) LintTBS(tbsBytes []byte) (*LintResult, error)
```

**Integration Points:**
1. Before precert signing: Lint precert template
2. Before final cert signing: Lint final cert with SCTs
3. Profile-based lint rule configuration

**Reference:** Boulder's `issuance/cert.go:357-361`

---

### P0-3: TBS Determinism Verification

**Boulder Implementation:** `github.com/letsencrypt/boulder/ca/ca.go:533-588`

**Current State:** go-xkms does not verify TBS determinism.

**Why Critical:** This detects bugs in signing code, HSM firmware issues, or encoding problems that could lead to misissuance. If the TBS bytes differ between lint cert and actual cert, something went wrong.

**Implementation Plan:**

```go
// pkg/ca/verification.go

// VerifyTBSDeterminism compares TBS bytes between two certificates
// Returns error if they differ (indicates misissuance risk)
func VerifyTBSDeterminism(lintCertDER, actualCertDER []byte) error {
    lintTBS, err := extractTBSBytes(lintCertDER)
    if err != nil {
        return fmt.Errorf("extract lint TBS: %w", err)
    }

    actualTBS, err := extractTBSBytes(actualCertDER)
    if err != nil {
        return fmt.Errorf("extract actual TBS: %w", err)
    }

    if !bytes.Equal(lintTBS, actualTBS) {
        return ErrTBSDeterminismFailure
    }
    return nil
}
```

**Integration:** Call after every signing operation, comparing lint cert to final cert.

---

### P0-4: Private Key Verification (Anti-Key-Smuggling)

**Boulder Implementation:** `github.com/letsencrypt/boulder/privatekey/privatekey.go:17-81`

**Current State:** the ACME CA relies on the xkms key backends but doesn't verify private keys.

**Why Critical:** Attackers can create private keys with mismatched embedded public keys (key smuggling attack). This tricks CAs into signing certificates for keys the attacker doesn't control.

**Reference:** https://blog.hboeck.de/archives/888-How-I-tricked-Symantec-with-a-Fake-Private-Key.html

**Implementation Plan:**

```go
// pkg/ca/keyverify/verify.go

// VerifyPrivateKey ensures the private key is valid and matches its embedded public key
func VerifyPrivateKey(signer crypto.Signer) (crypto.PublicKey, error) {
    // 1. Generate random 32-byte nonce
    nonce := make([]byte, 32)
    rand.Read(nonce)

    // 2. Hash the nonce
    hash := sha256.Sum256(nonce)

    // 3. Sign with private key
    sig, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)

    // 4. Verify signature with embedded public key
    // For RSA: rsa.VerifyPSS(pubKey, crypto.SHA256, hash[:], sig, &opts)
    // For ECDSA: ecdsa.VerifyASN1(pubKey, hash[:], sig)

    // 5. Return public key only if verification passes
}
```

---

### P1-1: Multi-Tier Domain Blocklisting

**Boulder Implementation:** `github.com/letsencrypt/boulder/policy/pa.go:32-154`

**Current State:** go-xkms may have basic domain validation but lacks comprehensive blocklisting.

**Missing Features:**
- Exact FQDN blocklist
- Wildcard blocklist cascade (blocking `example.com` auto-blocks `*.example.com`)
- IP prefix blocklist
- Label-wise suffix matching
- High-risk domain list
- Dynamic reloading with SHA256 checksum logging

**Implementation Plan:**

```go
// pkg/policy/blocklist.go

type Blocklist struct {
    mu                    sync.RWMutex
    domainBlocklist       map[string]bool     // Label-wise matching
    fqdnBlocklist         map[string]bool     // Exact match
    wildcardFqdnBlocklist map[string]bool     // Wildcard patterns
    ipPrefixBlocklist     []netip.Prefix      // CIDR ranges
}

// LoadFromFile loads blocklist with SHA256 audit logging
func (b *Blocklist) LoadFromFile(path string) error

// IsDomainBlocked checks all blocklist levels
func (b *Blocklist) IsDomainBlocked(domain string) (bool, string)

// IsIPBlocked checks IP against prefix blocklist
func (b *Blocklist) IsIPBlocked(ip netip.Addr) (bool, string)
```

---

### P1-2: Certificate Transparency Multi-Operator Policy

**Boulder Implementation:** `github.com/letsencrypt/boulder/ctpolicy/ctpolicy.go:105-213`

**Current State:** go-xkms likely has basic CT submission but lacks policy enforcement.

**Missing Features:**
- Multi-operator SCT requirement (≥2 operators)
- At least one RFC6962-compliant (non-tiled) log
- Temporal sharding awareness
- Staggered submission (prevents thundering herd)
- Context cancellation when sufficient SCTs obtained

**Implementation Plan:**

```go
// pkg/ct/policy.go

type CTPolicy struct {
    logs           []LogGroup
    minSCTs        int  // Usually 2
    minOperators   int  // Usually 2
    staggerDelay   time.Duration
}

// GetSCTs fetches SCTs from CT logs with policy enforcement
func (p *CTPolicy) GetSCTs(ctx context.Context, precert []byte, expiry time.Time) ([]SCT, error) {
    // 1. Filter logs valid at expiry time
    // 2. Submit to first N logs immediately
    // 3. Submit to remaining logs with stagger delay
    // 4. Cancel remaining submissions when policy satisfied
    // 5. Verify operator diversity
}
```

---

## Performance Enhancements

### P1-3: GCRA Token Bucket Rate Limiting

**Boulder Implementation:** `github.com/letsencrypt/boulder/ratelimits/gcra.go:9-107`

**Current State:** go-xkms uses simple token bucket in `pkg/acme/server/rate_limiter.go`.

**Why Better:** GCRA stores only a single timestamp per bucket (vs. token count), enabling:
- O(1) space per bucket
- Precise rate control
- No overflow from past time

**Implementation Plan:**

```go
// pkg/ratelimits/gcra.go

// TAT = Theoretical Arrival Time
type GCRA struct {
    emission time.Duration  // Time per token
    burst    time.Duration  // Maximum burst window
}

// Allow checks if request is allowed, returning new TAT
func (g *GCRA) Allow(now, tat time.Time, cost time.Duration) (newTAT time.Time, allowed bool) {
    // TAT = max(TAT, now) + cost
    // Allowed if TAT - now <= burst
}
```

---

### P1-4: Redis-Based Distributed Rate Limiting

**Boulder Implementation:** `github.com/letsencrypt/boulder/ratelimits/source_redis.go`

**Current State:** go-xkms uses in-memory rate limiting (single node only).

**Missing Features:**
- Redis Ring with consistent hashing
- Batch operations (pipeline multiple commands)
- Dynamic shard discovery via SRV DNS
- Per-subscriber overrides from database

**Implementation Plan:**

```go
// pkg/ratelimits/redis.go

type RedisLimiter struct {
    ring        *redis.Ring
    gcra        *GCRA
    overrides   *OverrideCache
}

// BatchSpend checks multiple limits in single Redis pipeline
func (r *RedisLimiter) BatchSpend(ctx context.Context, txns []Transaction) ([]Decision, error) {
    pipeline := r.ring.Pipeline()
    // Batch all IncrBy/Expire commands
    // Single round-trip to Redis
}
```

---

### P1-5: Nonce Encryption for Stateless Generation

**Boulder Implementation:** `github.com/letsencrypt/boulder/nonce/nonce.go:184-208`

**Current State:** go-xkms likely stores nonces in database/memory.

**Why Better:** Encrypted counter nonces require:
- Zero database lookups for generation
- No storage of generated nonces
- Cross-off list only for redemption tracking

**Implementation Plan:**

```go
// pkg/nonce/encrypted.go

type EncryptedNonceService struct {
    key     []byte           // AES-GCM key
    counter atomic.Uint64
    used    map[uint64]bool  // Cross-off list
    maxUsed int              // Auto-retire threshold
}

// Generate creates nonce by encrypting counter
func (s *EncryptedNonceService) Generate() (string, error) {
    counter := s.counter.Add(1)
    encrypted := aesGCMEncrypt(s.key, counterToBytes(counter))
    return base64URL(encrypted), nil
}
```

---

### P2-1: Retry-After Jitter

**Boulder Implementation:** `github.com/letsencrypt/boulder/ratelimits/limiter.go:100-102`

**Current State:** go-xkms likely returns exact Retry-After values.

**Why Important:** Without jitter, all rate-limited clients retry at exactly the same time (thundering herd).

**Implementation:**

```go
// Add 0-3% jitter to Retry-After
func jitteredRetryAfter(d time.Duration) time.Duration {
    jitter := time.Duration(rand.Float64() * 0.03 * float64(d))
    return d + jitter
}
```

---

### P2-2: gRPC Deadline Management

**Boulder Implementation:** `github.com/letsencrypt/boulder/grpc/interceptors.go:99-122`

**Current State:** go-xkms may not subtract return overhead from deadlines.

**Why Important:** Without this, sub-RPCs don't have time for error reporting.

**Implementation:**

```go
// Interceptor that subtracts return overhead (20ms) from deadline
func DeadlineInterceptor(returnOverhead time.Duration) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        deadline, ok := ctx.Deadline()
        if ok {
            remaining := time.Until(deadline) - returnOverhead
            if remaining < 100*time.Millisecond {
                return nil, status.Error(codes.DeadlineExceeded, "insufficient time")
            }
            ctx, cancel := context.WithTimeout(ctx, remaining)
            defer cancel()
        }
        return handler(ctx, req)
    }
}
```

---

## Architecture Enhancements

### P1-6: Two-Phase Issuance with Precert

**Boulder Implementation:** `github.com/letsencrypt/boulder/ca/ca.go:314-456`

**Current State:** go-xkms may sign certificates directly.

**Why Important:** Two-phase issuance enables:
1. Lint validation before committing to sign
2. SCT embedding in final certificate
3. Audit trail of signing intent
4. Serial persistence BEFORE signing (prevents duplicates on retry)

**Implementation Flow:**

```
1. Validate CSR
2. Generate serial
3. Persist serial to DB (BEFORE signing!)
4. Prepare linting precert
5. Run zlint → reject if fails
6. Persist precert intent (audit)
7. Sign precert
8. Verify TBS determinism
9. Submit to CT logs, get SCTs
10. Prepare final cert with SCTs
11. Sign final cert
12. Verify TBS determinism
13. Persist final cert
```

---

### P1-7: Typed Error System for gRPC Boundaries

**Boulder Implementation:** `github.com/letsencrypt/boulder/errors/errors.go:33-159`

**Current State:** go-xkms uses standard errors that may lose type information across gRPC.

**Why Important:** Typed errors enable:
- Semantic error handling across services
- Proper ACME Problem Document mapping
- RetryAfter metadata preservation

**Implementation:**

```go
// pkg/errors/boulder.go

type ErrorType int

const (
    InternalServer ErrorType = iota
    Malformed
    Unauthorized
    NotFound
    RateLimit
    // ... 20+ types
)

type TrustedCAError struct {
    Type       ErrorType
    Detail     string
    SubErrors  []SubError
    RetryAfter time.Duration
}

// GRPCStatus maps to gRPC status codes
func (e *TrustedCAError) GRPCStatus() *status.Status

// ACMEProblem converts to RFC 8555 Problem Document
func (e *TrustedCAError) ACMEProblem() *acme.Problem
```

---

### P2-3: Audit Log Checksums

**Boulder Implementation:** `github.com/letsencrypt/boulder/log/log.go:163-220`

**Current State:** go-xkms has structured audit logging but may lack integrity verification.

**Why Important:** CRC32 checksums detect log corruption/tampering.

**Implementation:**

```go
// pkg/audit/checksum.go

func LogLineChecksum(line string) string {
    crc := crc32.ChecksumIEEE([]byte(line))
    buf := make([]byte, 4)
    binary.LittleEndian.PutUint32(buf, crc)
    return base64.RawURLEncoding.EncodeToString(buf)
}

// Prepend checksum to every audit log line
func (l *Logger) formatWithChecksum(msg string) string {
    checksum := LogLineChecksum(msg)
    return fmt.Sprintf("%s %s", checksum, msg)
}
```

---

### P2-4: Multi-Perspective Domain Validation

**Boulder Implementation:** `github.com/letsencrypt/boulder/va/va.go:84-289`

**Current State:** go-xkms validates from single perspective.

**Why Important:** CABF BRs Section 3.2.2.9 requires multi-perspective validation:
- 2-5 perspectives: max 1 failure allowed
- 6+ perspectives: max 2 failures allowed

**Implementation:**

```go
// pkg/va/multi_perspective.go

type MultiPerspectiveVA struct {
    remoteVAs         []RemoteVA
    maxAllowedFailures int
}

func (m *MultiPerspectiveVA) Validate(ctx context.Context, challenge Challenge) error {
    // Fan out to all perspectives
    // Collect results with quorum checking
    // Return error if too many failures
}

func maxAllowedFailures(perspectiveCount int) int {
    if perspectiveCount < 2 { return 0 }
    if perspectiveCount < 6 { return 1 }
    return 2
}
```

---

### P2-5: Sharded CRL Generation

**Boulder Implementation:** `github.com/letsencrypt/boulder/crl/updater/updater.go`

**Current State:** go-xkms may generate monolithic CRLs.

**Why Important:** Sharded CRLs enable:
- Parallel generation per shard
- Smaller CRL files for faster distribution
- Deterministic shard assignment by serial

**Implementation:**

```go
// pkg/crl/sharded.go

type ShardedCRLUpdater struct {
    numShards      int
    shardWidth     time.Duration
    maxParallelism int
}

// UpdateShard generates CRL for specific shard
func (u *ShardedCRLUpdater) UpdateShard(ctx context.Context, issuer, shardIdx int) error {
    // 1. Lease shard (prevent concurrent updates)
    // 2. Query revoked certs for shard
    // 3. Generate and sign CRL
    // 4. Upload to distribution points
}

// Serial to shard mapping
func serialToShard(serial *big.Int, numShards int) int {
    return int(new(big.Int).Mod(serial, big.NewInt(int64(numShards))).Int64())
}
```

---

## Implementation Priority Matrix

| Enhancement | Priority | Effort | Impact |
|-------------|----------|--------|--------|
| Key Validation (goodkey) | P0 | High | Critical security |
| Certificate Linting (zlint) | P0 | Medium | Critical security |
| TBS Determinism Verification | P0 | Low | Critical security |
| Private Key Verification | P0 | Low | Critical security |
| Multi-Tier Blocklisting | P1 | Medium | High security |
| CT Multi-Operator Policy | P1 | High | Compliance |
| GCRA Rate Limiting | P1 | Medium | Performance |
| Redis Distributed Rate Limiting | P1 | High | Scalability |
| Encrypted Nonce Service | P1 | Medium | Performance |
| Two-Phase Issuance | P1 | High | Security/Audit |
| Typed Error System | P1 | Medium | Reliability |
| Retry-After Jitter | P2 | Low | Performance |
| gRPC Deadline Management | P2 | Low | Reliability |
| Audit Log Checksums | P2 | Low | Compliance |
| Multi-Perspective Validation | P2 | High | Compliance |
| Sharded CRL Generation | P2 | High | Scalability |

---

## Recommended Implementation Order

### Phase 1: Critical Security (Weeks 1-2)
1. **Key Validation Framework** - Prevent weak/compromised keys
2. **Private Key Verification** - Prevent key smuggling
3. **TBS Determinism Verification** - Detect misissuance

### Phase 2: Certificate Quality (Weeks 3-4)
4. **Zlint Integration** - Baseline Requirements compliance
5. **Two-Phase Issuance** - Audit trail and SCT embedding
6. **Multi-Tier Blocklisting** - Policy enforcement

### Phase 3: Performance & Scalability (Weeks 5-6)
7. **GCRA Rate Limiting** - Efficient rate control
8. **Redis Distributed Rate Limiting** - Horizontal scaling
9. **Encrypted Nonce Service** - Stateless nonce generation

### Phase 4: Compliance & Operations (Weeks 7-8)
10. **CT Multi-Operator Policy** - Chrome CT requirements
11. **Typed Error System** - Service boundary reliability
12. **Audit Log Checksums** - Log integrity

### Phase 5: Advanced Features (Future)
13. **Multi-Perspective Validation** - CABF BR compliance
14. **Sharded CRL Generation** - CRL scalability
15. **gRPC Deadline Management** - Service reliability

---

## References

- Boulder Source: `github.com/letsencrypt/boulder/`
- CABF Baseline Requirements: https://cabforum.org/baseline-requirements/
- RFC 8555 (ACME): https://tools.ietf.org/html/rfc8555
- NIST SP800-56A: https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final
- Zlint: https://github.com/zmap/zlint
- ROCA Vulnerability: https://crocs.fi.muni.cz/public/papers/rsa_ccs17
