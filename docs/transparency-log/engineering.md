# Transparency Log — Engineering Contract

> **Status: NORMATIVE** · Feature: `transparency-log` · Repo: `go-xkms` · Last verified: 2026-10-30

This page covers the `transparency-log` SPEC row in two packages:

- `pkg/ca/tlog`, the CA's transparency log. It runs over go-qrdb's
  verifiable log (vlog), and the CA key signs its heads.
- `pkg/ca/checkpoint`, the checkpoint and signed-note format that the log's
  heads use.

## Log service (`pkg/ca/tlog`)

```go
type Config struct {
	Name              string // the log's name in its database
	Origin            string // first line of every checkpoint
	AllowExpireBodies bool   // fixed when the log is created
}

func Create(ctx context.Context, client transport.VlogClient, cfg Config, signers *HeadSignerProvider) (*Log, error)
func Open(client transport.VlogClient, cfg Config, verifier *checkpoint.Verifier) (*Log, error)

func (l *Log) AppendCertIssued(ctx context.Context, e CertIssued) (uint64, error)
func (l *Log) AppendImageSigned(ctx context.Context, e ImageSigned) (uint64, error)
func (l *Log) AppendRevoked(ctx context.Context, e Revoked) (uint64, error)
func (l *Log) Entry(ctx context.Context, index uint64) (Entry, []byte, error)
func (l *Log) SignedTreeHead(ctx context.Context) (*TreeHead, error)
func (l *Log) VerifyCheckpoint(note []byte) (*checkpoint.Checkpoint, error)
func (l *Log) InclusionProof(ctx context.Context, index, size uint64) ([][]byte, error)
func (l *Log) ConsistencyProof(ctx context.Context, size1, size2 uint64) ([][]byte, error)
```

All of these are in `pkg/ca/tlog/log.go`: `Config` at `:40`, `TreeHead` at
`:57`, `Create` at `:68`, `Open` at `:93`, `AppendCertIssued` at `:107`,
`Entry` at `:135`, `SignedTreeHead` at `:158`, `VerifyCheckpoint` at `:205`,
`InclusionProof` at `:218` and `ConsistencyProof` at `:228`.

The log, its Merkle tree and its proofs belong to go-qrdb. `Log` encodes the
entries and checks every tree head under the CA key before it answers.

- `Create` checks the CA key first, then creates the go-qrdb log with the
  signing-key type of the CA key. `Open` binds an existing log to a verifier
  from `HeadSignerProvider.Verifier`, and makes no request.
- An append returns the entry's leaf index. The leaf is the entry's
  encoding, hashed as RFC 6962 §2.1 describes, so `InclusionProof` and
  `ConsistencyProof` verify against a checkpoint root with any RFC 6962
  verifier.
- `Entry` returns the decoded entry and its encoded bytes.
- `SignedTreeHead` is idempotent. go-qrdb keeps one checkpoint per tree
  size, so the method returns the latest checkpoint when it covers the
  current head. Otherwise it asks go-qrdb to sign the head. If that fails
  because a concurrent caller signed the same size first, it returns that
  caller's checkpoint.
- Every head is opened under the CA key, and its origin, size and root must
  match the head go-qrdb reported (`treeHead`, `log.go:192`).
- `VerifyCheckpoint` opens a note under the CA key and checks its origin.

### Errors

Every refusal is typed, in `pkg/ca/tlog/errors.go`:

| Error | Meaning |
|-------|---------|
| `ErrNoClient`, `ErrNoVerifier`, `ErrInvalidConfig` | `Open` or `Create` lacks a client, a verifier, a name or an origin |
| `ErrLogRequest` | a go-qrdb request failed; the cause is joined |
| `ErrEntryExpired` | the entry's body was expired; its leaf hash and proofs remain |
| `ErrCheckpointMismatch` | a note fails under the CA key, or names another origin or tree |
| `ErrInvalidEntry` | `Marshal` refused an entry |
| `ErrMalformedEntry`, `ErrUnsupportedVersion`, `ErrUnknownKind` | `Unmarshal` refused bytes |
| `ErrNoKeyProvider`, `ErrCAKeyUnavailable`, `ErrUnsupportedCAKey` | the CA key is missing, not initialized, or neither Ed25519 nor P-256 |
| `ErrKeyTypeMismatch`, `ErrKeyRefMismatch` | go-qrdb asked for another key type or key ref |

### Expiring bodies

When `AllowExpireBodies` is set at creation, an operator who holds go-qrdb's
`vlog:expire` can expire the bodies of old entries. The leaf hashes stay, so
every head and proof still verifies. The service principal does not hold
`vlog:expire`.

## Entry encoding, version 1

`Marshal` (`entry.go:171`) and `Unmarshal` (`entry.go:205`) use one
canonical encoding:

    version (1 byte, = 1) || kind (1 byte) || field...
    field = uint16 big-endian length || bytes

| Kind | Value | Fields, in order |
|------|-------|------------------|
| `KindCertIssued` | 1 | SHA-256 of the certificate DER (32 bytes), serial, profile, tenant |
| `KindImageSigned` | 2 | image digest, envelope digest, signer |
| `KindRevoked` | 3 | serial, reason (1 byte) |

Value 4 is reserved for external entries. The rules:

- A serial is its minimal big-endian magnitude, and it must be positive.
- Strings must be non-empty UTF-8.
- A reason is an RFC 5280 §5.3.1 CRLReason: at most 10, and never 7.
- A field holds at most 65535 bytes.

`Unmarshal` refuses trailing bytes, a missing field, a serial with a leading
zero, and any other non-canonical form, so each entry has exactly one
encoding.

## Head signer

`HeadSignerProvider` (`headsigner.go:42`) is go-qrdb's head-signer seam over
the CA key, installed with `WithHeadSignerProvider`. It is built with
`NewHeadSignerProvider(keys, keyName)` (`:52`).

- `CreateKey` (`:81`) returns the CA key as the log's key. Its ref is the
  hex SHA-256 of the key's DER SPKI. A request for another signature type
  fails with `ErrKeyTypeMismatch`.
- `HeadSigner` (`:98`) refuses any other ref with `ErrKeyRefMismatch`. The
  signer's key hash is go-qrdb's `HeadKeyHash`, which is the signed-note key
  ID. `Sign` (`:170`) signs the checkpoint body through `checkpoint.Sign`,
  verifies the result, and returns the signature without its 4-byte key ID,
  because go-qrdb writes that ID into the signature line itself.
- `Verifier` (`:69`) returns the CA key's checkpoint verifier.
- Only Ed25519 (signed-note type `0x01`) and ECDSA P-256 (type `0x02`) CA
  keys are supported. Any other key fails with `ErrUnsupportedCAKey`.

## CA wiring

The CA appends to the log through `ca.TransparencyLog`
(`pkg/ca/transparency_log.go`), an interface holding `AppendCertIssued`
and `AppendRevoked`. `*tlog.Log` satisfies it. `pkg/ca/tlog` does not import
`pkg/ca`, so the interface names tlog's entry types and no cycle forms.

- `(*CA).SetTransparencyLog` sets the log; `nil` removes it. It is a setter,
  not a `Params` field, because the log's heads are signed with the CA's own
  key, so the CA exists before the log can be opened. The CA holds the log in
  an `atomic.Pointer`, never a global.
- With no log set, issuance and revocation behave exactly as before.
- The context the CA is called with is the context of the append, so it
  must carry a principal holding `vlog:append`.

### cert-issued: fail closed

Every issued certificate is appended once, after signing and before it is
stored or returned. There are three issuance funnels, and each appends:

| Funnel | Hook | Verbs |
|---|---|---|
| `issueSignedSpec` | `pkg/ca/ca.go:2127` | `IssueCertificate`, `IssueCertificateWithProfile`, `IssueCertificateForKey`, `IssueCertificateRaw`, `SignCSR` and every CSR-signing verb |
| `issueTCGCertificate` | `pkg/ca/tcg.go:621` | EK, AK, IAK, IDevID and LAK issuance, including `IssueEKCertificateRaw` |
| `IssueSubordinateCA` | `pkg/ca/subordinate.go:228` | subordinate CAs |

The entry carries the certificate's SHA-256, serial, profile name and
tenant. A certificate issued in the system scope (no tenant) is logged under
go-qrdb's `SystemTenantID`. A precertificate (RFC 6962 §3.1) is not
appended; its final certificate is.

If the append fails, the call returns `ErrTransparencyLogAppend` wrapping the
cause, and the certificate is neither stored nor returned.

The CA's own root and intermediate certificates, created by `Init`, are not
appended: they exist before the log does.

### revoked: never undone

`Revoke` and `RevokeCert` share `recordRevocation`, which appends one
`revoked` entry after the revocation is recorded
(`pkg/ca/ca_extensions.go:804`). An already-revoked serial appends nothing.

If the append fails, the revocation stands, and the call returns
`ErrTransparencyLogEntryMissing` wrapping the cause. `RevokeCert` still runs
its key and certificate cleanup and joins that error with the cleanup's. A
reason outside 0–255 cannot be encoded and is reported the same way.

## Service-principal grant

The embedded node's service principal gets only the vlog actions the log
calls: `vlog:create`, `vlog:append`, `vlog:get`, `vlog:head`,
`vlog:sign_head` and `vlog:proof`. The grant is the `grant` list in
`pkg/embeddednode/serviceprincipal/serviceprincipal.go:63`. The log never
lists logs or expires bodies, so `vlog:list` and `vlog:expire` are not
granted.

## Build tag

go-qrdb serves verifiable logs only when it is built with its `qrdb_vlog`
tag. Without the tag, every vlog request to an embedded node fails. The
node-backed tests in `pkg/ca/tlog` (`node_test.go`, `log_test.go`) and
`pkg/ca/transparency_log_test.go` carry the tag.

The Makefile's `TEST_TAGS` and `SERVER_BUILD_TAGS` include `qrdb_vlog`, so
`make test`, the vet and lint gates (which use `TEST_TAGS`) and xkmsd's
embedded node all build with it. `coverage-ca` adds it to `BUILD_TAGS`.

Specifications, both pinned at C2SP commit `e5746a0b`:
[c2sp-tlog-checkpoint.md](../references/c2sp-tlog-checkpoint.md) and
[c2sp-signed-note.md](../references/c2sp-signed-note.md).

## Checkpoint format (`pkg/ca/checkpoint`)

`sdk/go/checkpoint` re-exports every name below unchanged, with type aliases
and `var` assignments, so `errors.Is` matches across the boundary.

```go
type Checkpoint struct {
	Origin     string
	Size       uint64
	Hash       []byte   // HashSize (32) bytes, RFC 6962 SHA-256 root
	Extensions []string // optional, each non-empty
}

func (c *Checkpoint) Marshal() ([]byte, error)
func ParseCheckpoint(text []byte) (*Checkpoint, error)
func SignCheckpoint(c *Checkpoint, signers ...*Signer) ([]byte, error)
func OpenCheckpoint(note []byte, verifiers ...*Verifier) (*Checkpoint, *Note, error)

func NewSigner(name string, signer crypto.Signer, opts ...SignerOption) (*Signer, error)
func WithAlgorithm(id string) SignerOption
func (s *Signer) VerifierKey() string
func (s *Signer) Verifier() *Verifier
func NewVerifier(vkey string) (*Verifier, error)

func Sign(text []byte, signers ...*Signer) ([]byte, error)
func Open(note []byte, verifiers ...*Verifier) (*Note, error)

func Register(alg Algorithm) error
```

`Checkpoint` is at `pkg/ca/checkpoint/checkpoint.go:28`, `Marshal` at `:46`,
`ParseCheckpoint` at `:69`, `SignCheckpoint` at `:117` and `OpenCheckpoint` at
`:128`. `NewSigner` is at `signer.go:62`, `WithAlgorithm` at `:49`,
`VerifierKey` at `:107` and `NewVerifier` at `:143`. `Sign` is at
`note.go:72` and `Open` at `:112`. `Algorithm` is at `algorithm.go:57` and
`Register` at `:169`.

## Checkpoint body

tlog-checkpoint §Note text. `ParseCheckpoint` (`checkpoint.go:69`) is strict:

- the text must be valid note text that ends in a newline;
- it must have at least three lines, and none may be empty;
- the tree size is ASCII decimal with no sign and no leading zero ("0" is
  allowed), and it must fit in 64 bits (`parseTreeSize`);
- the root hash is canonical padded standard base64 of exactly 32 bytes;
- any further lines are returned as `Extensions`.

`Marshal` refuses a root hash that is not 32 bytes, an empty line, a line
containing a newline, and a control character. Refusals are typed:
`ErrMalformedCheckpoint`, `ErrInvalidTreeSize` and `ErrInvalidRootHash`.

## Signed note

The format follows signed-note §Format and §Signatures.

`Sign` (`note.go:72`):

- refuses text that is empty, does not end in a newline, is not UTF-8, or
  holds a control character other than newline (`ErrInvalidText`);
- refuses two signers that share a name and a key ID (`ErrDuplicateSignature`);
- writes one `— <name> base64(keyID || sig)` line per signer.

`Open` (`note.go:112`) splits the note at its last blank line (`parseNote`,
`:167`). Every following line must be a signature line:

- the line starts with an em dash and a space;
- the key name is valid;
- the signature is canonical base64 of at least five bytes.

`Open` accepts at most `MaxSignatures` (100) signature lines; the spec
requires at least 16. It also refuses:

- a duplicated (name, key ID) pair: `ErrDuplicateSignature`, per
  tlog-checkpoint §Signatures;
- two verifiers for the same (name, key ID): `ErrDuplicateVerifier`;
- a signature from a known key that fails to verify: `ErrSignatureInvalid`;
- a note with no verified signature: `ErrNoValidSignature`.

Signatures from unknown keys are not errors. `Open` returns them in
`Note.Unverified`, so a cosigner can carry them forward.

`Signer.sign` (`signer.go:116`) verifies each signature it produces. A
`crypto.Signer` that signs with a scheme other than the selected algorithm's
fails with `ErrSigningFailed` and never yields a bad note.

### Verifier keys

signed-note §Verifier keys: `<name>+<hex(key ID)>+<base64(type || public key)>`.
`NewVerifier` (`signer.go:143`) refuses:

- a key ID that is not exactly eight lowercase hex digits;
- non-canonical base64;
- an unregistered type byte or extended identifier;
- a key ID that does not match the one derived from the name and key
  (`ErrKeyIDMismatch`).

The known-answer test is the specification's own example vkey and note
(`note_test.go:30`).

## Algorithms

The algorithm registry is the copy-on-write snapshot `algorithms`
(`algorithm.go:136`), held in an `atomic.Pointer`:

- lookups take no lock;
- `Register` publishes a new snapshot with a compare-and-swap loop;
- dispatch is by map, keyed both by ID and by type byte.

`NewSigner` takes the algorithm from the key's `Public()`
(`selectAlgorithm`, `algorithm.go:258`):

1. The algorithm named by `WithAlgorithm`, if given.
2. Otherwise, the registered algorithm with an assigned type byte that
   accepts the key.
3. Otherwise, the one extended algorithm that accepts it.
4. Otherwise, `ErrUnsupportedKey`, or `ErrAmbiguousAlgorithm` listing the
   candidates.

There is no default algorithm. An RSA key always needs `WithAlgorithm`: six
RSA algorithms accept it.

### Type bytes and the 0xff encoding

These assignments follow signed-note §Signature types.

| ID | Type | Key material | Signed message |
|----|------|--------------|----------------|
| `ed25519` | `0x01` | 32-byte RFC 8032 key | note text |
| `ecdsa` | `0x02` | DER SPKI, P-256/P-384/P-521 | SHA-256(text), ASN.1 signature |
| `go-xkms/ecdsa-p224-sha256` | `0xff` | DER SPKI, P-224 | SHA-256(text) |
| `go-xkms/ecdsa-p384-sha384` | `0xff` | DER SPKI, P-384 | SHA-384(text) |
| `go-xkms/ecdsa-p521-sha512` | `0xff` | DER SPKI, P-521 | SHA-512(text) |
| `go-xkms/rsa-pkcs1-sha{256,384,512}` | `0xff` | DER SPKI, ≥ 2048 bits | PKCS#1 v1.5 over the digest |
| `go-xkms/rsa-pss-sha{256,384,512}` | `0xff` | DER SPKI, ≥ 2048 bits | PSS, salt = digest length |
| `go-xkms/ml-dsa-{44,65,87}` | `0xff` | FIPS 204 public key | note text, empty context |

An extended (`0xff`) algorithm is encoded in the verifier key and in the key
ID hash as:

    0xff || uint8(len(ID)) || ID || public key

`Algorithm.keyType` is at `algorithm.go:95`. The key ID is
SHA-256(name || 0x0A || type || public key)[:4], where type is that whole
prefix (`recommendedKeyID`, `algorithm.go:119`). Two extended algorithms
therefore never share a key ID for the same name and key.

Type `0x02` uses SHA-256(SPKI)[:4], as signed-note requires (`spkiKeyID`,
`builtin.go:138`).

Pure ML-DSA is not type `0x06`. signed-note assigns that byte to the
timestamped ML-DSA-44 checkpoint cosignature of c2sp.org/tlog-cosignature,
which signs a different message.

`NewSigner` accepts a `*mldsa.PublicKey`, or any key with a
`MLDSA() (*mldsa.PublicKey, error)` method. The software key provider's
`MLDSAPublicKey` has that method (`pkg/keyprovider/quantum/signer.go:51`).

### Registering an algorithm

`Register` (`algorithm.go:169`) takes an `Algorithm`:

- `ID`: 1–255 printable ASCII bytes with no spaces, namespaced
  (`example.com/my-alg`);
- `Type`: `TypeExtended`, or an assigned byte that no algorithm holds yet;
- `SignerOpts`, `EncodePublicKey`, `DecodePublicKey` and `Verify`.

It refuses:

- an incomplete definition: `ErrInvalidAlgorithm`;
- the bytes `0x03`, `0xfa`–`0xfe`, or any byte not assigned:
  `ErrReservedType`;
- an ID or type byte that is already registered: `ErrDuplicateAlgorithm`.

A registered algorithm applies to every `NewSigner` and `NewVerifier` call
made after `Register` returns.

## Tests

`make test-ca` covers `pkg/ca/checkpoint`, with 99.7% statement coverage.
The tests check:

- a sign/open round trip and a tampered body for every built-in;
- the spec's known-answer vector;
- unknown keys, wrong keys and malformed notes;
- malformed verifier keys and malformed checkpoints;
- registry refusals, a concurrent `Register` under `-race`, and a custom
  Ed25519ph algorithm round trip.

`pkg/ca/tlog` has 95.2% statement coverage with the `qrdb_vlog` tag. Its
node-backed tests run each entry kind against an in-memory go-qrdb node with
the production service-principal grant. They check:

- the append, the read-back, and the inclusion and consistency proofs;
- checkpoint verification under Ed25519 and P-256 CA keys;
- repeated and concurrent `SignedTreeHead` calls;
- a checkpoint for another origin;
- failed requests;
- `ErrEntryExpired` on an expired body whose proof still verifies.

`pkg/ca/transparency_log_test.go` runs a real CA against a log on an
in-memory node, its heads signed with the CA key. It checks:

- each issuance funnel appends exactly one `cert-issued` entry whose
  inclusion proof verifies;
- `Revoke` and `RevokeCert` each append one `revoked` entry, and an
  already-revoked serial appends none;
- with no log set, nothing is appended;
- against a log the node never created, issuance fails with no certificate
  stored, and a revocation stands with `ErrTransparencyLogEntryMissing`.

The tests without the tag cover the entry encoding and its refusals, and the
head signer: its key hash equals `HeadKeyHash`, its signature verifies as the
signature line go-qrdb renders, and it refuses keys and refs it does not hold.
