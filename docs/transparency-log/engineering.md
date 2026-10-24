# Transparency Log — Engineering Contract

> **Status: NORMATIVE** · Feature: `transparency-log` · Repo: `go-xkms` · Last verified: 2026-10-24

This page covers the checkpoint format of the `transparency-log` SPEC row
(owner ruling 122): `pkg/ca/checkpoint`. The log itself, the append verbs and
the `HeadSignerProvider` wait on go-qrdb's verifiable-log type (go-qrdb #722,
#912) and are not on main.

Specifications, both pinned at C2SP commit `e5746a0b`:
[c2sp-tlog-checkpoint.md](../references/c2sp-tlog-checkpoint.md) and
[c2sp-signed-note.md](../references/c2sp-signed-note.md).

## Exported surface

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
