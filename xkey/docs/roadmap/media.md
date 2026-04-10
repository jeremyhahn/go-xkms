# Media Signing for Deep Fake Prevention

## Context

xkey needs the ability to sign photos and videos so that people appearing in media can cryptographically attest to their presence, preventing deep fake misrepresentation. Multiple people can sign the same media file, identifying the region (face/body) or time segment where they appear. A viewer with integrated verification shows who signed what and whether signatures are valid.

C2PA was evaluated but is unsuitable for MVP: no Go library exists, multi-signer is indirect (ingredient chains, not direct attestation), region support is document-focused (PDF/EPUB), and the spec is very complex (JUMBF/COSE Sign1/X.509 chains). A custom CBOR-based embedded format gives us exactly what we need. C2PA export can be added later for interoperability.

## Architecture Overview

```
Frontend (Svelte)
  MediaSign View    Contacts View    MediaViewer (Photo + Video)
       |                |                    |
       | Wails RPC      |                    |
Backend (Go)
  MediaSignService  ContactService   MediaSignService (verify)
       |                |                    |
  mediasign pkg    contactstore pkg
  (sign/verify/    (CRUD, public key mgmt)
   format/parse)
       |
  KeyService.SignData() / VerifySignature()
  (any backend: PIV, software, TPM2, PKCS#11...)
```

## Embedded Signature Format

Signatures are embedded directly inside the media file using format-specific metadata containers. No sidecar files - signatures travel with the media.

### Embedding Locations

| Format | Container | Details |
|--------|-----------|---------|
| JPEG | APP12 marker | Magic bytes `XKMS\x00` + CBOR payload. APP12 is rarely used. |
| PNG | `xkSg` private chunk | Ancillary, private, safe-to-copy chunk per PNG spec. Raw CBOR. |
| MP4/MOV | UUID box | Top-level uuid box with xkms UUID prefix + CBOR payload. |

Raw CBOR in format-specific containers (not XMP) because: no XML parsing overhead or base64 waste, more efficient storage and faster parsing, and our viewer is the primary consumer.

### Content-Only Hashing

Since signatures are embedded IN the file, we hash only the media content (excluding our metadata):

```
ContentHash(file) = SHA-256 of all file bytes EXCEPT:
  - JPEG: Skip APP12 markers with "XKMS\x00" magic
  - PNG:  Skip xkSg chunks
  - MP4:  Skip our UUID box
```

This produces a stable hash regardless of how many signatures are embedded. Adding a new signature doesn't change the content hash. If the actual media is modified, the hash changes and all signatures become invalid.

### CBOR Bundle Schema

```go
// SignatureBundle is the embedded CBOR payload
type SignatureBundle struct {
    Version     uint8              `cbor:"1,keyasint"` // Format version (1)
    MediaType   MediaType          `cbor:"2,keyasint"` // Photo or Video
    ContentHash []byte             `cbor:"3,keyasint"` // Content-only SHA-256
    Signatures  []MediaSignature   `cbor:"4,keyasint"` // All signatures
    Created     int64              `cbor:"5,keyasint"` // Unix timestamp of bundle creation
}

// MediaSignature is one person's signature on the media
type MediaSignature struct {
    SignerID    string          `cbor:"1,keyasint"` // Public key fingerprint (SHA-256 of DER pubkey)
    SignerName  string          `cbor:"2,keyasint"` // Display name (optional, informational)
    Algorithm   string          `cbor:"3,keyasint"` // "ES256", "Ed25519", etc.
    PublicKey   []byte          `cbor:"4,keyasint"` // DER-encoded public key
    Region      *SignedRegion   `cbor:"5,keyasint"` // Photo region (nil = whole image)
    Segment     *SignedSegment  `cbor:"6,keyasint"` // Video segment (nil = whole video)
    Timestamp   int64           `cbor:"7,keyasint"` // Unix timestamp of signing
    Signature   []byte          `cbor:"8,keyasint"` // Cryptographic signature bytes
    KeyBackend  string          `cbor:"9,keyasint"` // Backend used (informational)
    KeyID       string          `cbor:"10,keyasint"` // Key ID used (informational)
}

// SignedRegion defines a rectangular area in normalized coordinates [0.0, 1.0]
type SignedRegion struct {
    X      float64 `cbor:"1,keyasint"` // Left edge (0.0 = left, 1.0 = right)
    Y      float64 `cbor:"2,keyasint"` // Top edge (0.0 = top, 1.0 = bottom)
    Width  float64 `cbor:"3,keyasint"` // Width fraction
    Height float64 `cbor:"4,keyasint"` // Height fraction
    Label  string  `cbor:"5,keyasint"` // Optional label ("face", "body", etc.)
}

// SignedSegment defines a time range in a video
type SignedSegment struct {
    StartMs int64  `cbor:"1,keyasint"` // Start time in milliseconds
    EndMs   int64  `cbor:"2,keyasint"` // End time in milliseconds
    Label   string `cbor:"3,keyasint"` // Optional label
}
```

### Canonical Signing Payload

```go
type SigningPayload struct {
    Version     uint8          `cbor:"1,keyasint"` // Must match bundle version
    ContentHash []byte         `cbor:"2,keyasint"` // Content-only SHA-256
    Region      *SignedRegion  `cbor:"3,keyasint"` // Region being attested (nil = whole)
    Segment     *SignedSegment `cbor:"4,keyasint"` // Segment being attested (nil = whole)
    Timestamp   int64          `cbor:"5,keyasint"` // Signing timestamp
    SignerID    string         `cbor:"6,keyasint"` // Public key fingerprint
}
// Serialized with deterministic CBOR (canonical, sorted integer keys), then SHA-256 hashed, then signed
```

This binds each signature to: the exact media content (content-only hash), the specific region/segment, the signing time, and the signer identity. A signature cannot be moved to a different region, different media, or different signer.

### Format Parsers

```go
type Embedder interface {
    Extract(r io.ReadSeeker) (*SignatureBundle, error)
    Embed(r io.ReadSeeker, bundle *SignatureBundle, w io.Writer) error
    ContentHash(r io.ReadSeeker) ([]byte, error)
}
```

Format detection by magic bytes: JPEG (`FF D8`), PNG (`89 50 4E 47`), MP4 (`ftyp` box at offset 4).

## Package Structure

Reusable logic (wire formats, crypto, signing) goes in `go-xkms/pkg/`. xkey-specific glue (GUI services, local stores) stays in `xkey/`.

```
pkg/mediasign/                # REUSABLE: Wire format, signing payload, verification, embedding
  errors.go                   # Typed errors
  types.go                    # SignatureBundle, MediaSignature, SignedRegion, SignedSegment
  payload.go                  # Canonical SigningPayload construction + deterministic CBOR
  verifier.go                 # Verify() - signature verification against public key
  bundle.go                   # Bundle CBOR encode/decode
  embedder.go                 # Embedder interface + format detection + registry
  embed_jpeg.go               # JPEG APP12 marker embed/extract/content-hash
  embed_png.go                # PNG xkSg chunk embed/extract/content-hash
  embed_mp4.go                # MP4 UUID box embed/extract/content-hash

xkey/pkg/contactstore/       # XKEY-SPECIFIC: Contact/identity management
  errors.go
  types.go                   # Contact type definition
  store.go                   # Store interface
  memory_store.go            # In-memory implementation
  backend_store.go           # Barrier-backed file persistence

xkey/pkg/gui/services/       # XKEY-SPECIFIC: Wails GUI service wrappers
  media_sign_service.go      # Wails-bound media signing service
  contact_service.go         # Wails-bound contact service

xkey/cmd/xkey/cmd/           # CLI commands
  media.go                   # `xkey media` parent command
  media_sign.go              # `xkey media sign <file>`
  media_verify.go            # `xkey media verify <file>`
  media_list.go              # `xkey media list <file>`
  contact.go                 # `xkey contact` parent command
  contact_add.go             # `xkey contact add`
  contact_list.go            # `xkey contact list`
  contact_remove.go          # `xkey contact remove <id>`

xkey/frontend/src/views/     # Svelte frontend views
  MediaSign.svelte           # Main media signing view
  MediaViewer.svelte         # Photo viewer with region overlays + video player
  Contacts.svelte            # Contact store management
```

### Key Architecture Rule

- `pkg/mediasign/` does NOT perform signing itself - it constructs the canonical payload and verifies signatures using raw crypto primitives
- GUI service delegates actual key-backed signing to `KeyService.SignData()`
- CLI commands use the same `pkg/mediasign/` library for format handling

### Contact Store

```go
type Contact struct {
    ID          string    // SHA-256 fingerprint of public key
    Name        string
    Email       string
    PublicKey   []byte    // DER-encoded public key
    KeyType     string    // "EC", "Ed25519", "RSA"
    Algorithm   string    // "ES256", "Ed25519", etc.
    Notes       string
    Avatar      []byte
    ImportedAt  time.Time
    LastUsed    time.Time
    Trusted     bool      // Explicitly trusted by user
}

type Store interface {
    Add(contact *Contact) error
    Get(id string) (*Contact, error)
    GetByName(name string) ([]*Contact, error)
    List() ([]*Contact, error)
    Update(contact *Contact) error
    Delete(id string) error
    ImportPEM(pemData []byte, name string) (*Contact, error)
    ImportJWK(jwkData []byte, name string) (*Contact, error)
    Close() error
}
```

## Signing Flow

1. User selects a photo or video file
2. Backend detects format (JPEG/PNG/MP4) and selects appropriate embedder
3. Backend computes content-only hash (skipping any existing signature metadata)
4. Backend extracts existing SignatureBundle if present (for adding co-signatures)
5. User optionally draws a rectangle region (photo) or selects time segment (video)
6. User selects signing key (default: PIV 9C, or any key from KeyService.ListSigningKeys)
7. Backend constructs SigningPayload, serializes to deterministic CBOR, hashes with SHA-256
8. Backend calls `KeyService.SignData(backend, keyID, "SHA-256", payloadHash)` to get signature
9. Backend creates MediaSignature entry with public key, region/segment, and signature bytes
10. Backend appends signature to bundle (or creates new bundle), embeds into media file

The original file is copied to `<name>.original.<ext>` before the first signing as a backup.

## Verification Flow

1. User opens a media file
2. Backend detects format, extracts embedded SignatureBundle
3. Backend computes content-only hash and compares to bundle's ContentHash
4. For each signature: reconstruct SigningPayload, serialize to deterministic CBOR, hash, verify against embedded public key
5. Look up signer in ContactStore by fingerprint
6. Report: valid/invalid, known/unknown contact, trusted/untrusted
7. Frontend displays verification results as overlays on the media

### Verification Status Types

| Status | Meaning |
|--------|---------|
| Valid | Signature valid, known trusted contact |
| ValidUnknown | Signature valid, unknown signer |
| ValidUntrusted | Signature valid, known but untrusted |
| Invalid | Signature verification failed |
| MediaModified | Media hash mismatch |

## Frontend Design

### MediaSign View

- File picker for photos (jpg, png) and videos (mp4, mov)
- Image/video preview
- Canvas overlay for drawing rectangle regions on photos
- Time range slider for video segments
- Key selector dropdown (PIV 9C default)
- Existing signatures list

### MediaViewer View

- **Photo mode**: Full image with colored rectangle overlays per signed region. Hover tooltips with signer name, timestamp, verification status.
- **Video mode**: Video player with signature timeline bar. Colored segments showing signed ranges. Sidebar showing signers for current playback position.
- **Color coding**: Green (valid+trusted), Blue (valid+unknown), Yellow (valid+untrusted), Red (invalid)

### Contacts View

- Searchable contact list with name, email, key type, trust status
- Import via PEM file, JWK, or paste public key
- Detail view with public key fingerprint
- Trust toggle
- Export public key as PEM

## Implementation Phases

### Phase 1: Core Data Format & Signing Logic

**Location**: `pkg/mediasign/`

1. Types, errors, bundle CBOR encode/decode
2. Canonical signing payload construction (deterministic CBOR)
3. Signature verification (pure crypto against embedded public key)
4. Format embedders: JPEG APP12, PNG xkSg chunk, MP4 UUID box
5. Format detection and embedder registry
6. Full test suite (90%+ coverage, test fixtures: small JPEG, PNG, MP4 files)

### Phase 2: Contact Store

**Location**: `xkey/pkg/contactstore/`

1. Types, interface, typed errors
2. Memory store and barrier-backed store (follows oath backend_store pattern)
3. PEM/JWK import with public key fingerprint computation
4. Full test suite (90%+ coverage)

### Phase 3: GUI Services

**Location**: `xkey/pkg/gui/services/`

1. MediaSignService: HashMediaFile, SignMedia, VerifyMedia, ListSignatures, RemoveSignature, ListSigningKeys
2. ContactService: ListContacts, AddContact, ImportContactPEM, DeleteContact, SetTrusted, LookupByFingerprint
3. Wire both into `app.go` (fields, construction, SetContext, bindings, store init)
4. Service tests

### Phase 4: CLI Commands

**Location**: `xkey/cmd/xkey/cmd/`

1. `xkey media sign <file> [--key backend:keyID] [--region x,y,w,h] [--segment start,end]`
2. `xkey media verify <file>`
3. `xkey media list <file>`
4. `xkey contact add --name <name> --key <pem-file>`
5. `xkey contact list`
6. `xkey contact remove <id>`

### Phase 5: Frontend - Contacts View

1. Contact list with search/filter
2. Import public key dialog
3. Trust management toggle
4. Navigation item in App.svelte

### Phase 6: Frontend - Media Signing View

1. File picker, image/video preview
2. Canvas rectangle drawing tool for photos
3. Time range selector for videos
4. Key selector, sign action, existing signatures list

### Phase 7: Frontend - Media Viewer

1. Photo viewer with colored rectangle overlays
2. Hover tooltips for signer info
3. Video player with signature timeline bar
4. Verification status sidebar

### Phase 8: Documentation

**Location**: `xkey/docs/mediasign/`

1. Feature overview and user guide
2. Embedded data format specification
3. CLI usage guide

## Critical Files to Modify

| File | Change |
|------|--------|
| `xkey/pkg/gui/app.go` | Add mediaSignService + contactService fields, construction, SetContext, bindings, store init |
| `xkey/frontend/src/App.svelte` | Add nav items and view routing |
| `xkey/frontend/src/lib/api/backend.ts` | TypeScript interfaces for new services |
| `xkey/cmd/xkey/cmd/root.go` | Register media and contact parent commands |

## Key Reuse Points

- `xkey/pkg/gui/services/key_service.go`: SignData() and VerifySignature() for crypto operations
- `xkey/pkg/oath/backend_store.go`: Pattern for barrier-backed ContactStore persistence
- `xkey/pkg/gui/services/oath_service.go`: Pattern for store-backed Wails service
- `github.com/fxamacker/cbor/v2`: Already in go.mod, use for bundle encoding
- `github.com/abema/go-mp4`: NEW dependency for MP4 box manipulation
- `crypto/ecdsa`, `crypto/ed25519`: Standard library for verification

## Future Enhancements (post-MVP)

- C2PA export for interoperability
- Face detection to auto-suggest regions
- Per-frame video regions (track face positions across frames)
- Phone signing via BLE bridge
- Trusted third-party timestamping for non-repudiation
