// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package software

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// capturingStorage records the exact value slice handed to Put, by reference
// rather than by copy, so a test can inspect it after the call returns.
//
// Holding the reference is the point: it is the same backing array ImportKey
// unwrapped into, so reading it afterwards shows whether the plaintext was
// wiped. It also documents the contract the wipe depends on — a backend that
// retained this slice instead of consuming it would have its stored value
// zeroed underneath it.
type capturingStorage struct {
	storage.Backend

	captured []byte
	failPut  bool
}

// metadataKeyPrefix is the path prefix pkg/keyprovider/pkcs8 writes key
// metadata records under. An import writes the key material and then that
// record, so a capture that simply kept the most recent Put would hold the
// JSON record rather than the key and the wipe assertions would be vacuous.
const metadataKeyPrefix = "meta/"

func (s *capturingStorage) Put(ctx context.Context, key string, value []byte) error {
	// Capture only the key material, never the metadata record that
	// accompanies it. Selecting by path rather than by call order keeps this
	// correct however many records an import writes alongside the key.
	if !strings.HasPrefix(key, metadataKeyPrefix) {
		s.captured = value
	}
	if s.failPut {
		return &errs.Message{Msg: "injected put failure"}
	}
	return s.Backend.Put(ctx, key, value)
}

func newCapturingBackend(t *testing.T, failPut bool) (*SoftwareBackend, *capturingStorage) {
	t.Helper()

	capture := &capturingStorage{Backend: storage.New(), failPut: failPut}
	be, err := NewBackend(&Config{KeyStorage: capture})
	require.NoError(t, err)
	sb, ok := be.(*SoftwareBackend)
	require.True(t, ok)
	t.Cleanup(func() { _ = sb.Close() })
	return sb, capture
}

// wrapECDSAKeyForImport generates an ECDSA key, marshals it to PKCS#8, and
// wraps it for import, returning the wrapped material and the plaintext DER so
// a test can assert the captured slice really did hold the key.
func wrapECDSAKeyForImport(t *testing.T, be *SoftwareBackend, attrs *types.KeyAttributes) (*backend.WrappedKeyMaterial, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	params, err := be.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := be.WrapKey(context.Background(), der, params)
	require.NoError(t, err)

	return wrapped, der
}

// A successful import must not leave the unwrapped private key readable on the
// heap. The garbage collector neither zeroes the slice nor promises to reuse
// its pages promptly, so without an explicit wipe the plaintext key stays
// recoverable from ordinary process memory for an unbounded time (#68).
func TestImportKey_WipesUnwrappedMaterialOnSuccess(t *testing.T) {
	be, capture := newCapturingBackend(t, false)
	ctx := context.Background()

	attrs := createECDSAAttrs("wipe-success.example.com", "P-256")
	wrapped, der := wrapECDSAKeyForImport(t, be, attrs)

	require.NoError(t, be.ImportKey(ctx, attrs, wrapped))

	require.NotEmpty(t, capture.captured, "storage never received the key material")
	require.Len(t, capture.captured, len(der),
		"the captured slice must be the unwrapped key, or this test proves nothing")
	assert.True(t, allZero(capture.captured),
		"the unwrapped private key is still readable on the heap after a successful import")
}

// The failure paths matter as much as the success one: an import that fails
// after unwrapping has already decrypted the key, so returning without wiping
// leaves exactly the same plaintext behind.
func TestImportKey_WipesUnwrappedMaterialOnStorageFailure(t *testing.T) {
	be, capture := newCapturingBackend(t, true)
	ctx := context.Background()

	attrs := createECDSAAttrs("wipe-failure.example.com", "P-256")
	wrapped, der := wrapECDSAKeyForImport(t, be, attrs)

	err := be.ImportKey(ctx, attrs, wrapped)
	require.Error(t, err, "the injected storage failure must surface")

	require.NotEmpty(t, capture.captured, "storage never received the key material")
	require.Len(t, capture.captured, len(der))
	assert.True(t, allZero(capture.captured),
		"the unwrapped private key is still readable on the heap after a failed import")
}

// The wipe must not corrupt what was stored. Every reachable Backend.Put
// consumes the value before returning -- the memory engine copies it, the file
// engine writes and renames, pebble copies into its batch, and the qrdb path
// encodes it into a command buffer before proposing -- so wiping afterwards
// touches only the caller's copy. This asserts that contract from the outside:
// the key must read back intact.
func TestImportKey_WipeDoesNotCorruptTheStoredKey(t *testing.T) {
	// EVERY supported adapter, not just the in-memory one. The wipe is safe
	// because Backend.Put must consume the slice before returning
	// (pkg/storage.Backend), and that requirement is only worth as much as the
	// implementations that honour it -- so each is exercised end to end rather
	// than audited by reading.
	//
	// The qrdb PROPOSAL/APPLY path is what makes this table worth running, and
	// it is not a fourth row hiding behind the three below -- it IS them.
	// storage.NewFile and storage.NewPebble are thin wrappers over
	// pkg/storage/qrdb's factory (pkg/storage/constructors.go), which builds
	// the whole embedded stack: Storage -> FastStateMachine -> LocalBackend ->
	// KVService -> embedded.Transport -> qrdbsdk.Client -> qrdb.Backend. So
	// their Put is qrdb.Backend.Put, reaching the SDK client and the state
	// machine's DETACHED apply goroutine (FastStateMachine.Close is the only
	// join point -- see the factory's own comment). That goroutine reading a
	// slice the caller has since wiped is precisely the hazard, and these rows
	// exercise it.
	//
	// The explicit qrdb row is nonetheless kept, constructed straight from the
	// qrdb factory, so the coverage claim does not rest on a reader tracing
	// three constructors to discover what they delegate to. The only row that
	// is NOT the client path is "memory": storage.New goes through
	// NewEngineBackend, one layer under the transport.
	adapters := []struct {
		name string
		make func(t *testing.T) storage.Backend
	}{
		{"memory", func(t *testing.T) storage.Backend { return storage.New() }},
		{"file", func(t *testing.T) storage.Backend {
			b, err := storage.NewFile(t.TempDir())
			require.NoError(t, err)
			return b
		}},
		{"pebble", func(t *testing.T) storage.Backend {
			b, err := storage.NewPebble(t.TempDir())
			require.NoError(t, err)
			return b
		}},
		{"qrdb", func(t *testing.T) storage.Backend {
			b, err := qrdb.NewMemory()
			require.NoError(t, err)
			t.Cleanup(func() { _ = b.Close() })
			return b
		}},
	}

	for _, a := range adapters {
		t.Run(a.name, func(t *testing.T) {
			store := a.make(t)
			be, err := NewBackend(&Config{KeyStorage: store})
			require.NoError(t, err)
			sb := be.(*SoftwareBackend)
			defer func() { _ = sb.Close() }()

			ctx := context.Background()

			attrs := createECDSAAttrs("wipe-integrity.example.com", "P-256")
			wrapped, der := wrapECDSAKeyForImport(t, sb, attrs)

			require.NoError(t, sb.ImportKey(ctx, attrs, wrapped))

			stored, err := storage.GetKey(ctx, sb.storage, attrs.ID())
			require.NoError(t, err)
			assert.Equal(t, der, stored,
				"the stored key must survive the wipe of the caller's copy")

			// And it must still parse as the key it was, not merely match bytes.
			parsed, err := x509.ParsePKCS8PrivateKey(stored)
			require.NoError(t, err, "the stored key no longer parses; the wipe reached it")
			assert.IsType(t, &ecdsa.PrivateKey{}, parsed)
		})
	}
}

// A backend that RETAINS the caller's slice violates Backend.Put's documented
// requirement, and this records what that violation costs: the stored value is
// zeroed underneath it.
//
// It is deliberately an assertion about a NON-conforming implementation, not a
// bug report about a conforming one. The wipe is not what makes such a backend
// unsafe -- the retention is, and the same backend would already be corrupted
// by any caller that reused or wiped its buffer. Stating it as a test makes
// the contract's consequence executable rather than a paragraph nobody reads.
func TestImportKey_RetainingBackendViolatesThePutContract(t *testing.T) {
	capture := &capturingStorage{Backend: storage.New()}
	be, err := NewBackend(&Config{KeyStorage: capture})
	require.NoError(t, err)
	sb := be.(*SoftwareBackend)
	defer func() { _ = sb.Close() }()

	ctx := context.Background()
	attrs := createECDSAAttrs("retaining.example.com", "P-256")
	wrapped, _ := wrapECDSAKeyForImport(t, sb, attrs)

	require.NoError(t, sb.ImportKey(ctx, attrs, wrapped))

	// capturingStorage keeps the caller's slice by reference -- exactly what
	// the contract forbids -- so what it "stored" is now zeroed.
	require.NotEmpty(t, capture.captured)
	assert.True(t, allZero(capture.captured),
		"a retaining backend keeps a reference that the caller's wipe zeroes; "+
			"this is why Backend.Put must consume the slice before returning")

	// The conforming backend underneath it still holds the real key, which is
	// the point: the corruption belongs to the retention, not to the wipe.
	stored, err := storage.GetKey(ctx, sb.storage, attrs.ID())
	require.NoError(t, err)
	assert.False(t, allZero(stored),
		"the conforming backend beneath the capture must hold the real key")
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}

// The parsed private key must be zeroized too, and the wiring that does it
// must be pinned by a test that fails when the wiring goes away.
//
// zeroizeParsedPrivateKey is covered thoroughly as a unit in zeroize_test.go,
// but that says nothing about whether importAsymmetricKey calls it. It did
// not: deleting the `defer zeroizeParsedPrivateKey(privateKey)` line left the
// whole package green (measured 2026-08-27), so the second half of #68 --
// bounding the residency of the copy x509 materialises, as distinct from the
// DER -- was an unverified claim. Every gate agreed, including the review.
//
// The assertion is on the outcome rather than on the call: the ECDSA scalar's
// backing words are captured while they still hold the secret, and must all
// read zero once ImportKey returns. capturedMagnitude fails the test if the
// value is already zero at capture time, so a run where the parse produced
// nothing to wipe cannot pass vacuously.
func TestImportKey_ZeroizesTheParsedPrivateKey(t *testing.T) {
	var magnitude []big.Word

	original := parsePKCS8ForImport
	t.Cleanup(func() { parsePKCS8ForImport = original })
	parsePKCS8ForImport = func(der []byte) (any, error) {
		parsed, err := original(der)
		if err != nil {
			return parsed, err
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		require.True(t, ok, "this test drives the ECDSA path")
		magnitude = capturedMagnitude(t, key.D) //nolint:staticcheck // SA1019: D is the storage whose erasure is under test
		return parsed, nil
	}

	be, _ := newCapturingBackend(t, false)
	ctx := context.Background()

	attrs := createECDSAAttrs("wipe-parsed.example.com", "P-256")
	wrapped, _ := wrapECDSAKeyForImport(t, be, attrs)

	require.NoError(t, be.ImportKey(ctx, attrs, wrapped))

	require.NotNil(t, magnitude, "the parse seam never fired, so this test proves nothing")
	requireAllWordsZero(t, magnitude, "parsed ECDSA D")
}
