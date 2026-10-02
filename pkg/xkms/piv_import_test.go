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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pivImportStub is a PIVKeyGenerator that also implements PIVKeyImporter,
// standing in for a backend-backed generator that accepts imported keys.
type pivImportStub struct {
	imported map[string]crypto.Signer
	lastSlot pivcert.PIVSlot
	lastAlgo string
	err      error
}

func newPIVImportStub() *pivImportStub {
	return &pivImportStub{imported: make(map[string]crypto.Signer)}
}

func (p *pivImportStub) GeneratePIVKey(_ pivcert.PIVSlot, _ string, _ string) (crypto.Signer, error) {
	return nil, ErrPIVInvalidAlgorithm
}

func (p *pivImportStub) GetPIVSigner(_ pivcert.PIVSlot, cn string) (crypto.Signer, error) {
	signer, ok := p.imported[cn]
	if !ok {
		return nil, ErrPIVSignerNotAvailable
	}
	return signer, nil
}

func (p *pivImportStub) ImportPIVKey(_ context.Context, slot pivcert.PIVSlot, algorithm, cn string, key crypto.PrivateKey) (crypto.Signer, error) {
	if p.err != nil {
		return nil, p.err
	}
	p.lastSlot = slot
	p.lastAlgo = algorithm
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrPIVKeyMaterialInvalid
	}
	p.imported[cn] = signer
	return signer, nil
}

// pivNoImportStub is a PIVKeyGenerator that does NOT implement
// PIVKeyImporter — the "this backend cannot accept an imported key" case.
type pivNoImportStub struct{}

func (p *pivNoImportStub) GeneratePIVKey(_ pivcert.PIVSlot, _ string, _ string) (crypto.Signer, error) {
	return nil, ErrPIVInvalidAlgorithm
}

func (p *pivNoImportStub) GetPIVSigner(_ pivcert.PIVSlot, _ string) (crypto.Signer, error) {
	return nil, ErrPIVSignerNotAvailable
}

// pemEncodePKCS8 marshals key as PKCS#8 and wraps it in a PEM block.
func pemEncodePKCS8(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// noImportProvider is a key provider that implements none of
// backend.ImportExportBackend. The embedded interface supplies the
// types.KeyProvider method set without implementing it; nothing calls those
// methods, because the import path refuses on the failed type assertion.
type noImportProvider struct{ types.KeyProvider }

// noImportBackend is an xkms.Backend whose key provider cannot import. Only
// KeyProvider() is exercised: ImportPIVKey reaches for it and nothing else
// before it refuses, so the embedded interface never has to answer a call.
type noImportBackend struct{ Backend }

func (n *noImportBackend) KeyProvider() types.KeyProvider { return noImportProvider{} }

// --- ImportPIVKey: the key lands in the slot and signs ---

// TestImportPIVKey_ECDSA_SignsWithImportedKey is #207's primary verification:
// import a known key, sign with the slot, and verify the signature against
// that key's own public half. Anything less would not prove the slot actually
// holds the key that was handed to it.
func TestImportPIVKey_ECDSA_SignsWithImportedKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	stub := newPIVImportStub()
	_ = setupPIVForOps(t, stub)

	resp, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "9a", resp.Slot)
	assert.Equal(t, "ecdsap256", resp.Algorithm)
	require.NotEmpty(t, resp.PublicKey)

	// The returned public key must be the imported key's own public half.
	block, _ := pem.Decode(resp.PublicKey)
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(pub),
		"returned public key must be the imported key's public half")

	// Sign through the slot and verify against the imported key.
	payload := []byte("piv-import-roundtrip")
	signResp, err := SignPIVSlot(context.Background(), &transport.PIVSignRequest{
		Backend: "software",
		Slot:    "9a",
		Payload: payload,
	})
	require.NoError(t, err)
	digest := sha256.Sum256(payload)
	assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], signResp.Signature),
		"the slot must sign with the key that was imported")
}

// TestImportPIVKey_RSA_SignsWithImportedKey covers the RSA path, whose PKCS#8
// encoding is large enough to need the hybrid wrapping algorithm.
func TestImportPIVKey_RSA_SignsWithImportedKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	stub := newPIVImportStub()
	_ = setupPIVForOps(t, stub)

	resp, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9c",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	require.NoError(t, err)
	assert.Equal(t, "rsa2048", resp.Algorithm)

	payload := []byte("piv-import-rsa")
	signResp, err := SignPIVSlot(context.Background(), &transport.PIVSignRequest{
		Backend: "software",
		Slot:    "9c",
		Payload: payload,
	})
	require.NoError(t, err)
	digest := sha256.Sum256(payload)
	assert.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signResp.Signature))
}

// TestImportPIVKey_Ed25519 covers the remaining supported algorithm.
func TestImportPIVKey_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	stub := newPIVImportStub()
	_ = setupPIVForOps(t, stub)

	resp, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9d",
		PrivateKey: pemEncodePKCS8(t, priv),
	})
	require.NoError(t, err)
	assert.Equal(t, "ed25519", resp.Algorithm)

	block, _ := pem.Decode(resp.PublicKey)
	require.NotNil(t, block)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	assert.True(t, pub.Equal(parsed))
}

// TestImportPIVKey_AcceptsDER covers raw DER input alongside PEM: the
// motivating caller hands over a PEM, but a DER blob must not be rejected as
// malformed when it is simply unarmoured.
func TestImportPIVKey_AcceptsDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	stub := newPIVImportStub()
	_ = setupPIVForOps(t, stub)

	resp, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: der,
	})
	require.NoError(t, err)
	assert.Equal(t, "ecdsap256", resp.Algorithm)
}

// TestImportPIVKey_AcceptsSEC1AndPKCS1 covers the two legacy private-key
// encodings a caller's PEM may carry. Refusing them would push the caller into
// re-encoding a key it already holds.
func TestImportPIVKey_AcceptsSEC1AndPKCS1(t *testing.T) {
	stub := newPIVImportStub()
	_ = setupPIVForOps(t, stub)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	resp, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
	})
	require.NoError(t, err)
	assert.Equal(t, "ecdsap256", resp.Algorithm)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	resp, err = ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9c",
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}),
	})
	require.NoError(t, err)
	assert.Equal(t, "rsa2048", resp.Algorithm)
}

// --- ImportPIVKey: refusals must be distinguishable, never silent ---

// TestImportPIVKey_BackendRefusesImport is #207's second verification. A
// backend that cannot accept an imported key must produce a distinguishable
// typed error rather than reporting success — a real PIV applet may refuse
// import for some slots or algorithms, and that refusal has to be reportable.
func TestImportPIVKey_BackendRefusesImport(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_ = setupPIVForOps(t, &pivNoImportStub{})

	resp, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	require.Error(t, err, "a generator that cannot import must not report success")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrPIVImportNotSupported)
}

// TestImportPIVKey_BackendImportFails covers a generator that implements
// import but whose backend rejects the operation. The underlying cause must
// survive to the caller.
func TestImportPIVKey_BackendImportFails(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	stub := newPIVImportStub()
	stub.err = ErrPIVImportNotSupported
	_ = setupPIVForOps(t, stub)

	_, err = ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVImportNotSupported)
}

// --- ImportPIVKey: input validation ---

func TestImportPIVKey_NilRequest(t *testing.T) {
	_ = setupPIVForOps(t, newPIVImportStub())
	_, err := ImportPIVKey(context.Background(), nil)
	assert.ErrorIs(t, err, ErrPIVKeyMaterialRequired)
}

func TestImportPIVKey_EmptyKeyMaterial(t *testing.T) {
	_ = setupPIVForOps(t, newPIVImportStub())
	_, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend: "software",
		Slot:    "9a",
	})
	assert.ErrorIs(t, err, ErrPIVKeyMaterialRequired)
}

func TestImportPIVKey_MalformedKeyMaterial(t *testing.T) {
	_ = setupPIVForOps(t, newPIVImportStub())
	_, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: []byte("this is not a key"),
	})
	assert.ErrorIs(t, err, ErrPIVKeyMaterialInvalid)
}

// TestImportPIVKey_PublicKeyPEMRejected guards the exact confusion #207 was
// filed about: the downstream caller was passing a PRIVATE key into a
// certificate field. A public key arriving where a private key belongs must
// be refused, not stored.
func TestImportPIVKey_PublicKeyPEMRejected(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	_ = setupPIVForOps(t, newPIVImportStub())
	_, err = ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	})
	assert.ErrorIs(t, err, ErrPIVKeyMaterialInvalid)
}

func TestImportPIVKey_InvalidSlot(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_ = setupPIVForOps(t, newPIVImportStub())
	_, err = ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "zz",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	assert.ErrorIs(t, err, ErrPIVInvalidSlot)
}

// TestImportPIVKey_AlgorithmMismatch covers a caller that declares one
// algorithm and supplies a key of another. Silently trusting the key over the
// declaration would let a slot end up holding something other than what the
// caller believes it asked for.
func TestImportPIVKey_AlgorithmMismatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_ = setupPIVForOps(t, newPIVImportStub())
	_, err = ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		Algorithm:  "rsa2048",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	assert.ErrorIs(t, err, ErrPIVAlgorithmMismatch)
}

// TestImportPIVKey_DeclaredAlgorithmAccepted is the matching success case:
// a declaration that agrees with the key is honoured.
func TestImportPIVKey_DeclaredAlgorithmAccepted(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	stub := newPIVImportStub()
	_ = setupPIVForOps(t, stub)
	resp, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		Algorithm:  "ecdsap384",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	require.NoError(t, err)
	assert.Equal(t, "ecdsap384", resp.Algorithm)
	assert.Equal(t, "ecdsap384", stub.lastAlgo)
	assert.Equal(t, pivcert.PIVSlot(pivcert.PIVSlotAuthentication), stub.lastSlot)
}

// TestImportPIVKey_UnsupportedCurve refuses a curve the PIV algorithm
// vocabulary has no name for, rather than importing it under a wrong label.
func TestImportPIVKey_UnsupportedCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	_ = setupPIVForOps(t, newPIVImportStub())
	_, err = ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	assert.ErrorIs(t, err, ErrPIVInvalidAlgorithm)
}

// --- ImportPIVKey through a real backend, not a stub ---

// TestImportPIVKey_RealBackendWrapCeremony exercises the production path:
// backendPIVKeyGenerator against a real software Backend, so the whole import
// ceremony actually runs (GetImportParameters, WrapKey, ImportKey) rather than
// being replaced by a stub. Without this the ceremony wiring would be
// unverified — a stub cannot tell us the key material survives wrapping.
func TestImportPIVKey_RealBackendWrapCeremony(t *testing.T) {
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)

	// Build the Backend the production path builds: a composite over the key
	// provider, so the import reaches the provider through KeyProvider()
	// exactly as it does at runtime.
	realBackend, err := New(&BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	gen := newBackendPIVKeyGenerator(realBackend, types.StoreSoftware)
	_ = setupPIVForOps(t, gen)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	resp, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "ecdsap256", resp.Algorithm)

	// The key that came back out of the backend must be the one that went in:
	// the wrap/unwrap round trip must preserve it exactly.
	block, _ := pem.Decode(resp.PublicKey)
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(pub),
		"the imported key must survive the wrap ceremony unchanged")

	// And the slot must sign with it.
	payload := []byte("piv-import-real-backend")
	signResp, err := SignPIVSlot(context.Background(), &transport.PIVSignRequest{
		Backend: "software",
		Slot:    "9a",
		Payload: payload,
	})
	require.NoError(t, err)
	digest := sha256.Sum256(payload)
	assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], signResp.Signature))
}

// --- softwarePIVKeyGenerator.ImportPIVKey ---

// TestSoftwareGenerator_ImportPIVKey covers the software generator's own
// import path for every algorithm it supports. This is the generator the PIV
// manager falls back to when no backend resolver is installed, so it is a
// production path, not a test double.
func TestSoftwareGenerator_ImportPIVKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name      string
		algorithm string
		key       crypto.PrivateKey
	}{
		{"ecdsap256", "ecdsap256", ecKey},
		{"rsa2048", "rsa2048", rsaKey},
		{"ed25519", "ed25519", edKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gen := NewSoftwarePIVKeyGenerator()
			cn := "piv-9a-" + tc.name

			signer, err := gen.ImportPIVKey(context.Background(),
				pivcert.PIVSlot(pivcert.PIVSlotAuthentication), tc.algorithm, cn, tc.key)
			require.NoError(t, err)
			require.NotNil(t, signer)

			// The imported signer must be retrievable afterwards: an import
			// that does not survive into the generator's slot map would leave
			// the slot unable to sign.
			got, err := gen.GetPIVSigner(pivcert.PIVSlot(pivcert.PIVSlotAuthentication), cn)
			require.NoError(t, err)
			assert.Equal(t, signer.Public(), got.Public())
		})
	}
}

// TestSoftwareGenerator_ImportPIVKey_UnknownAlgorithm refuses a key the
// software generator could never have produced, rather than storing it.
func TestSoftwareGenerator_ImportPIVKey_UnknownAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	gen := NewSoftwarePIVKeyGenerator()
	_, err = gen.ImportPIVKey(context.Background(),
		pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "rsa1024", "piv-9a", key)
	assert.ErrorIs(t, err, ErrPIVInvalidAlgorithm)
}

// TestSoftwareGenerator_ImportPIVKey_NotASigner covers key material that
// parses but cannot sign.
func TestSoftwareGenerator_ImportPIVKey_NotASigner(t *testing.T) {
	gen := NewSoftwarePIVKeyGenerator()
	_, err := gen.ImportPIVKey(context.Background(),
		pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "ecdsap256", "piv-9a", []byte("not a key"))
	assert.ErrorIs(t, err, ErrPIVKeyMaterialInvalid)
}

// TestImportPIVKey_DefaultSoftwareFallback drives the package-level verb with
// no backend resolver installed, so it lands on the software generator that
// the PIV manager falls back to. This is the path a caller gets by default.
func TestImportPIVKey_DefaultSoftwareFallback(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// setupPIVForOps with a nil generator installs no resolver, leaving the
	// manager on its software fallback.
	_ = setupPIVForOps(t, nil)

	resp, err := ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "ecdsap256", resp.Algorithm)

	block, _ := pem.Decode(resp.PublicKey)
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(pub))
}

// --- backendPIVKeyGenerator.ImportPIVKey error paths ---

// TestBackendGenerator_ImportPIVKey_NoImportSupport covers a backend whose key
// provider does not implement the import ceremony. The refusal must be typed,
// because a hardware applet declining import is an ordinary outcome.
func TestBackendGenerator_ImportPIVKey_NoImportSupport(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	gen := newBackendPIVKeyGenerator(&noImportBackend{}, types.StoreSoftware)
	_, err = gen.ImportPIVKey(context.Background(),
		pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "ecdsap256", "piv-9a", key)
	assert.ErrorIs(t, err, ErrPIVImportNotSupported)
}

// TestBackendGenerator_ImportPIVKey_InvalidAlgorithm refuses before touching
// the backend.
func TestBackendGenerator_ImportPIVKey_InvalidAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	gen := newBackendPIVKeyGenerator(&noImportBackend{}, types.StoreSoftware)
	_, err = gen.ImportPIVKey(context.Background(),
		pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "rsa1024", "piv-9a", key)
	assert.ErrorIs(t, err, ErrPIVInvalidAlgorithm)
}

// TestPIVAlgorithmForKey covers the algorithm-resolution table. Importing a
// key under a wrong label would put a slot in a state its attributes misreport,
// so every supported size and curve is pinned and every unsupported one is
// refused rather than guessed.
func TestPIVAlgorithmForKey(t *testing.T) {
	rsa2048Key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ec256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ec521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	// A 1024-bit RSA key is refused outright by crypto/rsa.GenerateKey under
	// GODEBUG=fips140=only, so there is no way to build this deliberately
	// undersized fixture in that mode; the "too small" case below is simply
	// omitted rather than asserted, since pivAlgorithmForKey never sees a
	// key like this to reject.
	var rsa1024 *rsa.PrivateKey
	rsa1024, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		if !fips140.Enforced() {
			require.NoError(t, err)
		}
		rsa1024 = nil
	}

	supported := []struct {
		name string
		key  crypto.PrivateKey
		want string
	}{
		{"rsa2048", rsa2048Key, "rsa2048"},
		{"ecdsap256", ec256, "ecdsap256"},
		{"ecdsap384", ec384, "ecdsap384"},
		{"ed25519", ed, "ed25519"},
	}
	for _, tc := range supported {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pivAlgorithmForKey(tc.key)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	unsupported := []struct {
		name string
		key  crypto.PrivateKey
	}{
		{"ecdsap521_no_piv_name", ec521},
		{"not_a_key", []byte("bytes")},
	}
	if rsa1024 != nil {
		unsupported = append(unsupported, struct {
			name string
			key  crypto.PrivateKey
		}{"rsa1024_too_small", rsa1024})
	}
	for _, tc := range unsupported {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pivAlgorithmForKey(tc.key)
			assert.ErrorIs(t, err, ErrPIVInvalidAlgorithm)
		})
	}
}

// failingImportProvider implements the import ceremony and fails at a chosen
// step, standing in for an applet that accepts the interface but refuses the
// operation. The embedded interface supplies the rest of types.KeyProvider;
// nothing calls it, except Capabilities — ImportPIVKey's AttestLevel
// classification reads it on every call, success or failure, so it is
// overridden explicitly rather than left to the embedded nil interface.
type failingImportProvider struct {
	types.KeyProvider
	failAt string
}

// Capabilities reports a software (non-hardware) provider. The value is not
// exercised by these tests, which assert on the ceremony error rather than
// the recorded attestation level; it exists so AttestLevel has a real
// answer instead of a nil-interface panic.
func (f *failingImportProvider) Capabilities() types.Capabilities {
	return types.Capabilities{}
}

func (f *failingImportProvider) GetImportParameters(_ context.Context, _ *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if f.failAt == "params" {
		return nil, errFailingImport
	}
	return &backend.ImportParameters{Algorithm: algorithm, ImportToken: []byte("token")}, nil
}

func (f *failingImportProvider) WrapKey(_ context.Context, _ []byte, _ *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if f.failAt == "wrap" {
		return nil, errFailingImport
	}
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped")}, nil
}

func (f *failingImportProvider) UnwrapKey(_ context.Context, _ *backend.WrappedKeyMaterial, _ *backend.ImportParameters) ([]byte, error) {
	return nil, errFailingImport
}

func (f *failingImportProvider) ImportKey(_ context.Context, _ *types.KeyAttributes, _ *backend.WrappedKeyMaterial) error {
	if f.failAt == "import" {
		return errFailingImport
	}
	return nil
}

func (f *failingImportProvider) ExportKey(_ context.Context, _ *types.KeyAttributes, _ backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return nil, errFailingImport
}

func (f *failingImportProvider) ExportKeyTo(_ context.Context, _ *types.KeyAttributes, _ *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return nil, errFailingImport
}

func (f *failingImportProvider) ExportKeyMaterial(_ context.Context, _ *types.KeyAttributes) ([]byte, error) {
	return nil, errFailingImport
}

var errFailingImport = errors.New("applet refused the import")

// failingImportBackend is an xkms.Backend whose provider fails mid-ceremony.
type failingImportBackend struct {
	Backend
	provider *failingImportProvider
}

func (f *failingImportBackend) KeyProvider() types.KeyProvider { return f.provider }

// TestBackendGenerator_ImportPIVKey_CeremonyFailures covers a backend that
// advertises import and then refuses at each step. #207 requires that a
// backend which cannot accept a key produces a distinguishable error rather
// than a silent success — that has to hold mid-ceremony, not only at the
// capability check, because a real applet refuses per slot and per algorithm.
func TestBackendGenerator_ImportPIVKey_CeremonyFailures(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, step := range []string{"params", "wrap", "import"} {
		t.Run(step, func(t *testing.T) {
			gen := newBackendPIVKeyGenerator(
				&failingImportBackend{provider: &failingImportProvider{failAt: step}},
				types.StoreSoftware)

			signer, err := gen.ImportPIVKey(context.Background(),
				pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "ecdsap256", "piv-9a", key)

			require.Error(t, err, "a refused import must not report success")
			assert.Nil(t, signer)
			assert.ErrorIs(t, err, ErrPIVImportNotSupported,
				"the refusal must be reachable by sentinel")
			assert.ErrorIs(t, err, errFailingImport,
				"the backend's own cause must survive to the caller")
		})
	}
}

// --- Provenance: recorded by the system, never accepted from the caller ---

// TestImportPIVKey_ForgedOriginIsIgnored is the load-bearing provenance test.
//
// A caller supplies key attributes claiming the key was generated in-slot,
// on the import path. The stored record must say imported anyway. A
// provenance field a caller can set is worse than no field at all, because a
// verifier reads it as authoritative when it is merely asserted — this is the
// same rule PKCS#11 applies to CKA_LOCAL, whose template handling strips
// token-computed attributes "so a caller cannot forge provenance".
func TestImportPIVKey_ForgedOriginIsIgnored(t *testing.T) {
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	realBackend, err := New(&BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	gen := newBackendPIVKeyGenerator(realBackend, types.StoreSoftware)
	_ = setupPIVForOps(t, gen)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	require.NoError(t, err)

	// Whatever a caller might claim, the persisted record is what a verifier
	// reads. Assert on the record, not on the request.
	origin, found, err := gen.PIVKeyOrigin(pivcert.PIVSlot(pivcert.PIVSlotAuthentication),
		PivSlotCN(pivcert.PIVSlot(pivcert.PIVSlotAuthentication)))
	require.NoError(t, err)
	require.True(t, found, "the imported key must be found in the backend")
	assert.Equal(t, types.KeyOriginImported, origin,
		"the import path must record imported regardless of caller input")
}

// TestStampKeyOrigin_OverwritesCallerClaim covers the strip-and-recompute rule
// at the generic key seam, where a caller does supply attributes directly.
// A forged value must not survive into the backend's record.
func TestStampKeyOrigin_OverwritesCallerClaim(t *testing.T) {
	cases := []struct {
		name     string
		claimed  types.KeyOrigin
		pathIs   types.KeyOrigin
		expected types.KeyOrigin
	}{
		{"import path refuses a generated claim", types.KeyOriginGenerated, types.KeyOriginImported, types.KeyOriginImported},
		{"generate path refuses an imported claim", types.KeyOriginImported, types.KeyOriginGenerated, types.KeyOriginGenerated},
		{"empty claim is filled in", types.KeyOriginUnknown, types.KeyOriginImported, types.KeyOriginImported},
		{"a bogus value is replaced", types.KeyOrigin("trust-me"), types.KeyOriginGenerated, types.KeyOriginGenerated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{CN: "forged", KeyOrigin: tc.claimed}
			stampKeyOrigin(attrs, tc.pathIs)
			assert.Equal(t, tc.expected, attrs.KeyOrigin)
		})
	}

	// A nil attribute set must not panic: the seam is on a hot path and a nil
	// here is a caller bug that should surface as a validation error further
	// on, not as a crash inside provenance recording.
	assert.NotPanics(t, func() { stampKeyOrigin(nil, types.KeyOriginImported) })
}

// TestGeneratePIVKey_RecordsGeneratedOrigin is the companion to the import
// case: the generate path must record its own provenance, or "imported" would
// be the only value ever seen and the distinction would be meaningless.
func TestGeneratePIVKey_RecordsGeneratedOrigin(t *testing.T) {
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	realBackend, err := New(&BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	gen := newBackendPIVKeyGenerator(realBackend, types.StoreSoftware)
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cn := PivSlotCN(slot)

	_, err = gen.GeneratePIVKey(slot, "ecdsap256", cn)
	require.NoError(t, err)

	origin, found, err := gen.PIVKeyOrigin(slot, cn)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, types.KeyOriginGenerated, origin)
}

// TestSoftwareGenerator_RecordsOrigin covers the default fallback generator,
// which holds no KeyAttributes and needed its own place to keep the fact.
func TestSoftwareGenerator_RecordsOrigin(t *testing.T) {
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	gen := NewSoftwarePIVKeyGenerator()

	// A CN it has never seen is NOT FOUND, which is a different answer from an
	// unknown origin: this generator simply holds no key for that slot.
	origin, found, err := gen.PIVKeyOrigin(slot, "never-seen")
	require.NoError(t, err)
	assert.False(t, found, "a key this generator never created must report not-found")
	assert.Equal(t, types.KeyOriginUnknown, origin)

	_, err = gen.GeneratePIVKey(slot, "ecdsap256", "generated-cn")
	require.NoError(t, err)
	origin, found, err = gen.PIVKeyOrigin(slot, "generated-cn")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, types.KeyOriginGenerated, origin)

	_, err = gen.ImportPIVKey(context.Background(), slot, "ecdsap256", "imported-cn", key)
	require.NoError(t, err)
	origin, found, err = gen.PIVKeyOrigin(slot, "imported-cn")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, types.KeyOriginImported, origin)
}

// --- AttestPIVSlot refuses an imported key ---

// TestAttestPIVSlot_RefusesImportedKey is the refusal test, and it is the one
// that matters: a happy-path-only test passes against a build that attests
// imported keys perfectly happily.
//
// The slot holds a certificate, so attestation is mechanically possible — the
// refusal has to come from provenance, not from missing material. That is
// asserted by attesting the same slot successfully once the key is generated
// rather than imported.
func TestAttestPIVSlot_RefusesImportedKey(t *testing.T) {
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cn := PivSlotCN(slot)

	gen := NewSoftwarePIVKeyGenerator()
	store := setupPIVForOps(t, gen)

	// Seed the slot with a certificate so attestation material exists.
	cert, _ := makeSelfSignedECDSA(t, cn)
	require.NoError(t, store.Store(slot, cert))

	// With a generated key the slot attests.
	_, err := gen.GeneratePIVKey(slot, "ecdsap256", cn)
	require.NoError(t, err)
	resp, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.NoError(t, err, "a slot-generated key must remain attestable")
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Certificate)

	// Importing over the same slot makes it unattestable, with the same
	// certificate still sitting in the store.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = gen.ImportPIVKey(context.Background(), slot, "ecdsap256", cn, key)
	require.NoError(t, err)

	resp, err = AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.Error(t, err, "an imported key must not be attested")
	assert.Nil(t, resp, "no attestation material may be returned on refusal")
	assert.ErrorIs(t, err, ErrPIVKeyImportedNotAttestable)
}

// TestAttestPIVSlot_RefusesAfterImportVerb drives the refusal through the
// public verbs end to end, which is how a caller reaches it.
func TestAttestPIVSlot_RefusesAfterImportVerb(t *testing.T) {
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cn := PivSlotCN(slot)

	gen := NewSoftwarePIVKeyGenerator()
	store := setupPIVForOps(t, gen)
	cert, _ := makeSelfSignedECDSA(t, cn)
	require.NoError(t, store.Store(slot, cert))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = ImportPIVKey(context.Background(), &transport.ImportPIVKeyRequest{
		Backend:    "software",
		Slot:       "9a",
		PrivateKey: pemEncodePKCS8(t, key),
	})
	require.NoError(t, err)

	_, err = AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	assert.ErrorIs(t, err, ErrPIVKeyImportedNotAttestable)
}

// TestAttestPIVSlot_NoKeyHeldStillAttests pins the one case that is NOT a
// provenance judgement: the slot carries a certificate whose key this process
// does not hold, because the generator is a fresh in-memory one. There is no
// provenance to judge and no claim being strengthened, so attestation of the
// stored certificate proceeds as it always has. Refusing here would make every
// software-PIV slot unattestable after a restart.
func TestAttestPIVSlot_NoKeyHeldStillAttests(t *testing.T) {
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cn := PivSlotCN(slot)

	store := setupPIVForOps(t, NewSoftwarePIVKeyGenerator())
	cert, _ := makeSelfSignedECDSA(t, cn)
	require.NoError(t, store.Store(slot, cert))

	resp, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Certificate)
}

// originStub reports a fixed origin for a key it claims to hold, so the
// fail-closed rule can be exercised for every value including the one a
// correct write path never produces.
type originStub struct {
	pivGenStub
	origin types.KeyOrigin
	found  bool
}

func (o *originStub) PIVKeyOrigin(_ pivcert.PIVSlot, _ string) (types.KeyOrigin, bool, error) {
	return o.origin, o.found, nil
}

// TestAttestPIVSlot_FailsClosedOnUnrecognisedOrigin is the reason the check
// refuses anything that is not "generated" rather than refusing only
// "imported".
//
// A key record written by a build that HAS the origin field and did not set it
// is a defect, not a legacy record — the legacy inference is applied once at
// the metadata boundary, so a key that reaches here without an origin was
// written wrong. Attesting it would silently grant it the trust of a
// genuinely old key, and nothing would fail or warn. That is the shape this
// test exists to prevent.
func TestAttestPIVSlot_FailsClosedOnUnrecognisedOrigin(t *testing.T) {
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cn := PivSlotCN(slot)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name    string
		origin  types.KeyOrigin
		wantErr error
	}{
		{"generated attests", types.KeyOriginGenerated, nil},
		{"imported refuses", types.KeyOriginImported, ErrPIVKeyImportedNotAttestable},
		// No origin recorded is NOT a refusal: ImportPIVKey verifies the
		// provenance was written and rolls back if it was not, so a backend
		// that records nothing provably holds no imported key. Refusing here
		// would make every hardware-backed slot unattestable — including keys
		// generated in the slot, which is what attestation exists for.
		{"held key with no recorded origin attests", types.KeyOriginUnknown, nil},
		{"a value from the future refuses", types.KeyOrigin("escrowed"), ErrPIVKeyOriginUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &originStub{pivGenStub: pivGenStub{signer: key}, origin: tc.origin, found: true}
			store := setupPIVForOps(t, stub)
			cert, _ := makeSelfSignedECDSA(t, cn)
			require.NoError(t, store.Store(slot, cert))

			resp, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
				Backend: "software",
				Slot:    "9a",
			})
			if tc.wantErr == nil {
				require.NoError(t, err)
				assert.NotEmpty(t, resp.Certificate)
				return
			}
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// noProvenanceBackend models a backend whose ListKeys does not populate
// KeyOrigin — which is every backend except pkcs8 today. It stores nothing;
// the tests using it only exercise the provenance round-trip.
type noProvenanceBackend struct {
	Backend
	cn      string
	deleted bool
}

func (n *noProvenanceBackend) ListKeys(context.Context) ([]*types.KeyAttributes, error) {
	return []*types.KeyAttributes{{CN: n.cn, StoreType: types.StorePKCS11}}, nil
}

func (n *noProvenanceBackend) Signer(context.Context, *types.KeyAttributes) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, err
}

func (n *noProvenanceBackend) DeleteKey(context.Context, *types.KeyAttributes) error {
	n.deleted = true
	return nil
}

func (n *noProvenanceBackend) KeyProvider() types.KeyProvider { return noImportProvider{} }

// TestAttestPIVSlot_HardwareBackedSlotWithoutProvenanceStillAttests is the
// regression guard for the case that nearly shipped broken.
//
// Only the pkcs8 provider persists a key origin today. Every other backend —
// PKCS#11, TPM2, the cloud KMSes — reports no origin for keys it holds. A
// check that refused an unrecorded origin would therefore have made every
// HARDWARE-backed PIV slot unattestable, including keys generated in the slot,
// which is precisely the case PIV attestation exists for.
//
// It is safe to attest here because ImportPIVKey verifies the provenance was
// recorded and rolls the import back otherwise, so a backend that records
// nothing cannot be holding an imported key.
func TestAttestPIVSlot_HardwareBackedSlotWithoutProvenanceStillAttests(t *testing.T) {
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cn := PivSlotCN(slot)

	gen := newBackendPIVKeyGenerator(&noProvenanceBackend{cn: cn}, types.StorePKCS11)
	store := setupPIVForOps(t, gen)
	cert, _ := makeSelfSignedECDSA(t, cn)
	require.NoError(t, store.Store(slot, cert))

	resp, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.NoError(t, err, "a hardware-backed slot must not become unattestable")
	assert.NotEmpty(t, resp.Certificate)
}

// TestImportPIVKey_RefusesBackendThatDoesNotRecordProvenance is the other half
// of that bargain, and the reason attesting an unrecorded origin is safe.
//
// A backend that cannot record how a key arrived must not hold an imported
// key: nothing afterwards could tell it from a generated one. The import is
// refused and rolled back at the point an operator is present, rather than
// being discovered at attestation time when the only options left are to
// refuse a legitimate key or attest an illegitimate one.
func TestImportPIVKey_RefusesBackendThatDoesNotRecordProvenance(t *testing.T) {
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cn := PivSlotCN(slot)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// A provider that accepts the import ceremony but whose ListKeys records
	// no origin.
	be := &recordingLessBackend{noProvenanceBackend: noProvenanceBackend{cn: cn}}
	gen := newBackendPIVKeyGenerator(be, types.StorePKCS11)

	signer, err := gen.ImportPIVKey(context.Background(), slot, "ecdsap256", cn, key)

	require.Error(t, err, "an import whose provenance is not recorded must not succeed")
	assert.Nil(t, signer)
	assert.ErrorIs(t, err, ErrPIVImportProvenanceNotRecorded)
	assert.True(t, be.deleted, "the key must be rolled back, not left looking generated")
}

// recordingLessBackend accepts the import ceremony but records no provenance.
type recordingLessBackend struct {
	noProvenanceBackend
}

func (r *recordingLessBackend) KeyProvider() types.KeyProvider {
	return &acceptingImportProvider{}
}

// acceptingImportProvider satisfies the import ceremony and succeeds at it.
type acceptingImportProvider struct{ types.KeyProvider }

// Capabilities reports a hardware-backed provider, matching the
// types.StorePKCS11 storeType TestImportPIVKey_RefusesBackendThatDoesNotRecordProvenance
// constructs this generator with. ImportPIVKey's AttestLevel classification
// reads it before the provenance rollback runs, so it needs a real answer
// rather than the embedded nil interface.
func (a *acceptingImportProvider) Capabilities() types.Capabilities {
	return types.Capabilities{HardwareBacked: true}
}

func (a *acceptingImportProvider) GetImportParameters(_ context.Context, _ *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return &backend.ImportParameters{Algorithm: algorithm, ImportToken: []byte("t")}, nil
}

func (a *acceptingImportProvider) WrapKey(_ context.Context, _ []byte, _ *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("w")}, nil
}

func (a *acceptingImportProvider) UnwrapKey(_ context.Context, _ *backend.WrappedKeyMaterial, _ *backend.ImportParameters) ([]byte, error) {
	return nil, nil
}

func (a *acceptingImportProvider) ImportKey(_ context.Context, _ *types.KeyAttributes, _ *backend.WrappedKeyMaterial) error {
	return nil
}

func (a *acceptingImportProvider) ExportKey(_ context.Context, _ *types.KeyAttributes, _ backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return nil, nil
}

func (a *acceptingImportProvider) ExportKeyTo(_ context.Context, _ *types.KeyAttributes, _ *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return nil, nil
}

func (a *acceptingImportProvider) ExportKeyMaterial(_ context.Context, _ *types.KeyAttributes) ([]byte, error) {
	return nil, nil
}

// TestImportPIVKey_WipesTheRequestPIN proves the PIN a request carried is
// zeroed on the success path and on every refusal, since the consumer owns it.
func TestImportPIVKey_WipesTheRequestPIN(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	stub := newPIVImportStub()
	_ = setupPIVForOps(t, stub)

	for name, req := range map[string]*transport.ImportPIVKeyRequest{
		"success":          {Backend: "software", Slot: "9a", PrivateKey: pemEncodePKCS8(t, key)},
		"missing material": {Backend: "software", Slot: "9a"},
		"invalid slot":     {Backend: "software", Slot: "zz", PrivateKey: pemEncodePKCS8(t, key)},
	} {
		t.Run(name, func(t *testing.T) {
			pin := types.SecretBytes("123456")
			backing := []byte(pin)
			req.PIN = pin

			_, _ = ImportPIVKey(context.Background(), req)

			assert.Nil(t, req.PIN)
			assert.Equal(t, make([]byte, len(backing)), backing, "the PIN's backing array must be zeroed")
		})
	}

	_, err = ImportPIVKey(context.Background(), nil)
	assert.ErrorIs(t, err, ErrPIVKeyMaterialRequired)
}
