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

// Backend-binding integration test for the MakeCredential ceremony.
//
// This file proves the end-to-end FIDO2 backend-binding path: running a full
// CTAP2 MakeCredential ceremony while the CompositeBackend's default is set to
// a given backend type creates the new credential's key on THAT backend. It
// closes the gap between the composite routing tests (which call
// GenerateCredentialKey directly) and the authenticator ceremony.
//
// Three distinct backend types are covered in the default unit suite:
//
//   - BackendTypeSoftware: non-hardware-backed, exportable keys.
//   - BackendTypeTPM2:     hardware-backed, non-exportable (simulates TPM2).
//   - BackendTypeAWSKMS:   hardware-backed, non-exportable (simulates cloud KMS).
//
// No build tag is required: all providers are self-contained, in-process
// implementations backed by sync.Map key stores and real ECDSA key generation.
// They do not import any cloud SDK or hardware driver.

package authenticator

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// bindingTestProvider — self-contained in-process KeyProvider
// ---------------------------------------------------------------------------

// bindingTestProvider implements xkms.KeyProvider for TestMakeCredential_BindsToSelectedBackend.
// Each instance has an isolated in-memory key store so that LoadKey on the
// wrong backend correctly returns ErrKeyNotFound, letting the composite route
// to the backend that actually generated the key.
//
// The hwBacked flag controls how the provider responds to GetKey:
//
//   - false (software semantics): GetKey returns the real private key, so
//     BackendAdapter.ExportPrivateKey succeeds and privateKeyBytes is stored.
//
//   - true (hardware semantics): GetKey returns (nil, nil), causing
//     x509.MarshalPKCS8PrivateKey to fail inside the adapter, which maps to
//     ErrExportNotSupported. MakeCredential handles this gracefully and stores
//     the credential with nil PrivateKey (signing at assertion time uses
//     backend.Sign instead).
type bindingTestProvider struct {
	bt       xkms.BackendType
	hwBacked bool
	mu       sync.Mutex
	keys     map[string]crypto.Signer // CN → Signer
}

func newBindingTestProvider(bt xkms.BackendType, hwBacked bool) *bindingTestProvider {
	return &bindingTestProvider{
		bt:       bt,
		hwBacked: hwBacked,
		keys:     make(map[string]crypto.Signer),
	}
}

// Type returns the backend type supplied at construction.
func (p *bindingTestProvider) Type() xkms.BackendType { return p.bt }

// Capabilities reports hardware backing and exportability consistent with hwBacked.
func (p *bindingTestProvider) Capabilities() xkms.Capabilities {
	return xkms.Capabilities{
		Keys:           true,
		HardwareBacked: p.hwBacked,
		Signing:        true,
		Export:         !p.hwBacked,
	}
}

// GenerateKey creates a real ECDSA key, stores it, and returns it. Returning
// the real key (not nil) is the critical contract: BackendAdapter extracts the
// public key via a crypto.Signer type-switch immediately after GenerateKey.
func (p *bindingTestProvider) GenerateKey(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, &MessageError{Msg: "bindingTestProvider: nil key attributes"}
	}
	key, err := p.makeKey(attrs)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.keys[attrs.CN] = key
	p.mu.Unlock()
	return key, nil
}

// makeKey generates an ECDSA key matching attrs.ECCAttributes.Curve.
func (p *bindingTestProvider) makeKey(attrs *xkms.KeyAttributes) (crypto.Signer, error) {
	switch attrs.KeyAlgorithm {
	case x509.ECDSA:
		curve := elliptic.P256()
		if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
			curve = attrs.ECCAttributes.Curve
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, &MessageError{Msg: fmt.Sprintf("bindingTestProvider: unsupported key algorithm %v", attrs.KeyAlgorithm)}
	}
}

// GetKey simulates hardware non-exportability. For hw-backed providers it
// returns (nil, nil) — the key is present but private material is inaccessible —
// which causes BackendAdapter.ExportPrivateKey → ErrExportNotSupported.
// For software providers it returns the actual key.
func (p *bindingTestProvider) GetKey(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.PrivateKey, error) {
	p.mu.Lock()
	_, ok := p.keys[attrs.CN]
	p.mu.Unlock()
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("bindingTestProvider: key not found: %s", attrs.CN)}
	}
	if p.hwBacked {
		return nil, nil // present but not extractable — simulates hardware HSM
	}
	p.mu.Lock()
	key := p.keys[attrs.CN]
	p.mu.Unlock()
	return key, nil
}

// Signer returns the stored key as a crypto.Signer, enabling real ECDSA
// signatures in Sign and LoadKey probes regardless of hwBacked status.
func (p *bindingTestProvider) Signer(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.Signer, error) {
	p.mu.Lock()
	key, ok := p.keys[attrs.CN]
	p.mu.Unlock()
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("bindingTestProvider: key not found: %s", attrs.CN)}
	}
	return key, nil
}

// Decrypter is not used by the FIDO2 adapter and returns an error.
func (p *bindingTestProvider) Decrypter(ctx context.Context, attrs *xkms.KeyAttributes) (crypto.Decrypter, error) {
	return nil, &MessageError{Msg: "bindingTestProvider: decryption not supported"}
}

// DeleteKey removes the key from the in-memory store.
func (p *bindingTestProvider) DeleteKey(ctx context.Context, attrs *xkms.KeyAttributes) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.keys[attrs.CN]; !ok {
		return &MessageError{Msg: fmt.Sprintf("bindingTestProvider: key not found: %s", attrs.CN)}
	}
	delete(p.keys, attrs.CN)
	return nil
}

// ListKeys enumerates all keys in the store.
func (p *bindingTestProvider) ListKeys(ctx context.Context) ([]*xkms.KeyAttributes, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*xkms.KeyAttributes, 0, len(p.keys))
	for cn := range p.keys {
		out = append(out, &xkms.KeyAttributes{CN: cn})
	}
	return out, nil
}

// RotateKey is not exercised by the FIDO2 adapter.
func (p *bindingTestProvider) RotateKey(ctx context.Context, attrs *xkms.KeyAttributes) error {
	return &MessageError{Msg: "bindingTestProvider: key rotation not supported"}
}

// Close is a no-op; the in-memory store requires no cleanup.
func (p *bindingTestProvider) Close() error { return nil }

// Compile-time interface check.
var _ xkms.KeyProvider = (*bindingTestProvider)(nil)

// ---------------------------------------------------------------------------
// buildBindingComposite — helper to assemble the CompositeBackend under test
// ---------------------------------------------------------------------------

// bindingComposite holds the three adapters and the composite for assertion.
type bindingComposite struct {
	composite   *keybackend.CompositeBackend
	swProvider  *bindingTestProvider
	tpmProvider *bindingTestProvider
	awsProvider *bindingTestProvider
}

// buildBindingComposite creates three backend adapters — software, tpm2, and
// awskms — each backed by an isolated bindingTestProvider, and registers them
// in a CompositeBackend with software as the initial default. The composite is
// closed via t.Cleanup.
func buildBindingComposite(t *testing.T) *bindingComposite {
	t.Helper()

	swProvider := newBindingTestProvider(xkms.BackendTypeSoftware, false)
	tpmProvider := newBindingTestProvider(xkms.BackendTypeTPM2, true)
	awsProvider := newBindingTestProvider(xkms.BackendTypeAWSKMS, true)

	swAdapter := keybackend.NewBackendAdapter(swProvider, xkms.BackendTypeSoftware)
	tpmAdapter := keybackend.NewBackendAdapter(tpmProvider, xkms.BackendTypeTPM2)
	awsAdapter := keybackend.NewBackendAdapter(awsProvider, xkms.BackendTypeAWSKMS)

	composite := keybackend.NewCompositeBackend(xkms.BackendTypeSoftware)
	composite.Register(xkms.BackendTypeSoftware, swAdapter)
	composite.Register(xkms.BackendTypeTPM2, tpmAdapter)
	composite.Register(xkms.BackendTypeAWSKMS, awsAdapter)
	t.Cleanup(func() { _ = composite.Close() })

	return &bindingComposite{
		composite:   composite,
		swProvider:  swProvider,
		tpmProvider: tpmProvider,
		awsProvider: awsProvider,
	}
}

// newBindingAuthenticator creates an Authenticator whose KeyBackend is the
// supplied composite. PIN is enabled but not set, so the auto-grant user
// presence path is used (matching the pattern in createMakeCredentialTestAuthenticator).
func newBindingAuthenticator(t *testing.T, composite *keybackend.CompositeBackend) *Authenticator {
	t.Helper()

	storage := NewMemoryStorage()
	config := &Config{
		AAGUID:                     DefaultAAGUID,
		SupportedAlgorithms:        []int{COSEAlgES256},
		MaxCredentials:             100,
		MaxResidentCredentials:     25,
		PINMinLength:               4,
		PINMaxRetries:              8,
		EnablePIN:                  true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		Storage:                    storage,
		KeyBackend:                 composite,
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err, "NewAuthenticator must not fail")
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

// ---------------------------------------------------------------------------
// TestMakeCredential_BindsToSelectedBackend — capstone table-driven test
// ---------------------------------------------------------------------------

// TestMakeCredential_BindsToSelectedBackend verifies that a full CTAP2
// MakeCredential ceremony routes key generation to the CompositeBackend's
// current default and that the resulting credential is bound to that backend.
//
// For each target backend (software, tpm2, awskms) the test:
//
//  1. Sets the composite default to the target backend.
//  2. Builds an Authenticator with the composite as its KeyBackend.
//  3. Runs MakeCredential (ES256) and asserts the ceremony succeeds.
//  4. Asserts the stored credential's BackendID equals the target backend.
//  5. Calls composite.LoadKey and asserts the returned handle's BackendID
//     equals the target backend — proving the key physically lives there.
//  6. Calls composite.Sign with the loaded handle and asserts it succeeds —
//     proving the key is usable on its backend.
func TestMakeCredential_BindsToSelectedBackend(t *testing.T) {
	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "binding-test.example.com", Name: "Backend Binding Test RP"}
	pubKeyCredParams := []PublicKeyCredentialParam{
		{Type: "public-key", Alg: COSEAlgES256},
	}

	testCases := []struct {
		name string
		bt   xkms.BackendType
	}{
		{"software", xkms.BackendTypeSoftware},
		{"tpm2", xkms.BackendTypeTPM2},
		{"awskms", xkms.BackendTypeAWSKMS},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Each subtest owns its own composite so that auth.Close() (which
			// closes the composite) in one subtest's cleanup does not poison the
			// adapters needed by the next subtest.
			bc := buildBindingComposite(t)

			// Switch the composite default to the target backend BEFORE creating
			// the authenticator. The authenticator reads the backend via the
			// composite at ceremony time, so SetDefault must happen first.
			bc.composite.SetDefault(tc.bt)
			require.Equal(t, tc.bt, bc.composite.DefaultID(),
				"composite default must be set to target backend before ceremony")

			auth := newBindingAuthenticator(t, bc.composite)

			// Use a unique user per subtest to avoid credential conflicts.
			user := User{
				ID:   []byte("uid-" + tc.name),
				Name: tc.name + "@binding-test.example.com",
			}

			// ----------------------------------------------------------------
			// Step 1: Run the full MakeCredential ceremony.
			// ----------------------------------------------------------------

			resp, err := auth.MakeCredential(clientDataHash, rp, user, pubKeyCredParams, nil)
			require.NoError(t, err, "MakeCredential ceremony must succeed for backend %s", tc.name)
			require.NotNil(t, resp, "MakeCredentialResponse must not be nil")

			authData, err := ParseAuthData(resp.AuthData)
			require.NoError(t, err, "ParseAuthData must succeed")
			credentialID := authData.CredentialID
			require.NotEmpty(t, credentialID, "credentialID must be present in authData")

			// ----------------------------------------------------------------
			// Step 2: Verify the stored credential's BackendID.
			// ----------------------------------------------------------------

			storedCred, err := auth.storage.Load(credentialID)
			require.NoError(t, err, "credential must be retrievable from storage")
			require.Equal(t, tc.bt, storedCred.BackendID,
				"StoredCredential.BackendID must identify the backend that generated the key")

			// ----------------------------------------------------------------
			// Step 3: composite.LoadKey must return a handle for the correct backend.
			// Each bindingTestProvider has an isolated store, so only the provider
			// that generated the key will return a Signer for this credentialID.
			// The composite therefore routes the loaded handle to that backend.
			// ----------------------------------------------------------------

			handle, err := bc.composite.LoadKey(credentialID, COSEAlgES256)
			require.NoError(t, err, "composite.LoadKey must find the key for backend %s", tc.name)
			require.Equal(t, tc.bt, handle.BackendID(),
				"handle.BackendID() must identify the backend that owns the key")

			// ----------------------------------------------------------------
			// Step 4: composite.Sign with the loaded handle must succeed,
			// proving the key is fully usable on its backend.
			// ----------------------------------------------------------------

			testData := []byte("authData || clientDataHash — backend binding sign probe")
			sig, err := bc.composite.Sign(handle, COSEAlgES256, testData)
			require.NoError(t, err, "composite.Sign must succeed for backend %s", tc.name)
			require.NotEmpty(t, sig, "signature must be non-empty for backend %s", tc.name)
		})
	}
}

// ---------------------------------------------------------------------------
// TestMakeCredential_TwoCredentials_SeparateBackends
// ---------------------------------------------------------------------------

// TestMakeCredential_TwoCredentials_SeparateBackends verifies that two
// consecutive MakeCredential calls — each with a different composite default —
// place each credential on its respective backend. This confirms that changing
// the default between ceremonies has per-credential effect and that the two
// credentials do not share a backend.
func TestMakeCredential_TwoCredentials_SeparateBackends(t *testing.T) {
	bc := buildBindingComposite(t)

	clientDataHash := make([]byte, ClientDataHashSize)
	rp := RelyingParty{ID: "two-creds.example.com", Name: "Two Credentials Test RP"}
	pubKeyCredParams := []PublicKeyCredentialParam{
		{Type: "public-key", Alg: COSEAlgES256},
	}

	// Shared authenticator — same storage and composite across both ceremonies.
	auth := newBindingAuthenticator(t, bc.composite)

	// ---- Ceremony A: default = software ----

	bc.composite.SetDefault(xkms.BackendTypeSoftware)

	userA := User{ID: []byte("uid-a"), Name: "a@two-creds.example.com"}
	respA, err := auth.MakeCredential(clientDataHash, rp, userA, pubKeyCredParams, nil)
	require.NoError(t, err, "MakeCredential A (software) must succeed")

	authDataA, err := ParseAuthData(respA.AuthData)
	require.NoError(t, err)
	credIDA := authDataA.CredentialID
	require.NotEmpty(t, credIDA)

	storedA, err := auth.storage.Load(credIDA)
	require.NoError(t, err)
	require.Equal(t, xkms.BackendTypeSoftware, storedA.BackendID,
		"credential A must be bound to the software backend")

	// ---- Ceremony B: default = tpm2 ----

	bc.composite.SetDefault(xkms.BackendTypeTPM2)

	userB := User{ID: []byte("uid-b"), Name: "b@two-creds.example.com"}
	respB, err := auth.MakeCredential(clientDataHash, rp, userB, pubKeyCredParams, nil)
	require.NoError(t, err, "MakeCredential B (tpm2) must succeed")

	authDataB, err := ParseAuthData(respB.AuthData)
	require.NoError(t, err)
	credIDB := authDataB.CredentialID
	require.NotEmpty(t, credIDB)

	storedB, err := auth.storage.Load(credIDB)
	require.NoError(t, err)
	require.Equal(t, xkms.BackendTypeTPM2, storedB.BackendID,
		"credential B must be bound to the tpm2 backend")

	// ---- Verify cross-backend isolation via LoadKey ----

	handleA, err := bc.composite.LoadKey(credIDA, COSEAlgES256)
	require.NoError(t, err, "credential A must be loadable from composite")
	require.Equal(t, xkms.BackendTypeSoftware, handleA.BackendID(),
		"credential A's key must live on the software backend")

	handleB, err := bc.composite.LoadKey(credIDB, COSEAlgES256)
	require.NoError(t, err, "credential B must be loadable from composite")
	require.Equal(t, xkms.BackendTypeTPM2, handleB.BackendID(),
		"credential B's key must live on the tpm2 backend")

	// ---- Both keys must be independently signable ----

	probe := []byte("two-credentials sign probe")

	sigA, err := bc.composite.Sign(handleA, COSEAlgES256, probe)
	require.NoError(t, err, "signing with credential A (software) must succeed")
	require.NotEmpty(t, sigA)

	sigB, err := bc.composite.Sign(handleB, COSEAlgES256, probe)
	require.NoError(t, err, "signing with credential B (tpm2) must succeed")
	require.NotEmpty(t, sigB)
}
