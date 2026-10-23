// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// admissionCase is one key-use path the key policy admits: prepare creates
// the keys the path needs and returns the call, and keyID names the key
// whose status and policy the case changes.
type admissionCase struct {
	name  string
	keyID string
	// allow is a usage a policy names to admit the path; empty when no
	// policy restricting the key's operations admits it.
	allow   transport.KeyUsage
	prepare func(t *testing.T, svc *XKMSService) func() error
}

// wrapByID wraps target under kek with AES key wrap.
func wrapByID(svc *XKMSService, kek, target string) (*transport.WrapKeyByIDResponse, error) {
	return svc.WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{
		WrappingKeyID: kek, WrappingKeyBackend: "software", TargetKeyID: target, TargetKeyBackend: "software", Algorithm: string(types.WrapAESKW),
	})
}

func prepareWrap(t *testing.T, svc *XKMSService) func() error {
	storeSymmetricKey(t, svc, "kek")
	storeSymmetricKey(t, svc, "target")
	return func() error {
		_, err := wrapByID(svc, "kek", "target")
		return err
	}
}

func admissionCases() []admissionCase {
	return []admissionCase{
		{name: "wrap key by id, wrapping key", keyID: "kek", allow: transport.KeyUsageWrapKey, prepare: prepareWrap},
		{name: "wrap key by id, wrapped key", keyID: "target", prepare: prepareWrap},
		{name: "unwrap key by id", keyID: "kek", allow: transport.KeyUsageWrapKey, prepare: func(t *testing.T, svc *XKMSService) func() error {
			storeSymmetricKey(t, svc, "kek")
			storeSymmetricKey(t, svc, "target")
			wrapped, err := wrapByID(svc, "kek", "target")
			require.NoError(t, err)
			calls := 0
			return func() error {
				calls++
				_, err := svc.UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{
					WrappedKey: wrapped.WrappedKey, UnwrappingKeyID: "kek", UnwrappingKeyBackend: "software", Algorithm: string(types.WrapAESKW),
					TargetKeyID: fmt.Sprintf("unwrapped-%d", calls), TargetKeyBackend: "software", TargetKeyType: "aes", TargetKeySize: 256,
				})
				return err
			}
		}},
		{name: "derive key ecdh", keyID: "ecdh", allow: transport.KeyUsageDeriveKey, prepare: func(t *testing.T, svc *XKMSService) func() error {
			storeTenantECDSAKey(t, svc, "", "ecdh")
			peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			der, err := x509.MarshalPKIXPublicKey(&peer.PublicKey)
			require.NoError(t, err)
			return func() error {
				_, err := svc.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{Backend: "software", KeyID: "ecdh", PeerPublicKey: der})
				return err
			}
		}},
		{name: "derive key", keyID: "kdf-base", allow: transport.KeyUsageDeriveKey, prepare: func(t *testing.T, svc *XKMSService) func() error {
			storeSymmetricKey(t, svc, "kdf-base")
			return func() error {
				_, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
					Backend: "software", KeyID: "kdf-base", Algorithm: "hkdf", Hash: "SHA-256", KeyLength: 32, Info: []byte("ctx"),
				})
				return err
			}
		}},
		{name: "seal", keyID: "sealer", allow: transport.KeyUsageEncrypt, prepare: func(t *testing.T, svc *XKMSService) func() error {
			storeTenantECDSAKey(t, svc, "", "sealer")
			return func() error {
				_, err := svc.Seal(context.Background(), &transport.SealRequest{Backend: "software", KeyID: "sealer", Data: []byte("sealed")})
				return err
			}
		}},
		{name: "unseal", keyID: "sealer", allow: transport.KeyUsageDecrypt, prepare: func(t *testing.T, svc *XKMSService) func() error {
			storeTenantECDSAKey(t, svc, "", "sealer")
			blob := sealAs(t, svc, "", "sealer", []byte("sealed"))
			return func() error {
				_, err := unsealAs(svc, "", "sealer", blob)
				return err
			}
		}},
		{name: "export key", keyID: "exported", prepare: func(t *testing.T, svc *XKMSService) func() error {
			storeSymmetricKey(t, svc, "exported")
			return func() error {
				_, err := svc.ExportKey(context.Background(), &transport.ExportKeyRequest{Backend: "software", KeyID: "exported", Algorithm: "RSAES_OAEP_SHA_256"})
				return err
			}
		}},
		{name: "export key material", keyID: "exported", prepare: func(t *testing.T, svc *XKMSService) func() error {
			storeSymmetricKey(t, svc, "exported")
			return func() error {
				_, err := svc.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{Backend: "software", KeyID: "exported"})
				return err
			}
		}},
		{name: "copy key", keyID: "exported", prepare: func(t *testing.T, svc *XKMSService) func() error {
			storeSymmetricKey(t, svc, "exported")
			calls := 0
			return func() error {
				calls++
				_, err := svc.CopyKey(context.Background(), &transport.CopyKeyRequest{
					SourceBackend: "software", SourceKeyID: "exported", DestBackend: "software", DestKeyID: fmt.Sprintf("copy-%d", calls),
				})
				return err
			}
		}},
	}
}

// admissionService is a software-backed service with a key policy store,
// so every key carries a status and a policy.
func admissionService(t *testing.T) *XKMSService {
	t.Helper()
	svc := setupDeriveService(t)
	store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	svc.SetKeyPolicyStore(store)
	return svc
}

func setPolicy(t *testing.T, svc *XKMSService, keyID string, usages ...transport.KeyUsage) {
	t.Helper()
	_, err := svc.SetKeyPolicy(context.Background(), &transport.SetKeyPolicyRequest{
		Backend: "software", KeyID: keyID, Policy: &transport.KeyPolicy{AllowedOperations: usages},
	})
	require.NoError(t, err)
}

// TestKeyUse_AdmittedThroughTheKeyPolicy proves every key-use path refuses
// a revoked or disabled key and one whose policy does not allow the
// operation, so revocation is terminal and no path bypasses the policy.
func TestKeyUse_AdmittedThroughTheKeyPolicy(t *testing.T) {
	for _, tc := range admissionCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("active", func(t *testing.T) {
				svc := admissionService(t)
				call := tc.prepare(t, svc)
				require.NoError(t, call())
			})
			t.Run("revoked", func(t *testing.T) {
				svc := admissionService(t)
				call := tc.prepare(t, svc)
				_, err := svc.RevokeKey(context.Background(), &transport.RevokeKeyRequest{Backend: "software", KeyID: tc.keyID, Reason: "compromised"})
				require.NoError(t, err)
				var unavailable *keypolicy.KeyUnavailableError
				require.ErrorAs(t, call(), &unavailable)
				assert.Equal(t, keypolicy.StatusRevoked, unavailable.Status)
			})
			t.Run("disabled", func(t *testing.T) {
				svc := admissionService(t)
				call := tc.prepare(t, svc)
				_, err := svc.UpdateKeyStatus(context.Background(), &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: tc.keyID, Status: transport.KeyStatusDisabled})
				require.NoError(t, err)
				var unavailable *keypolicy.KeyUnavailableError
				require.ErrorAs(t, call(), &unavailable)
				assert.Equal(t, keypolicy.StatusDisabled, unavailable.Status)
			})
			t.Run("operation not allowed", func(t *testing.T) {
				svc := admissionService(t)
				call := tc.prepare(t, svc)
				setPolicy(t, svc, tc.keyID, transport.KeyUsageVerifyMAC)
				var denied *keypolicy.PolicyDeniedError
				require.ErrorAs(t, call(), &denied)
			})
			if tc.allow == "" {
				return
			}
			t.Run("operation allowed", func(t *testing.T) {
				svc := admissionService(t)
				call := tc.prepare(t, svc)
				setPolicy(t, svc, tc.keyID, tc.allow)
				require.NoError(t, call())
			})
		})
	}
}

// TestWrapKeyByID_ConsumesTheSafetyLimit proves wrapping under an AES-GCM
// key counts toward its usage limits, so the limit trips.
func TestWrapKeyByID_ConsumesTheSafetyLimit(t *testing.T) {
	svc := admissionService(t)
	call := prepareWrap(t, svc)
	_, err := svc.SetKeySafety(context.Background(), &transport.SetKeySafetyRequest{Backend: "software", KeyID: "kek", MaxOperations: 1})
	require.NoError(t, err)

	require.NoError(t, call())
	var limit *keypolicy.SafetyLimitError
	require.ErrorAs(t, call(), &limit)
	assert.Equal(t, "operations", limit.Limit)
}

// TestGetPublicKey_SoftwareKeys proves the public key of each software
// asymmetric algorithm is returned as a SubjectPublicKeyInfo.
func TestGetPublicKey_SoftwareKeys(t *testing.T) {
	tests := []struct {
		algorithm string
		size      int
		want      crypto.PublicKey
	}{
		{algorithm: "rsa", size: 2048, want: &rsa.PublicKey{}},
		{algorithm: "ecdsa", want: &ecdsa.PublicKey{}},
		{algorithm: "ed25519", want: ed25519.PublicKey{}},
	}
	for _, tc := range tests {
		t.Run(tc.algorithm, func(t *testing.T) {
			svc := setupDeriveService(t)
			genKey(t, svc, "", "k", tc.algorithm, tc.size)
			resp, err := svc.GetPublicKey(context.Background(), &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k"})
			require.NoError(t, err)
			pub, err := x509.ParsePKIXPublicKey(resp.PublicKey)
			require.NoError(t, err)
			assert.IsType(t, tc.want, pub)
		})
	}
}

// TestGetPublicKey_X25519 proves an X25519 key's storage wrapper is
// unwrapped before it is marshalled. FIPS 140-only mode refuses X25519, so
// there the key is never created.
func TestGetPublicKey_X25519(t *testing.T) {
	svc := setupDeriveService(t)
	b, err := svc.resolveTenantBackend("software", "")
	require.NoError(t, err)
	_, err = b.KeyProvider().GenerateKey(context.Background(), &types.KeyAttributes{
		CN: "x", KeyType: types.KeyTypeEncryption, StoreType: types.StoreSoftware, X25519Attributes: &types.X25519Attributes{},
	})
	if fips140.Enforced() {
		require.Error(t, err)
		return
	}
	require.NoError(t, err)

	resp, err := svc.GetPublicKey(context.Background(), &transport.GetPublicKeyRequest{Backend: "software", KeyID: "x"})
	require.NoError(t, err)
	pub, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	require.NoError(t, err)
	ecdhPub, ok := pub.(*ecdh.PublicKey)
	require.True(t, ok)
	assert.Equal(t, ecdh.X25519(), ecdhPub.Curve())
}

// TestStandardPublicKey proves a standard key passes through and an X25519
// wrapper holding no key is refused.
func TestStandardPublicKey(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err := standardPublicKey(signer.Public())
	require.NoError(t, err)
	assert.Equal(t, signer.Public(), pub)

	_, err = standardPublicKey(&x25519.PublicKeyStorage{})
	var malformed *ErrMalformedPublicKey
	require.ErrorAs(t, err, &malformed)
}

// nonExtractableBackend is a Backend whose GetKey returns no private key,
// as the cloud KMS backends do for a non-extractable key. noSigner also
// refuses the signer, leaving the decrypter.
type nonExtractableBackend struct {
	Backend
	noSigner  bool
	noDecrypt bool
}

func (b *nonExtractableBackend) GetKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}

func (b *nonExtractableBackend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	if b.noSigner {
		return nil, errNoSigner
	}
	return b.Backend.Signer(ctx, attrs)
}

func (b *nonExtractableBackend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if b.noDecrypt {
		return nil, errNoSigner
	}
	return b.Backend.Decrypter(ctx, attrs)
}

var errNoSigner = errors.New("test: no signer")

// nonExtractableService serves the software backend through
// nonExtractableBackend under the name "software".
func nonExtractableService(t *testing.T, wrapper *nonExtractableBackend) *XKMSService {
	t.Helper()
	Reset()
	t.Cleanup(Reset)
	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)
	provider, err := factory(map[string]interface{}{"key_dir": "memory"})
	require.NoError(t, err)
	b, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	wrapper.Backend = b
	require.NoError(t, Initialize(&ServiceConfig{Backends: map[string]Backend{"software": wrapper}, DefaultBackend: "software"}))
	svc, err := Get()
	require.NoError(t, err)
	wireKeyVersionStore(t)
	return svc
}

// TestGetPublicKey_NonExtractableKey proves a key whose private material
// never leaves its backend still yields its public key, through the signer
// or the decrypter, and that a key offering neither is refused.
func TestGetPublicKey_NonExtractableKey(t *testing.T) {
	tests := []struct {
		name    string
		wrapper *nonExtractableBackend
		wantErr bool
	}{
		{name: "signer", wrapper: &nonExtractableBackend{}},
		{name: "decrypter", wrapper: &nonExtractableBackend{noSigner: true}},
		{name: "neither", wrapper: &nonExtractableBackend{noSigner: true, noDecrypt: true}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := nonExtractableService(t, tc.wrapper)
			genKey(t, svc, "", "k", "rsa", 2048)
			resp, err := svc.GetPublicKey(context.Background(), &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k"})
			if tc.wantErr {
				var op *ErrKeyOperation
				require.ErrorAs(t, err, &op)
				assert.ErrorIs(t, err, errNoSigner)
				return
			}
			require.NoError(t, err)
			pub, err := x509.ParsePKIXPublicKey(resp.PublicKey)
			require.NoError(t, err)
			assert.IsType(t, &rsa.PublicKey{}, pub)
		})
	}
}
