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

package mcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// twoEmptyBackendServer builds an MCP server over two INDEPENDENT stores
// registered as "software" (the default) and "tpm2", each with its own storage
// and neither holding any key.
//
// It is the fixture for the key-lifecycle verbs, which create the key they
// operate on. twoBackendServer cannot serve them: it pre-creates the key in
// both stores, so it cannot distinguish "created in the named backend" from
// "created in the default one".
//
// Both names are served by the software implementation. What is under test is
// the routing, not the hardware.
func twoEmptyBackendServer(t *testing.T) *Server {
	t.Helper()
	xkms.Reset()
	t.Cleanup(cleanupXKMS)

	build := func() xkms.Backend {
		be, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
		require.NoError(t, err)
		ks, err := xkms.New(&xkms.BackendConfig{Backend: be, CertStorage: storage.New()})
		require.NoError(t, err)
		return ks
	}

	// "symmetric" is a third INDEPENDENT store, not an alias of the default.
	// It is what makes this transport's symmetric fallback observable: with the
	// shared fixture's aliasing, a key landing in the default backend and a key
	// landing in the symmetric one are indistinguishable.
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software":           build(),
			"tpm2":               build(),
			symmetricBackendName: build(),
		},
		DefaultBackend: "software",
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)

	server, err := NewServer(&Config{
		XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	return server
}

// keyIDsIn reports the common names the named backend holds, read straight
// from the backend rather than through any handler, so the assertion does not
// depend on the routing it is testing.
func keyIDsIn(t *testing.T, backendName string) []string {
	t.Helper()
	svc, err := xkms.Get()
	require.NoError(t, err)
	ks, err := svc.LookupBackend(backendName)
	require.NoError(t, err)
	attrs, err := ks.ListKeys(context.Background())
	require.NoError(t, err)

	names := make([]string, 0, len(attrs))
	for _, a := range attrs {
		names = append(names, a.CN)
	}
	return names
}

// rsaPublicFromPEM parses the PEM a handler reports into an RSA public key.
func rsaPublicFromPEM(t *testing.T, pemStr string) *rsa.PublicKey {
	t.Helper()
	require.NotEmpty(t, pemStr, "the handler reported no public key")
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	pub, ok := parsed.(*rsa.PublicKey)
	require.True(t, ok, "expected an RSA public key, got %T", parsed)
	return pub
}

// publicKeyIn returns the public half of the key the named backend holds under
// keyID, read directly from the backend.
func publicKeyIn(t *testing.T, backendName, keyID string) *rsa.PublicKey {
	t.Helper()
	svc, err := xkms.Get()
	require.NoError(t, err)
	ks, err := svc.LookupBackend(backendName)
	require.NoError(t, err)

	attrs, err := ks.ListKeys(context.Background())
	require.NoError(t, err)
	for _, a := range attrs {
		if a.CN != keyID {
			continue
		}
		key, keyErr := ks.GetKey(context.Background(), a)
		require.NoError(t, keyErr)
		signer, ok := key.(crypto.Signer)
		require.True(t, ok)
		pub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok)
		return pub
	}
	t.Fatalf("backend %q holds no key named %q", backendName, keyID)
	return nil
}

// TestHandler_GenerateKey_CreatesInNamedBackendNotDefault proves the request's
// backend is the one the key is created in.
//
// The handler resolved params.Backend only far enough to stamp
// KeyAttributes.StoreType and then generated with s.keystore, the process
// default backend. The key therefore landed in the default store carrying
// attributes that claimed a different one -- the same "named backend, default
// keystore" split that made the wrong key sign, and just as invisible: the
// response reported success and a public key either way.
//
// The oracle is which store holds the key afterwards, read directly from the
// backends. A response-only assertion passes against the old behaviour.
func TestHandler_GenerateKey_CreatesInNamedBackendNotDefault(t *testing.T) {
	server := twoEmptyBackendServer(t)
	const keyID = "routed-to-named-backend"

	result, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: keyID, Backend: "tpm2", KeyType: "rsa", Algorithm: "rsa", KeySize: 2048,
	})
	require.NoError(t, err)

	assert.Contains(t, keyIDsIn(t, "tpm2"), keyID,
		"the named backend must be the one that holds the generated key")
	assert.NotContains(t, keyIDsIn(t, "software"), keyID,
		"the default backend must not hold a key the caller asked another backend to create")

	// The reported public key must be the one the named backend actually holds,
	// not merely some well-formed key.
	reported := rsaPublicFromPEM(t, result.(GenerateKeyResult).PublicKeyPEM)
	assert.Equal(t, publicKeyIn(t, "tpm2", keyID).N, reported.N,
		"the reported public key must belong to the key in the named backend")
}

// TestHandler_GenerateKey_UnknownBackendRefused is the bad-input half: a
// backend that does not exist must be refused rather than quietly served by
// the default one.
func TestHandler_GenerateKey_UnknownBackendRefused(t *testing.T) {
	server := twoEmptyBackendServer(t)

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "unknown-backend-key", Backend: "nosuchbackend", KeyType: "rsa", Algorithm: "rsa", KeySize: 2048,
	})
	require.Error(t, err)

	assert.NotContains(t, keyIDsIn(t, "software"), "unknown-backend-key",
		"a refused request must not leave a key behind in the default backend")
}

// TestHandler_GetKey_ReadsNamedBackendNotDefault proves the request's backend
// decides which key is read.
//
// The handler resolved the key with findKeyByCN, which scans every backend and
// ignores params.Backend entirely, and then read it out of s.keystore. A
// caller naming the second backend was answered with the default backend's key
// whenever both held the same key ID -- and both public keys are well-formed,
// so only the key itself distinguishes right from wrong.
func TestHandler_GetKey_ReadsNamedBackendNotDefault(t *testing.T) {
	const keyID = "same-name-different-key"
	server, defaultPub, namedPub := twoBackendServer(t, keyID)

	result, err := mcpCall(t, server.handleGetKey, "xkms.getKey", GetKeyParams{
		KeyID: keyID, Backend: "tpm2",
	})
	require.NoError(t, err)

	reported := rsaPublicFromPEM(t, result.(GetKeyResult).PublicKeyPEM)
	assert.Equal(t, namedPub.N, reported.N, "the named backend's key must be the one returned")
	assert.NotEqual(t, defaultPub.N, reported.N, "the default backend's key must not be returned")
}

// TestHandler_GetKey_UnknownBackendRefused is the bad-input half.
func TestHandler_GetKey_UnknownBackendRefused(t *testing.T) {
	const keyID = "same-name-different-key"
	server, _, _ := twoBackendServer(t, keyID)

	_, err := mcpCall(t, server.handleGetKey, "xkms.getKey", GetKeyParams{
		KeyID: keyID, Backend: "nosuchbackend",
	})
	require.Error(t, err, "an unknown backend must be refused, not served by the default one")
}

// TestHandler_RotateKey_RotatesInNamedBackendNotDefault proves rotation
// replaces the key in the backend the request names.
//
// The handler resolved attributes with findKeyByCN, overwrote their StoreType
// from params.Backend, and then rotated with s.keystore. The default backend's
// key was replaced while the named backend's key was left untouched, and the
// response reported the new public key as though it belonged to the named
// backend.
//
// The oracle is which of the two stored keys changed. Rotation always produces
// a valid new key, so success alone proves nothing.
func TestHandler_RotateKey_RotatesInNamedBackendNotDefault(t *testing.T) {
	const keyID = "same-name-different-key"
	server, defaultPubBefore, namedPubBefore := twoBackendServer(t, keyID)

	result, err := mcpCall(t, server.handleRotateKey, "xkms.rotateKey", RotateKeyParams{
		KeyID: keyID, Backend: "tpm2",
	})
	require.NoError(t, err)

	namedPubAfter := publicKeyIn(t, "tpm2", keyID)
	defaultPubAfter := publicKeyIn(t, "software", keyID)

	assert.NotEqual(t, namedPubBefore.N, namedPubAfter.N,
		"the named backend's key must be the one that was replaced")
	assert.Equal(t, defaultPubBefore.N, defaultPubAfter.N,
		"the default backend's key must be left untouched")

	reported := rsaPublicFromPEM(t, result.(RotateKeyResult).PublicKeyPEM)
	assert.Equal(t, namedPubAfter.N, reported.N,
		"the reported public key must be the named backend's new key")
}

// TestHandler_RotateKey_UnknownBackendRefused is the bad-input half: an
// unknown backend must not silently rotate the default backend's key.
func TestHandler_RotateKey_UnknownBackendRefused(t *testing.T) {
	const keyID = "same-name-different-key"
	server, defaultPubBefore, _ := twoBackendServer(t, keyID)

	_, err := mcpCall(t, server.handleRotateKey, "xkms.rotateKey", RotateKeyParams{
		KeyID: keyID, Backend: "nosuchbackend",
	})
	require.Error(t, err)

	assert.Equal(t, defaultPubBefore.N, publicKeyIn(t, "software", keyID).N,
		"a refused request must not have rotated the default backend's key")
}

// TestHandler_GenerateKey_SymmetricUsesNamedBackend is the symmetric
// counterpart of the routing assertion: an AES key must be created in the
// backend the caller names.
func TestHandler_GenerateKey_SymmetricUsesNamedBackend(t *testing.T) {
	server := twoEmptyBackendServer(t)
	const keyID = "routed-symmetric-key"

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: keyID, Backend: "tpm2", KeyType: "symmetric", Algorithm: "aes256-gcm",
	})
	require.NoError(t, err)

	assert.Contains(t, keyIDsIn(t, "tpm2"), keyID,
		"the named backend must hold the generated symmetric key")
	assert.NotContains(t, keyIDsIn(t, "software"), keyID,
		"the default backend must not hold it")
}

// TestHandler_GenerateKey_StoreTypeMatchesBackend pins the two attributes
// that identify where a generated key lives (go-xkms#312): Backend names the
// registry entry the caller addressed, and StoreType reports what KIND of
// backend that is via its own Type() -- not a parse of the name.
//
// twoEmptyBackendServer registers a real software-implemented backend under
// the name "tpm2" specifically so this is observable: the fixture's own doc
// comment says "what is under test is the routing, not the hardware", so a
// key generated through it must carry Backend "tpm2" (the name that routed
// it there) and StoreType StoreSoftware (what the backend actually is), not
// StoreTPM2 -- which is what ParseStoreType("tpm2") would have produced
// before Backend existed, and is exactly the name/type conflation #312
// tracks.
func TestHandler_GenerateKey_StoreTypeMatchesBackend(t *testing.T) {
	server := twoEmptyBackendServer(t)
	const keyID = "store-type-follows-backend"

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: keyID, Backend: "tpm2", KeyType: "rsa", Algorithm: "rsa", KeySize: 2048,
	})
	require.NoError(t, err)

	svc, err := xkms.Get()
	require.NoError(t, err)
	ks, err := svc.LookupBackend("tpm2")
	require.NoError(t, err)
	attrs, err := ks.ListKeys(context.Background())
	require.NoError(t, err)

	var found *types.KeyAttributes
	for _, a := range attrs {
		if a.CN == keyID {
			found = a
			break
		}
	}
	require.NotNil(t, found, "the named backend must hold the key")
	assert.Equal(t, types.StoreSoftware, found.StoreType,
		"StoreType must report the backend's real kind, not a parse of its registry name")
}

// sha256Digest is a small helper keeping the signing assertions readable.
func sha256Digest(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// TestHandler_GenerateKey_GeneratedKeyIsUsableThroughTheNamedBackend closes
// the loop: a key created in the named backend must be the key that signs when
// the same backend is named on the signing request.
//
// This is the end-to-end consequence of the routing defect. Sign already
// delegates to the service and so resolves the named backend correctly, which
// means a key generated into the wrong store was simply not there.
func TestHandler_GenerateKey_GeneratedKeyIsUsableThroughTheNamedBackend(t *testing.T) {
	server := twoEmptyBackendServer(t)
	const keyID = "generated-then-signed"

	result, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: keyID, Backend: "tpm2", KeyType: "rsa", Algorithm: "rsa", KeySize: 2048,
	})
	require.NoError(t, err)
	reported := rsaPublicFromPEM(t, result.(GenerateKeyResult).PublicKeyPEM)

	message := []byte("sign me with the key that was just created")
	signed, err := mcpCall(t, server.handleSign, "xkms.sign", SignParams{
		KeyID: keyID, Backend: "tpm2", Data: message, Hash: "SHA-256",
	})
	require.NoError(t, err, "a key generated into the named backend must be signable there")

	assert.NoError(t,
		rsa.VerifyPKCS1v15(reported, crypto.SHA256, sha256Digest(message), signatureBytes(t, signed)),
		"the signature must verify under the key the generate call reported")
}

// ============================================================================
// Parameter arrival
//
// Routing a handler through the service layer is only correct if every
// parameter the request carries survives the trip. Each test below moves one
// field and reads the consequence off the key that was created, so dropping
// that field alone fails the test.
// ============================================================================

// TestHandler_GenerateKey_KeySizeArrives proves the requested RSA modulus size
// is the one generated. A dropped key_size still produces a valid RSA key --
// the servicer defaults to 2048 -- so the oracle is the modulus bit length.
func TestHandler_GenerateKey_KeySizeArrives(t *testing.T) {
	server := twoEmptyBackendServer(t)

	result, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "sized-key", Backend: "tpm2", KeyType: "rsa", Algorithm: "rsa", KeySize: 3072,
	})
	require.NoError(t, err)

	pub := rsaPublicFromPEM(t, result.(GenerateKeyResult).PublicKeyPEM)
	assert.Equal(t, 3072, pub.N.BitLen(),
		"the generated key must have the requested modulus size, not the default")
}

// TestHandler_GenerateKey_RejectsAnUnusableKeySize is the bad-input half.
func TestHandler_GenerateKey_RejectsAnUnusableKeySize(t *testing.T) {
	server := twoEmptyBackendServer(t)

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "tiny-key", Backend: "tpm2", KeyType: "rsa", Algorithm: "rsa", KeySize: 17,
	})
	require.Error(t, err, "a key size no RSA implementation accepts must be refused")
}

// TestHandler_GenerateKey_CurveArrives proves the named curve is the one
// generated. A dropped curve still produces a valid ECDSA key on P-256, so the
// oracle is the curve the returned public key sits on.
func TestHandler_GenerateKey_CurveArrives(t *testing.T) {
	server := twoEmptyBackendServer(t)

	result, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "curved-key", Backend: "tpm2", KeyType: "ecdsa", Algorithm: "ecdsa", Curve: "P-384",
	})
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(result.(GenerateKeyResult).PublicKeyPEM))
	require.NotNil(t, block)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	pub, ok := parsed.(*ecdsa.PublicKey)
	require.True(t, ok, "expected an ECDSA public key, got %T", parsed)

	assert.Equal(t, elliptic.P384(), pub.Curve,
		"the generated key must sit on the requested curve, not the default P-256")
}

// TestHandler_GenerateKey_RejectsAnUnknownCurve is the bad-input half, and the
// reason the curve name is validated at this boundary: the service layer
// substitutes P-256 for a name it cannot parse, which would hand the caller a
// key on a curve it did not ask for and report success.
func TestHandler_GenerateKey_RejectsAnUnknownCurve(t *testing.T) {
	server := twoEmptyBackendServer(t)

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "bad-curve-key", Backend: "tpm2", KeyType: "ecdsa", Algorithm: "ecdsa", Curve: "P-999",
	})
	require.Error(t, err)

	assert.NotContains(t, keyIDsIn(t, "tpm2"), "bad-curve-key",
		"a refused curve must not leave a key on some other curve behind")
}

// TestHandler_GenerateKey_AlgorithmArrivesIndependentlyOfKeyType proves the
// algorithm field is read when the key type names a purpose rather than an
// algorithm. Dropping it leaves the service with only "tls", which selects its
// ECDSA P-256 default -- a perfectly valid key of the wrong algorithm.
func TestHandler_GenerateKey_AlgorithmArrivesIndependentlyOfKeyType(t *testing.T) {
	server := twoEmptyBackendServer(t)

	result, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "purpose-and-algorithm", Backend: "tpm2", KeyType: "tls", Algorithm: "ed25519",
	})
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(result.(GenerateKeyResult).PublicKeyPEM))
	require.NotNil(t, block)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	assert.IsType(t, ed25519.PublicKey{}, parsed,
		"the algorithm field must select the algorithm when the key type names a purpose")
}

// TestHandler_GenerateKey_RejectsAnUnsupportedAlgorithm is the bad-input half.
func TestHandler_GenerateKey_RejectsAnUnsupportedAlgorithm(t *testing.T) {
	server := twoEmptyBackendServer(t)

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "bad-algorithm", Backend: "tpm2", KeyType: "tls", Algorithm: "rot13",
	})
	require.Error(t, err)
}

// TestHandler_GenerateKey_ExportableArrives proves the exportability flag
// reaches the stored attributes.
//
// The flag is invisible at creation time and decides whether the key can ever
// be read back, so the oracle is a later ExportKeyMaterial: it succeeds for a
// key generated exportable and fails for one that was not. Asserting only that
// generation succeeded passes whatever the flag was.
func TestHandler_GenerateKey_ExportableArrives(t *testing.T) {
	server := twoEmptyBackendServer(t)

	exportMaterial := func(keyID string) error {
		_, err := mcpCall(t, server.handleExportKeyMaterial, "xkms.exportKeyMaterial",
			transport.ExportKeyMaterialRequest{Backend: "tpm2", KeyID: keyID})
		return err
	}

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "exportable-key", Backend: "tpm2", KeyType: "symmetric",
		Algorithm: "aes256-gcm", Exportable: true,
	})
	require.NoError(t, err)
	assert.NoError(t, exportMaterial("exportable-key"),
		"a key generated exportable must be readable back")

	_, err = mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: "sealed-key", Backend: "tpm2", KeyType: "symmetric",
		Algorithm: "aes256-gcm", Exportable: false,
	})
	require.NoError(t, err)
	assert.Error(t, exportMaterial("sealed-key"),
		"a key generated non-exportable must not be readable back")
}

// TestHandler_GenerateKey_TenantIDForwarded proves the caller's tenant reaches
// the service layer.
//
// The oracle is key identity, not visibility. types.KeyAttributes.ID() prefixes
// the tenant, so the same common name generated once with a tenant and once
// without is two distinct stored keys; if the tenant were dropped on the way
// in, the second generation would address the identical identifier and replace
// the first, leaving one key behind instead of two.
//
// Identity remains the oracle rather than visibility even now that the key
// providers repopulate KeyAttributes.TenantID when they reconstruct attributes
// from a stored identifier: a listing that reported every key as belonging to
// whoever asked would also "show" a tenant its key, whereas two stored keys
// under one name can only exist if the tenant reached the store.
func TestHandler_GenerateKey_TenantIDForwarded(t *testing.T) {
	server := twoEmptyBackendServer(t)
	const keyID = "tenant-vs-shared"

	raw, err := json.Marshal(GenerateKeyParams{
		KeyID: keyID, Backend: "tpm2", KeyType: "rsa", Algorithm: "rsa", KeySize: 2048,
	})
	require.NoError(t, err)
	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: raw, ID: 1}

	_, err = server.handleGenerateKey(context.Background(), req)
	require.NoError(t, err)

	tenantCtx := auth.WithIdentity(context.Background(),
		&auth.Identity{Subject: "svc", TenantID: "tenant-a"})
	_, err = server.handleGenerateKey(tenantCtx, req)
	require.NoError(t, err)

	occurrences := 0
	for _, name := range keyIDsIn(t, "tpm2") {
		if name == keyID {
			occurrences++
		}
	}
	assert.Equal(t, 2, occurrences,
		"a tenant-scoped key and a shared key of the same name must be two distinct keys; "+
			"one means the tenant never reached the service layer")
}

// TestHandler_GenerateKey_DifferentTenantsDoNotCollide is the counterpart:
// two different tenants asking for the same name must not overwrite one
// another either.
func TestHandler_GenerateKey_DifferentTenantsDoNotCollide(t *testing.T) {
	server := twoEmptyBackendServer(t)
	const keyID = "shared-name-two-tenants"

	raw, err := json.Marshal(GenerateKeyParams{
		KeyID: keyID, Backend: "tpm2", KeyType: "rsa", Algorithm: "rsa", KeySize: 2048,
	})
	require.NoError(t, err)
	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: raw, ID: 1}

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		ctx := auth.WithIdentity(context.Background(),
			&auth.Identity{Subject: "svc", TenantID: tenant})
		_, err = server.handleGenerateKey(ctx, req)
		require.NoError(t, err, "tenant %s", tenant)
	}

	occurrences := 0
	for _, name := range keyIDsIn(t, "tpm2") {
		if name == keyID {
			occurrences++
		}
	}
	assert.Equal(t, 2, occurrences,
		"each tenant must get its own key, not a shared one the other overwrote")
}

// TestHandler_GetKey_ReportsTheResolvedBackend proves the backend named in the
// response is the one the service resolved, not the one the request spelled.
//
// The handler used to echo params.Backend straight back, so a request that
// named no backend was answered with an empty backend field while the key came
// from the default one -- and a request that named the wrong backend was
// answered with its own wrong name, which is what made the mismatch invisible.
func TestHandler_GetKey_ReportsTheResolvedBackend(t *testing.T) {
	const keyID = "same-name-different-key"
	server, _, _ := twoBackendServer(t, keyID)

	result, err := mcpCall(t, server.handleGetKey, "xkms.getKey", GetKeyParams{
		KeyID: keyID,
	})
	require.NoError(t, err)

	assert.Equal(t, "software", result.(GetKeyResult).Backend,
		"a request naming no backend must report the backend actually read")
}

// TestHandler_GenerateKey_SymmetricWithoutBackendUsesSymmetricBackend pins this
// transport's historical fallback: a symmetric key generated without an
// explicit backend goes to the "symmetric" backend, not to the service default.
//
// Only an independent third store can show this. If the fallback were dropped,
// the key would land in the default backend and every assertion that merely
// checked the call succeeded would still pass.
func TestHandler_GenerateKey_SymmetricWithoutBackendUsesSymmetricBackend(t *testing.T) {
	server := twoEmptyBackendServer(t)
	const keyID = "fallback-symmetric-key"

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: keyID, KeyType: "symmetric", Algorithm: "aes256-gcm",
	})
	require.NoError(t, err)

	assert.Contains(t, keyIDsIn(t, symmetricBackendName), keyID,
		"a symmetric key with no backend named must go to the symmetric backend")
	assert.NotContains(t, keyIDsIn(t, "software"), keyID,
		"it must not go to the service default backend")
}

// TestHandler_GenerateKey_AsymmetricWithoutBackendUsesTheDefault is the
// counterpart, and the reason the fallback is conditional: an asymmetric
// request naming no backend must still reach the service default.
func TestHandler_GenerateKey_AsymmetricWithoutBackendUsesTheDefault(t *testing.T) {
	server := twoEmptyBackendServer(t)
	const keyID = "default-asymmetric-key"

	_, err := mcpCall(t, server.handleGenerateKey, "xkms.generateKey", GenerateKeyParams{
		KeyID: keyID, KeyType: "rsa", Algorithm: "rsa", KeySize: 2048,
	})
	require.NoError(t, err)

	assert.Contains(t, keyIDsIn(t, "software"), keyID,
		"an asymmetric key with no backend named must go to the service default")
	assert.NotContains(t, keyIDsIn(t, symmetricBackendName), keyID,
		"the symmetric fallback must not capture an asymmetric request")
}
