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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// providerOnly narrows a key provider to types.KeyProvider, so the backend
// it belongs to does not offer import/export.
type providerOnly struct{ types.KeyProvider }

// noImportBackend is a registered backend that cannot run the import
// ceremony and records the store type each TLS retrieval carries:
// everything else is a real software backend.
type noImportBackend struct {
	xkms.Backend
	tlsStoreType atomic.Value
}

func (b *noImportBackend) KeyProvider() types.KeyProvider {
	return providerOnly{b.Backend.KeyProvider()}
}

func (b *noImportBackend) GetTLSCertificate(ctx context.Context, keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	b.tlsStoreType.Store(attrs.StoreType)
	return b.Backend.GetTLSCertificate(ctx, keyID, attrs)
}

// createTwoBackendServer returns a server whose default backend is
// "software" and whose second registered backend, "second", has its own key
// and certificate storage and no import/export capability. A handler that
// honours the backend name behaves differently on the two; one that quietly
// uses the default cannot tell them apart.
func createTwoBackendServer(t *testing.T) (*Server, *noImportBackend) {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	newKeystore := func() xkms.Backend {
		b, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
		require.NoError(t, err)
		ks, err := xkms.New(&xkms.BackendConfig{Backend: b, CertStorage: storage.New()})
		require.NoError(t, err)
		return ks
	}
	second := &noImportBackend{Backend: newKeystore()}
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": newKeystore(),
			"second":   second,
		},
		DefaultBackend: "software",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)
	return server, second
}

func rpc(t *testing.T, method string, params any) *JSONRPCRequest {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

// TestGetImportParameters_RunsAgainstTheNamedBackend proves the wrapping
// parameters come from the backend the request names: the default backend
// answers, and the named backend without import/export refuses, where a
// handler reading the default backend's provider would have answered for
// both and handed the caller the wrong ceremony.
func TestGetImportParameters_RunsAgainstTheNamedBackend(t *testing.T) {
	server, _ := createTwoBackendServer(t)

	_, err := server.handleGetImportParameters(context.Background(),
		rpc(t, "xkms.getImportParameters", GetImportParametersParams{KeyID: "routed", Backend: "software", Algorithm: "RSAES_OAEP_SHA_256"}))
	require.NoError(t, err, "the default backend supports import")

	_, err = server.handleGetImportParameters(context.Background(),
		rpc(t, "xkms.getImportParameters", GetImportParametersParams{KeyID: "routed", Backend: "second", Algorithm: "RSAES_OAEP_SHA_256"}))
	require.Error(t, err, "the named backend has no import capability")
	assert.Contains(t, err.Error(), backend.ErrImportNotSupported.Error(),
		"the refusal names the missing import half")
	assert.False(t, errors.Is(err, ErrInvalidBackend), "a registered backend is not an invalid one")
}

// TestGetTLSCertificate_LooksTheKeyUpInTheNamedBackend proves the key and
// its certificate are read from the backend the request names: a key and
// certificate that exist only in "second" are returned for that name and
// reported missing for the default backend, where a handler looking the key
// up in the default backend would report it missing for the name that holds
// it.
func TestGetTLSCertificate_LooksTheKeyUpInTheNamedBackend(t *testing.T) {
	server, second := createTwoBackendServer(t)

	// The key is provisioned by the backend itself, which records its real
	// store type; the service records a parse of the backend name, which is
	// StoreUnknown for a name like "second". saveCert has no backend
	// parameter either, so the certificate is saved into "second" directly,
	// the only place either exists.
	_, err := second.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "routed-tls",
		StoreType:     types.StoreSoftware,
		KeyType:       types.KeyTypeSigning,
		KeyAlgorithm:  x509.RSA,
		Hash:          crypto.SHA256,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "routed-tls"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &signer.PublicKey, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	require.NoError(t, second.SaveCert(context.Background(), "routed-tls", cert))

	result, err := server.handleGetTLSCertificate(context.Background(),
		rpc(t, "xkms.getTLSCertificate", GetTLSCertificateParams{KeyID: "routed-tls", Backend: "second"}))
	require.NoError(t, err, "the named backend holds the key and the certificate")
	tlsResult, ok := result.(transport.GetTLSCertificateResponse)
	require.True(t, ok)
	assert.Contains(t, tlsResult.CertificatePEM, "BEGIN CERTIFICATE")
	// The bundle is read from the certificate store. It carries no private
	// key, so the private key is never loaded to build it (go-xkms#1228).
	assert.Nil(t, second.tlsStoreType.Load(), "the private key must not be loaded for a public bundle")

	_, err = server.handleGetTLSCertificate(context.Background(),
		rpc(t, "xkms.getTLSCertificate", GetTLSCertificateParams{KeyID: "routed-tls"}))
	require.Error(t, err, "the default backend does not hold the certificate")
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code)
}

// TestAsymmetricCrypto_ChecksTheKeyInTheNamedBackend proves the key
// precheck of asymmetricEncrypt and asymmetricDecrypt runs in the backend
// the request names: a key that exists only in "second" passes the precheck
// for that name and is reported missing for the default, where a precheck
// against the default backend would refuse valid named-backend crypto with
// "key not found".
func TestAsymmetricCrypto_ChecksTheKeyInTheNamedBackend(t *testing.T) {
	server, _ := createTwoBackendServer(t)
	_, err := server.handleGenerateKey(context.Background(),
		rpc(t, "xkms.generateKey", GenerateKeyParams{KeyID: "routed-rsa", Backend: "second", Algorithm: "RSA", KeySize: 2048}))
	require.NoError(t, err)

	result, err := server.handleAsymmetricEncrypt(context.Background(),
		rpc(t, "xkms.asymmetricEncrypt", AsymmetricEncryptParams{KeyID: "routed-rsa", Backend: "second", Plaintext: []byte("routed")}))
	require.NoError(t, err, "the named backend holds the key")
	encrypted, ok := result.(AsymmetricEncryptResult)
	require.True(t, ok)

	result, err = server.handleAsymmetricDecrypt(context.Background(),
		rpc(t, "xkms.asymmetricDecrypt", AsymmetricDecryptParams{KeyID: "routed-rsa", Backend: "second", Ciphertext: encrypted.Ciphertext}))
	require.NoError(t, err, "the named backend holds the key")
	decrypted, ok := result.(AsymmetricDecryptResult)
	require.True(t, ok)
	assert.Equal(t, []byte("routed"), decrypted.Plaintext)

	_, err = server.handleAsymmetricEncrypt(context.Background(),
		rpc(t, "xkms.asymmetricEncrypt", AsymmetricEncryptParams{KeyID: "routed-rsa", Plaintext: []byte("routed")}))
	require.Error(t, err, "the default backend does not hold the key")
	assert.Contains(t, err.Error(), "key not found")

	_, err = server.handleAsymmetricDecrypt(context.Background(),
		rpc(t, "xkms.asymmetricDecrypt", AsymmetricDecryptParams{KeyID: "routed-rsa", Ciphertext: encrypted.Ciphertext}))
	require.Error(t, err, "the default backend does not hold the key")
	assert.Contains(t, err.Error(), "key not found")
}
