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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers realKeyVaultClient (go-xkms#705): every Backend method is
// tested exclusively against MockKeyVaultClient (mock_client.go), so
// realKeyVaultClient's wire adapter -- the code that actually calls the
// Azure Key Vault REST API -- has never run. A mock proves Backend's own
// logic; it proves nothing about whether realKeyVaultClient forwards the
// right request to the right endpoint and hands back the right response
// field, which is exactly the class of bug (wrong path, swapped parameter, a
// rename that misses one call site) a mock cannot catch because it never
// invokes the real method body.
//
// fakeKeyVaultServer stands in for Key Vault's REST API, speaking the real
// challenge/bearer-token handshake
// (github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal) against
// the real generated client (azkeys.Client), so these tests exercise
// realKeyVaultClient exactly as production traffic does -- only the process
// on the other end of the socket is a fake, reached over TLS with the test
// server's own certificate (httptest.NewTLSServer), never
// InsecureSkipVerify.

// staticTokenCredential is a minimal azcore.TokenCredential returning a
// fixed bearer token with no network I/O, standing in for
// azidentity.ClientSecretCredential/DefaultAzureCredential in these tests.
type staticTokenCredential struct{}

func (staticTokenCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// fakeKeyVaultServer is a minimal Key Vault keys-REST implementation backing
// these tests. Every request without an Authorization header is challenged
// with a 401 + WWW-Authenticate, exactly like the real service, so the
// azkeys.Client's built-in challenge policy runs unmodified. It records the
// last request body it received per operation (so a test can assert the
// adapter forwarded the right fields) and returns a per-operation canned
// response or status code, set by the test before the call.
type fakeKeyVaultServer struct {
	mu       sync.Mutex
	lastReq  map[string][]byte
	statuses map[string]int
	bodies   map[string][]byte
}

func newFakeKeyVaultServer() *fakeKeyVaultServer {
	return &fakeKeyVaultServer{
		lastReq:  make(map[string][]byte),
		statuses: make(map[string]int),
		bodies:   make(map[string][]byte),
	}
}

// setResponse configures op's next successful response body.
func (f *fakeKeyVaultServer) setResponse(op string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies[op] = body
}

// setError configures op's next call to fail with the given HTTP status.
func (f *fakeKeyVaultServer) setError(op string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses[op] = status
}

// requestFor returns the raw body of the last authorized request seen for
// op.
func (f *fakeKeyVaultServer) requestFor(op string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq[op]
}

// classifyOp maps a Key Vault keys-REST method+path to the logical
// operation name used by setResponse/setError/requestFor.
func classifyOp(method, path string) string {
	switch {
	case method == http.MethodPost && strings.HasSuffix(path, "/create"):
		return "CreateKey"
	case method == http.MethodGet:
		return "GetKey"
	case method == http.MethodDelete:
		return "DeleteKey"
	case method == http.MethodPost && strings.HasSuffix(path, "/sign"):
		return "Sign"
	case method == http.MethodPost && strings.HasSuffix(path, "/verify"):
		return "Verify"
	case method == http.MethodPost && strings.HasSuffix(path, "/decrypt"):
		return "Decrypt"
	case method == http.MethodPut:
		return "ImportKey"
	case method == http.MethodPost && strings.HasSuffix(path, "/rotate"):
		return "RotateKey"
	default:
		return "Unknown:" + method + ":" + path
	}
}

func (f *fakeKeyVaultServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		// Elicit the challenge/bearer-token handshake exactly like the real
		// service: an unauthenticated probe gets a 401 naming the resource,
		// then the SDK retries with a token and the original body.
		w.Header().Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/fake-tenant", resource="https://vault.azure.net"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	op := classifyOp(r.Method, r.URL.Path)
	body, _ := io.ReadAll(r.Body)

	f.mu.Lock()
	f.lastReq[op] = body
	status := f.statuses[op]
	respBody := f.bodies[op]
	f.mu.Unlock()

	if status != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":{"code":"Injected","message":"injected failure"}}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if respBody != nil {
		_, _ = w.Write(respBody)
		return
	}
	_, _ = w.Write([]byte(`{}`))
}

// newFakeKeyVaultBackend starts an in-process fake Key Vault HTTPS server
// (httptest.NewTLSServer, never InsecureSkipVerify -- the returned client
// trusts the test server's own certificate through srv.Client()) and returns
// a *realKeyVaultClient dialed against it, plus the fake server so the test
// can configure responses and inspect what the adapter sent.
func newFakeKeyVaultBackend(t *testing.T) (*realKeyVaultClient, *fakeKeyVaultServer) {
	t.Helper()

	fake := newFakeKeyVaultServer()
	srv := httptest.NewTLSServer(http.HandlerFunc(fake.ServeHTTP))
	t.Cleanup(srv.Close)

	client, err := azkeys.NewClient(srv.URL, staticTokenCredential{}, &azkeys.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: srv.Client(),
		},
		DisableChallengeResourceVerification: true,
	})
	require.NoError(t, err)

	return &realKeyVaultClient{Client: client}, fake
}

// marshalOrFatal JSON-encodes v using the azkeys type's own MarshalJSON
// (base64url field encoding, etc.), so the fake server's canned responses
// are byte-for-byte what the real service would send.
func marshalOrFatal(t *testing.T, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	require.NoError(t, err)
	return body
}

// TestRealKeyVaultClient_WrapperMethods_RoundTrip drives every
// realKeyVaultClient method over the real HTTPS wire against
// fakeKeyVaultServer, and proves both that the request the fake server
// received is the one the caller built and that the response it returns
// comes back through unmodified.
func TestRealKeyVaultClient_WrapperMethods_RoundTrip(t *testing.T) {
	client, fake := newFakeKeyVaultBackend(t)
	ctx := context.Background()

	t.Run("CreateKey", func(t *testing.T) {
		fake.setResponse("CreateKey", marshalOrFatal(t, azkeys.KeyBundle{
			Key: &azkeys.JSONWebKey{Kty: ptrTo(azkeys.KeyTypeRSA), KID: ptrTo(azkeys.ID("https://mock-vault.vault.azure.net/keys/test-key/v1"))},
		}))
		resp, err := client.CreateKey(ctx, "test-key", azkeys.CreateKeyParameters{Kty: ptrTo(azkeys.KeyTypeRSA)}, nil)
		require.NoError(t, err)
		require.NotNil(t, resp.Key)
		assert.Equal(t, azkeys.KeyTypeRSA, *resp.Key.Kty)
		assert.Contains(t, string(fake.requestFor("CreateKey")), `"kty":"RSA"`)
	})

	t.Run("GetKey", func(t *testing.T) {
		fake.setResponse("GetKey", marshalOrFatal(t, azkeys.KeyBundle{
			Key: &azkeys.JSONWebKey{Kty: ptrTo(azkeys.KeyTypeRSA), KID: ptrTo(azkeys.ID("https://mock-vault.vault.azure.net/keys/test-key/v1"))},
		}))
		resp, err := client.GetKey(ctx, "test-key", "v1", nil)
		require.NoError(t, err)
		require.NotNil(t, resp.Key)
		assert.Equal(t, azkeys.ID("https://mock-vault.vault.azure.net/keys/test-key/v1"), *resp.Key.KID)
	})

	t.Run("DeleteKey", func(t *testing.T) {
		fake.setResponse("DeleteKey", marshalOrFatal(t, azkeys.DeletedKey{
			Key: &azkeys.JSONWebKey{Kty: ptrTo(azkeys.KeyTypeRSA)},
		}))
		resp, err := client.DeleteKey(ctx, "test-key", nil)
		require.NoError(t, err)
		require.NotNil(t, resp.Key)
		assert.Equal(t, azkeys.KeyTypeRSA, *resp.Key.Kty)
	})

	t.Run("Sign", func(t *testing.T) {
		fake.setResponse("Sign", marshalOrFatal(t, azkeys.KeyOperationResult{Result: []byte("signature-bytes")}))
		resp, err := client.Sign(ctx, "test-key", "v1", azkeys.SignParameters{
			Algorithm: ptrTo(azkeys.SignatureAlgorithmRS256),
			Value:     []byte("digest"),
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, []byte("signature-bytes"), resp.Result)
		assert.Contains(t, string(fake.requestFor("Sign")), `"alg":"RS256"`)
	})

	t.Run("Verify", func(t *testing.T) {
		fake.setResponse("Verify", marshalOrFatal(t, azkeys.KeyVerifyResult{Value: ptrTo(true)}))
		resp, err := client.Verify(ctx, "test-key", "v1", azkeys.VerifyParameters{
			Algorithm: ptrTo(azkeys.SignatureAlgorithmRS256),
			Digest:    []byte("digest"),
			Signature: []byte("sig"),
		}, nil)
		require.NoError(t, err)
		require.NotNil(t, resp.Value)
		assert.True(t, *resp.Value)
	})

	t.Run("Decrypt", func(t *testing.T) {
		fake.setResponse("Decrypt", marshalOrFatal(t, azkeys.KeyOperationResult{Result: []byte("plaintext-bytes")}))
		resp, err := client.Decrypt(ctx, "test-key", "v1", azkeys.KeyOperationParameters{
			Algorithm: ptrTo(azkeys.EncryptionAlgorithmRSAOAEP256),
			Value:     []byte("ciphertext"),
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, []byte("plaintext-bytes"), resp.Result)
	})

	t.Run("ImportKey", func(t *testing.T) {
		fake.setResponse("ImportKey", marshalOrFatal(t, azkeys.KeyBundle{
			Key: &azkeys.JSONWebKey{Kty: ptrTo(azkeys.KeyTypeRSA)},
		}))
		resp, err := client.ImportKey(ctx, "test-key", azkeys.ImportKeyParameters{
			Key: &azkeys.JSONWebKey{Kty: ptrTo(azkeys.KeyTypeRSA)},
		}, nil)
		require.NoError(t, err)
		require.NotNil(t, resp.Key)
		assert.Equal(t, azkeys.KeyTypeRSA, *resp.Key.Kty)
		assert.Contains(t, string(fake.requestFor("ImportKey")), `"kty":"RSA"`)
	})

	t.Run("RotateKey", func(t *testing.T) {
		fake.setResponse("RotateKey", marshalOrFatal(t, azkeys.KeyBundle{
			Key: &azkeys.JSONWebKey{Kty: ptrTo(azkeys.KeyTypeRSA), KID: ptrTo(azkeys.ID("https://mock-vault.vault.azure.net/keys/test-key/v2"))},
		}))
		resp, err := client.RotateKey(ctx, "test-key", nil)
		require.NoError(t, err)
		require.NotNil(t, resp.Key)
		assert.Equal(t, azkeys.ID("https://mock-vault.vault.azure.net/keys/test-key/v2"), *resp.Key.KID)
	})

	t.Run("Close", func(t *testing.T) {
		// realKeyVaultClient.Close is a documented no-op: the Azure SDK
		// client owns no closeable resource (azurekv.go:134-137).
		assert.NoError(t, client.Close())
	})
}

// TestRealKeyVaultClient_GetPublicKey_RoundTrip proves the composite
// GetPublicKey wrapper (azurekv.go:103) -- GetKey over the wire, then
// JWK-to-PKIX conversion -- returns a DER-encoded public key matching the
// RSA modulus/exponent the fake server sent, not just that no error
// occurred.
func TestRealKeyVaultClient_GetPublicKey_RoundTrip(t *testing.T) {
	client, fake := newFakeKeyVaultBackend(t)

	// Modulus/exponent of a throwaway 512-bit RSA key: small enough to keep
	// the test fast, and GetPublicKey never validates key strength -- it
	// only converts the JWK fields Azure returned.
	n := new(big.Int).SetBytes([]byte{
		0xc8, 0x38, 0x73, 0x56, 0x9c, 0xba, 0xc7, 0x1c, 0x73, 0x62, 0xe6, 0x9c, 0x5a, 0x2c, 0x8b, 0x0e,
		0x88, 0x1f, 0x5a, 0x27, 0x9f, 0x0c, 0x59, 0x2f, 0x71, 0xa4, 0x9f, 0x1e, 0xf1, 0x1b, 0x2c, 0x9a,
		0x1e, 0x6b, 0x3c, 0x7a, 0x2f, 0x0a, 0x2e, 0x33, 0x5c, 0x9a, 0x1f, 0x3d, 0x7b, 0x0e, 0x2a, 0x4c,
		0x9f, 0x1a, 0x5c, 0x3e, 0x0b, 0x7a, 0x2d, 0x9c, 0x1f, 0x3a, 0x5e, 0x0b, 0x7c, 0x2a, 0x4d, 0x9f,
	})
	e := big.NewInt(65537)

	fake.setResponse("GetKey", marshalOrFatal(t, azkeys.KeyBundle{
		Key: &azkeys.JSONWebKey{
			Kty: ptrTo(azkeys.KeyTypeRSA),
			N:   n.Bytes(),
			E:   e.Bytes(),
		},
	}))

	der, err := client.GetPublicKey(context.Background(), "test-key", "v1")
	require.NoError(t, err)
	require.NotEmpty(t, der)

	pub, err := x509.ParsePKIXPublicKey(der)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok, "expected *rsa.PublicKey, got %T", pub)
	assert.Equal(t, n, rsaPub.N)
	assert.Equal(t, int(e.Int64()), rsaPub.E)
}

// TestRealKeyVaultClient_WrapperMethods_ErrorPropagation proves an HTTP
// error the server returns reaches the caller as an *azcore.ResponseError
// carrying the real status code, rather than being swallowed or replaced --
// the failure mode a one-line forwarding bug (discarding the error,
// returning a zero value) would produce.
func TestRealKeyVaultClient_WrapperMethods_ErrorPropagation(t *testing.T) {
	client, fake := newFakeKeyVaultBackend(t)
	ctx := context.Background()

	fake.setError("GetKey", http.StatusNotFound)
	_, err := client.GetKey(ctx, "missing", "", nil)
	require.Error(t, err)
	assertStatusCode(t, err, http.StatusNotFound)

	fake.setError("Sign", http.StatusForbidden)
	_, err = client.Sign(ctx, "test-key", "v1", azkeys.SignParameters{
		Algorithm: ptrTo(azkeys.SignatureAlgorithmRS256),
		Value:     []byte("digest"),
	}, nil)
	require.Error(t, err)
	assertStatusCode(t, err, http.StatusForbidden)

	fake.setError("Decrypt", http.StatusBadRequest)
	_, err = client.Decrypt(ctx, "test-key", "v1", azkeys.KeyOperationParameters{
		Algorithm: ptrTo(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     []byte("ciphertext"),
	}, nil)
	require.Error(t, err)
	assertStatusCode(t, err, http.StatusBadRequest)
}

// TestRealKeyVaultClient_GetPublicKey_ErrorPropagation proves GetPublicKey
// surfaces the underlying GetKey failure rather than a nil-dereference
// panic when the fake server rejects the request.
func TestRealKeyVaultClient_GetPublicKey_ErrorPropagation(t *testing.T) {
	client, fake := newFakeKeyVaultBackend(t)

	fake.setError("GetKey", http.StatusNotFound)
	_, err := client.GetPublicKey(context.Background(), "missing", "")
	require.Error(t, err)
	assertStatusCode(t, err, http.StatusNotFound)
}

// TestRealKeyVaultClient_GetPublicKey_NoKeyInResponse proves GetPublicKey
// rejects a well-formed 200 response whose body carries no Key field,
// rather than dereferencing a nil *JSONWebKey.
func TestRealKeyVaultClient_GetPublicKey_NoKeyInResponse(t *testing.T) {
	client, fake := newFakeKeyVaultBackend(t)

	fake.setResponse("GetKey", marshalOrFatal(t, azkeys.KeyBundle{}))
	_, err := client.GetPublicKey(context.Background(), "test-key", "v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key in response")
}

// TestRealKeyVaultClient_GetPublicKey_UnconvertibleJWK proves GetPublicKey
// surfaces jwkToPublicKey's own validation failure (here, a JWK with no key
// type) wrapped, rather than panicking or returning a zero-value key.
func TestRealKeyVaultClient_GetPublicKey_UnconvertibleJWK(t *testing.T) {
	client, fake := newFakeKeyVaultBackend(t)

	fake.setResponse("GetKey", marshalOrFatal(t, azkeys.KeyBundle{Key: &azkeys.JSONWebKey{}}))
	_, err := client.GetPublicKey(context.Background(), "test-key", "v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to convert JWK to public key")
}

// assertStatusCode fails t unless err unwraps to an *azcore.ResponseError
// carrying the given HTTP status code.
func assertStatusCode(t *testing.T, err error, want int) {
	t.Helper()
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		t.Fatalf("expected *azcore.ResponseError in chain, got %T: %v", err, err)
	}
	assert.Equal(t, want, respErr.StatusCode)
}

func ptrTo[T any](v T) *T { return &v }
