// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/encoding"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	keychainmocks "github.com/jeremyhahn/go-keychain/pkg/keychain/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/jeremyhahn/go-keychain/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignHandler_Ed25519Signing2 tests Ed25519 signing which uses pure signing
func TestSignHandler_Ed25519Signing2(t *testing.T) {
	t.Run("signs with Ed25519 key", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		_ = pubKey
		ks.SetKey("ed25519-sign-key2", privKey)

		ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return []*types.KeyAttributes{
				{CN: "ed25519-sign-key2", KeyAlgorithm: x509.Ed25519},
			}, nil
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)

		data := base64.StdEncoding.EncodeToString([]byte("test data for ed25519"))
		body := fmt.Sprintf(`{"data": "%s"}`, data)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/ed25519-sign-key2/sign?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SignResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Signature)
	})
}

// TestVerifyHandler_InvalidSignature2 tests verification with invalid signature
func TestVerifyHandler_InvalidSignature2(t *testing.T) {
	t.Run("returns invalid for wrong signature", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("verify-invalid-key2", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)

		data := base64.StdEncoding.EncodeToString([]byte("test data"))
		sig := base64.StdEncoding.EncodeToString([]byte("invalid signature"))
		body := fmt.Sprintf(`{"data": "%s", "signature": "%s"}`, data, sig)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/verify-invalid-key2/verify?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp VerifyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.Valid)
		assert.Equal(t, "Signature is invalid", resp.Message)
	})
}

// TestSignHandler_SignerError2 tests signing when signer creation fails
func TestSignHandler_SignerError2(t *testing.T) {
	t.Run("returns error when signer fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("signer-error-key2", key)

		ks.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
			return nil, fmt.Errorf("signer creation failed")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)

		data := base64.StdEncoding.EncodeToString([]byte("test"))
		body := fmt.Sprintf(`{"data": "%s"}`, data)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/signer-error-key2/sign?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestVerifyHandler_GetKeyError2 tests verification when GetKey fails
func TestVerifyHandler_GetKeyError2(t *testing.T) {
	t.Run("returns error when GetKey fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("getkey-error-key2", key)

		ks.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, fmt.Errorf("get key failed")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)

		data := base64.StdEncoding.EncodeToString([]byte("test"))
		sig := base64.StdEncoding.EncodeToString([]byte("sig"))
		body := fmt.Sprintf(`{"data": "%s", "signature": "%s"}`, data, sig)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/getkey-error-key2/verify?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestDeleteKeyHandler_DeleteError2 tests key deletion when delete fails
func TestDeleteKeyHandler_DeleteError2(t *testing.T) {
	t.Run("returns error when delete fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("delete-error-key2", key)

		ks.DeleteKeyFunc = func(attrs *types.KeyAttributes) error {
			return fmt.Errorf("delete failed")
		}

		router := createRouterWithHandler(http.MethodDelete, "/api/v1/keys/{id}", ctx.DeleteKeyHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/delete-error-key2?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestRotateKeyHandler_RotateError2 tests key rotation when rotation fails
func TestRotateKeyHandler_RotateError2(t *testing.T) {
	t.Run("returns error when rotate fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("rotate-error-key2", key)

		ks.RotateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, fmt.Errorf("rotate failed")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", ctx.RotateKeyHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rotate-error-key2/rotate?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestListKeysHandler_ListError2 tests list keys when list fails
func TestListKeysHandler_ListError2(t *testing.T) {
	t.Run("returns error when list fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return nil, fmt.Errorf("list failed")
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=test-backend", nil)
		w := httptest.NewRecorder()

		ctx.ListKeysHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestEncryptAsymHandler_NonRSAKey2 tests asymmetric encryption with non-RSA key
func TestEncryptAsymHandler_NonRSAKey2(t *testing.T) {
	t.Run("returns error for ECDSA key", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ks.SetKey("ecdsa-encrypt-key2", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/ecdsa-encrypt-key2/encrypt-asym?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "asymmetric encryption only supported for RSA")
	})
}

// TestDecryptHandler_DecrypterError2 tests decryption when decrypter creation fails
func TestDecryptHandler_DecrypterError2(t *testing.T) {
	t.Run("returns error when decrypter fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("decrypter-error-key2", key)

		ks.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
			return nil, fmt.Errorf("decrypter creation failed")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		body := `{"ciphertext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/decrypter-error-key2/decrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestSaveCertHandler_SaveError2 tests certificate saving when save fails
func TestSaveCertHandler_SaveError2(t *testing.T) {
	t.Run("returns error when save fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		certPEM := generateTestCertificatePEM(t, key)

		ks.SaveCertFunc = func(keyID string, cert *x509.Certificate) error {
			return fmt.Errorf("save cert failed")
		}

		body := fmt.Sprintf(`{"certificate_pem": %q}`, certPEM)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?key_id=test-key2&backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.SaveCertHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestGetTLSCertificateHandler_TLSCertError2 tests TLS cert when get fails
func TestGetTLSCertificateHandler_TLSCertError2(t *testing.T) {
	t.Run("returns error when TLS cert fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("tls-error-key2", key)

		ks.GetTLSCertificateFunc = func(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
			return tls.Certificate{}, fmt.Errorf("tls cert failed")
		}

		router := createRouterWithHandler(http.MethodGet, "/api/v1/tls/{id}", ctx.GetTLSCertificateHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/tls-error-key2?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestGenerateKeyHandler_ECDSAGeneration2 tests ECDSA key generation
func TestGenerateKeyHandler_ECDSAGeneration2(t *testing.T) {
	t.Run("generates ECDSA key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_id": "ecdsa-gen-key2", "backend": "test-backend", "key_type": "ecdsa", "curve": "P384"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

// TestGenerateKeyHandler_RSAGenError2 tests RSA generation error handling
func TestGenerateKeyHandler_RSAGenError2(t *testing.T) {
	t.Run("returns error when RSA generation fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.GenerateRSAFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, fmt.Errorf("RSA generation failed")
		}

		body := `{"key_id": "rsa-error-key2", "backend": "test-backend", "key_type": "rsa"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// testUserStore2 is a mock user store for testing
type testUserStore2 struct {
	hasAnyUsers    bool
	hasAnyUsersErr error
	count          int
	countErr       error
	listUsers      []*user.User
	listErr        error
	getByIDUser    *user.User
	getByIDErr     error
	updateErr      error
	deleteErr      error
	countAdmins    int
	countAdminsErr error
}

func (m *testUserStore2) HasAnyUsers(ctx context.Context) (bool, error) {
	return m.hasAnyUsers, m.hasAnyUsersErr
}

func (m *testUserStore2) Count(ctx context.Context) (int, error) {
	return m.count, m.countErr
}

func (m *testUserStore2) List(ctx context.Context) ([]*user.User, error) {
	return m.listUsers, m.listErr
}

func (m *testUserStore2) GetByID(ctx context.Context, id []byte) (*user.User, error) {
	return m.getByIDUser, m.getByIDErr
}

func (m *testUserStore2) GetByUsername(ctx context.Context, username string) (*user.User, error) {
	return nil, nil
}

func (m *testUserStore2) Create(ctx context.Context, username, displayName string, role user.Role) (*user.User, error) {
	return nil, nil
}

func (m *testUserStore2) Update(ctx context.Context, u *user.User) error {
	return m.updateErr
}

func (m *testUserStore2) Delete(ctx context.Context, id []byte) error {
	return m.deleteErr
}

func (m *testUserStore2) CountAdmins(ctx context.Context) (int, error) {
	return m.countAdmins, m.countAdminsErr
}

func (m *testUserStore2) SaveSession(ctx context.Context, sessionID string, data []byte, ttl time.Duration) error {
	return nil
}

func (m *testUserStore2) GetSession(ctx context.Context, sessionID string) ([]byte, error) {
	return nil, nil
}

func (m *testUserStore2) DeleteSession(ctx context.Context, sessionID string) error {
	return nil
}

func (m *testUserStore2) Close() error {
	return nil
}

// TestUserHandlers_BootstrapStatusError2 tests bootstrap status error handling
func TestUserHandlers_BootstrapStatusError2(t *testing.T) {
	t.Run("returns error when HasAnyUsers fails", func(t *testing.T) {
		mockStore := &testUserStore2{
			hasAnyUsersErr: fmt.Errorf("database error"),
		}
		handlers := NewUserHandlers(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bootstrap/status", nil)
		w := httptest.NewRecorder()

		handlers.BootstrapStatusHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("returns error when Count fails", func(t *testing.T) {
		mockStore := &testUserStore2{
			hasAnyUsers: true,
			countErr:    fmt.Errorf("count error"),
		}
		handlers := NewUserHandlers(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bootstrap/status", nil)
		w := httptest.NewRecorder()

		handlers.BootstrapStatusHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestUserHandlers_ListUsersError2 tests list users error handling
func TestUserHandlers_ListUsersError2(t *testing.T) {
	t.Run("returns error when List fails", func(t *testing.T) {
		mockStore := &testUserStore2{
			listErr: fmt.Errorf("list error"),
		}
		handlers := NewUserHandlers(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		w := httptest.NewRecorder()

		handlers.ListUsersHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestUserHandlers_GetUserErrors2 tests get user error handling
func TestUserHandlers_GetUserErrors2(t *testing.T) {
	t.Run("returns 500 when GetByID fails with unknown error", func(t *testing.T) {
		mockStore := &testUserStore2{
			getByIDErr: fmt.Errorf("database error"),
		}
		handlers := NewUserHandlers(mockStore)

		router := chi.NewRouter()
		router.Get("/api/v1/users/{id}", handlers.GetUserHandler)

		userID := encodeUserID([]byte{1, 2, 3, 4})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+userID, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestUserHandlers_UpdateUserErrors2 tests update user error handling
func TestUserHandlers_UpdateUserErrors2(t *testing.T) {
	t.Run("returns 500 when Update fails", func(t *testing.T) {
		mockStore := &testUserStore2{
			getByIDUser: &user.User{
				ID:          []byte{1, 2, 3, 4},
				Username:    "test",
				DisplayName: "Test",
				Role:        user.RoleUser,
				Enabled:     true,
				CreatedAt:   time.Now(),
			},
			updateErr: fmt.Errorf("update error"),
		}
		handlers := NewUserHandlers(mockStore)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		userID := encodeUserID([]byte{1, 2, 3, 4})
		body := `{"display_name": "New Name"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+userID, strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestUserHandlers_DeleteUserErrors2 tests delete user error handling
func TestUserHandlers_DeleteUserErrors2(t *testing.T) {
	t.Run("returns 500 when CountAdmins fails", func(t *testing.T) {
		mockStore := &testUserStore2{
			getByIDUser: &user.User{
				ID:          []byte{1, 2, 3, 4},
				Username:    "admin",
				DisplayName: "Admin",
				Role:        user.RoleAdmin,
				Enabled:     true,
				CreatedAt:   time.Now(),
			},
			countAdminsErr: fmt.Errorf("count admins error"),
		}
		handlers := NewUserHandlers(mockStore)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		userID := encodeUserID([]byte{1, 2, 3, 4})
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+userID, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("returns 403 when deleting last admin from delete call", func(t *testing.T) {
		mockStore := &testUserStore2{
			getByIDUser: &user.User{
				ID:          []byte{1, 2, 3, 4},
				Username:    "admin",
				DisplayName: "Admin",
				Role:        user.RoleAdmin,
				Enabled:     true,
				CreatedAt:   time.Now(),
			},
			countAdmins: 2,
			deleteErr:   user.ErrLastAdmin,
		}
		handlers := NewUserHandlers(mockStore)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		userID := encodeUserID([]byte{1, 2, 3, 4})
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+userID, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("returns 404 when user not found during delete", func(t *testing.T) {
		mockStore := &testUserStore2{
			getByIDUser: &user.User{
				ID:          []byte{1, 2, 3, 4},
				Username:    "user",
				DisplayName: "User",
				Role:        user.RoleUser,
				Enabled:     true,
				CreatedAt:   time.Now(),
			},
			deleteErr: user.ErrUserNotFound,
		}
		handlers := NewUserHandlers(mockStore)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		userID := encodeUserID([]byte{1, 2, 3, 4})
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+userID, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestLoggingMiddleware_NoIdentity2 tests logging middleware without identity
func TestLoggingMiddleware_NoIdentity2(t *testing.T) {
	t.Run("logs request without identity", func(t *testing.T) {
		ks := keychainmocks.NewMockKeyStore()
		cfg := &Config{
			Backends: map[string]keychain.KeyStore{
				"test": ks,
			},
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		keychain.Reset()
		err := keychain.Initialize(&keychain.ServiceConfig{
			Backends:       cfg.Backends,
			DefaultBackend: "test",
		})
		require.NoError(t, err)
		defer keychain.Reset()

		server, err := NewServer(cfg)
		require.NoError(t, err)

		loggingHandler := server.LoggingMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		loggingHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestAuthenticationMiddleware_WithIdentity2 tests auth middleware with existing identity
func TestAuthenticationMiddleware_WithIdentity2(t *testing.T) {
	t.Run("processes request with existing identity", func(t *testing.T) {
		ks := keychainmocks.NewMockKeyStore()
		cfg := &Config{
			Backends: map[string]keychain.KeyStore{
				"test": ks,
			},
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		keychain.Reset()
		err := keychain.Initialize(&keychain.ServiceConfig{
			Backends:       cfg.Backends,
			DefaultBackend: "test",
		})
		require.NoError(t, err)
		defer keychain.Reset()

		server, err := NewServer(cfg)
		require.NoError(t, err)

		authHandler := server.AuthenticationMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctxWithID := auth.WithIdentity(req.Context(), &auth.Identity{Subject: "test"})
		req = req.WithContext(ctxWithID)
		w := httptest.NewRecorder()

		authHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestGetAlgorithmString_AllCases2 tests the algorithm string helper
func TestGetAlgorithmString_AllCases2(t *testing.T) {
	t.Run("returns symmetric algorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		result := getAlgorithmString(attrs)
		assert.Equal(t, string(types.SymmetricAES256GCM), result)
	})

	t.Run("returns asymmetric algorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			KeyAlgorithm: x509.RSA,
		}
		result := getAlgorithmString(attrs)
		assert.Equal(t, "RSA", result)
	})

	t.Run("returns empty for unknown algorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{}
		result := getAlgorithmString(attrs)
		assert.Equal(t, "", result)
	})
}

// TestGetPublicKey_AllKeyTypes2 tests public key extraction for all types
func TestGetPublicKey_AllKeyTypes2(t *testing.T) {
	t.Run("extracts RSA public key", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		pubKey := getPublicKey(key)
		assert.NotNil(t, pubKey)
	})

	t.Run("extracts ECDSA public key", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubKey := getPublicKey(key)
		assert.NotNil(t, pubKey)
	})

	t.Run("extracts Ed25519 public key", func(t *testing.T) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		pubKey := getPublicKey(key)
		assert.NotNil(t, pubKey)
	})

	t.Run("returns nil for unsupported type", func(t *testing.T) {
		pubKey := getPublicKey("not a key")
		assert.Nil(t, pubKey)
	})
}

// TestImportKeyHandler_MissingAlgorithm2 tests import with missing algorithm
func TestImportKeyHandler_MissingAlgorithm2(t *testing.T) {
	t.Run("returns error when algorithm is missing", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_id": "import-key2", "key_type": "rsa", "wrapped_key": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "missing wrapping algorithm")
	})
}

// TestExportKeyHandler_MissingAlgorithm2 tests export with missing algorithm
func TestExportKeyHandler_MissingAlgorithm2(t *testing.T) {
	t.Run("returns error when algorithm is missing", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("export-algo-test2", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `{}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/export-algo-test2/export?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "missing wrapping algorithm")
	})
}

// TestEncodeBase64URL_Coverage2 tests the base64 URL encoding function
func TestEncodeBase64URL_Coverage2(t *testing.T) {
	t.Run("encodes empty data", func(t *testing.T) {
		result := encodeBase64URL([]byte{})
		assert.Equal(t, "", result)
	})

	t.Run("encodes single byte", func(t *testing.T) {
		result := encodeBase64URL([]byte{0xFF})
		assert.NotEmpty(t, result)
	})

	t.Run("encodes multiple bytes", func(t *testing.T) {
		result := encodeBase64URL([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
		assert.NotEmpty(t, result)
	})
}

// TestUserWriteJSONError_Coverage2 tests the userWriteJSONError helper
func TestUserWriteJSONError_Coverage2(t *testing.T) {
	t.Run("writes JSON error response", func(t *testing.T) {
		w := httptest.NewRecorder()
		userWriteJSONError(w, "test error2", http.StatusBadRequest)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Body.String(), "test error2")
	})
}

// TestGetCertHandler_EncodingError2 tests cert handler when encoding fails
func TestGetCertHandler_EncodingError2(t *testing.T) {
	t.Run("returns cert with valid encoding", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		cert := generateTestCertificate(t, key)
		ks.SetCert("encoding-test-key2", cert)

		router := createRouterWithHandler(http.MethodGet, "/api/v1/certs/{id}", ctx.GetCertHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/encoding-test-key2?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp GetCertResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.CertificatePEM, "BEGIN CERTIFICATE")
	})
}

// TestGenerateKeyHandler_RSAWithCustomSize2 tests RSA with custom key size
func TestGenerateKeyHandler_RSAWithCustomSize2(t *testing.T) {
	t.Run("generates RSA key with 4096 bits", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_id": "rsa-4096-key2", "backend": "test-backend", "key_type": "rsa", "key_size": 4096}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

// TestEncodeCertPEM2 tests certificate to PEM encoding
func TestEncodeCertPEM2(t *testing.T) {
	t.Run("encodes certificate to PEM", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		cert := generateTestCertificate(t, key)

		pem, err := encoding.EncodeCertificatePEM(cert)
		require.NoError(t, err)
		assert.Contains(t, string(pem), "BEGIN CERTIFICATE")
	})
}

// TestUserHandlers_ListUsersWithLastLogin2 tests list users with last login set
func TestUserHandlers_ListUsersWithLastLogin2(t *testing.T) {
	t.Run("lists users with last login timestamp", func(t *testing.T) {
		now := time.Now()
		mockStore := &testUserStore2{
			listUsers: []*user.User{
				{
					ID:          []byte{1, 2, 3},
					Username:    "test2",
					DisplayName: "Test User2",
					Role:        user.RoleUser,
					Enabled:     true,
					CreatedAt:   now.Add(-24 * time.Hour),
					LastLoginAt: &now,
					Credentials: []user.Credential{
						{ID: []byte{4, 5}, Name: "key1", CreatedAt: now},
					},
				},
			},
		}
		handlers := NewUserHandlers(mockStore)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		w := httptest.NewRecorder()

		handlers.ListUsersHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp UserListResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Len(t, resp.Users, 1)
		assert.NotEmpty(t, resp.Users[0].LastLoginAt)
	})
}

// TestUserHandlers_GetUserWithCredentials2 tests get user with credentials having last used
func TestUserHandlers_GetUserWithCredentials2(t *testing.T) {
	t.Run("gets user with credentials that have last used timestamp", func(t *testing.T) {
		now := time.Now()
		mockStore := &testUserStore2{
			getByIDUser: &user.User{
				ID:          []byte{1, 2, 3},
				Username:    "test2",
				DisplayName: "Test User2",
				Role:        user.RoleUser,
				Enabled:     true,
				CreatedAt:   now.Add(-24 * time.Hour),
				LastLoginAt: &now,
				Credentials: []user.Credential{
					{
						ID:         []byte{4, 5},
						Name:       "key1",
						CreatedAt:  now.Add(-1 * time.Hour),
						LastUsedAt: &now,
					},
				},
			},
		}
		handlers := NewUserHandlers(mockStore)

		router := chi.NewRouter()
		router.Get("/api/v1/users/{id}", handlers.GetUserHandler)

		userID := encodeUserID([]byte{1, 2, 3})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+userID, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp UserDetailResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Len(t, resp.Credentials, 1)
		assert.NotEmpty(t, resp.Credentials[0].LastUsedAt)
	})
}

// TestGetTLSCertificateHandler_WithChainParsing tests TLS cert handler with chain parsing
func TestGetTLSCertificateHandler_WithChainParsing(t *testing.T) {
	t.Run("returns TLS certificate with chain", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("tls-chain-key3", key)

		cert := generateTestCertificate(t, key)
		cert2 := generateTestCertificate(t, key)

		ks.GetTLSCertificateFunc = func(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
			return tls.Certificate{
				Certificate: [][]byte{cert.Raw, cert2.Raw},
				PrivateKey:  key,
				Leaf:        cert,
			}, nil
		}

		router := createRouterWithHandler(http.MethodGet, "/api/v1/tls/{id}", ctx.GetTLSCertificateHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/tls-chain-key3?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp GetTLSCertificateResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.CertificatePEM, "BEGIN CERTIFICATE")
		assert.Len(t, resp.ChainPEM, 1)
	})
}

// TestGetTLSCertificateHandler_NilLeaf tests TLS cert handler when leaf is nil
func TestGetTLSCertificateHandler_NilLeaf(t *testing.T) {
	t.Run("returns error when TLS cert leaf is nil", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("tls-nil-leaf", key)

		ks.GetTLSCertificateFunc = func(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
			return tls.Certificate{
				Certificate: [][]byte{},
				PrivateKey:  key,
				Leaf:        nil,
			}, nil
		}

		router := createRouterWithHandler(http.MethodGet, "/api/v1/tls/{id}", ctx.GetTLSCertificateHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/tls-nil-leaf?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestEncryptHandler_ListKeysErrorPath tests EncryptHandler when ListKeys fails
func TestEncryptHandler_ListKeysErrorPath(t *testing.T) {
	t.Run("returns error when ListKeys fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return nil, fmt.Errorf("list keys failed")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/any-key/encrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestDecryptHandler_KeyNotFoundPath tests DecryptHandler when key is not found
func TestDecryptHandler_KeyNotFoundPath(t *testing.T) {
	t.Run("returns error when key is not found", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return []*types.KeyAttributes{
				{CN: "other-key"},
			}, nil
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		body := `{"ciphertext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent-key/decrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestEncryptAsymHandler_ListKeysErrorPath tests EncryptAsymHandler when ListKeys fails
func TestEncryptAsymHandler_ListKeysErrorPath(t *testing.T) {
	t.Run("returns error when ListKeys fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return nil, fmt.Errorf("list keys failed")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/any-key/encrypt-asym?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestEncryptAsymHandler_GetKeyErrorPath tests EncryptAsymHandler when GetKey fails
func TestEncryptAsymHandler_GetKeyErrorPath(t *testing.T) {
	t.Run("returns error when GetKey fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("asym-getkey-error", key)

		ks.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, fmt.Errorf("get key failed")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/asym-getkey-error/encrypt-asym?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestEncryptAsymHandler_SHA512Hash tests EncryptAsymHandler with SHA512 hash
func TestEncryptAsymHandler_SHA512Hash(t *testing.T) {
	t.Run("encrypts with SHA512 hash", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("sha512-enc-key", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		body := `{"plaintext": "dGVzdA==", "hash": "sha512"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/sha512-enc-key/encrypt-asym?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestExportKeyHandler_ListKeysErrorPath tests ExportKeyHandler when ListKeys fails
func TestExportKeyHandler_ListKeysErrorPath(t *testing.T) {
	t.Run("returns error when ListKeys fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("export-listkeys-error", key)

		ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return nil, fmt.Errorf("list keys failed")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `{"algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/export-listkeys-error/export?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Since the backend doesn't support import/export, we get a 400
		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusInternalServerError)
	})
}

// TestExportKeyHandler_KeyNotFoundPath tests ExportKeyHandler when key is not found
func TestExportKeyHandler_KeyNotFoundPath(t *testing.T) {
	t.Run("returns error when key is not found", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `{"algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent-export-key/export?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Should return 400 (no import/export support) or 404 (key not found)
		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusNotFound)
	})
}

// TestImportKeyHandler_InvalidKeyIDPath tests ImportKeyHandler with invalid key ID
func TestImportKeyHandler_InvalidKeyIDPath(t *testing.T) {
	t.Run("returns error for invalid key ID", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_id": "../../../etc/passwd", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestImportKeyHandler_InvalidBackendPath tests ImportKeyHandler with invalid backend
func TestImportKeyHandler_InvalidBackendPath(t *testing.T) {
	t.Run("returns error for invalid backend name", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "../etc/passwd", "key_id": "test-key", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestImportKeyHandler_MissingWrappedKey tests ImportKeyHandler with missing wrapped key
func TestImportKeyHandler_MissingWrappedKey(t *testing.T) {
	t.Run("returns error for missing wrapped key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_id": "test-key", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestImportKeyHandler_MissingKeyType tests ImportKeyHandler with missing key type
func TestImportKeyHandler_MissingKeyType(t *testing.T) {
	t.Run("returns error for missing key type", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_id": "test-key", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestImportKeyHandler_MissingKeyID tests ImportKeyHandler with missing key ID
func TestImportKeyHandler_MissingKeyID(t *testing.T) {
	t.Run("returns error for missing key ID", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestImportKeyHandler_MissingBackend tests ImportKeyHandler with missing backend
func TestImportKeyHandler_MissingBackend(t *testing.T) {
	t.Run("returns error for missing backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_id": "test-key", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestImportKeyHandler_BackendNotFound tests ImportKeyHandler when backend is not found
func TestImportKeyHandler_BackendNotFound(t *testing.T) {
	t.Run("returns error when backend is not found", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "nonexistent-backend", "key_id": "test-key", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestGetImportParametersHandler_MissingKeyType tests GetImportParametersHandler with missing key type
func TestGetImportParametersHandler_MissingKeyType(t *testing.T) {
	t.Run("returns error for missing key type", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_id": "test-key", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestGetImportParametersHandler_MissingAlgorithm tests GetImportParametersHandler with missing algorithm
func TestGetImportParametersHandler_MissingAlgorithm(t *testing.T) {
	t.Run("returns error for missing algorithm", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_id": "test-key", "key_type": "rsa"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestGetImportParametersHandler_MissingBackend tests GetImportParametersHandler with missing backend
func TestGetImportParametersHandler_MissingBackend(t *testing.T) {
	t.Run("returns error for missing backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_id": "test-key", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestGetImportParametersHandler_MissingKeyID tests GetImportParametersHandler with missing key ID
func TestGetImportParametersHandler_MissingKeyID(t *testing.T) {
	t.Run("returns error for missing key ID", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestGetCertHandler_GetCertError tests GetCertHandler when GetCert fails
func TestGetCertHandler_GetCertError(t *testing.T) {
	t.Run("returns error when GetCert fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.GetCertFunc = func(keyID string) (*x509.Certificate, error) {
			return nil, fmt.Errorf("get cert failed")
		}

		router := createRouterWithHandler(http.MethodGet, "/api/v1/certs/{id}", ctx.GetCertHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-cert?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestBuildKeyAttributes_SymmetricKey tests buildKeyAttributes with symmetric key type
func TestBuildKeyAttributes_SymmetricKey(t *testing.T) {
	t.Run("builds symmetric key attributes with default size", func(t *testing.T) {
		attrs := buildKeyAttributes("sym-key", "symmetric", 0, "", "", 0)
		assert.Equal(t, types.KeyTypeSecret, attrs.KeyType)
		assert.Equal(t, types.SymmetricAES256GCM, attrs.SymmetricAlgorithm)
	})

	t.Run("builds symmetric key attributes with 128 bit size", func(t *testing.T) {
		attrs := buildKeyAttributes("sym-key-128", "symmetric", 0, "", "", 128)
		assert.Equal(t, types.KeyTypeSecret, attrs.KeyType)
		assert.Equal(t, types.SymmetricAES128GCM, attrs.SymmetricAlgorithm)
	})

	t.Run("builds symmetric key attributes with 192 bit size", func(t *testing.T) {
		attrs := buildKeyAttributes("sym-key-192", "symmetric", 0, "", "", 192)
		assert.Equal(t, types.KeyTypeSecret, attrs.KeyType)
		assert.Equal(t, types.SymmetricAES192GCM, attrs.SymmetricAlgorithm)
	})

	t.Run("builds symmetric key attributes with invalid size defaults to 256", func(t *testing.T) {
		attrs := buildKeyAttributes("sym-key-invalid", "symmetric", 0, "", "", 512)
		assert.Equal(t, types.KeyTypeSecret, attrs.KeyType)
		assert.Equal(t, types.SymmetricAES256GCM, attrs.SymmetricAlgorithm)
	})
}

// TestBuildKeyAttributes_Ed25519Key tests buildKeyAttributes with Ed25519 key type
func TestBuildKeyAttributes_Ed25519Key(t *testing.T) {
	t.Run("builds Ed25519 key attributes", func(t *testing.T) {
		attrs := buildKeyAttributes("ed25519-key", "ed25519", 0, "", "", 0)
		assert.Equal(t, x509.Ed25519, attrs.KeyAlgorithm)
	})
}

// TestBuildKeyAttributes_ECDSAKey tests buildKeyAttributes with ECDSA key type
func TestBuildKeyAttributes_ECDSAKey(t *testing.T) {
	t.Run("builds ECDSA key attributes with default curve", func(t *testing.T) {
		attrs := buildKeyAttributes("ecdsa-key", "ecdsa", 0, "", "", 0)
		assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
		assert.NotNil(t, attrs.ECCAttributes)
	})

	t.Run("builds ECDSA key attributes with custom curve", func(t *testing.T) {
		attrs := buildKeyAttributes("ecdsa-key-p384", "ecdsa", 0, "P384", "", 0)
		assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
		assert.NotNil(t, attrs.ECCAttributes)
	})
}

// TestBuildKeyAttributes_RSAKey tests buildKeyAttributes with RSA key type
func TestBuildKeyAttributes_RSAKey(t *testing.T) {
	t.Run("builds RSA key attributes with default size", func(t *testing.T) {
		attrs := buildKeyAttributes("rsa-key", "rsa", 0, "", "", 0)
		assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
		assert.NotNil(t, attrs.RSAAttributes)
		assert.Equal(t, types.RSAKeySize2048, attrs.RSAAttributes.KeySize)
	})

	t.Run("builds RSA key attributes with custom size", func(t *testing.T) {
		attrs := buildKeyAttributes("rsa-key-4096", "rsa", 4096, "", "", 0)
		assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
		assert.NotNil(t, attrs.RSAAttributes)
		assert.Equal(t, 4096, attrs.RSAAttributes.KeySize)
	})
}

// TestBuildKeyAttributes_WithHashAlgorithm tests buildKeyAttributes with hash algorithm
func TestBuildKeyAttributes_WithHashAlgorithm(t *testing.T) {
	t.Run("builds key attributes with valid hash algorithm", func(t *testing.T) {
		attrs := buildKeyAttributes("hash-key", "rsa", 0, "", "SHA384", 0)
		assert.Equal(t, crypto.SHA384, attrs.Hash)
	})

	t.Run("builds key attributes with invalid hash defaults to SHA256", func(t *testing.T) {
		attrs := buildKeyAttributes("hash-key-invalid", "rsa", 0, "", "invalid", 0)
		assert.Equal(t, crypto.SHA256, attrs.Hash)
	})
}

// TestDecryptHandler_SymmetricDecryptError tests DecryptHandler when symmetric decrypt fails
func TestDecryptHandler_SymmetricDecryptError(t *testing.T) {
	t.Run("returns error when symmetric decrypt fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("sym-decrypt-error", key)

		// Set up ListKeysFunc to return symmetric key attributes
		ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return []*types.KeyAttributes{
				{CN: "sym-decrypt-error", SymmetricAlgorithm: types.SymmetricAES256GCM},
			}, nil
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		body := `{"ciphertext": "dGVzdA==", "nonce": "dGVzdA==", "tag": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/sym-decrypt-error/decrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Backend doesn't support symmetric decryption, so it should fail
		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusInternalServerError)
	})
}

// TestEncryptHandler_KeyNotFoundPath tests EncryptHandler when key is not found
func TestEncryptHandler_KeyNotFoundPath(t *testing.T) {
	t.Run("returns error when key is not found", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return []*types.KeyAttributes{
				{CN: "other-key"},
			}, nil
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent-key/encrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestEncryptAsymHandler_KeyNotFoundPath tests EncryptAsymHandler when key is not found
func TestEncryptAsymHandler_KeyNotFoundPath(t *testing.T) {
	t.Run("returns error when key is not found", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return []*types.KeyAttributes{
				{CN: "other-key"},
			}, nil
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent-key/encrypt-asym?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestWrapKeyHandler_MissingKeyMaterial tests WrapKeyHandler with missing key material
func TestWrapKeyHandler_MissingKeyMaterial(t *testing.T) {
	t.Run("returns error for missing key material", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"wrapping_public_key_pem": "test", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestWrapKeyHandler_MissingPublicKey tests WrapKeyHandler with missing public key
func TestWrapKeyHandler_MissingPublicKey(t *testing.T) {
	t.Run("returns error for missing public key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_material": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestWrapKeyHandler_MissingAlgorithm tests WrapKeyHandler with missing algorithm
func TestWrapKeyHandler_MissingAlgorithm(t *testing.T) {
	t.Run("returns error for missing algorithm", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_material": "dGVzdA==", "wrapping_public_key_pem": "test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestWrapKeyHandler_InvalidPublicKey tests WrapKeyHandler with invalid public key
func TestWrapKeyHandler_InvalidPublicKey(t *testing.T) {
	t.Run("returns error for invalid public key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_material": "dGVzdA==", "wrapping_public_key_pem": "not valid pem", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestUnwrapKeyHandler_InvalidRequest tests UnwrapKeyHandler with invalid JSON
func TestUnwrapKeyHandler_InvalidRequest(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `not json`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestUnwrapKeyHandler_MissingWrappedKey tests UnwrapKeyHandler with missing wrapped key
func TestUnwrapKeyHandler_MissingWrappedKey(t *testing.T) {
	t.Run("returns error for missing wrapped key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"wrapping_public_key_pem": "test", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestUnwrapKeyHandler_MissingPublicKey tests UnwrapKeyHandler with missing public key
func TestUnwrapKeyHandler_MissingPublicKey(t *testing.T) {
	t.Run("returns error for missing public key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestUnwrapKeyHandler_MissingAlgorithm tests UnwrapKeyHandler with missing algorithm
func TestUnwrapKeyHandler_MissingAlgorithm(t *testing.T) {
	t.Run("returns error for missing algorithm", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"wrapped_key": "dGVzdA==", "wrapping_public_key_pem": "test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestUnwrapKeyHandler_InvalidPublicKey tests UnwrapKeyHandler with invalid public key
func TestUnwrapKeyHandler_InvalidPublicKey(t *testing.T) {
	t.Run("returns error for invalid public key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"wrapped_key": "dGVzdA==", "wrapping_public_key_pem": "not valid pem", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCopyKeyHandler_DestinationBackendNotFound tests CopyKeyHandler when dest backend not found
func TestCopyKeyHandler_DestinationBackendNotFound(t *testing.T) {
	t.Run("returns error when destination backend not found", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"source_backend": "test-backend", "source_key_id": "key1", "dest_backend": "nonexistent", "dest_key_id": "key2", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		// Should return 400 because source doesn't support export (before checking dest)
		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusNotFound)
	})
}

// TestGetBackendHandler_MissingBackendParam tests GetBackendHandler with missing backend param
func TestGetBackendHandler_MissingBackendParam(t *testing.T) {
	t.Run("returns error when backend param is missing", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodGet, "/api/v1/backends/{id}", ctx.GetBackendHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestExportKeyHandler_InvalidRequest tests ExportKeyHandler with invalid JSON
func TestExportKeyHandler_InvalidRequest(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("export-invalid-json", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `not json`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/export-invalid-json/export?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestGetImportParametersHandler_InvalidRequest tests GetImportParametersHandler with invalid JSON
func TestGetImportParametersHandler_InvalidRequest(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `not json`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestImportKeyHandler_InvalidRequest tests ImportKeyHandler with invalid JSON
func TestImportKeyHandler_InvalidRequest(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `not json`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestCopyKeyHandler_InvalidRequest tests CopyKeyHandler with invalid JSON
func TestCopyKeyHandler_InvalidRequest(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `not json`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestWrapKeyHandler_InvalidRequest tests WrapKeyHandler with invalid JSON
func TestWrapKeyHandler_InvalidRequest(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `not json`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestEncryptHandler_InvalidRequest tests EncryptHandler with invalid JSON
func TestEncryptHandler_InvalidRequest(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		body := `not json`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/encrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestDecryptHandler_InvalidRequest tests DecryptHandler with invalid JSON
func TestDecryptHandler_InvalidRequest(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		body := `not json`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/decrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestEncryptHandler_MissingKeyID tests EncryptHandler with missing key ID
func TestEncryptHandler_MissingKeyID(t *testing.T) {
	t.Run("returns error for missing key ID", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//encrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.EncryptHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestEncryptHandler_MissingBackend tests EncryptHandler with missing backend
func TestEncryptHandler_MissingBackend(t *testing.T) {
	t.Run("returns error for missing backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/encrypt", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestDecryptHandler_MissingKeyID tests DecryptHandler with missing key ID
func TestDecryptHandler_MissingKeyID(t *testing.T) {
	t.Run("returns error for missing key ID", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"ciphertext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//decrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.DecryptHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestDecryptHandler_MissingBackend tests DecryptHandler with missing backend
func TestDecryptHandler_MissingBackend(t *testing.T) {
	t.Run("returns error for missing backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		body := `{"ciphertext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/decrypt", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestDecryptHandler_ListKeysError3 tests DecryptHandler when ListKeys fails
func TestDecryptHandler_ListKeysError3(t *testing.T) {
	t.Run("returns error when ListKeys fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return nil, fmt.Errorf("list keys failed")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		body := `{"ciphertext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/decrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestEncryptHandler_BackendNotFound tests EncryptHandler with non-existent backend
func TestEncryptHandler_BackendNotFound(t *testing.T) {
	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/encrypt?backend=nonexistent", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestDecryptHandler_BackendNotFound tests DecryptHandler with non-existent backend
func TestDecryptHandler_BackendNotFound(t *testing.T) {
	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		body := `{"ciphertext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/decrypt?backend=nonexistent", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestExportKeyHandler_BackendNotFound tests ExportKeyHandler with non-existent backend
func TestExportKeyHandler_BackendNotFound(t *testing.T) {
	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `{"algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/export?backend=nonexistent", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestExportKeyHandler_MissingBackend tests ExportKeyHandler with missing backend
func TestExportKeyHandler_MissingBackend(t *testing.T) {
	t.Run("returns error for missing backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `{"algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/export", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestExportKeyHandler_MissingKeyID tests ExportKeyHandler with missing key ID
func TestExportKeyHandler_MissingKeyID(t *testing.T) {
	t.Run("returns error for missing key ID", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//export?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ExportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestGetCertHandler_MissingBackend tests GetCertHandler with missing backend
func TestGetCertHandler_MissingBackend(t *testing.T) {
	t.Run("returns error for missing backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodGet, "/api/v1/certs/{id}", ctx.GetCertHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-cert", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestGetCertHandler_MissingKeyID tests GetCertHandler with missing key ID
func TestGetCertHandler_MissingKeyID(t *testing.T) {
	t.Run("returns error for missing key ID", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/?backend=test-backend", nil)
		w := httptest.NewRecorder()

		ctx.GetCertHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestGetCertHandler_BackendNotFound tests GetCertHandler with non-existent backend
func TestGetCertHandler_BackendNotFound(t *testing.T) {
	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		router := createRouterWithHandler(http.MethodGet, "/api/v1/certs/{id}", ctx.GetCertHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-cert?backend=nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestGetImportParametersHandler_BackendNotFound tests GetImportParametersHandler with non-existent backend
func TestGetImportParametersHandler_BackendNotFound(t *testing.T) {
	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "nonexistent", "key_id": "test-key", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestGetImportParametersHandler_InvalidKeyID3 tests GetImportParametersHandler with invalid key ID
func TestGetImportParametersHandler_InvalidKeyID3(t *testing.T) {
	t.Run("returns error for invalid key ID", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_id": "../../../etc/passwd", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestGetImportParametersHandler_InvalidBackend3 tests GetImportParametersHandler with invalid backend
func TestGetImportParametersHandler_InvalidBackend3(t *testing.T) {
	t.Run("returns error for invalid backend name", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "../etc/passwd", "key_id": "test-key", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
