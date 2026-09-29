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

//go:build frost

package rest

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// frostBackendKeyStore is a test xkms.Backend whose KeyProvider() returns a
// real *frost.FrostBackend so the xkms service can resolve it.
type frostBackendKeyStore struct {
	*xkmsmocks.MockKeyStore
	provider types.KeyProvider
}

func (f *frostBackendKeyStore) KeyProvider() types.KeyProvider {
	return f.provider
}

// frostSecretBackend is an in-memory types.KeyProvider that stores raw FROST
// secret shares keyed by CN via the SealData field, mirroring the canonical
// frost secret-backend contract (see pkg/keyprovider/frost mock secret backend).
// frostSecretBackend is an in-memory types.SealingKeyProvider that "seals"
// FROST secret shares by prefixing them with a fixed marker, mirroring the
// secret-backend contract pkg/keyprovider/frost expects without a real
// cipher.
type frostSecretBackend struct{}

func newFrostSecretBackend() *frostSecretBackend {
	return &frostSecretBackend{}
}

func (m *frostSecretBackend) Type() types.BackendType { return types.BackendTypeSoftware }
func (m *frostSecretBackend) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Signing: true, Sealing: true}
}
func (m *frostSecretBackend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}
func (m *frostSecretBackend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("frost secret share not found")
}
func (m *frostSecretBackend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return nil
}
func (m *frostSecretBackend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	return nil, nil
}
func (m *frostSecretBackend) Signer(ctx context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}
func (m *frostSecretBackend) Decrypter(ctx context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not implemented")
}
func (m *frostSecretBackend) RotateKey(ctx context.Context, _ *types.KeyAttributes) error {
	return errors.New("not implemented")
}
func (m *frostSecretBackend) Close() error { return nil }

// frostSealMarker prefixes every "sealed" payload this fixture produces, so
// Unseal can detect (and reject) a payload it did not produce.
const frostSealMarker = "frost-test-sealed:"

func (m *frostSecretBackend) CanSeal() bool { return true }

func (m *frostSecretBackend) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	return &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: append([]byte(frostSealMarker), data...),
	}, nil
}

func (m *frostSecretBackend) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	if sealed == nil || len(sealed.Ciphertext) < len(frostSealMarker) || string(sealed.Ciphertext[:len(frostSealMarker)]) != frostSealMarker {
		return nil, errors.New("frost secret share not found")
	}
	return sealed.Ciphertext[len(frostSealMarker):], nil
}

// newFrostBackend builds a fully in-memory FROST backend backed by an
// in-memory secret share store.
func newFrostBackend(t *testing.T) *frost.FrostBackend {
	t.Helper()

	be, err := frost.NewBackend(&frost.Config{
		PublicStorage:    storage.NewMemory(),
		SecretBackend:    newFrostSecretBackend(),
		Algorithm:        types.FrostAlgorithmEd25519,
		DefaultThreshold: 2,
		DefaultTotal:     3,
	})
	require.NoError(t, err)
	return be
}

// setupFrostService registers a FROST backend with the global xkms service so
// the handlers' xkms service can locate it.
func setupFrostService(t *testing.T) *frost.FrostBackend {
	t.Helper()
	be := newFrostBackend(t)

	xkms.Reset()
	ks := &frostBackendKeyStore{
		MockKeyStore: xkmsmocks.NewMockKeyStore(),
		provider:     be,
	}
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"frost": ks},
		DefaultBackend: "frost",
	})
	require.NoError(t, err)
	t.Cleanup(func() { xkms.Reset() })
	return be
}

func frostRequest(t *testing.T, method, target string, body interface{}) *http.Request {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		rdr = bytes.NewReader(data)
	} else {
		rdr = bytes.NewReader(nil)
	}
	return httptest.NewRequest(method, target, rdr)
}

// withURLParam attaches a chi route param to the request context.
func withURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// TestFrostHexHelpers exercises the pure hex helpers directly.
func TestFrostHexHelpers(t *testing.T) {
	t.Run("encode/decode round trip", func(t *testing.T) {
		data := []byte{0xde, 0xad, 0xbe, 0xef}
		enc := hexEncode(data)
		assert.Equal(t, "deadbeef", enc)
		dec, err := hexDecode(enc)
		require.NoError(t, err)
		assert.Equal(t, data, dec)
	})

	t.Run("decode strips 0x prefix", func(t *testing.T) {
		dec, err := hexDecode("0xdeadbeef")
		require.NoError(t, err)
		assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, dec)

		dec, err = hexDecode("0XBEEF")
		require.NoError(t, err)
		assert.Equal(t, []byte{0xbe, 0xef}, dec)
	})

	t.Run("decode rejects invalid hex", func(t *testing.T) {
		_, err := hexDecode("zz")
		assert.Error(t, err)
	})
}

// TestFrostHandlers_NotConfigured verifies a service with no FROST backend
// refuses a FROST request with the service's ErrFrostNotConfigured.
func TestFrostHandlers_NotConfigured(t *testing.T) {
	setupTestService(t, "software")
	ctx := newTestHandlerContext()

	w := httptest.NewRecorder()
	ctx.FrostListKeysHandler(w, httptest.NewRequest(http.MethodGet, "/frost/keys", nil))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestFrostGenerateKeyHandler_Validation covers the request-validation branches.
func TestFrostGenerateKeyHandler_Validation(t *testing.T) {
	t.Run("bad json body", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/frost/keys", strings.NewReader("{bad"))
		w := httptest.NewRecorder()
		ctx.FrostGenerateKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("threshold too low", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/keys", FrostGenerateKeyRequest{Threshold: 1, Total: 3})
		w := httptest.NewRecorder()
		ctx.FrostGenerateKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("total less than threshold", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/keys", FrostGenerateKeyRequest{Threshold: 3, Total: 2})
		w := httptest.NewRecorder()
		ctx.FrostGenerateKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service not initialized", func(t *testing.T) {
		xkms.Reset()
		t.Cleanup(func() { xkms.Reset() })
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/keys", FrostGenerateKeyRequest{Threshold: 2, Total: 3, DealerMode: true})
		w := httptest.NewRecorder()
		ctx.FrostGenerateKeyHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("participant mode requires participant_id", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/keys", FrostGenerateKeyRequest{Threshold: 2, Total: 3})
		w := httptest.NewRecorder()
		ctx.FrostGenerateKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestFrostGenerateKeyHandler_DealerMode covers the dealer-mode success path.
func TestFrostGenerateKeyHandler_DealerMode(t *testing.T) {
	setupFrostService(t)
	ctx := newTestHandlerContext()

	req := frostRequest(t, http.MethodPost, "/frost/keys", FrostGenerateKeyRequest{
		KeyID:        "dealer-key",
		Threshold:    2,
		Total:        3,
		Participants: []string{"alice", "bob", "carol"},
		DealerMode:   true,
	})
	w := httptest.NewRecorder()
	ctx.FrostGenerateKeyHandler(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp FrostGenerateKeyResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "dealer-key", resp.KeyID)
	assert.Len(t, resp.Packages, 3)
	assert.NotEmpty(t, resp.GroupPublicKey)
	assert.Equal(t, "alice", resp.Packages[0].ParticipantName)
}

// TestFrostListKeysHandler_InvalidPageParam proves a non-numeric page
// parameter is rejected with 400 rather than silently defaulting to an
// unpaginated list.
func TestFrostListKeysHandler_InvalidPageParam(t *testing.T) {
	setupFrostService(t)
	ctx := newTestHandlerContext()

	w := httptest.NewRecorder()
	ctx.FrostListKeysHandler(w, httptest.NewRequest(http.MethodGet, "/frost/keys?page=notanumber", nil))
	require.Equal(t, http.StatusBadRequest, w.Code)
}

// TestFrostFullLifecycle wires a complete dealer-generate → import → list → get
// → nonces → sign → aggregate → verify flow through the HTTP handlers.
func TestFrostFullLifecycle(t *testing.T) {
	setupFrostService(t)
	ctx := newTestHandlerContext()

	// 1. Dealer-generate to obtain packages.
	genReq := frostRequest(t, http.MethodPost, "/frost/keys", FrostGenerateKeyRequest{
		KeyID:        "lifecycle-key",
		Threshold:    2,
		Total:        3,
		Participants: []string{"p1", "p2", "p3"},
		DealerMode:   true,
	})
	genW := httptest.NewRecorder()
	ctx.FrostGenerateKeyHandler(genW, genReq)
	require.Equal(t, http.StatusCreated, genW.Code)

	var genResp FrostGenerateKeyResponse
	require.NoError(t, json.NewDecoder(genW.Body).Decode(&genResp))
	require.Len(t, genResp.Packages, 3)

	// 2. Import this node's package (participant 1).
	impReq := frostRequest(t, http.MethodPost, "/frost/keys/import", FrostImportKeyRequest{
		Package: genResp.Packages[0],
	})
	impW := httptest.NewRecorder()
	ctx.FrostImportKeyHandler(impW, impReq)
	require.Equal(t, http.StatusCreated, impW.Code, impW.Body.String())

	var impResp FrostImportKeyResponse
	require.NoError(t, json.NewDecoder(impW.Body).Decode(&impResp))
	assert.True(t, impResp.Success)
	assert.Equal(t, "lifecycle-key", impResp.KeyID)

	// 3. List keys.
	listW := httptest.NewRecorder()
	ctx.FrostListKeysHandler(listW, httptest.NewRequest(http.MethodGet, "/frost/keys", nil))
	require.Equal(t, http.StatusOK, listW.Code)
	var listResp FrostListKeysResponse
	require.NoError(t, json.NewDecoder(listW.Body).Decode(&listResp))
	assert.GreaterOrEqual(t, listResp.Total, 1)

	// 4. Get the key.
	getReq := withURLParam(httptest.NewRequest(http.MethodGet, "/frost/keys/lifecycle-key", nil), "id", "lifecycle-key")
	getW := httptest.NewRecorder()
	ctx.FrostGetKeyHandler(getW, getReq)
	require.Equal(t, http.StatusOK, getW.Code, getW.Body.String())
	var getResp FrostKeyInfo
	require.NoError(t, json.NewDecoder(getW.Body).Decode(&getResp))
	assert.Equal(t, "lifecycle-key", getResp.KeyID)
	assert.NotEmpty(t, getResp.GroupPublicKey)

	// 5. Generate nonces.
	nonceReq := withURLParam(httptest.NewRequest(http.MethodPost, "/frost/keys/lifecycle-key/nonces", nil), "id", "lifecycle-key")
	nonceW := httptest.NewRecorder()
	ctx.FrostGenerateNoncesHandler(nonceW, nonceReq)
	require.Equal(t, http.StatusOK, nonceW.Code, nonceW.Body.String())
	var nonceResp FrostGenerateNoncesResponse
	require.NoError(t, json.NewDecoder(nonceW.Body).Decode(&nonceResp))
	assert.NotEmpty(t, nonceResp.HidingNonce)
	assert.NotEmpty(t, nonceResp.HidingCommitment)
}

// TestFrostImportKeyHandler_Errors covers import error branches.
func TestFrostImportKeyHandler_Errors(t *testing.T) {
	t.Run("bad json", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/frost/keys/import", strings.NewReader("{bad"))
		w := httptest.NewRecorder()
		ctx.FrostImportKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/keys/import", FrostImportKeyRequest{})
		w := httptest.NewRecorder()
		ctx.FrostImportKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid secret_share hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/keys/import", FrostImportKeyRequest{
			Package: FrostKeyPackage{KeyID: "k", SecretShare: "zz"},
		})
		w := httptest.NewRecorder()
		ctx.FrostImportKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid group_public_key hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/keys/import", FrostImportKeyRequest{
			Package: FrostKeyPackage{KeyID: "k", SecretShare: "deadbeef", GroupPublicKey: "zz"},
		})
		w := httptest.NewRecorder()
		ctx.FrostImportKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid verification_share hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/keys/import", FrostImportKeyRequest{
			Package: FrostKeyPackage{
				KeyID:              "k",
				SecretShare:        "deadbeef",
				GroupPublicKey:     "beef",
				VerificationShares: map[uint32]string{1: "zz"},
			},
		})
		w := httptest.NewRecorder()
		ctx.FrostImportKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestFrostGetKeyHandler_Errors covers get error branches.
func TestFrostGetKeyHandler_Errors(t *testing.T) {
	t.Run("missing id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/frost/keys/", nil), "id", "")
		w := httptest.NewRecorder()
		ctx.FrostGetKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("key not found", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/frost/keys/nope", nil), "id", "nope")
		w := httptest.NewRecorder()
		ctx.FrostGetKeyHandler(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestFrostDeleteKeyHandler covers delete success and error branches.
func TestFrostDeleteKeyHandler(t *testing.T) {
	t.Run("missing id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/frost/keys/", nil), "id", "")
		w := httptest.NewRecorder()
		ctx.FrostDeleteKeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("delete imported key", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()

		// Generate + import a key first.
		genReq := frostRequest(t, http.MethodPost, "/frost/keys", FrostGenerateKeyRequest{
			KeyID: "del-key", Threshold: 2, Total: 3, DealerMode: true,
		})
		genW := httptest.NewRecorder()
		ctx.FrostGenerateKeyHandler(genW, genReq)
		require.Equal(t, http.StatusCreated, genW.Code)
		var genResp FrostGenerateKeyResponse
		require.NoError(t, json.NewDecoder(genW.Body).Decode(&genResp))

		impReq := frostRequest(t, http.MethodPost, "/frost/keys/import", FrostImportKeyRequest{Package: genResp.Packages[0]})
		impW := httptest.NewRecorder()
		ctx.FrostImportKeyHandler(impW, impReq)
		require.Equal(t, http.StatusCreated, impW.Code)

		delReq := withURLParam(httptest.NewRequest(http.MethodDelete, "/frost/keys/del-key", nil), "id", "del-key")
		delW := httptest.NewRecorder()
		ctx.FrostDeleteKeyHandler(delW, delReq)
		require.Equal(t, http.StatusOK, delW.Code, delW.Body.String())
		var delResp FrostDeleteKeyResponse
		require.NoError(t, json.NewDecoder(delW.Body).Decode(&delResp))
		assert.True(t, delResp.Success)
	})
}

// TestFrostGenerateNoncesHandler_Errors covers nonce error branches.
func TestFrostGenerateNoncesHandler_Errors(t *testing.T) {
	t.Run("missing id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/frost/keys//nonces", nil), "id", "")
		w := httptest.NewRecorder()
		ctx.FrostGenerateNoncesHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unknown key", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/frost/keys/missing/nonces", nil), "id", "missing")
		w := httptest.NewRecorder()
		ctx.FrostGenerateNoncesHandler(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestFrostSignRoundHandler_Errors covers the validation branches of sign round.
func TestFrostSignRoundHandler_Errors(t *testing.T) {
	t.Run("missing id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := withURLParam(frostRequest(t, http.MethodPost, "/frost/keys//sign", FrostSignRoundRequest{}), "id", "")
		w := httptest.NewRecorder()
		ctx.FrostSignRoundHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad json", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/frost/keys/k/sign", strings.NewReader("{bad")), "id", "k")
		w := httptest.NewRecorder()
		ctx.FrostSignRoundHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid message hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := withURLParam(frostRequest(t, http.MethodPost, "/frost/keys/k/sign", FrostSignRoundRequest{Message: "zz"}), "id", "k")
		w := httptest.NewRecorder()
		ctx.FrostSignRoundHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid hiding_nonce hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := withURLParam(frostRequest(t, http.MethodPost, "/frost/keys/k/sign", FrostSignRoundRequest{
			Message: "beef", HidingNonce: "zz",
		}), "id", "k")
		w := httptest.NewRecorder()
		ctx.FrostSignRoundHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid binding_nonce hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := withURLParam(frostRequest(t, http.MethodPost, "/frost/keys/k/sign", FrostSignRoundRequest{
			Message: "beef", HidingNonce: "aa", BindingNonce: "zz",
		}), "id", "k")
		w := httptest.NewRecorder()
		ctx.FrostSignRoundHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid hiding_commitment hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := withURLParam(frostRequest(t, http.MethodPost, "/frost/keys/k/sign", FrostSignRoundRequest{
			Message: "beef", HidingNonce: "aa", BindingNonce: "bb", HidingCommitment: "zz",
		}), "id", "k")
		w := httptest.NewRecorder()
		ctx.FrostSignRoundHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid binding_commitment hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := withURLParam(frostRequest(t, http.MethodPost, "/frost/keys/k/sign", FrostSignRoundRequest{
			Message: "beef", HidingNonce: "aa", BindingNonce: "bb", HidingCommitment: "cc", BindingCommitment: "zz",
		}), "id", "k")
		w := httptest.NewRecorder()
		ctx.FrostSignRoundHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("key not found", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := withURLParam(frostRequest(t, http.MethodPost, "/frost/keys/missing/sign", FrostSignRoundRequest{
			Message: "beef", HidingNonce: "aa", BindingNonce: "bb", HidingCommitment: "cc", BindingCommitment: "dd",
			Commitments: []FrostCommitment{{ParticipantID: 1, HidingCommitment: "aa", BindingCommitment: "bb"}},
		}), "id", "missing")
		w := httptest.NewRecorder()
		ctx.FrostSignRoundHandler(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid commitment hiding hex", func(t *testing.T) {
		be := setupFrostService(t)
		ctx := newTestHandlerContext()
		seedFrostKey(t, ctx, be)
		req := withURLParam(frostRequest(t, http.MethodPost, "/frost/keys/seed/sign", FrostSignRoundRequest{
			Message: "beef", HidingNonce: "aa", BindingNonce: "bb", HidingCommitment: "cc", BindingCommitment: "dd",
			Commitments: []FrostCommitment{{ParticipantID: 1, HidingCommitment: "zz"}},
		}), "id", "seed")
		w := httptest.NewRecorder()
		ctx.FrostSignRoundHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// seedFrostKey dealer-generates and imports a key named "seed" so handlers that
// require an existing local key package have one to operate on.
func seedFrostKey(t *testing.T, ctx *HandlerContext, _ *frost.FrostBackend) {
	t.Helper()
	genReq := frostRequest(t, http.MethodPost, "/frost/keys", FrostGenerateKeyRequest{
		KeyID: "seed", Threshold: 2, Total: 3, DealerMode: true,
	})
	genW := httptest.NewRecorder()
	ctx.FrostGenerateKeyHandler(genW, genReq)
	require.Equal(t, http.StatusCreated, genW.Code)
	var genResp FrostGenerateKeyResponse
	require.NoError(t, json.NewDecoder(genW.Body).Decode(&genResp))

	impReq := frostRequest(t, http.MethodPost, "/frost/keys/import", FrostImportKeyRequest{Package: genResp.Packages[0]})
	impW := httptest.NewRecorder()
	ctx.FrostImportKeyHandler(impW, impReq)
	require.Equal(t, http.StatusCreated, impW.Code)
}

// TestFrostAggregateHandler_Errors covers aggregate error branches.
func TestFrostAggregateHandler_Errors(t *testing.T) {
	t.Run("bad json", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/frost/aggregate", strings.NewReader("{bad"))
		w := httptest.NewRecorder()
		ctx.FrostAggregateHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/aggregate", FrostAggregateRequest{})
		w := httptest.NewRecorder()
		ctx.FrostAggregateHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid message hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/aggregate", FrostAggregateRequest{KeyID: "k", Message: "zz"})
		w := httptest.NewRecorder()
		ctx.FrostAggregateHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid commitment hiding hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/aggregate", FrostAggregateRequest{
			KeyID: "k", Message: "beef",
			Commitments: []FrostCommitment{{ParticipantID: 1, HidingCommitment: "zz"}},
		})
		w := httptest.NewRecorder()
		ctx.FrostAggregateHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid commitment binding hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/aggregate", FrostAggregateRequest{
			KeyID: "k", Message: "beef",
			Commitments: []FrostCommitment{{ParticipantID: 1, HidingCommitment: "aa", BindingCommitment: "zz"}},
		})
		w := httptest.NewRecorder()
		ctx.FrostAggregateHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid share hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/aggregate", FrostAggregateRequest{
			KeyID: "k", Message: "beef",
			Shares: []FrostSignatureShare{{ParticipantID: 1, Share: "zz"}},
		})
		w := httptest.NewRecorder()
		ctx.FrostAggregateHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("no shares is refused", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/aggregate", FrostAggregateRequest{
			KeyID: "k", Message: "beef",
			Commitments: []FrostCommitment{{ParticipantID: 1, HidingCommitment: "aa", BindingCommitment: "bb"}},
		})
		w := httptest.NewRecorder()
		ctx.FrostAggregateHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestFrostVerifyHandler_Errors covers verify error branches.
func TestFrostVerifyHandler_Errors(t *testing.T) {
	t.Run("bad json", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/frost/verify", strings.NewReader("{bad"))
		w := httptest.NewRecorder()
		ctx.FrostVerifyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/verify", FrostVerifyRequest{})
		w := httptest.NewRecorder()
		ctx.FrostVerifyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid message hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/verify", FrostVerifyRequest{KeyID: "k", Message: "zz"})
		w := httptest.NewRecorder()
		ctx.FrostVerifyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid signature hex", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/verify", FrostVerifyRequest{KeyID: "k", Message: "beef", Signature: "zz"})
		w := httptest.NewRecorder()
		ctx.FrostVerifyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unknown key is 404", func(t *testing.T) {
		setupFrostService(t)
		ctx := newTestHandlerContext()
		req := frostRequest(t, http.MethodPost, "/frost/verify", FrostVerifyRequest{KeyID: "k", Message: "beef", Signature: "beef"})
		w := httptest.NewRecorder()
		ctx.FrostVerifyHandler(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("verification failure returns 200 invalid", func(t *testing.T) {
		be := setupFrostService(t)
		ctx := newTestHandlerContext()
		seedFrostKey(t, ctx, be)
		req := frostRequest(t, http.MethodPost, "/frost/verify", FrostVerifyRequest{KeyID: "seed", Message: "beef", Signature: "beef"})
		w := httptest.NewRecorder()
		ctx.FrostVerifyHandler(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		var resp FrostVerifyResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.False(t, resp.Valid)
	})
}
