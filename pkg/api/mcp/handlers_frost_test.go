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

//go:build frost

// handlers_frost_test.go covers the frost-tagged MCP FROST handlers'
// wire-code classification (go-xkms#930): request validation, hex-decode
// failures, key-not-found and the no-FROST-backend-configured refusal must
// all reach dispatch as a *KeyOpError, matching pkg/api/grpc/service_frost.go's
// classification where a counterpart exists.
package mcp

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// frostBackendKeyStore is a test xkms.Backend whose KeyProvider() returns a
// real *frost.FrostBackend, so the xkms service can resolve it. Mirrors
// pkg/api/rest/handlers_frost_real_test.go's fixture of the same name.
type frostBackendKeyStore struct {
	*xkmsmocks.MockKeyStore
	provider types.KeyProvider
}

func (f *frostBackendKeyStore) KeyProvider() types.KeyProvider { return f.provider }

// frostSecretBackend is an in-memory types.KeyProvider storing raw FROST
// secret shares keyed by CN via the SealData field, mirroring
// pkg/api/rest/handlers_frost_real_test.go's fixture of the same name.
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
func (m *frostSecretBackend) GenerateKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}
func (m *frostSecretBackend) GetKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("frost secret share not found")
}
func (m *frostSecretBackend) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error {
	return nil
}
func (m *frostSecretBackend) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	return nil, nil
}
func (m *frostSecretBackend) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}
func (m *frostSecretBackend) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not implemented")
}
func (m *frostSecretBackend) RotateKey(_ context.Context, _ *types.KeyAttributes) error {
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

// newFrostMCPServer registers a real *frost.FrostBackend with the xkms
// service and returns an MCP *Server that resolves it, so handleFrost*
// error paths beyond "not configured" can be exercised.
func newFrostMCPServer(t *testing.T) *Server {
	t.Helper()

	be, err := frost.NewBackend(&frost.Config{
		DAOs:             testutil.NewMemoryDAOFactory(),
		SecretBackend:    newFrostSecretBackend(),
		Algorithm:        types.FrostAlgorithmEd25519,
		DefaultThreshold: 2,
		DefaultTotal:     3,
	})
	require.NoError(t, err)

	xkms.Reset()
	ks := &frostBackendKeyStore{MockKeyStore: xkmsmocks.NewMockKeyStore(), provider: be}
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"frost": ks},
		DefaultBackend: "frost",
	}))
	t.Cleanup(func() { xkms.Reset() })

	svc, err := xkms.Get()
	require.NoError(t, err)

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)
	return server
}

func frostReq(t *testing.T, method string, params interface{}) *JSONRPCRequest {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

// TestFrostMethods_Dispatchable proves every frost.* registration in
// rpcMethods reaches a compiled-in handler under the frost tag: none of them
// answers method-not-found, the !frost stub's reply.
func TestFrostMethods_Dispatchable(t *testing.T) {
	server := newFrostMCPServer(t)
	methods := 0
	for method, entry := range rpcMethods {
		if !strings.HasPrefix(method, "frost.") {
			continue
		}
		methods++
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: json.RawMessage(`{}`)}
		_, err := entry.handler(server, context.Background(), req)
		var keyErr *KeyOpError
		if errors.As(err, &keyErr) {
			assert.NotEqualf(t, ErrCodeMethodNotFound, keyErr.Code, "%s must reach the FROST handler", method)
		}
	}
	assert.Equal(t, 9, methods, "the nine FROST methods are registered")
}

func TestHandleFrostGenerateKey_Validation(t *testing.T) {
	server := newFrostMCPServer(t)
	ctx := context.Background()

	t.Run("threshold too low", func(t *testing.T) {
		_, err := server.handleFrostGenerateKey(ctx, frostReq(t, "frost.generateKey", FrostGenerateKeyParams{Threshold: 1, Total: 3}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("total less than threshold", func(t *testing.T) {
		_, err := server.handleFrostGenerateKey(ctx, frostReq(t, "frost.generateKey", FrostGenerateKeyParams{Threshold: 3, Total: 2}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("participant mode requires participant_id", func(t *testing.T) {
		_, err := server.handleFrostGenerateKey(ctx, frostReq(t, "frost.generateKey", FrostGenerateKeyParams{Threshold: 2, Total: 3}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("no backend configured", func(t *testing.T) {
		xkms.Reset()
		t.Cleanup(func() { xkms.Reset() })

		require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
			Backends:       map[string]xkms.Backend{"software": xkmsmocks.NewMockKeyStore()},
			DefaultBackend: "software",
		}))
		svc, err := xkms.Get()
		require.NoError(t, err)
		noFrostServer, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
		require.NoError(t, err)

		_, err = noFrostServer.handleFrostGenerateKey(ctx, frostReq(t, "frost.generateKey",
			FrostGenerateKeyParams{Threshold: 2, Total: 3, DealerMode: true}))
		require.Error(t, err)
		// go-xkms#930: the service's ErrFrostNotConfigured reaches dispatch
		// as a *KeyOpError carrying ErrCodeInternalError, matching gRPC's
		// codes.Internal for the same refusal.
		assertKeyOpCode(t, err, ErrCodeInternalError)
	})
}

func TestHandleFrostImportKey_Validation(t *testing.T) {
	server := newFrostMCPServer(t)
	ctx := context.Background()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := server.handleFrostImportKey(ctx, frostReq(t, "frost.importKey", FrostImportKeyParams{}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("invalid secret_share hex", func(t *testing.T) {
		_, err := server.handleFrostImportKey(ctx, frostReq(t, "frost.importKey", FrostImportKeyParams{
			Package: FrostKeyPackage{KeyID: "k", SecretShare: "zz"},
		}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("invalid group_public_key hex", func(t *testing.T) {
		_, err := server.handleFrostImportKey(ctx, frostReq(t, "frost.importKey", FrostImportKeyParams{
			Package: FrostKeyPackage{KeyID: "k", SecretShare: "deadbeef", GroupPublicKey: "zz"},
		}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("invalid verification_share hex", func(t *testing.T) {
		_, err := server.handleFrostImportKey(ctx, frostReq(t, "frost.importKey", FrostImportKeyParams{
			Package: FrostKeyPackage{
				KeyID: "k", SecretShare: "deadbeef", GroupPublicKey: "beef",
				VerificationShares: map[uint32]string{1: "zz"},
			},
		}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})
}

func TestHandleFrostGetKey_NotFound(t *testing.T) {
	server := newFrostMCPServer(t)

	_, err := server.handleFrostGetKey(context.Background(), frostReq(t, "frost.getKey", FrostGetKeyParams{KeyID: "does-not-exist"}))
	require.Error(t, err)
	assertKeyOpCode(t, err, sdkssh.JSONRPCCodeNotFound)
}

func TestHandleFrostGetKey_MissingKeyID(t *testing.T) {
	server := newFrostMCPServer(t)

	_, err := server.handleFrostGetKey(context.Background(), frostReq(t, "frost.getKey", FrostGetKeyParams{}))
	require.Error(t, err)
	assertKeyOpCode(t, err, ErrCodeInvalidParams)
}

func TestHandleFrostSignRound_Validation(t *testing.T) {
	server := newFrostMCPServer(t)
	ctx := context.Background()

	t.Run("invalid message hex", func(t *testing.T) {
		_, err := server.handleFrostSignRound(ctx, frostReq(t, "frost.signRound", FrostSignRoundParams{KeyID: "k", Message: "zz"}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("key not found", func(t *testing.T) {
		_, err := server.handleFrostSignRound(ctx, frostReq(t, "frost.signRound", FrostSignRoundParams{
			KeyID: "missing", Message: "beef", HidingNonce: "aa", BindingNonce: "bb",
			HidingCommitment: "cc", BindingCommitment: "dd",
			Commitments: []FrostCommitment{{ParticipantID: 1, HidingCommitment: "aa", BindingCommitment: "bb"}},
		}))
		require.Error(t, err)
		assertKeyOpCode(t, err, sdkssh.JSONRPCCodeNotFound)
	})
}

func TestHandleFrostAggregate_Validation(t *testing.T) {
	server := newFrostMCPServer(t)
	ctx := context.Background()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := server.handleFrostAggregate(ctx, frostReq(t, "frost.aggregate", FrostAggregateParams{}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("invalid message hex", func(t *testing.T) {
		_, err := server.handleFrostAggregate(ctx, frostReq(t, "frost.aggregate", FrostAggregateParams{KeyID: "k", Message: "zz"}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("invalid share hex", func(t *testing.T) {
		_, err := server.handleFrostAggregate(ctx, frostReq(t, "frost.aggregate", FrostAggregateParams{
			KeyID: "k", Message: "beef",
			Shares: []FrostSignatureShare{{ParticipantID: 1, Share: "zz"}},
		}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})
}

func TestHandleFrostVerify_Validation(t *testing.T) {
	server := newFrostMCPServer(t)
	ctx := context.Background()

	t.Run("missing key_id", func(t *testing.T) {
		_, err := server.handleFrostVerify(ctx, frostReq(t, "frost.verify", FrostVerifyParams{}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("invalid message hex", func(t *testing.T) {
		_, err := server.handleFrostVerify(ctx, frostReq(t, "frost.verify", FrostVerifyParams{KeyID: "k", Message: "zz"}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})

	t.Run("invalid signature hex", func(t *testing.T) {
		_, err := server.handleFrostVerify(ctx, frostReq(t, "frost.verify", FrostVerifyParams{KeyID: "k", Message: "beef", Signature: "zz"}))
		require.Error(t, err)
		assertKeyOpCode(t, err, ErrCodeInvalidParams)
	})
}

func TestHandleFrostDeleteKey_MissingKeyID(t *testing.T) {
	server := newFrostMCPServer(t)

	_, err := server.handleFrostDeleteKey(context.Background(), frostReq(t, "frost.deleteKey", FrostDeleteKeyParams{}))
	require.Error(t, err)
	assertKeyOpCode(t, err, ErrCodeInvalidParams)
}

func TestHandleFrostGenerateNonces_MissingKeyID(t *testing.T) {
	server := newFrostMCPServer(t)

	_, err := server.handleFrostGenerateNonces(context.Background(), frostReq(t, "frost.generateNonces", FrostGenerateNoncesParams{}))
	require.Error(t, err)
	assertKeyOpCode(t, err, ErrCodeInvalidParams)
}

// TestFrostMethods_WireCodesThroughInvokeMethod drives a representative
// FROST validation failure through Server.InvokeMethod -- the production
// dispatch path -- and pins the code a caller actually sees (go-xkms#930).
func TestFrostMethods_WireCodesThroughInvokeMethod(t *testing.T) {
	server := newFrostMCPServer(t)

	resp := invokeRequest(server, context.Background(), frostReq(t, "frost.generateKey", FrostGenerateKeyParams{Threshold: 1, Total: 3}))
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidParams, resp.Error.Code)

	resp = invokeRequest(server, context.Background(), frostReq(t, "frost.getKey", FrostGetKeyParams{KeyID: "missing"}))
	require.NotNil(t, resp.Error)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, resp.Error.Code)
}
