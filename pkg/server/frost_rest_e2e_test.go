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

package server

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// testFrostSecretBackend is an in-memory types.SealingKeyProvider that
// stands in for backends.frost.secret_backend in this test: GetKey/GenerateKey
// hold a placeholder "wrapping key" object (so Server.initFrostBackend's
// real seal.EnsurePrivateSealKey provisioning step, exercised exactly as it
// runs against the real software/PKCS#8 backends, succeeds against this
// double too), and Seal/Unseal "encrypt" a FROST secret share by prefixing
// it with a fixed marker, so this test can validate what #836 delivers --
// config-driven construction, registration in s.keyProviders, and the REST
// handlers resolving and driving that registered backend -- without a real
// cipher. It is the same shape as pkg/api/rest's own frostSecretBackend test
// double (handlers_frost_real_test.go).
type testFrostSecretBackend struct {
	data map[string][]byte
}

// testFrostSealMarker prefixes every "sealed" payload this fixture
// produces, so Unseal can detect (and reject) a payload it did not produce.
const testFrostSealMarker = "server-test-sealed:"

func newTestFrostSecretBackend() *testFrostSecretBackend {
	return &testFrostSecretBackend{data: make(map[string][]byte)}
}

func (m *testFrostSecretBackend) Type() types.BackendType { return types.BackendTypeSoftware }
func (m *testFrostSecretBackend) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Signing: true, Sealing: true}
}

// GenerateKey and GetKey model the wrap key seal.EnsurePrivateSealKey
// provisions (software/PKCS#8's AsymmetricSecretSealKeyAttributes): a
// placeholder object stored by CN, not real key material, since this
// double's Seal/Unseal (below) never read it back.
func (m *testFrostSecretBackend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.data[attrs.CN] = []byte("placeholder-wrap-key")
	return nil, nil
}
func (m *testFrostSecretBackend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if v, ok := m.data[attrs.CN]; ok {
		return v, nil
	}
	return nil, backend.ErrKeyNotFound
}
func (m *testFrostSecretBackend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	delete(m.data, attrs.CN)
	return nil
}
func (m *testFrostSecretBackend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	return nil, nil
}
func (m *testFrostSecretBackend) Signer(ctx context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}
func (m *testFrostSecretBackend) Decrypter(ctx context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not implemented")
}
func (m *testFrostSecretBackend) RotateKey(ctx context.Context, _ *types.KeyAttributes) error {
	return errors.New("not implemented")
}
func (m *testFrostSecretBackend) Close() error { return nil }

func (m *testFrostSecretBackend) CanSeal() bool { return true }

func (m *testFrostSecretBackend) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	return &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: append([]byte(testFrostSealMarker), data...),
	}, nil
}

func (m *testFrostSecretBackend) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	if sealed == nil || len(sealed.Ciphertext) < len(testFrostSealMarker) || string(sealed.Ciphertext[:len(testFrostSealMarker)]) != testFrostSealMarker {
		return nil, errors.New("frost secret share not found")
	}
	return sealed.Ciphertext[len(testFrostSealMarker):], nil
}

// TestFrostRESTLifecycle_ServerRegisteredBackend drives a full FROST
// threshold-signing ceremony — dealer keygen, round 1, round 2, aggregate,
// and verify — through the real REST handlers (pkg/api/rest) backed by a
// FROST backend that came from the real server wiring
// (config.Config.Backends.Frost -> Server.initFrostBackend ->
// Server.initializeKeyStore -> xkms.Initialize), rather than a hand-injected
// mock. This is the gap #836 closes: before it, the only way to reach the
// FROST REST API at all was a test that injected a *frost.FrostBackend by
// hand, because nothing ever registered one from configuration.
//
// A genuine 2-of-2 signature needs two participants, each holding a
// distinct secret share for the same key — the same share storage key
// (frost/secrets/<keyID>) can only ever hold one participant's share at a
// time, by design. In a real deployment that means two xkms nodes. In this
// process it means two *server.Server instances, each with their own
// backends.frost section — but only one *xkms.XKMSService can be the
// package-level singleton pkg/api/rest's HandlerContext resolves through at
// a time (pkg/xkms.Initialize is a sync.Once). So participant 1's every step
// below — including round 1 and round 2 — goes through server1's real REST
// HandlerContext; participant 2's round 1 and round 2 call the identical,
// real *frost.FrostBackend methods directly, on the backend server2's own
// initFrostBackend produced. This mirrors
// test/integration/frost/signing_integration_test.go's own multi-participant
// setup, which drives every participant's backend directly for the same
// reason.
func TestFrostRESTLifecycle_ServerRegisteredBackend(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	const keyID = "e2e-lifecycle-key"
	message := []byte("go-xkms #836 FROST REST end-to-end lifecycle")
	messageHex := hex.EncodeToString(message)

	// server1 constructs first: xkms.Initialize's sync.Once means its call
	// (inside initializeKeyStore below) is the one that wins the singleton,
	// so it is the service every HandlerContext in this test resolves
	// against.
	server1 := newFrostServerForTest(t, "software")
	frostBackend1, ok := server1.keyProviders["frost"].(*frost.FrostBackend)
	require.True(t, ok, "server1 must have registered a *frost.FrostBackend")

	server2 := newFrostServerForTest(t, "software")
	frostBackend2, ok := server2.keyProviders["frost"].(*frost.FrostBackend)
	require.True(t, ok, "server2 must have registered a *frost.FrostBackend")

	svc, err := xkms.Get()
	require.NoError(t, err)

	ctx := rest.NewHandlerContext("v1")
	ctx.SetXKMSService(svc)

	// --- Keygen: dealer mode, via REST, against server1's registered backend.
	genReq := frostJSONRequest(t, http.MethodPost, "/frost/keys", rest.FrostGenerateKeyRequest{
		KeyID:        keyID,
		Threshold:    2,
		Total:        2,
		Participants: []string{"p1", "p2"},
		DealerMode:   true,
	})
	genW := httptest.NewRecorder()
	ctx.FrostGenerateKeyHandler(genW, genReq)
	require.Equal(t, http.StatusCreated, genW.Code, genW.Body.String())

	var genResp rest.FrostGenerateKeyResponse
	require.NoError(t, json.NewDecoder(genW.Body).Decode(&genResp))
	require.Len(t, genResp.Packages, 2)

	pkg1 := findFrostPackage(t, genResp.Packages, 1)
	pkg2 := findFrostPackage(t, genResp.Packages, 2)

	// --- Import: participant 1's package via REST, into server1's backend.
	impReq := frostJSONRequest(t, http.MethodPost, "/frost/keys/import", rest.FrostImportKeyRequest{Package: pkg1})
	impW := httptest.NewRecorder()
	ctx.FrostImportKeyHandler(impW, impReq)
	require.Equal(t, http.StatusCreated, impW.Code, impW.Body.String())

	// --- Import: participant 2's package directly into server2's backend,
	// through the same KeyStore.StoreKeyPackage call FrostImportKeyHandler
	// itself makes (see handlers_frost.go).
	importFrostPackageDirect(t, frostBackend2, pkg2)

	// --- Round 1: participant 1 via REST.
	nonce1Req := withChiURLParam(httptest.NewRequest(http.MethodPost, "/frost/keys/"+keyID+"/nonces", nil), "id", keyID)
	nonce1W := httptest.NewRecorder()
	ctx.FrostGenerateNoncesHandler(nonce1W, nonce1Req)
	require.Equal(t, http.StatusOK, nonce1W.Code, nonce1W.Body.String())
	var nonce1Resp rest.FrostGenerateNoncesResponse
	require.NoError(t, json.NewDecoder(nonce1W.Body).Decode(&nonce1Resp))

	// --- Round 1: participant 2 directly against server2's backend.
	noncePkg2, err := frostBackend2.GenerateNonces(keyID)
	require.NoError(t, err)

	commitments := []rest.FrostCommitment{
		{
			ParticipantID:     1,
			HidingCommitment:  nonce1Resp.HidingCommitment,
			BindingCommitment: nonce1Resp.BindingCommitment,
		},
		{
			ParticipantID:     noncePkg2.ParticipantID,
			HidingCommitment:  hex.EncodeToString(noncePkg2.Commitments.HidingCommitment),
			BindingCommitment: hex.EncodeToString(noncePkg2.Commitments.BindingCommitment),
		},
	}

	// --- Round 2: participant 1 via REST.
	sign1Req := withChiURLParam(frostJSONRequest(t, http.MethodPost, "/frost/keys/"+keyID+"/sign", rest.FrostSignRoundRequest{
		KeyID:             keyID,
		Message:           messageHex,
		SessionID:         nonce1Resp.SessionID,
		HidingNonce:       nonce1Resp.HidingNonce,
		BindingNonce:      nonce1Resp.BindingNonce,
		HidingCommitment:  nonce1Resp.HidingCommitment,
		BindingCommitment: nonce1Resp.BindingCommitment,
		Commitments:       commitments,
	}), "id", keyID)
	sign1W := httptest.NewRecorder()
	ctx.FrostSignRoundHandler(sign1W, sign1Req)
	require.Equal(t, http.StatusOK, sign1W.Code, sign1W.Body.String())
	var sign1Resp rest.FrostSignRoundResponse
	require.NoError(t, json.NewDecoder(sign1W.Body).Decode(&sign1Resp))

	// --- Round 2: participant 2 directly against server2's backend.
	frostCommitments := []*frost.Commitment{
		{
			ParticipantID: 1,
			Commitments: &frost.SigningCommitments{
				ParticipantID:     1,
				HidingCommitment:  mustHexDecode(t, nonce1Resp.HidingCommitment),
				BindingCommitment: mustHexDecode(t, nonce1Resp.BindingCommitment),
			},
		},
		{
			ParticipantID: noncePkg2.ParticipantID,
			Commitments:   noncePkg2.Commitments,
		},
	}
	share2, err := frostBackend2.SignRound(keyID, message, noncePkg2, frostCommitments)
	require.NoError(t, err)

	// --- Aggregate: via REST, against server1's backend.
	aggReq := frostJSONRequest(t, http.MethodPost, "/frost/aggregate", rest.FrostAggregateRequest{
		KeyID:       keyID,
		Message:     messageHex,
		Commitments: commitments,
		Shares: []rest.FrostSignatureShare{
			{ParticipantID: 1, SessionID: sign1Resp.SessionID, Share: sign1Resp.SignatureShare},
			{ParticipantID: share2.ParticipantID, SessionID: share2.SessionID, Share: hex.EncodeToString(share2.Share)},
		},
		Verify: true,
	})
	aggW := httptest.NewRecorder()
	ctx.FrostAggregateHandler(aggW, aggReq)
	require.Equal(t, http.StatusOK, aggW.Code, aggW.Body.String())
	var aggResp rest.FrostAggregateResponse
	require.NoError(t, json.NewDecoder(aggW.Body).Decode(&aggResp))
	require.NotEmpty(t, aggResp.Signature)
	require.True(t, aggResp.Verified, "aggregate handler's own Verify=true pass must succeed")

	// --- Verify: via REST, against server1's backend, as an independent call.
	verifyReq := frostJSONRequest(t, http.MethodPost, "/frost/verify", rest.FrostVerifyRequest{
		KeyID:     keyID,
		Message:   messageHex,
		Signature: aggResp.Signature,
	})
	verifyW := httptest.NewRecorder()
	ctx.FrostVerifyHandler(verifyW, verifyReq)
	require.Equal(t, http.StatusOK, verifyW.Code, verifyW.Body.String())
	var verifyResp rest.FrostVerifyResponse
	require.NoError(t, json.NewDecoder(verifyW.Body).Decode(&verifyResp))
	require.True(t, verifyResp.Valid, "verify handler must accept the aggregated signature: %s", verifyResp.Message)

	_ = frostBackend1 // constructed to prove registration; driven entirely via ctx above.
}

// newFrostServerForTest builds a *Server with backends.frost enabled,
// pointed at a testFrostSecretBackend registered under secretBackendName,
// and runs the real Server.initFrostBackend and Server.initializeKeyStore —
// the same two calls Server.New makes — so the returned server's "frost"
// keyProvider and its entry in the xkms singleton came from the real
// production wiring under test, not a hand-built substitute for either.
func newFrostServerForTest(t *testing.T, secretBackendName string) *Server {
	t.Helper()

	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "memory"},
		Default: config.DefaultConfig("frost"),
		Backends: config.BackendsConfig{
			Frost: &config.FrostConfig{
				Enabled:          true,
				PublicPath:       "frost/public",
				SecretBackend:    secretBackendName,
				Algorithm:        string(types.FrostAlgorithmEd25519),
				DefaultThreshold: 2,
				DefaultTotal:     2,
			},
		},
	})

	s.keyProviders = map[string]types.KeyProvider{
		secretBackendName: newTestFrostSecretBackend(),
	}
	require.NoError(t, s.initFrostBackend())

	s.backends = map[string]xkms.Backend{}
	require.NoError(t, s.initializeKeyStore())

	return s
}

// findFrostPackage returns the dealer-mode package for participantID, or
// fails the test if it is not present.
func findFrostPackage(t *testing.T, packages []rest.FrostKeyPackage, participantID uint32) rest.FrostKeyPackage {
	t.Helper()
	for _, pkg := range packages {
		if pkg.ParticipantID == participantID {
			return pkg
		}
	}
	t.Fatalf("no dealer package for participant %d", participantID)
	return rest.FrostKeyPackage{}
}

// importFrostPackageDirect stores pkg into be's keystore through the same
// frost.KeyStore.StoreKeyPackage call rest.HandlerContext.FrostImportKeyHandler
// makes, without going through a second REST layer (see
// TestFrostRESTLifecycle_ServerRegisteredBackend's doc comment for why).
func importFrostPackageDirect(t *testing.T, be *frost.FrostBackend, pkg rest.FrostKeyPackage) {
	t.Helper()

	vsMap := make(map[uint32][]byte, len(pkg.VerificationShares))
	for id, vsHex := range pkg.VerificationShares {
		vsMap[id] = mustHexDecode(t, vsHex)
	}

	keyPackage := &frost.KeyPackage{
		ParticipantID:      pkg.ParticipantID,
		SecretShare:        &frost.SecretKeyShare{Value: mustHexDecode(t, pkg.SecretShare)},
		GroupPublicKey:     mustHexDecode(t, pkg.GroupPublicKey),
		VerificationShares: vsMap,
		MinSigners:         uint32(pkg.Threshold),
		MaxSigners:         uint32(pkg.Total),
		Algorithm:          types.FrostAlgorithm(pkg.Algorithm),
	}
	metadata := &frost.KeyMetadata{
		KeyID:             pkg.KeyID,
		Algorithm:         types.FrostAlgorithm(pkg.Algorithm),
		Threshold:         pkg.Threshold,
		Total:             pkg.Total,
		ParticipantID:     pkg.ParticipantID,
		CreatedAt:         time.Now().Unix(),
		SecretBackendType: types.BackendTypeSoftware,
	}

	require.NoError(t, be.KeyStore().StoreKeyPackage(context.Background(), pkg.KeyID, keyPackage, metadata))
}

// frostJSONRequest builds an httptest.Request with body JSON-encoded.
func frostJSONRequest(t *testing.T, method, target string, body interface{}) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)
	return httptest.NewRequest(method, target, bytes.NewReader(data))
}

// withChiURLParam attaches a chi route param to the request context, the
// same way the real chi router would when this handler is mounted.
func withChiURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// mustHexDecode decodes hex-encoded test fixture data, failing the test on
// any decode error rather than proceeding with a zero-value byte slice.
func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
