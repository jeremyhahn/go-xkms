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

package grpc

import (
	"context"
	"crypto"
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// frostBackendKeyStore is a test xkms.Backend whose KeyProvider() returns a
// real *frost.FrostBackend, which is how the xkms service resolves
// the FROST provider out of the registered backends.
type frostBackendKeyStore struct {
	*xkmsmocks.MockKeyStore
	provider types.KeyProvider
}

func (f *frostBackendKeyStore) KeyProvider() types.KeyProvider {
	return f.provider
}

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
	return nil, errFrostUnsupported
}

func (m *frostSecretBackend) GetKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errFrostShareNotFound
}

func (m *frostSecretBackend) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error {
	return nil
}

func (m *frostSecretBackend) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	return nil, nil
}

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
		return nil, errFrostShareNotFound
	}
	return sealed.Ciphertext[len(frostSealMarker):], nil
}

func (m *frostSecretBackend) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errFrostUnsupported
}

func (m *frostSecretBackend) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errFrostUnsupported
}

func (m *frostSecretBackend) RotateKey(_ context.Context, _ *types.KeyAttributes) error {
	return errFrostUnsupported
}

func (m *frostSecretBackend) Close() error { return nil }

// errFrostShareNotFound reports a share the in-memory secret backend does not
// hold. errFrostUnsupported reports an operation the fixture does not model.
var (
	errFrostShareNotFound = errors.New("frost secret share not found")
	errFrostUnsupported   = errors.New("not supported by the frost test fixture")
)

// pairAllowingRBAC allows exactly one resource:action pair and refuses every
// other. It records what it was asked so a test can prove the gate demanded
// the pair the wire contract names, not merely that some gate exists.
type pairAllowingRBAC struct {
	allowResource string
	allowAction   string

	gotResource string
	gotAction   string
}

func (c *pairAllowingRBAC) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	c.gotResource = resource
	c.gotAction = action
	if resource == c.allowResource && action == c.allowAction {
		return nil
	}
	return errFrostPermissionDenied
}

func (c *pairAllowingRBAC) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

// errFrostPermissionDenied is the refusal the test RBAC client returns.
var errFrostPermissionDenied = errors.New("denied by test")

// setupFrostXKMS registers an in-memory FROST backend with the global xkms
// service and returns the service handle the gRPC Service is constructed with.
func setupFrostXKMS(t *testing.T) *xkms.XKMSService {
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
	t.Cleanup(func() { xkms.Reset() })

	ks := &frostBackendKeyStore{
		MockKeyStore: xkmsmocks.NewMockKeyStore(),
		provider:     be,
	}
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"frost": ks},
		DefaultBackend: "frost",
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)
	return svc
}

// frostCall invokes one FROST RPC on the given Service. Each case supplies a
// request that is valid enough to reach — and pass — every validation branch
// ahead of the authorization gate, so a denial can only come from the gate.
type frostCall struct {
	name     string
	resource string
	action   string
	invoke   func(context.Context, *Service) error
}

// frostCalls is every FROST RPC together with the resource:action pair its
// gate must demand. The pairs are spelled out as literals on purpose: this is
// the wire contract go-qrdb decides against, and it is the same contract the
// QUIC handlers and the MCP frost.* permission table carry, so a divergence
// here is a cross-transport authorization bug.
var frostCalls = []frostCall{
	{
		name: "FrostGenerateKey", resource: "keys", action: "create",
		invoke: func(ctx context.Context, s *Service) error {
			_, err := s.FrostGenerateKey(ctx, &pb.FrostGenerateKeyRequest{
				KeyId: "authz-key", Threshold: 2, Total: 3, DealerMode: true,
			})
			return err
		},
	},
	{
		name: "FrostImportKey", resource: "keys", action: "import",
		invoke: func(ctx context.Context, s *Service) error {
			_, err := s.FrostImportKey(ctx, &pb.FrostImportKeyRequest{
				Package: &pb.FrostKeyPackage{
					KeyId:          "imported-key",
					Algorithm:      string(types.FrostAlgorithmEd25519),
					Threshold:      2,
					Total:          3,
					ParticipantId:  1,
					SecretShare:    []byte("share-bytes"),
					GroupPublicKey: []byte("group-public-key"),
				},
			})
			return err
		},
	},
	{
		name: "FrostListKeys", resource: "keys", action: "list",
		invoke: func(ctx context.Context, s *Service) error {
			_, err := s.FrostListKeys(ctx, &pb.FrostListKeysRequest{})
			return err
		},
	},
	{
		name: "FrostGetKey", resource: "keys", action: "get",
		invoke: func(ctx context.Context, s *Service) error {
			_, err := s.FrostGetKey(ctx, &pb.FrostGetKeyRequest{KeyId: "authz-key"})
			return err
		},
	},
	{
		name: "FrostDeleteKey", resource: "keys", action: "delete",
		invoke: func(ctx context.Context, s *Service) error {
			_, err := s.FrostDeleteKey(ctx, &pb.FrostDeleteKeyRequest{KeyId: "authz-key"})
			return err
		},
	},
	{
		name: "FrostGenerateNonces", resource: "keys", action: "sign",
		invoke: func(ctx context.Context, s *Service) error {
			_, err := s.FrostGenerateNonces(ctx, &pb.FrostGenerateNoncesRequest{KeyId: "authz-key"})
			return err
		},
	},
	{
		name: "FrostSignRound", resource: "keys", action: "sign",
		invoke: func(ctx context.Context, s *Service) error {
			_, err := s.FrostSignRound(ctx, &pb.FrostSignRoundRequest{
				KeyId:        "authz-key",
				Message:      []byte("message"),
				HidingNonce:  []byte("hiding"),
				BindingNonce: []byte("binding"),
				Commitments: []*pb.FrostCommitment{{
					ParticipantId:     1,
					HidingCommitment:  []byte("hc"),
					BindingCommitment: []byte("bc"),
				}},
			})
			return err
		},
	},
	{
		name: "FrostAggregate", resource: "keys", action: "sign",
		invoke: func(ctx context.Context, s *Service) error {
			_, err := s.FrostAggregate(ctx, &pb.FrostAggregateRequest{
				KeyId:   "authz-key",
				Message: []byte("message"),
				Commitments: []*pb.FrostCommitment{{
					ParticipantId:     1,
					HidingCommitment:  []byte("hc"),
					BindingCommitment: []byte("bc"),
				}},
				Shares: []*pb.FrostSignatureShare{{ParticipantId: 1, Share: []byte("share")}},
			})
			return err
		},
	},
	{
		name: "FrostVerify", resource: "keys", action: "verify",
		invoke: func(ctx context.Context, s *Service) error {
			_, err := s.FrostVerify(ctx, &pb.FrostVerifyRequest{
				KeyId:     "authz-key",
				Message:   []byte("message"),
				Signature: []byte("signature"),
			})
			return err
		},
	},
}

// frostIdentityCtx returns a context carrying an authenticated identity, so an
// enabled authorizer reaches a genuine permission decision rather than
// rejecting the call for a missing identity.
func frostIdentityCtx() context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "frost-subject",
		Roles:   []string{"guest"},
	})
}

// TestFrostRPCs_UnauthorizedCallerRefused proves every FROST RPC is gated: a
// caller the policy refuses gets codes.PermissionDenied, and never a response
// carrying threshold key material. FROST covers distributed key generation,
// share distribution, and signing, so an ungated RPC here is an unauthenticated
// path to threshold key material.
func TestFrostRPCs_UnauthorizedCallerRefused(t *testing.T) {
	xkmsSvc := setupFrostXKMS(t)
	svc := NewService(auth.NewAuthorizer(&denyingRBAC{}), nil, xkmsSvc)
	ctx := frostIdentityCtx()

	for _, tc := range frostCalls {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.invoke(ctx, svc)
			require.Error(t, err, "an ungated FROST RPC reached the backend")

			st, ok := status.FromError(err)
			require.True(t, ok, "error must be a gRPC status")
			assert.Equal(t, codes.PermissionDenied, st.Code())
		})
	}
}

// TestFrostRPCs_MissingIdentityRefused proves the gate rejects a caller with no
// identity as unauthenticated rather than letting an anonymous request through.
func TestFrostRPCs_MissingIdentityRefused(t *testing.T) {
	xkmsSvc := setupFrostXKMS(t)
	svc := NewService(auth.NewAuthorizer(&denyingRBAC{}), nil, xkmsSvc)

	for _, tc := range frostCalls {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.invoke(context.Background(), svc)
			require.Error(t, err)

			st, ok := status.FromError(err)
			require.True(t, ok, "error must be a gRPC status")
			assert.Equal(t, codes.Unauthenticated, st.Code())
		})
	}
}

// TestFrostRPCs_AuthorizedCallerAdmitted is the positive control the negative
// tests need to mean anything: an authorize call that refused unconditionally
// would satisfy every denial assertion above. It proves two things per RPC —
// the gate asks go-qrdb for exactly the wire-contract pair, and a caller
// holding that grant is admitted to the handler (the RPC may still fail on its
// own merits, but never with PermissionDenied or Unauthenticated).
func TestFrostRPCs_AuthorizedCallerAdmitted(t *testing.T) {
	ctx := frostIdentityCtx()

	for _, tc := range frostCalls {
		t.Run(tc.name, func(t *testing.T) {
			xkmsSvc := setupFrostXKMS(t)
			rbac := &pairAllowingRBAC{allowResource: tc.resource, allowAction: tc.action}
			svc := NewService(auth.NewAuthorizer(rbac), nil, xkmsSvc)

			err := tc.invoke(ctx, svc)

			assert.Equal(t, tc.resource, rbac.gotResource, "gate asked for the wrong resource")
			assert.Equal(t, tc.action, rbac.gotAction, "gate asked for the wrong action")

			if err != nil {
				st, ok := status.FromError(err)
				require.True(t, ok, "error must be a gRPC status")
				assert.NotEqual(t, codes.PermissionDenied, st.Code(),
					"a caller holding the required grant must pass the gate")
				assert.NotEqual(t, codes.Unauthenticated, st.Code(),
					"an authenticated caller must not be rejected as anonymous")
			}
		})
	}
}

// TestFrostGenerateKey_AuthorizedCallerSucceeds is the end-to-end positive
// control: a caller holding keys:create receives real dealer-generated FROST
// packages. It proves the gate admits the operation rather than merely
// failing later for an unrelated reason.
func TestFrostGenerateKey_AuthorizedCallerSucceeds(t *testing.T) {
	xkmsSvc := setupFrostXKMS(t)
	rbac := &pairAllowingRBAC{allowResource: auth.ResourceKeys, allowAction: auth.ActionCreate}
	svc := NewService(auth.NewAuthorizer(rbac), nil, xkmsSvc)

	resp, err := svc.FrostGenerateKey(frostIdentityCtx(), &pb.FrostGenerateKeyRequest{
		KeyId: "positive-control", Threshold: 2, Total: 3, DealerMode: true,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "positive-control", resp.KeyId)
	assert.Len(t, resp.Packages, 3)
	assert.NotEmpty(t, resp.GroupPublicKey)
}
