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

//go:build !frost

package grpc

import (
	"context"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setupTestWithPasswordStore initializes xkms with a software backend and a
// static password store, returning a gRPC service ready for password tests.
func setupTestWithPasswordStore(t *testing.T) *Service {
	t.Helper()
	xkms.Reset()

	keyStorage := storage.New()
	certStorage := storage.New()

	backend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     backend,
		CertStorage: certStorage,
	})
	require.NoError(t, err)

	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": ks,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	svc, err := xkms.Get()
	require.NoError(t, err)

	pwBackend := storage.NewMemory()
	store := staticpw.NewStore(pwBackend)
	svc.SetPasswordStore(store)

	return NewService(nil, nil)
}

// ---- AttestKey with initialized backend ----

func TestAttestKey_BackendDoesNotSupportAttestation(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	ctx := context.Background()
	_, err := service.AttestKey(ctx, &pb.AttestKeyRequest{
		Backend: "software",
		KeyId:   "nonexistent",
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
	assert.Contains(t, st.Message(), "does not support attestation")
}

// ---- Seal/Unseal with initialized backend ----

func TestSealUnseal_WithBackend(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	ctx := context.Background()

	_, err := service.GenerateKey(ctx, &pb.GenerateKeyRequest{
		KeyId: "seal-key", Backend: "software", KeyType: "tls", Algorithm: "rsa", KeySize: 2048,
	})
	require.NoError(t, err)

	plaintext := []byte("secret data for sealing")
	sealResp, err := service.Seal(ctx, &pb.SealRequest{
		Backend: "software", Data: plaintext, KeyId: "seal-key",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, sealResp.Ciphertext)

	unsealResp, err := service.Unseal(ctx, &pb.UnsealRequest{
		Backend: sealResp.Backend, Ciphertext: sealResp.Ciphertext,
		Nonce: sealResp.Nonce, Tag: sealResp.Tag,
		KeyId: "seal-key",
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, unsealResp.Plaintext)
}

func TestSeal_WithoutKeyID_ReturnsError(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	// Seal without key ID requires KeyAttributes in options, which is not
	// provided — verifying the error path through xkms.SealWithBackend.
	_, err := service.Seal(context.Background(), &pb.SealRequest{
		Backend: "software", Data: []byte("backend-only seal"),
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestSeal_KeyNotFound(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	_, err := service.Seal(context.Background(), &pb.SealRequest{
		Backend: "software", Data: []byte("test"), KeyId: "nonexistent-key",
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ---- WrapKeyByID / UnwrapKeyByID with non-existent backend ----

func TestWrapKeyByID_NonExistentBackend(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	_, err := service.WrapKeyByID(context.Background(), &pb.WrapKeyByIDRequest{
		WrappingKeyId: "k1", WrappingKeyBackend: "nonexistent",
		TargetKeyId: "k2", TargetKeyBackend: "software", Algorithm: "AES-KW",
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestUnwrapKeyByID_NonExistentBackend(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	_, err := service.UnwrapKeyByID(context.Background(), &pb.UnwrapKeyByIDRequest{
		WrappedKey: []byte("wrapped"), UnwrappingKeyId: "k1",
		UnwrappingKeyBackend: "nonexistent", Algorithm: "AES-KW",
		TargetKeyId: "k2", TargetKeyBackend: "software",
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ---- Password CRUD with initialized store ----

func TestPasswordAdd_WithPasswordStore(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	resp, err := service.PasswordAdd(context.Background(), &pb.PasswordAddRequest{
		Name: "My Account", Username: "user@example.com", Password: "s3cr3t!",
		Url: "https://example.com", Notes: "Test notes",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Id)
	assert.Equal(t, "My Account", resp.Name)
}

func TestPasswordGet_WithPasswordStore(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	ctx := context.Background()

	addResp, err := service.PasswordAdd(ctx, &pb.PasswordAddRequest{
		Name: "Get Test", Username: "test", Password: "pass123",
	})
	require.NoError(t, err)

	getResp, err := service.PasswordGet(ctx, &pb.PasswordGetRequest{Id: addResp.Id, Decrypt: true})
	require.NoError(t, err)
	assert.Equal(t, "Get Test", getResp.Entry.Name)
	assert.Equal(t, "test", getResp.Entry.Username)
}

func TestPasswordList_WithPasswordStore(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	ctx := context.Background()

	_, err := service.PasswordAdd(ctx, &pb.PasswordAddRequest{Name: "L1", Username: "u1", Password: "p1"})
	require.NoError(t, err)
	_, err = service.PasswordAdd(ctx, &pb.PasswordAddRequest{Name: "L2", Username: "u2", Password: "p2"})
	require.NoError(t, err)

	listResp, err := service.PasswordList(ctx, &pb.PasswordListRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(listResp.Passwords), 2)
}

func TestPasswordUpdate_WithPasswordStore(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	ctx := context.Background()

	addResp, err := service.PasswordAdd(ctx, &pb.PasswordAddRequest{
		Name: "Update Test", Username: "orig", Password: "origpass",
	})
	require.NoError(t, err)

	newName := "Updated"
	updateResp, err := service.PasswordUpdate(ctx, &pb.PasswordUpdateRequest{Id: addResp.Id, Name: &newName})
	require.NoError(t, err)
	assert.Contains(t, updateResp.Message, "updated")
}

func TestPasswordDelete_WithPasswordStore(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	ctx := context.Background()

	addResp, err := service.PasswordAdd(ctx, &pb.PasswordAddRequest{
		Name: "Del Test", Username: "del", Password: "delpass",
	})
	require.NoError(t, err)

	delResp, err := service.PasswordDelete(ctx, &pb.PasswordDeleteRequest{Id: addResp.Id})
	require.NoError(t, err)
	assert.True(t, delResp.Success)
}

func TestPasswordGenerate_WithPasswordStore(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	resp, err := service.PasswordGenerate(context.Background(), &pb.PasswordGenerateRequest{
		Length: 24, Upper: true, Lower: true, Digits: true, Symbols: true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Password)
	assert.Equal(t, int32(24), resp.Length)
}

func TestPasswordStoreStatus_WithPasswordStore(t *testing.T) {
	service := setupTestWithPasswordStore(t)
	defer xkms.Reset()

	resp, err := service.PasswordStoreStatus(context.Background(), &pb.PasswordStoreStatusRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// ---- PIV operations with non-PIV backend ----

func TestListPIVSlots_NonPIVBackend(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	_, err := service.ListPIVSlots(context.Background(), &pb.ListPIVSlotsRequest{Backend: "software"})
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.NotEqual(t, codes.OK, st.Code())
}

// ---- mapPIVError tests ----

func TestMapPIVError_Nil(t *testing.T) {
	assert.Nil(t, mapPIVError(nil, "test"))
}

func TestMapPIVError_Known(t *testing.T) {
	st, _ := status.FromError(mapPIVError(xkms.ErrPIVNotInitialized, "test"))
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestMapPIVError_Unknown(t *testing.T) {
	st, _ := status.FromError(mapPIVError(assert.AnError, "test op"))
	assert.Equal(t, codes.Internal, st.Code())
}

// ---- DeriveKeyECDH with non-existent backend ----

func TestDeriveKeyECDH_NonExistentBackend(t *testing.T) {
	service := setupExtendedTest(t)
	defer xkms.Reset()

	_, err := service.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId: "k1", Backend: "nonexistent", PeerPublicKey: []byte("key"),
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// ---- Proto conversion helpers ----

func TestPasswordGetResponseToProto_AllFields(t *testing.T) {
	resp := passwordGetResponseToProto(&transport.PasswordGetResponse{
		ID: "id1", Name: "test", CreatedAt: "2025-01-15T10:30:00Z",
		UpdatedAt: "2025-03-01T12:00:00Z", ExpiresAt: "2026-01-15T10:30:00Z",
	})
	assert.Equal(t, "id1", resp.Entry.Id)
	assert.NotNil(t, resp.Entry.CreatedAt)
	assert.NotNil(t, resp.Entry.UpdatedAt)
	assert.NotNil(t, resp.Entry.ExpiresAt)
}

func TestPasswordGetResponseToProto_NoTimestamps(t *testing.T) {
	resp := passwordGetResponseToProto(&transport.PasswordGetResponse{ID: "id2", Name: "t2"})
	assert.Nil(t, resp.Entry.CreatedAt)
	assert.Nil(t, resp.Entry.UpdatedAt)
	assert.Nil(t, resp.Entry.ExpiresAt)
}

func TestPasswordEntryToProto_AllFields(t *testing.T) {
	entry := passwordEntryToProto(&transport.PasswordGetResponse{
		ID: "id1", Name: "e", ReadOnly: true, Shared: true, OwnerID: "o1",
		CreatedAt: "2025-01-15T10:30:00Z", UpdatedAt: "2025-03-01T12:00:00Z",
		ExpiresAt: "2026-01-15T10:30:00Z",
	})
	assert.True(t, entry.ReadOnly)
	assert.True(t, entry.Shared)
	assert.NotNil(t, entry.CreatedAt)
}

// ---- Password operations with xkms not initialized ----

func TestPasswordOps_XKMSNotInitialized(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil)
	ctx := context.Background()

	_, err := svc.PasswordAdd(ctx, &pb.PasswordAddRequest{Name: "t", Password: "p"})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())

	_, err = svc.PasswordGet(ctx, &pb.PasswordGetRequest{Id: "t"})
	st, _ = status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())

	_, err = svc.PasswordUpdate(ctx, &pb.PasswordUpdateRequest{Id: "t"})
	st, _ = status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())

	_, err = svc.PasswordDelete(ctx, &pb.PasswordDeleteRequest{Id: "t"})
	st, _ = status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())

	_, err = svc.PasswordStoreLock(ctx, nil)
	st, _ = status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())
}
