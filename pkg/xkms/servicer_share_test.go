package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ErrNotConfigured guards ---

func TestSubmitShare_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.SubmitShare(context.Background(), &transport.SubmitShareRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestListShares_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListShares(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestGetShareCollectionStatus_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetShareCollectionStatus(context.Background(), "group-1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- Nil request guards ---

func TestSubmitShare_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithShareStore(t)

	_, err := svc.SubmitShare(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

// --- Delegation tests ---

func setupServiceWithShareStore(t *testing.T) (*XKMSService, *mockShareStore) {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)
	store := newMockShareStore()
	svc.SetShareStore(store)
	return svc, store
}

func TestSubmitShare_Success(t *testing.T) {
	svc, store := setupServiceWithShareStore(t)

	resp, err := svc.SubmitShare(context.Background(), &transport.SubmitShareRequest{
		ServerURL:  "https://xkms.example.com",
		GroupID:    "group-1",
		GroupName:  "Admins",
		ShareIndex: 1,
		ShareData:  []byte("share-data-1"),
		Purpose:    "barrier-unseal",
		TenantID:   "tenant-1",
	})
	require.NoError(t, err)
	assert.True(t, resp.Accepted)
	assert.Len(t, store.entries, 1)
	assert.Equal(t, "group-1", store.entries[0].GroupID)
	assert.Equal(t, []byte("share-data-1"), store.entries[0].ShareData)
}

func TestListShares_Success(t *testing.T) {
	svc, store := setupServiceWithShareStore(t)
	ctx := context.Background()

	store.entries = []*sharestore.ShareEntry{
		{ServerURL: "https://a.com", GroupID: "g1", ShareData: []byte("s1")},
		{ServerURL: "https://b.com", GroupID: "g2", ShareData: []byte("s2")},
	}

	resp, err := svc.ListShares(ctx)
	require.NoError(t, err)
	assert.Len(t, resp.Shares, 2)
	assert.Equal(t, "g1", resp.Shares[0].GroupID)
	assert.Equal(t, "g2", resp.Shares[1].GroupID)
}

func TestListShares_Empty(t *testing.T) {
	svc, _ := setupServiceWithShareStore(t)

	resp, err := svc.ListShares(context.Background())
	require.NoError(t, err)
	assert.Empty(t, resp.Shares)
}

func TestGetShareCollectionStatus_NoShares(t *testing.T) {
	svc, _ := setupServiceWithShareStore(t)

	resp, err := svc.GetShareCollectionStatus(context.Background(), "group-1")
	require.NoError(t, err)
	assert.Equal(t, "group-1", resp.GroupID)
	assert.Equal(t, 0, resp.Collected)
	assert.Equal(t, 0, resp.Threshold)
	assert.False(t, resp.Ready)
}

func TestGetShareCollectionStatus_WithShares(t *testing.T) {
	svc, store := setupServiceWithShareStore(t)

	store.entries = []*sharestore.ShareEntry{
		{GroupID: "group-1", ShareData: []byte("s1")},
		{GroupID: "group-1", ShareData: []byte("s2")},
		{GroupID: "group-2", ShareData: []byte("s3")},
	}

	resp, err := svc.GetShareCollectionStatus(context.Background(), "group-1")
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Collected)
	// Without a custodian service, threshold and total are 0
	assert.Equal(t, 0, resp.Threshold)
	assert.False(t, resp.Ready)
}

// --- GetShareCollectionStatus with custodian service ---

func TestGetShareCollectionStatus_WithCustodianService(t *testing.T) {
	svc, store := setupServiceWithShareStore(t)

	// Wire up a custodian service with a group.
	custodianStore := newMockCustodianStore()
	custodianSvc, err := custodian.NewService(custodianStore)
	require.NoError(t, err)
	svc.SetCustodianService(custodianSvc)

	ctx := context.Background()
	groupID := "test-group-001"

	// Create a group via the custodian service.
	_, err = svc.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID:        groupID,
		Name:      "test-group",
		Threshold: 2,
		Total:     3,
		Purpose:   "barrier-unseal",
	})
	require.NoError(t, err)

	// Add shares for this group.
	store.entries = []*sharestore.ShareEntry{
		{GroupID: groupID, ShareData: []byte("s1")},
		{GroupID: groupID, ShareData: []byte("s2")},
	}

	resp, err := svc.GetShareCollectionStatus(ctx, groupID)
	require.NoError(t, err)
	assert.Equal(t, groupID, resp.GroupID)
	assert.Equal(t, 2, resp.Collected)
	assert.Equal(t, 2, resp.Threshold)
	assert.Equal(t, 3, resp.Total)
	assert.True(t, resp.Ready) // 2 collected >= 2 threshold
}
