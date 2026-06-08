package xkms

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
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

func TestGetShare_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetShare(context.Background(), "https://x.com", "group-1", 1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestDeleteShare_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeleteShare(context.Background(), "https://x.com", "group-1", 1)
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
	svc, _ := setupServiceWithShareClient(t)

	_, err := svc.SubmitShare(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

// --- Delegation tests ---

func setupServiceWithShareClient(t *testing.T) (*XKMSService, *fakeShareClient) {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)
	client := newFakeShareClient()
	svc.SetShareClient(client)
	return svc, client
}

func TestSubmitShare_Success(t *testing.T) {
	svc, client := setupServiceWithShareClient(t)

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
	require.Len(t, client.shares, 1)
	assert.Equal(t, "group-1", client.shares[0].GroupID)
	assert.Equal(t, []byte("share-data-1"), client.shares[0].ShareData)
}

func TestSubmitShare_ClientError(t *testing.T) {
	svc, client := setupServiceWithShareClient(t)
	client.err = errors.New("backend failure")

	_, err := svc.SubmitShare(context.Background(), &transport.SubmitShareRequest{
		ServerURL: "https://x.com",
		GroupID:   "g1",
		ShareData: []byte("s1"),
	})
	require.Error(t, err)
}

func TestListShares_Success(t *testing.T) {
	svc, client := setupServiceWithShareClient(t)
	ctx := context.Background()

	client.shares = []qrdbtransport.ShareInfo{
		{ServerURL: "https://a.com", GroupID: "g1", ShareData: []byte("s1")},
		{ServerURL: "https://b.com", GroupID: "g2", ShareData: []byte("s2")},
	}

	resp, err := svc.ListShares(ctx)
	require.NoError(t, err)
	require.Len(t, resp.Shares, 2)
	assert.Equal(t, "g1", resp.Shares[0].GroupID)
	assert.Equal(t, "g2", resp.Shares[1].GroupID)
}

func TestListShares_Empty(t *testing.T) {
	svc, _ := setupServiceWithShareClient(t)

	resp, err := svc.ListShares(context.Background())
	require.NoError(t, err)
	assert.Empty(t, resp.Shares)
}

func TestGetShare_Success(t *testing.T) {
	svc, client := setupServiceWithShareClient(t)
	client.shares = []qrdbtransport.ShareInfo{
		{ServerURL: "https://a.com", GroupID: "g1", ShareIndex: 2, ShareData: []byte("s1")},
	}

	info, err := svc.GetShare(context.Background(), "https://a.com", "g1", 2)
	require.NoError(t, err)
	assert.Equal(t, "g1", info.GroupID)
	assert.Equal(t, 2, info.ShareIndex)
}

func TestGetShare_NotFound(t *testing.T) {
	svc, _ := setupServiceWithShareClient(t)

	_, err := svc.GetShare(context.Background(), "https://a.com", "g1", 9)
	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrCeremonyShareNotFound))
}

func TestDeleteShare_Success(t *testing.T) {
	svc, client := setupServiceWithShareClient(t)
	client.shares = []qrdbtransport.ShareInfo{
		{ServerURL: "https://a.com", GroupID: "g1", ShareIndex: 1, ShareData: []byte("s1")},
	}

	err := svc.DeleteShare(context.Background(), "https://a.com", "g1", 1)
	require.NoError(t, err)
	assert.Empty(t, client.shares)
}

func TestDeleteShare_NotFound(t *testing.T) {
	svc, _ := setupServiceWithShareClient(t)

	err := svc.DeleteShare(context.Background(), "https://a.com", "g1", 9)
	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrCeremonyShareNotFound))
}

func TestGetShareCollectionStatus_NoShares(t *testing.T) {
	svc, _ := setupServiceWithShareClient(t)

	resp, err := svc.GetShareCollectionStatus(context.Background(), "group-1")
	require.NoError(t, err)
	assert.Equal(t, "group-1", resp.GroupID)
	assert.Equal(t, 0, resp.Collected)
	assert.Equal(t, 0, resp.Threshold)
	assert.False(t, resp.Ready)
}

func TestGetShareCollectionStatus_WithShares(t *testing.T) {
	svc, client := setupServiceWithShareClient(t)
	client.threshold = 2
	client.total = 3
	client.shares = []qrdbtransport.ShareInfo{
		{GroupID: "group-1", ShareData: []byte("s1")},
		{GroupID: "group-1", ShareData: []byte("s2")},
		{GroupID: "group-2", ShareData: []byte("s3")},
	}

	resp, err := svc.GetShareCollectionStatus(context.Background(), "group-1")
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Collected)
	assert.Equal(t, 2, resp.Threshold)
	assert.Equal(t, 3, resp.Total)
	assert.True(t, resp.Ready) // 2 collected >= 2 threshold
}
