package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPCRReader implements policy.PCRReader for testing.
type mockPCRReader struct {
	values map[int][]byte
}

func (m *mockPCRReader) ReadPCRs(_ string, indices []int) (map[int][]byte, error) {
	result := make(map[int][]byte, len(indices))
	for _, idx := range indices {
		if v, ok := m.values[idx]; ok {
			result[idx] = v
		} else {
			result[idx] = make([]byte, 32) // zero-fill
		}
	}
	return result, nil
}

// mockPolicyStore implements policy.PolicyStore for testing.
type mockPolicyStore struct {
	policies map[string]*policy.PolicyDefinition
}

func newMockPolicyStore() *mockPolicyStore {
	return &mockPolicyStore{policies: make(map[string]*policy.PolicyDefinition)}
}

func (m *mockPolicyStore) SavePolicy(name string, def *policy.PolicyDefinition) error {
	m.policies[name] = def
	return nil
}

func (m *mockPolicyStore) LoadPolicy(name string) (*policy.PolicyDefinition, error) {
	p, ok := m.policies[name]
	if !ok {
		return nil, policy.ErrPolicyNotFound
	}
	return p, nil
}

func (m *mockPolicyStore) DeletePolicy(name string) error {
	if _, ok := m.policies[name]; !ok {
		return policy.ErrPolicyNotFound
	}
	delete(m.policies, name)
	return nil
}

func (m *mockPolicyStore) ListPolicies() ([]*policy.PolicyDefinition, error) {
	result := make([]*policy.PolicyDefinition, 0, len(m.policies))
	for _, p := range m.policies {
		result = append(result, p)
	}
	return result, nil
}

// --- ErrNotConfigured guards ---

func TestPolicyCreate_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PolicyCreate(context.Background(), &transport.PolicyCreateRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPolicyGet_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PolicyGet(context.Background(), &transport.PolicyGetRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPolicyList_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PolicyList(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPolicyDelete_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.PolicyDelete(context.Background(), &transport.PolicyDeleteRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPolicyRefresh_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PolicyRefresh(context.Background(), &transport.PolicyRefreshRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPolicyVerify_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PolicyVerify(context.Background(), &transport.PolicyVerifyRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPolicyExport_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PolicyExport(context.Background(), &transport.PolicyExportRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- Nil request guards ---

func TestPolicyCreate_NilRequest(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	_, err := svc.PolicyCreate(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPolicyGet_NilRequest(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	_, err := svc.PolicyGet(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPolicyDelete_NilRequest(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	err := svc.PolicyDelete(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPolicyRefresh_NilRequest(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	_, err := svc.PolicyRefresh(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPolicyVerify_NilRequest(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	_, err := svc.PolicyVerify(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPolicyExport_NilRequest(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	_, err := svc.PolicyExport(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

// --- Delegation tests ---

func setupServiceWithPolicy(t *testing.T) *XKMSService {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)

	reader := &mockPCRReader{
		values: map[int][]byte{
			0: {0x01, 0x02, 0x03},
			1: {0x04, 0x05, 0x06},
			7: {0x07, 0x08, 0x09},
		},
	}
	store := newMockPolicyStore()
	mgr, err := policy.NewManager(reader, store)
	require.NoError(t, err)

	svc.SetPolicyManager(mgr)
	return svc
}

func TestPolicyCreate_Success(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	resp, err := svc.PolicyCreate(context.Background(), &transport.PolicyCreateRequest{
		Name: "boot-policy",
		Bank: "sha256",
		PCRs: []int{0, 1, 7},
	})
	require.NoError(t, err)
	assert.Equal(t, "boot-policy", resp.Name)
	assert.Equal(t, "sha256", resp.Bank)
	assert.Len(t, resp.PCRs, 3)
	assert.Len(t, resp.Values, 3)
}

func TestPolicyGet_Success(t *testing.T) {
	svc := setupServiceWithPolicy(t)
	ctx := context.Background()

	_, err := svc.PolicyCreate(ctx, &transport.PolicyCreateRequest{
		Name: "get-policy", Bank: "sha256", PCRs: []int{0},
	})
	require.NoError(t, err)

	resp, err := svc.PolicyGet(ctx, &transport.PolicyGetRequest{Name: "get-policy"})
	require.NoError(t, err)
	assert.Equal(t, "get-policy", resp.Name)
}

func TestPolicyGet_NotFound(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	_, err := svc.PolicyGet(context.Background(), &transport.PolicyGetRequest{Name: "nope"})
	require.Error(t, err)
}

func TestPolicyList_Success(t *testing.T) {
	svc := setupServiceWithPolicy(t)
	ctx := context.Background()

	_, err := svc.PolicyCreate(ctx, &transport.PolicyCreateRequest{
		Name: "p1", Bank: "sha256", PCRs: []int{0},
	})
	require.NoError(t, err)
	_, err = svc.PolicyCreate(ctx, &transport.PolicyCreateRequest{
		Name: "p2", Bank: "sha256", PCRs: []int{1},
	})
	require.NoError(t, err)

	resp, err := svc.PolicyList(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Total)
	assert.Len(t, resp.Policies, 2)
}

func TestPolicyDelete_Success(t *testing.T) {
	svc := setupServiceWithPolicy(t)
	ctx := context.Background()

	_, err := svc.PolicyCreate(ctx, &transport.PolicyCreateRequest{
		Name: "del-policy", Bank: "sha256", PCRs: []int{0},
	})
	require.NoError(t, err)

	err = svc.PolicyDelete(ctx, &transport.PolicyDeleteRequest{Name: "del-policy"})
	require.NoError(t, err)

	_, err = svc.PolicyGet(ctx, &transport.PolicyGetRequest{Name: "del-policy"})
	require.Error(t, err)
}

func TestPolicyDelete_NotFound(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	err := svc.PolicyDelete(context.Background(), &transport.PolicyDeleteRequest{Name: "ghost"})
	require.Error(t, err)
}

func TestPolicyRefresh_Success(t *testing.T) {
	svc := setupServiceWithPolicy(t)
	ctx := context.Background()

	_, err := svc.PolicyCreate(ctx, &transport.PolicyCreateRequest{
		Name: "refresh-me", Bank: "sha256", PCRs: []int{0, 1},
	})
	require.NoError(t, err)

	resp, err := svc.PolicyRefresh(ctx, &transport.PolicyRefreshRequest{Name: "refresh-me"})
	require.NoError(t, err)
	assert.Equal(t, "refresh-me", resp.Name)
}

func TestPolicyVerify_Success(t *testing.T) {
	svc := setupServiceWithPolicy(t)
	ctx := context.Background()

	_, err := svc.PolicyCreate(ctx, &transport.PolicyCreateRequest{
		Name: "verify-me", Bank: "sha256", PCRs: []int{0},
	})
	require.NoError(t, err)

	resp, err := svc.PolicyVerify(ctx, &transport.PolicyVerifyRequest{Name: "verify-me"})
	require.NoError(t, err)
	assert.Equal(t, "verify-me", resp.Name)
	assert.True(t, resp.Valid)
}

func TestPolicyExport_Success(t *testing.T) {
	svc := setupServiceWithPolicy(t)
	ctx := context.Background()

	_, err := svc.PolicyCreate(ctx, &transport.PolicyCreateRequest{
		Name: "export-me", Bank: "sha256", PCRs: []int{0},
	})
	require.NoError(t, err)

	resp, err := svc.PolicyExport(ctx, &transport.PolicyExportRequest{Name: "export-me"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Data)
}

func TestPolicyExport_NotFound(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	_, err := svc.PolicyExport(context.Background(), &transport.PolicyExportRequest{Name: "ghost"})
	require.Error(t, err)
}

// --- Delegation error tests ---

func TestPolicyCreate_InvalidName(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	_, err := svc.PolicyCreate(context.Background(), &transport.PolicyCreateRequest{
		Name: "", // Empty name triggers ErrInvalidName
		Bank: "sha256",
		PCRs: []int{0},
	})
	require.Error(t, err)
}

func TestPolicyRefresh_NotFound(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	_, err := svc.PolicyRefresh(context.Background(), &transport.PolicyRefreshRequest{
		Name: "nonexistent-policy",
	})
	require.Error(t, err)
}

func TestPolicyVerify_NotFound(t *testing.T) {
	svc := setupServiceWithPolicy(t)

	_, err := svc.PolicyVerify(context.Background(), &transport.PolicyVerifyRequest{
		Name: "nonexistent-policy",
	})
	require.Error(t, err)
}
