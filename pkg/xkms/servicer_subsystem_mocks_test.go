package xkms

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// mockKeyProvider implements types.KeyProvider for backend tests.
// Only Type() and Capabilities() return meaningful values; other methods
// return errors since they aren't called from ListBackends/GetBackend.
type mockKeyProvider struct {
	providerType types.BackendType
}

func (m *mockKeyProvider) Type() types.BackendType { return m.providerType }
func (m *mockKeyProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Signing: true, Decryption: true}
}
func (m *mockKeyProvider) GenerateKey(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKeyProvider) GetKey(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKeyProvider) DeleteKey(_ *types.KeyAttributes) error {
	return errors.New("not implemented")
}
func (m *mockKeyProvider) ListKeys() ([]*types.KeyAttributes, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKeyProvider) Signer(_ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKeyProvider) Decrypter(_ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKeyProvider) RotateKey(_ *types.KeyAttributes) error {
	return errors.New("not implemented")
}
func (m *mockKeyProvider) Close() error { return nil }

// setupServiceWithProviders creates a service with mock key providers set on each backend.
func setupServiceWithProviders(t *testing.T) (*XKMSService, *mockKeyStore, *mockKeyStore) {
	t.Helper()
	Reset()

	software := newMockKeyStore("software")
	software.backend = &mockKeyProvider{providerType: types.BackendTypeSoftware}
	pkcs11Mock := newMockKeyStore("pkcs11")
	pkcs11Mock.backend = &mockKeyProvider{providerType: types.BackendTypePKCS11}

	config := &ServiceConfig{
		Backends: map[string]Backend{
			"software": software,
			"pkcs11":   pkcs11Mock,
		},
		DefaultBackend: "software",
	}

	err := Initialize(config)
	require.NoError(t, err)

	svc, err := Get()
	require.NoError(t, err)

	return svc, software, pkcs11Mock
}

// mockPINManager implements qrdbsdk.PINBackend for testing.
type mockPINManager struct {
	soPin      string
	userPin    string
	lockStatus *qrdbsdk.PINLockoutStatus
	err        error
}

func (m *mockPINManager) Strategy() qrdbsdk.PINStrategyID { return "mock" }

func (m *mockPINManager) SetSOPIN(current, newPin string) error {
	if m.err != nil {
		return m.err
	}
	m.soPin = newPin
	return nil
}

func (m *mockPINManager) SetUserPIN(soPin, newPin string) error {
	if m.err != nil {
		return m.err
	}
	m.userPin = newPin
	return nil
}

func (m *mockPINManager) ChangeSOPIN(current, newPin string) error {
	if m.err != nil {
		return m.err
	}
	m.soPin = newPin
	return nil
}

func (m *mockPINManager) ChangeUserPIN(current, newPin string) error {
	if m.err != nil {
		return m.err
	}
	m.userPin = newPin
	return nil
}

func (m *mockPINManager) VerifySOPIN(p string) error {
	if p != m.soPin {
		return errors.New("invalid SO PIN")
	}
	return nil
}

func (m *mockPINManager) VerifyUserPIN(p string) error {
	if p != m.userPin {
		return errors.New("invalid user PIN")
	}
	return nil
}

func (m *mockPINManager) GetLockoutStatus() *qrdbsdk.PINLockoutStatus {
	if m.lockStatus != nil {
		return m.lockStatus
	}
	return &qrdbsdk.PINLockoutStatus{MaxAttempts: 3}
}

func (m *mockPINManager) ResetLockout(soPin string) error {
	if soPin != m.soPin {
		return errors.New("invalid SO PIN")
	}
	return nil
}

func (m *mockPINManager) IsInitialized() bool { return m.soPin != "" }
func (m *mockPINManager) SOPINSet() bool      { return m.soPin != "" }
func (m *mockPINManager) UserPINSet() bool    { return m.userPin != "" }

// mockPlatformStore implements seal.PlatformStore for testing.
type mockPlatformStore struct {
	secrets map[string][]byte
	err     error
}

func newMockPlatformStore() *mockPlatformStore {
	return &mockPlatformStore{secrets: make(map[string][]byte)}
}

func (m *mockPlatformStore) Put(ctx context.Context, name string, secret []byte) error {
	if m.err != nil {
		return m.err
	}
	m.secrets[name] = secret
	return nil
}

func (m *mockPlatformStore) Get(ctx context.Context, name string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	s, ok := m.secrets[name]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return s, nil
}

func (m *mockPlatformStore) Delete(ctx context.Context, name string) error {
	if m.err != nil {
		return m.err
	}
	delete(m.secrets, name)
	return nil
}

func (m *mockPlatformStore) Exists(ctx context.Context, name string) (bool, error) {
	_, ok := m.secrets[name]
	return ok, nil
}

func (m *mockPlatformStore) List(ctx context.Context) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	names := make([]string, 0, len(m.secrets))
	for k := range m.secrets {
		names = append(names, k)
	}
	return names, nil
}

func (m *mockPlatformStore) Reseal(ctx context.Context, name string) error {
	return nil
}

// fakeShareClient implements qrdbtransport.ShareClient for testing. It mirrors
// the behaviour of the embedded go-qrdb node's share client by storing
// submitted shares in memory.
type fakeShareClient struct {
	shares    []qrdbtransport.ShareInfo
	threshold int
	total     int
	err       error
}

func newFakeShareClient() *fakeShareClient {
	return &fakeShareClient{}
}

func (f *fakeShareClient) SubmitShare(ctx context.Context, req *qrdbtransport.SubmitShareRequest) (*qrdbtransport.SubmitShareResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.shares = append(f.shares, qrdbtransport.ShareInfo{
		ServerURL:  req.ServerURL,
		GroupID:    req.GroupID,
		GroupName:  req.GroupName,
		ShareIndex: req.ShareIndex,
		ShareData:  req.ShareData,
		Purpose:    req.Purpose,
		ReceivedAt: time.Now().UTC(),
		TenantID:   req.TenantID,
	})
	return &qrdbtransport.SubmitShareResponse{Accepted: true}, nil
}

func (f *fakeShareClient) ListShares(ctx context.Context) (*qrdbtransport.ListSharesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &qrdbtransport.ListSharesResponse{Shares: f.shares}, nil
}

func (f *fakeShareClient) GetShare(ctx context.Context, serverURL, groupID string, shareIndex int) (*qrdbtransport.ShareInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	for i := range f.shares {
		s := f.shares[i]
		if s.ServerURL == serverURL && s.GroupID == groupID && s.ShareIndex == shareIndex {
			return &s, nil
		}
	}
	return nil, qrdbsdk.ErrCeremonyShareNotFound
}

func (f *fakeShareClient) DeleteShare(ctx context.Context, serverURL, groupID string, shareIndex int) error {
	if f.err != nil {
		return f.err
	}
	for i := range f.shares {
		s := f.shares[i]
		if s.ServerURL == serverURL && s.GroupID == groupID && s.ShareIndex == shareIndex {
			f.shares = append(f.shares[:i], f.shares[i+1:]...)
			return nil
		}
	}
	return qrdbsdk.ErrCeremonyShareNotFound
}

func (f *fakeShareClient) GetShareCollectionStatus(ctx context.Context, groupID string) (*qrdbtransport.ShareCollectionStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	collected := 0
	for i := range f.shares {
		if f.shares[i].GroupID == groupID {
			collected++
		}
	}
	return &qrdbtransport.ShareCollectionStatus{
		GroupID:   groupID,
		Threshold: f.threshold,
		Total:     f.total,
		Collected: collected,
		Ready:     f.threshold > 0 && collected >= f.threshold,
	}, nil
}
