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

package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/autofill"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
)

// ===========================================================================
// Part 9: Final coverage push from 89.8% to 90%+
// Targets: 23 additional statements across tenant, agent, password
// protection, fido2, setup wizard, autofill, and piv services.
// ===========================================================================

// ---------------------------------------------------------------------------
// Mock: agent.EnrollmentStore with configurable ListAgents error
// ---------------------------------------------------------------------------

type p9FailingEnrollmentStore struct {
	listErr error
	agents  map[string]*agent.AgentInfo
}

func (s *p9FailingEnrollmentStore) SaveAgent(a *agent.AgentInfo) error {
	if a == nil || a.ID == "" {
		return errors.New("invalid agent")
	}
	s.agents[a.ID] = a
	return nil
}

func (s *p9FailingEnrollmentStore) GetAgent(id string) (*agent.AgentInfo, error) {
	a, ok := s.agents[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return a, nil
}

func (s *p9FailingEnrollmentStore) ListAgents() ([]*agent.AgentInfo, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	result := make([]*agent.AgentInfo, 0, len(s.agents))
	for _, a := range s.agents {
		result = append(result, a)
	}
	return result, nil
}

func (s *p9FailingEnrollmentStore) DeleteAgent(id string) error {
	delete(s.agents, id)
	return nil
}

// ---------------------------------------------------------------------------
// Mock: agent.CAService (minimal, for creating EnrollmentService)
// ---------------------------------------------------------------------------

type p9MockCAService struct{}

func (m *p9MockCAService) SignCSR([]byte) ([]byte, error) { return nil, errors.New("not implemented") }
func (m *p9MockCAService) GetCACertificate() ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (m *p9MockCAService) RevokeCertificate(string) error { return errors.New("not implemented") }

// ---------------------------------------------------------------------------
// Mock: staticpw.Store with configurable List error
// ---------------------------------------------------------------------------

type p9FailingStaticPWStore struct {
	listErr error
}

func (m *p9FailingStaticPWStore) Add(*staticpw.StaticPassword) error { return nil }
func (m *p9FailingStaticPWStore) Get(string) (*staticpw.StaticPassword, error) {
	return nil, errors.New("not found")
}
func (m *p9FailingStaticPWStore) List() ([]*staticpw.StaticPassword, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return nil, nil
}
func (m *p9FailingStaticPWStore) Update(*staticpw.StaticPassword) error { return nil }
func (m *p9FailingStaticPWStore) Delete(string) error                   { return nil }
func (m *p9FailingStaticPWStore) ForceDelete(string) error              { return nil }
func (m *p9FailingStaticPWStore) ListByFolder(string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (m *p9FailingStaticPWStore) ListByFolderDirect(string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (m *p9FailingStaticPWStore) ListFolders() ([]string, error)    { return nil, nil }
func (m *p9FailingStaticPWStore) MoveToFolder(string, string) error { return nil }
func (m *p9FailingStaticPWStore) Close() error                      { return nil }
func (m *p9FailingStaticPWStore) CreateFolder(string) error         { return nil }
func (m *p9FailingStaticPWStore) RemoveFolder(string) error         { return nil }

// ===========================================================================
// TenantService: getClient error paths (lines 110, 156, 208)
// ===========================================================================

func TestP9_TenantService_GetTenant_NoClient(t *testing.T) {
	svc := NewTenantService()
	svc.ctx = context.Background()

	_, err := svc.GetTenant("test-tenant")
	assert.ErrorIs(t, err, ErrTenantServiceNoClient)
}

func TestP9_TenantService_DeleteTenant_NoClient(t *testing.T) {
	svc := NewTenantService()
	svc.ctx = context.Background()

	err := svc.DeleteTenant("test-tenant")
	assert.ErrorIs(t, err, ErrTenantServiceNoClient)
}

func TestP9_TenantService_BarrierUnseal_NoClient(t *testing.T) {
	svc := NewTenantService()
	svc.ctx = context.Background()

	err := svc.BarrierUnseal("test-tenant", []byte("share"), nil)
	assert.ErrorIs(t, err, ErrTenantServiceNoClient)
}

// ===========================================================================
// AgentService: StartServer with nil enrollment (lines 149-152)
// ===========================================================================

func TestP9_AgentService_StartServer_NilEnrollment(t *testing.T) {
	svc := NewAgentService()
	// enrollment is nil by default.

	err := svc.StartServer("127.0.0.1:0")
	assert.ErrorIs(t, err, ErrAgentServiceNotReady)
}

// ===========================================================================
// AgentService: StartServer with bad address (lines 154-157)
// Requires a valid enrollment so NewServer succeeds, but Start fails.
// ===========================================================================

func TestP9_AgentService_StartServer_BadAddress(t *testing.T) {
	svc := NewAgentService()

	// Create a real EnrollmentService with AdminApproval only
	// (no OneTimeCode) to satisfy the nil check.
	cfg := agent.DefaultConfig()
	cfg.EnrollmentMethods = []agent.EnrollmentMethod{agent.EnrollAdminApproval}
	enrollment, err := agent.NewEnrollmentService(
		cfg, &p9MockCAService{}, agent.NewMemoryStore(), slog.Default())
	require.NoError(t, err)

	svc.SetEnrollmentService(enrollment)

	// Use an address that will fail to bind.
	err = svc.StartServer("invalid-address-no-port")
	assert.ErrorIs(t, err, ErrAgentServerNotStarted)
}

// ===========================================================================
// AgentService: GenerateEnrollmentCode with method not allowed (lines 241-244)
// ===========================================================================

func TestP9_AgentService_GenerateEnrollmentCode_MethodNotAllowed(t *testing.T) {
	svc := NewAgentService()

	// Create an EnrollmentService WITHOUT EnrollOneTimeCode.
	cfg := agent.DefaultConfig()
	cfg.EnrollmentMethods = []agent.EnrollmentMethod{agent.EnrollAdminApproval}
	enrollment, err := agent.NewEnrollmentService(
		cfg, &p9MockCAService{}, agent.NewMemoryStore(), slog.Default())
	require.NoError(t, err)

	svc.SetEnrollmentService(enrollment)

	_, err = svc.GenerateEnrollmentCode()
	assert.ErrorIs(t, err, ErrAgentEnrollmentFailed)
}

// ===========================================================================
// AgentService: ListAgents with store returning error (lines 361-363)
// ===========================================================================

func TestP9_AgentService_ListAgents_StoreError(t *testing.T) {
	svc := NewAgentService()
	svc.SetEnrollmentStore(&p9FailingEnrollmentStore{
		listErr: errors.New("database connection lost"),
		agents:  make(map[string]*agent.AgentInfo),
	})

	_, err := svc.ListAgents()
	assert.ErrorIs(t, err, ErrAgentEnrollmentFailed)
}

// ===========================================================================
// PasswordProtectionService: GetStatus with sealSvc (line 109-111)
// ===========================================================================

func TestP9_PasswordProtection_GetStatus_WithSealService(t *testing.T) {
	sealSvc := NewSealService(t.TempDir())
	ppSvc := NewPasswordProtectionService("", nil, sealSvc)

	status, err := ppSvc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)
	// sealSvc.CanSeal returns false (no client), so TPMAvailable should be false.
	assert.False(t, status.TPMAvailable)
}

// ===========================================================================
// FIDO2Service: storedToFIDO2Credential with unknown CredProtect (line 634-636)
// Covers the "if cpLabel == "" { cpLabel = "None" }" branch.
// ===========================================================================

func TestP9_FIDO2_StoredToFIDO2Credential_UnknownCredProtect(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x01, 0x02},
		RPID:         "example.com",
		RPName:       "Example",
		UserName:     "alice",
		Algorithm:    -7, // ES256
		CredProtect:  99, // Not in credProtectLabels map
		CreatedAt:    time.Now().Unix(),
	}

	cred := storedToFIDO2Credential(stored)
	// The unknown CredProtect value (99) should still be stored as the int value.
	assert.Equal(t, 99, cred.CredProtect)
	// BackendType should be "hardware" because PrivateKey is nil.
	assert.Equal(t, "hardware", cred.BackendType)
}

// ===========================================================================
// SetupWizardService: ProbeEnvironment with sealSvc (line 408-410)
// ===========================================================================

func TestP9_SetupWizard_ProbeEnvironment_WithSealService(t *testing.T) {
	svc := NewSetupWizardService()
	sealSvc := NewSealService(t.TempDir())
	svc.SetSealService(sealSvc)

	probe, err := svc.ProbeEnvironment()
	require.NoError(t, err)
	require.NotNil(t, probe)
	// AvailableSealers will be empty (no client on the SealService).
	assert.Empty(t, probe.AvailableSealers)
}

// ===========================================================================
// AutoFill: SearchCredentials with ListPasswords error (line 285-287)
// ===========================================================================

func TestP9_AutoFill_SearchCredentials_ListPasswordsError(t *testing.T) {
	failStore := &p9FailingStaticPWStore{listErr: errors.New("barrier sealed")}
	pwSvc := NewStaticPasswordService(failStore)
	svc := NewAutoFillService(pwSvc, nil, nil, nil, slog.Default())
	svc.enabled.Store(true)

	_, err := svc.SearchCredentials("example.com")
	assert.Error(t, err)
}

// ===========================================================================
// AutoFill: GetCredential with rate limit exhausted (line 341-343)
// ===========================================================================

func TestP9_AutoFill_GetCredential_RateLimited(t *testing.T) {
	pwSvc := NewStaticPasswordService(nil)
	svc := NewAutoFillService(pwSvc, nil, nil, nil, slog.Default())
	svc.enabled.Store(true)

	// Set rate limiter to 1 fill per minute.
	svc.rateLimiter = autofill.NewRateLimiter(1)

	// Exhaust the rate limiter with a SearchCredentials call
	// (SearchCredentials and GetCredential share the same rate limiter).
	// We need the store to be non-nil for SearchCredentials to reach the
	// rate limiter. Use a store that returns an empty list.
	pwSvc.store = &p9FailingStaticPWStore{} // List returns nil, nil
	_, _ = svc.SearchCredentials("example.com")

	// Now GetCredential should be rate-limited.
	_, err := svc.GetCredential("some-id", "challenge")
	assert.ErrorIs(t, err, ErrAutoFillRateLimit)
}

// ===========================================================================
// AutoFill: GetTOTPForDomain with OATHService.ListAccounts error (line 404-406)
// ===========================================================================

func TestP9_AutoFill_GetTOTPForDomain_ListAccountsError(t *testing.T) {
	// Create OATHService with nil store so ListAccounts returns error.
	oathSvc := NewOATHService(nil)
	svc := NewAutoFillService(nil, oathSvc, nil, nil, slog.Default())
	svc.enabled.Store(true)

	_, err := svc.GetTOTPForDomain("example.com")
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)
}

// ===========================================================================
// PIV Service: certKeySize with RSA key (line 589-591)
// ===========================================================================

func TestP9_CertKeySize_RSA(t *testing.T) {
	// Generate a 2048-bit RSA key.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a minimal certificate with the RSA public key.
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		PublicKey:    &privKey.PublicKey,
	}

	size := certKeySize(cert)
	assert.Equal(t, 2048, size)
}

func TestP9_CertKeySize_RSA4096(t *testing.T) {
	// Generate a 4096-bit RSA key (verifies correct size calculation).
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		PublicKey:    &privKey.PublicKey,
	}

	size := certKeySize(cert)
	assert.Equal(t, 4096, size)
}

// ===========================================================================
// FIDO2Service: storedToFIDO2Credential with known CredProtect values
// Verify known values resolve correctly via the credProtectLabels map.
// ===========================================================================

func TestP9_FIDO2_StoredToFIDO2Credential_KnownCredProtect(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x03, 0x04},
		RPID:         "example.com",
		RPName:       "Example",
		UserName:     "bob",
		Algorithm:    -7,           // ES256
		CredProtect:  3,            // UV Required
		PrivateKey:   []byte{0x01}, // Non-nil = software backend
		CreatedAt:    time.Now().Unix(),
	}

	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, 3, cred.CredProtect)
	assert.Equal(t, "software", cred.BackendType)
}

// ===========================================================================
// FIDO2Service: storedToFIDO2Credential with nil PrivateKey and empty BackendID
// This covers the "hardware" heuristic branch (line 646-649).
// ===========================================================================

func TestP9_FIDO2_StoredToFIDO2Credential_HardwareHeuristic(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x05, 0x06},
		RPID:         "example.com",
		RPName:       "Example",
		UserName:     "carol",
		Algorithm:    -7,
		CredProtect:  255, // Unknown - covers line 634-636 too
		PrivateKey:   nil, // No exportable key = hardware
		BackendID:    "",  // Empty backend ID triggers heuristic
		CreatedAt:    time.Now().Unix(),
	}

	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, "hardware", cred.BackendType)
	assert.Equal(t, 255, cred.CredProtect)
}
