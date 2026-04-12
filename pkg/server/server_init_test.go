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

package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ============================================================================
// mockXKMSCA — minimal mock implementing ca.XKMSCA for unit tests
// ============================================================================

type mockXKMSCA struct {
	initialized bool
	tlsCert     tls.Certificate
	tlsCertErr  error
	caCert      *x509.Certificate
}

func (m *mockXKMSCA) IsInitialized() bool { return m.initialized }

func (m *mockXKMSCA) TLSCertificate(_ *types.KeyAttributes) (tls.Certificate, error) {
	return m.tlsCert, m.tlsCertErr
}

// Stubs for the rest of the ca.XKMSCA interface — not exercised in these tests.

func (m *mockXKMSCA) Init() error { return nil }
func (m *mockXKMSCA) Load() error { return nil }
func (m *mockXKMSCA) Public() crypto.PublicKey {
	if m.caCert != nil {
		return m.caCert.PublicKey
	}
	return nil
}
func (m *mockXKMSCA) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
func (m *mockXKMSCA) SignCSR(_ []byte, _ *ca.SignOptions) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockXKMSCA) CreateCSR(_ *ca.CertificateRequest) ([]byte, error) { return nil, nil }
func (m *mockXKMSCA) IssueCertificate(_ *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	return nil, nil
}
func (m *mockXKMSCA) IssueCertificateWithProfile(_ *ca.CertificateRequest, _ string) (*ca.IssuedCertificate, error) {
	return nil, nil
}
func (m *mockXKMSCA) CACertificate() (*x509.Certificate, error) { return m.caCert, nil }
func (m *mockXKMSCA) CABundle() ([]byte, error)                 { return nil, nil }
func (m *mockXKMSCA) Verify(_ *x509.Certificate) ([][]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockXKMSCA) Revoke(_ *big.Int, _ int) error     { return nil }
func (m *mockXKMSCA) GenerateCRL() ([]byte, error)       { return nil, nil }
func (m *mockXKMSCA) IsRevoked(_ *big.Int) (bool, error) { return false, nil }
func (m *mockXKMSCA) TLSConfig(_ *types.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *mockXKMSCA) QuantumSafeTLSConfig(_ *types.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *mockXKMSCA) CABundleCertPool() (*x509.CertPool, error)                               { return nil, nil }
func (m *mockXKMSCA) TrustedRootCertPool(_ *x509.Certificate) (*x509.CertPool, error)         { return nil, nil }
func (m *mockXKMSCA) TrustedIntermediateCertPool(_ *x509.Certificate) (*x509.CertPool, error) { return nil, nil }
func (m *mockXKMSCA) OSTrustStore() (*x509.CertPool, error)                                   { return nil, nil }
func (m *mockXKMSCA) KeyStore() xkms.Backend         { return nil }
func (m *mockXKMSCA) CertStore() certstore.CertStore { return nil }
func (m *mockXKMSCA) Config() *ca.Identity           { return nil }
func (m *mockXKMSCA) Identity() string               { return "mock-ca" }

// Compile-time check
var _ ca.XKMSCA = (*mockXKMSCA)(nil)

// ============================================================================
// Test helpers
// ============================================================================

// generateSelfSignedCert creates an ECDSA P-256 self-signed certificate and
// returns it as both a tls.Certificate and a raw *x509.Certificate.
func generateSelfSignedCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: ecdsa.GenerateKey failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: CreateCertificate failed: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: ParseCertificate failed: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        parsedCert,
	}

	return tlsCert, parsedCert
}

// writeCertAndKeyFiles writes a self-signed certificate and private key to
// PEM files inside the given directory, returning the file paths.
func writeCertAndKeyFiles(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("writeCertAndKeyFiles: ecdsa.GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("writeCertAndKeyFiles: CreateCertificate: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("writeCertAndKeyFiles: WriteFile cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("writeCertAndKeyFiles: MarshalECPrivateKey: %v", err)
	}

	keyPath = filepath.Join(dir, "key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("writeCertAndKeyFiles: WriteFile key: %v", err)
	}

	return certPath, keyPath
}

// newMinimalServer constructs a Server with only the fields required to
// exercise buildTLSConfig / initializeCredentialService without running
// the full New() constructor (which needs backends, storage, etc.).
func newMinimalServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	return &Server{
		config: cfg,
		logger: setupLogger(config.LoggingConfig{Level: "error", Format: "json"}),
	}
}

// ============================================================================
// Tests — buildTLSConfig
// ============================================================================

func TestBuildTLSConfig_TLSDisabled(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLSConfig{Enabled: false},
	}
	s := newMinimalServer(t, cfg)

	_, err := s.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error when TLS is disabled, got nil")
	}
	if !errors.Is(err, ErrTLSNotEnabled) {
		t.Fatalf("expected ErrTLSNotEnabled, got: %v", err)
	}
}

func TestBuildTLSConfig_CABacked(t *testing.T) {
	tlsCert, _ := generateSelfSignedCert(t)
	mock := &mockXKMSCA{
		initialized: true,
		tlsCert:     tlsCert,
	}

	cfg := &config.Config{
		TLS: config.TLSConfig{
			Enabled:  true,
			ServerCN: "test-server",
		},
		CA: &ca.MultiIdentityCAConfig{
			SelectedCA: 0,
			Identity: []ca.Identity{
				{
					Subject: ca.Subject{
						CommonName: "Test Root CA",
					},
					KeystoreType: types.StoreSoftware,
					Keys: []*types.KeyConfig{
						{
							KeyAlgorithm: types.AlgorithmECDSA,
							ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
						},
					},
				},
			},
		},
	}
	s := newMinimalServer(t, cfg)
	s.ca = mock

	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2 minimum, got %d", tlsConfig.MinVersion)
	}
}

func TestBuildTLSConfig_CANotInitialized_FallbackToFile(t *testing.T) {
	// CA exists but is not initialized -- should skip CA path.
	// File-based TLS is configured, so it should fall back to file.
	tmpDir := t.TempDir()
	certPath, keyPath := writeCertAndKeyFiles(t, tmpDir)

	mock := &mockXKMSCA{initialized: false}

	cfg := &config.Config{
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}
	s := newMinimalServer(t, cfg)
	s.ca = mock

	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}
}

func TestBuildTLSConfig_CATLSCertificateError(t *testing.T) {
	mock := &mockXKMSCA{
		initialized: true,
		tlsCertErr:  errors.New("hardware token unavailable"),
	}

	cfg := &config.Config{
		TLS: config.TLSConfig{
			Enabled:  true,
			ServerCN: "test-server",
		},
		CA: &ca.MultiIdentityCAConfig{
			SelectedCA: 0,
			Identity: []ca.Identity{
				{
					Subject: ca.Subject{
						CommonName: "Test Root CA",
					},
					KeystoreType: types.StoreSoftware,
					Keys: []*types.KeyConfig{
						{
							KeyAlgorithm: types.AlgorithmECDSA,
							ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
						},
					},
				},
			},
		},
	}
	s := newMinimalServer(t, cfg)
	s.ca = mock

	_, err := s.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error when CA TLS cert fails, got nil")
	}
	if !errors.Is(err, ErrCATLSCertFailed) {
		t.Fatalf("expected ErrCATLSCertFailed, got: %v", err)
	}
}

func TestBuildTLSConfig_FileBased(t *testing.T) {
	tmpDir := t.TempDir()
	certPath, keyPath := writeCertAndKeyFiles(t, tmpDir)

	cfg := &config.Config{
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}
	s := newMinimalServer(t, cfg)

	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}
}

func TestBuildTLSConfig_FileBasedBadPaths(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
	}
	s := newMinimalServer(t, cfg)

	_, err := s.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid cert/key paths, got nil")
	}
}

func TestBuildTLSConfig_NoCertSource(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLSConfig{
			Enabled: true,
			// No CA, no CertFile, no KeyFile
		},
	}
	s := newMinimalServer(t, cfg)

	_, err := s.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error when no cert source, got nil")
	}
}

func TestBuildTLSConfig_MinMaxVersion(t *testing.T) {
	tmpDir := t.TempDir()
	certPath, keyPath := writeCertAndKeyFiles(t, tmpDir)

	cfg := &config.Config{
		TLS: config.TLSConfig{
			Enabled:    true,
			CertFile:   certPath,
			KeyFile:    keyPath,
			MinVersion: "TLS1.3",
			MaxVersion: "TLS1.3",
		},
	}
	s := newMinimalServer(t, cfg)

	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected MinVersion TLS 1.3, got %d", tlsConfig.MinVersion)
	}
	if tlsConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("expected MaxVersion TLS 1.3, got %d", tlsConfig.MaxVersion)
	}
}

func TestBuildTLSConfig_ClientAuth(t *testing.T) {
	t.Run("require_and_verify", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath, keyPath := writeCertAndKeyFiles(t, tmpDir)

		cfg := &config.Config{
			TLS: config.TLSConfig{
				Enabled:    true,
				CertFile:   certPath,
				KeyFile:    keyPath,
				ClientAuth: "require_and_verify",
			},
		}
		s := newMinimalServer(t, cfg)

		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Fatalf("expected RequireAndVerifyClientCert, got %v", tlsConfig.ClientAuth)
		}
	})

	t.Run("verify", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath, keyPath := writeCertAndKeyFiles(t, tmpDir)

		cfg := &config.Config{
			TLS: config.TLSConfig{
				Enabled:    true,
				CertFile:   certPath,
				KeyFile:    keyPath,
				ClientAuth: "verify",
			},
		}
		s := newMinimalServer(t, cfg)

		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tlsConfig.ClientAuth != tls.VerifyClientCertIfGiven {
			t.Fatalf("expected VerifyClientCertIfGiven, got %v", tlsConfig.ClientAuth)
		}
	})

	t.Run("none", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath, keyPath := writeCertAndKeyFiles(t, tmpDir)

		cfg := &config.Config{
			TLS: config.TLSConfig{
				Enabled:  true,
				CertFile: certPath,
				KeyFile:  keyPath,
			},
		}
		s := newMinimalServer(t, cfg)

		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tlsConfig.ClientAuth != tls.NoClientCert {
			t.Fatalf("expected NoClientCert, got %v", tlsConfig.ClientAuth)
		}
	})
}

// ============================================================================
// Tests — initializeCredentialService
// ============================================================================

func TestInitializeCredentialService_DefaultManual(t *testing.T) {
	cfg := &config.Config{
		Credentials: config.CredentialsConfig{
			SealStrategy: "",
		},
	}
	s := newMinimalServer(t, cfg)

	if err := s.initializeCredentialService(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.credentialService == nil {
		t.Fatal("expected credentialService to be initialized")
	}
	if s.credentialService.Strategy() != "manual" {
		t.Fatalf("expected strategy 'manual', got %q", s.credentialService.Strategy())
	}
}

func TestInitializeCredentialService_ExplicitStrategy(t *testing.T) {
	cfg := &config.Config{
		Credentials: config.CredentialsConfig{
			SealStrategy: "manual",
		},
	}
	s := newMinimalServer(t, cfg)

	if err := s.initializeCredentialService(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.credentialService == nil {
		t.Fatal("expected credentialService to be initialized")
	}
	if s.credentialService.Strategy() != "manual" {
		t.Fatalf("expected strategy 'manual', got %q", s.credentialService.Strategy())
	}
}

func TestInitializeCredentialService_BarrierRequiresNonNilBarrier(t *testing.T) {
	cfg := &config.Config{
		Credentials: config.CredentialsConfig{
			SealStrategy: "barrier",
		},
	}
	s := newMinimalServer(t, cfg)
	// barrier is nil

	err := s.initializeCredentialService()
	if err == nil {
		t.Fatal("expected error when barrier strategy used without barrier, got nil")
	}
	if !errors.Is(err, ErrCredentialServiceFailed) {
		t.Fatalf("expected ErrCredentialServiceFailed, got: %v", err)
	}
}

func TestInitializeCredentialService_InvalidStrategy(t *testing.T) {
	cfg := &config.Config{
		Credentials: config.CredentialsConfig{
			SealStrategy: "invalid-strategy-xyz",
		},
	}
	s := newMinimalServer(t, cfg)

	err := s.initializeCredentialService()
	if err == nil {
		t.Fatal("expected error for invalid strategy, got nil")
	}
	if !errors.Is(err, ErrCredentialServiceFailed) {
		t.Fatalf("expected ErrCredentialServiceFailed, got: %v", err)
	}
}

// ============================================================================
// Tests — SetCA / SetCeremonyService / SetCredentialService / CredentialService
// ============================================================================

func TestSetCA(t *testing.T) {
	cfg := &config.Config{}
	s := newMinimalServer(t, cfg)

	if s.ca != nil {
		t.Fatal("expected ca to be nil initially")
	}

	mock := &mockXKMSCA{initialized: true}
	s.SetCA(mock)

	if s.ca == nil {
		t.Fatal("expected ca to be set after SetCA")
	}
	if s.ca != mock {
		t.Fatal("expected ca to equal the mock we set")
	}
}

func TestSetCA_Nil(t *testing.T) {
	cfg := &config.Config{}
	s := newMinimalServer(t, cfg)

	mock := &mockXKMSCA{initialized: true}
	s.SetCA(mock)
	if s.ca == nil {
		t.Fatal("expected ca to be set")
	}

	s.SetCA(nil)
	if s.ca != nil {
		t.Fatal("expected ca to be nil after SetCA(nil)")
	}
}

func TestSetCeremonyService(t *testing.T) {
	cfg := &config.Config{}
	s := newMinimalServer(t, cfg)

	if s.ceremonyService != nil {
		t.Fatal("expected ceremonyService to be nil initially")
	}

	// We cannot easily construct a real CeremonyService without many deps,
	// so verify the setter works by assigning and reading back.
	var svc *initialize.CeremonyService
	s.SetCeremonyService(svc)
	if s.ceremonyService != nil {
		t.Fatal("expected ceremonyService to be nil when set with nil")
	}
}

func TestSetCredentialService(t *testing.T) {
	cfg := &config.Config{
		Credentials: config.CredentialsConfig{SealStrategy: "manual"},
	}
	s := newMinimalServer(t, cfg)

	// Initialize manually so we have a service to test with.
	svc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: "manual"},
		nil, nil, s.logger,
	)
	if err != nil {
		t.Fatalf("failed to create credential service: %v", err)
	}

	s.SetCredentialService(svc)
	if s.credentialService != svc {
		t.Fatal("expected credentialService to match the service we set")
	}
}

func TestSetCredentialService_Nil(t *testing.T) {
	cfg := &config.Config{}
	s := newMinimalServer(t, cfg)

	s.SetCredentialService(nil)
	if s.credentialService != nil {
		t.Fatal("expected credentialService to be nil after SetCredentialService(nil)")
	}
}

func TestCredentialService_Getter(t *testing.T) {
	cfg := &config.Config{
		Credentials: config.CredentialsConfig{SealStrategy: "manual"},
	}
	s := newMinimalServer(t, cfg)

	// Before initialization
	if s.CredentialService() != nil {
		t.Fatal("expected CredentialService() to return nil before initialization")
	}

	// Initialize
	if err := s.initializeCredentialService(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	svc := s.CredentialService()
	if svc == nil {
		t.Fatal("expected CredentialService() to return non-nil after initialization")
	}
	if svc.Strategy() != "manual" {
		t.Fatalf("expected strategy 'manual', got %q", svc.Strategy())
	}
}

func TestCredentialService_SetThenGet(t *testing.T) {
	cfg := &config.Config{}
	s := newMinimalServer(t, cfg)

	svc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: "manual"},
		nil, nil, s.logger,
	)
	if err != nil {
		t.Fatalf("failed to create credential service: %v", err)
	}

	s.SetCredentialService(svc)
	got := s.CredentialService()
	if got != svc {
		t.Fatal("CredentialService() should return the service set via SetCredentialService()")
	}
}
