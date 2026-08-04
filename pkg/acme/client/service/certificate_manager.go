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

package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"net"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client"
)

// Compile-time interface check.
var _ CertificateManager = (*certificateManager)(nil)

// CertificateManager manages the lifecycle of certificates defined in the configuration.
type CertificateManager interface {
	// Request obtains a new certificate from the ACME server for the named spec.
	Request(ctx context.Context, name string) (*CertResult, error)

	// Renew renews the certificate for the named spec by performing a new request.
	Renew(ctx context.Context, name string) (*CertResult, error)

	// Revoke revokes the managed certificate for the named spec with the given reason code.
	Revoke(ctx context.Context, name string, reason int) error

	// Deploy writes the managed certificate and key to the paths configured in the spec.
	Deploy(ctx context.Context, name string) error

	// List returns certificate specs, optionally filtered by account name.
	List(accountFilter string) map[string]*CertificateSpec

	// Show returns metadata about a managed certificate.
	Show(name string) (*ManagedCertInfo, error)
}

// CertResult holds the outcome of a certificate request or renewal.
type CertResult struct {
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
}

// ManagedCertInfo holds metadata about an issued certificate.
type ManagedCertInfo struct {
	Name        string
	Spec        *CertificateSpec
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
	IssuedAt    time.Time
	ExpiresAt   time.Time
	DeployedAt  *time.Time
}

// certificateManager is the concrete implementation of CertificateManager.
type certificateManager struct {
	config   *Config
	accounts AccountManager
	deployer *Deployer
	logger   *slog.Logger
	managed  sync.Map // map[string]*ManagedCertInfo
}

// NewCertificateManager creates a new CertificateManager backed by the given
// configuration, account manager, deployer, and logger.
func NewCertificateManager(
	config *Config,
	accounts AccountManager,
	deployer *Deployer,
	logger *slog.Logger,
) CertificateManager {

	return &certificateManager{
		config:   config,
		accounts: accounts,
		deployer: deployer,
		logger:   logger,
	}
}

// Request obtains a new certificate from the ACME server for the named spec.
func (cm *certificateManager) Request(ctx context.Context, name string) (*CertResult, error) {
	spec, ok := cm.config.Certificates[name]
	if !ok {
		return nil, ErrCertSpecNotFound{Name: name}
	}

	if spec.Key == nil {
		return nil, ErrMissingKeyConfig{Context: name}
	}

	acmeClient, err := cm.accounts.Client(ctx, spec.Account)
	if err != nil {
		return nil, err
	}

	certKey, err := generateSigner(spec.Key)
	if err != nil {
		return nil, err
	}

	csrDER, err := buildCSR(spec, certKey)
	if err != nil {
		return nil, err
	}

	challengeType := spec.Challenge
	if challengeType == "" {
		challengeType = "http-01"
	}

	certReq := &client.CertificateRequest{
		AuthzType:     "dns",
		AuthzValue:    spec.Subject.CN,
		ChallengeType: challengeType,
		CSR:           csrDER,
	}

	cert, err := acmeClient.RequestCertificate(ctx, certReq)
	if err != nil {
		return nil, err
	}

	certPEM := encodeCertPEM(cert)

	keyPEM, err := encodeKeyPEM(certKey)
	if err != nil {
		return nil, err
	}

	info := &ManagedCertInfo{
		Name:        name,
		Spec:        spec,
		Certificate: cert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		IssuedAt:    cert.NotBefore,
		ExpiresAt:   cert.NotAfter,
	}
	cm.managed.Store(name, info)

	cm.logger.InfoContext(ctx, "certificate issued",
		slog.String("name", name),
		slog.String("subject", cert.Subject.CommonName),
		slog.Time("expires", cert.NotAfter),
	)

	if spec.Deploy != nil {
		if err := cm.Deploy(ctx, name); err != nil {
			return nil, err
		}
	}

	return &CertResult{
		Certificate: cert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// Renew renews the certificate for the named spec by performing a new request.
func (cm *certificateManager) Renew(ctx context.Context, name string) (*CertResult, error) {
	if _, ok := cm.config.Certificates[name]; !ok {
		return nil, ErrCertSpecNotFound{Name: name}
	}

	cm.logger.InfoContext(ctx, "renewing certificate", slog.String("name", name))

	result, err := cm.Request(ctx, name)
	if err != nil {
		return nil, err
	}

	cm.logger.InfoContext(ctx, "certificate renewed",
		slog.String("name", name),
		slog.String("subject", result.Certificate.Subject.CommonName),
		slog.Time("expires", result.Certificate.NotAfter),
	)

	return result, nil
}

// Revoke revokes the managed certificate for the named spec with the given reason code.
// Returns ErrCertSpecNotFound when the spec does not exist in the configuration,
// and ErrNoIssuedCertificate when the spec exists but no certificate has been
// issued yet (i.e., Request has not been called successfully).
func (cm *certificateManager) Revoke(ctx context.Context, name string, reason int) error {
	val, ok := cm.managed.Load(name)
	if !ok {
		if _, specExists := cm.config.Certificates[name]; specExists {
			return ErrNoIssuedCertificate{Name: name}
		}
		return ErrCertSpecNotFound{Name: name}
	}
	info := val.(*ManagedCertInfo)

	acmeClient, err := cm.accounts.Client(ctx, info.Spec.Account)
	if err != nil {
		return err
	}

	if err := acmeClient.RevokeCertificate(ctx, info.Certificate, acme.CRLReasonCode(reason)); err != nil {
		return err
	}

	cm.managed.Delete(name)

	cm.logger.InfoContext(ctx, "certificate revoked",
		slog.String("name", name),
		slog.String("subject", info.Certificate.Subject.CommonName),
		slog.Int("reason", reason),
	)

	return nil
}

// Deploy writes the managed certificate and key to the paths configured in the spec.
// Returns ErrCertSpecNotFound when the spec does not exist in the configuration,
// and ErrNoIssuedCertificate when the spec exists but no certificate has been
// issued yet (i.e., Request has not been called successfully).
func (cm *certificateManager) Deploy(ctx context.Context, name string) error {
	val, ok := cm.managed.Load(name)
	if !ok {
		if _, specExists := cm.config.Certificates[name]; specExists {
			return ErrNoIssuedCertificate{Name: name}
		}
		return ErrCertSpecNotFound{Name: name}
	}
	info := val.(*ManagedCertInfo)

	if info.Spec.Deploy == nil {
		return ErrDeployFailed{
			CertName: name,
			Err:      ErrNothingToDeploy{Name: name},
		}
	}

	if err := cm.deployer.Deploy(ctx, info.CertPEM, info.KeyPEM, info.Spec.Deploy); err != nil {
		return err
	}

	now := time.Now()
	info.DeployedAt = &now
	cm.managed.Store(name, info)

	cm.logger.InfoContext(ctx, "certificate deployed",
		slog.String("name", name),
		slog.Time("deployed_at", now),
	)

	return nil
}

// List returns certificate specs, optionally filtered by account name.
// If accountFilter is empty, all specs are returned.
func (cm *certificateManager) List(accountFilter string) map[string]*CertificateSpec {
	if accountFilter == "" {
		return cm.config.Certificates
	}

	filtered := make(map[string]*CertificateSpec)
	for name, spec := range cm.config.Certificates {
		if spec.Account == accountFilter {
			filtered[name] = spec
		}
	}
	return filtered
}

// Show returns metadata about a managed certificate.
func (cm *certificateManager) Show(name string) (*ManagedCertInfo, error) {
	val, ok := cm.managed.Load(name)
	if !ok {
		return nil, ErrCertSpecNotFound{Name: name}
	}
	return val.(*ManagedCertInfo), nil
}

// buildCSR creates a DER-encoded CSR from a CertificateSpec and signing key.
func buildCSR(spec *CertificateSpec, key crypto.Signer) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   spec.Subject.CN,
			Organization: spec.Subject.Organization,
			Country:      spec.Subject.Country,
			Province:     spec.Subject.Province,
			Locality:     spec.Subject.Locality,
		},
		DNSNames:       spec.SANs.DNS,
		EmailAddresses: spec.SANs.Email,
	}

	for _, ipStr := range spec.SANs.IP {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, ErrCSRCreation{Err: ErrInvalidIP{Value: ipStr}}
		}
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	for _, uriStr := range spec.SANs.URI {
		u, err := url.Parse(uriStr)
		if err != nil {
			return nil, ErrCSRCreation{Err: ErrInvalidURI{Value: uriStr, Err: err}}
		}
		template.URIs = append(template.URIs, u)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, ErrCSRCreation{Err: err}
	}

	return csrDER, nil
}

// encodeCertPEM encodes an x509 certificate to PEM bytes.
func encodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// encodeKeyPEM encodes a crypto.Signer private key to PKCS8 PEM bytes.
func encodeKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrKeyEncoding{Err: err}
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}
