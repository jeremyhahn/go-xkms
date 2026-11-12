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

package services

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"golang.org/x/crypto/acme"
)

// ACMEConnection names the ACME server and the account key file. The GUI
// passes paths only; the key never crosses the binding.
type ACMEConnection struct {
	DirectoryURL     string   `json:"directoryUrl"`
	AccountKeyPath   string   `json:"accountKeyPath"`
	TrustedRootPaths []string `json:"trustedRootPaths"`
	SystemRoots      bool     `json:"systemRoots"`
}

// ACMEAccountInfo is the account as the server reports it.
type ACMEAccountInfo struct {
	URI      string   `json:"uri"`
	Status   string   `json:"status"`
	Contacts []string `json:"contacts"`
}

// ACMERenewRequest names the certificate to renew and the identifier to
// authorize, as xkey acme renew takes them.
type ACMERenewRequest struct {
	CertPath  string `json:"certPath"`
	Domain    string `json:"domain"`
	AuthzType string `json:"authzType"`
	Challenge string `json:"challenge"`
	CSRPath   string `json:"csrPath"`
}

// ACMEEnrollRequest names the device challenge and its listener for
// EnrollDevice and EndorseDevice. Zero Port and TimeoutSeconds take the
// client defaults.
type ACMEEnrollRequest struct {
	Challenge      string `json:"challenge"`
	IPAddress      string `json:"ipAddress"`
	Port           int    `json:"port"`
	ListenHost     string `json:"listenHost"`
	CommonName     string `json:"commonName"`
	PCRs           []int  `json:"pcrs"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

// ACMEEnrollmentInfo is the PEM view of an enrollment result: certificates
// only, never key material.
type ACMEEnrollmentInfo struct {
	IDevIDPEM string `json:"idevidPem"`
	IAKPEM    string `json:"iakPem"`
	ChainPEM  string `json:"chainPem"`
}

// ACMEService is the Wails-bound ACME client of the GUI: a thin caller of
// the sdk/go ACME client, sharing NewACMEClient with the xkey acme CLI.
type ACMEService struct {
	ctx       context.Context
	log       *slog.Logger
	newClient func(ACMEClientOptions) (ACMEClient, error)
	tpmSource func() (sdkacme.ACMETPMModule, func(), error)
}

// NewACMEService returns a service that builds sdk/go ACME clients.
func NewACMEService() *ACMEService {
	return &ACMEService{
		log:       slog.Default().With("service", "acme"),
		newClient: NewACMEClient,
	}
}

// SetContext sets the Wails runtime context.
func (s *ACMEService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetTPMSource sets the TPM that EnrollDevice and EndorseDevice use: fn
// returns the module and a release func. app.go wires it to the shared
// TPMAccessor through NewACMETPMSource, so the GUI never opens a second TPM.
func (s *ACMEService) SetTPMSource(fn func() (sdkacme.ACMETPMModule, func(), error)) {
	s.tpmSource = fn
}

func (s *ACMEService) context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// recoverPanic converts a panic in a Wails-bound method into an error.
func (s *ACMEService) recoverPanic(method string, retErr *error) {
	if r := recover(); r != nil {
		s.log.Error("panic in "+method, "recover", r)
		*retErr = &MessageError{Msg: fmt.Sprintf("acme_service: panic in %s: %v", method, r)}
	}
}

// withClient validates conn, loads the account key and trusted roots,
// builds a client, runs fn and closes the client.
func (s *ACMEService) withClient(conn ACMEConnection, contact string, fn func(ACMEClient) error) (err error) {
	if conn.DirectoryURL == "" {
		return errors.New("acme: directory URL is required")
	}
	if conn.AccountKeyPath == "" {
		return errors.New("acme: account key path is required")
	}
	signer, err := LoadACMEAccountKey(conn.AccountKeyPath)
	if err != nil {
		return err
	}
	roots := make([]string, 0, len(conn.TrustedRootPaths))
	for _, path := range conn.TrustedRootPaths {
		data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
		if err != nil {
			return fmt.Errorf("acme: trusted root %s: %w", path, err)
		}
		roots = append(roots, string(data))
	}
	client, err := s.newClient(ACMEClientOptions{
		DirectoryURL: conn.DirectoryURL,
		Contact:      strings.TrimPrefix(contact, "mailto:"),
		Signer:       signer,
		TrustedRoots: roots,
		SystemRoots:  conn.SystemRoots,
		Logger:       s.log,
	})
	if err != nil {
		return err
	}
	defer func() {
		if cerr := client.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("acme: close client: %w", cerr)
		}
	}()
	return fn(client)
}

func acmeAccountInfo(a *acme.Account) *ACMEAccountInfo {
	if a == nil {
		return nil
	}
	return &ACMEAccountInfo{URI: a.URI, Status: a.Status, Contacts: a.Contact}
}

// RegisterAccount registers the account key with the server, or finds the
// existing account, with an optional contact email.
func (s *ACMEService) RegisterAccount(conn ACMEConnection, contact string) (info *ACMEAccountInfo, err error) {
	defer s.recoverPanic("RegisterAccount", &err)
	err = s.withClient(conn, contact, func(c ACMEClient) error {
		account, err := c.RegisterAccount()
		if err != nil {
			return fmt.Errorf("acme: register account: %w", err)
		}
		info = acmeAccountInfo(account)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// UpdateAccount replaces the account contacts.
func (s *ACMEService) UpdateAccount(conn ACMEConnection, contacts []string) (info *ACMEAccountInfo, err error) {
	defer s.recoverPanic("UpdateAccount", &err)
	err = s.withClient(conn, "", func(c ACMEClient) error {
		account, err := c.UpdateAccount(s.context(), contacts)
		if err != nil {
			return fmt.Errorf("acme: update account: %w", err)
		}
		info = acmeAccountInfo(account)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// DeactivateAccount deactivates the account for good; it refuses unless
// confirm is set, as the CLI refuses without --yes.
func (s *ACMEService) DeactivateAccount(conn ACMEConnection, confirm bool) (err error) {
	defer s.recoverPanic("DeactivateAccount", &err)
	if !confirm {
		return errors.New("acme: deactivation is permanent; confirm it to proceed")
	}
	return s.withClient(conn, "", func(c ACMEClient) error {
		if err := c.DeactivateAccount(s.context()); err != nil {
			return fmt.Errorf("acme: deactivate account: %w", err)
		}
		return nil
	})
}

// RevokeCertificate revokes the PEM certificate at certPath with an
// RFC 5280 reason name or number.
func (s *ACMEService) RevokeCertificate(conn ACMEConnection, certPath, reason string) (err error) {
	defer s.recoverPanic("RevokeCertificate", &err)
	if reason == "" {
		reason = "unspecified"
	}
	code, err := ParseACMERevocationReason(reason)
	if err != nil {
		return err
	}
	cert, err := LoadCertificatePEM(certPath)
	if err != nil {
		return err
	}
	return s.withClient(conn, "", func(c ACMEClient) error {
		if err := c.RevokeCertificate(s.context(), cert, code); err != nil {
			return fmt.Errorf("acme: revoke certificate: %w", err)
		}
		return nil
	})
}

// RenewCertificate requests a new certificate for the identifier of the
// certificate at req.CertPath and returns it as PEM. No key material is
// returned.
func (s *ACMEService) RenewCertificate(conn ACMEConnection, req ACMERenewRequest) (out string, err error) {
	defer s.recoverPanic("RenewCertificate", &err)
	if req.CertPath == "" {
		return "", errors.New("acme: renew needs a certificate path")
	}
	if req.Domain == "" {
		return "", errors.New("acme: renew needs a domain")
	}
	oldCert, err := LoadCertificatePEM(req.CertPath)
	if err != nil {
		return "", err
	}
	authzType := req.AuthzType
	if authzType == "" {
		authzType = "dns"
	}
	certReq := &sdkacme.ACMECertificateRequest{
		AuthzType:     authzType,
		AuthzValue:    req.Domain,
		ChallengeType: req.Challenge,
	}
	if req.CSRPath != "" {
		if certReq.CSR, err = LoadACMECSR(req.CSRPath); err != nil {
			return "", err
		}
	}
	err = s.withClient(conn, "", func(c ACMEClient) error {
		cert, err := c.RenewCertificate(s.context(), oldCert, certReq)
		if err != nil {
			return fmt.Errorf("acme: renew certificate: %w", err)
		}
		out = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		return nil
	})
	if err != nil {
		return "", err
	}
	return out, nil
}

// EnrollDevice runs a device enrollment challenge (enroll-01, endorse-01 or
// device-attest-01; empty means enroll-01) on the GUI's shared TPM and
// returns the issued certificates as PEM. No key material is returned.
func (s *ACMEService) EnrollDevice(conn ACMEConnection, req ACMEEnrollRequest) (info *ACMEEnrollmentInfo, err error) {
	defer s.recoverPanic("EnrollDevice", &err)
	if req.Challenge == "" {
		req.Challenge = sdkacme.ACMEChallengeTypeEnroll01
	}
	err = s.withDeviceTPM(conn, req, "enroll", func(c ACMEClient, cfg *sdkacme.ACMEEnrollmentConfig) error {
		res, err := c.EnrollDevice(s.context(), cfg)
		if err != nil {
			return fmt.Errorf("acme: enroll device: %w", err)
		}
		if res == nil {
			return errors.New("acme: enroll device: no result")
		}
		info = &ACMEEnrollmentInfo{
			IDevIDPEM: certificatesPEM(res.IDevIDCertificate),
			IAKPEM:    certificatesPEM(res.IAKCertificate),
			ChainPEM:  certificatesPEM(res.Chain...),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

// EndorseDevice requests an EK certificate with the endorse-01 challenge on
// the GUI's shared TPM and returns it as PEM.
func (s *ACMEService) EndorseDevice(conn ACMEConnection, req ACMEEnrollRequest) (out string, err error) {
	defer s.recoverPanic("EndorseDevice", &err)
	req.Challenge = sdkacme.ACMEChallengeTypeEndorse01
	err = s.withDeviceTPM(conn, req, "endorse", func(c ACMEClient, cfg *sdkacme.ACMEEnrollmentConfig) error {
		cert, err := c.RequestEndorsementKeyCertificate(s.context(), cfg)
		if err != nil {
			return fmt.Errorf("acme: request EK certificate: %w", err)
		}
		if cert == nil {
			return errors.New("acme: request EK certificate: no certificate")
		}
		out = certificatesPEM(cert)
		return nil
	})
	if err != nil {
		return "", err
	}
	return out, nil
}

// withDeviceTPM validates req, takes the shared TPM, builds the enrollment
// config and runs fn on a client. The TPM is released, never closed.
func (s *ACMEService) withDeviceTPM(conn ACMEConnection, req ACMEEnrollRequest, op string,
	fn func(ACMEClient, *sdkacme.ACMEEnrollmentConfig) error) error {
	switch req.Challenge {
	case sdkacme.ACMEChallengeTypeEnroll01, sdkacme.ACMEChallengeTypeEndorse01:
		if req.IPAddress == "" {
			return fmt.Errorf("acme: %s needs an IP address", op)
		}
	case sdkacme.ACMEChallengeTypeDeviceAttest01:
	default:
		return fmt.Errorf("acme: %s: unknown challenge %q", op, req.Challenge)
	}
	if req.TimeoutSeconds < 0 {
		return fmt.Errorf("acme: %s: timeout must not be negative", op)
	}
	if req.Port < 0 {
		return fmt.Errorf("acme: %s: port must not be negative", op)
	}
	if s.tpmSource == nil {
		return ErrTPMNotAvailable
	}
	tpm, release, err := s.tpmSource()
	if err != nil {
		return err
	}
	defer release()
	port := ""
	if req.Port > 0 {
		port = strconv.Itoa(req.Port)
	}
	cfg := &sdkacme.ACMEEnrollmentConfig{
		Challenge:    req.Challenge,
		IPAddress:    req.IPAddress,
		TPMModule:    tpm,
		Port:         port,
		ListenHost:   req.ListenHost,
		CommonName:   req.CommonName,
		PCRSelection: req.PCRs,
		Timeout:      time.Duration(req.TimeoutSeconds) * time.Second,
	}
	return s.withClient(conn, "", func(c ACMEClient) error { return fn(c, cfg) })
}

// certificatesPEM concatenates CERTIFICATE PEM blocks, skipping nil.
func certificatesPEM(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		if c != nil {
			b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		}
	}
	return b.String()
}
