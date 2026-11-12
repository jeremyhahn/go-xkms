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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"golang.org/x/crypto/acme"
)

// ACMEClient is the part of the sdk/go ACME client the xkey acme CLI verbs
// and the GUI ACMEService call. *sdkacme.ACMEClient satisfies it; tests
// swap in a fake.
type ACMEClient interface {
	RegisterAccount() (*acme.Account, error)
	UpdateAccount(ctx context.Context, contacts []string) (*acme.Account, error)
	DeactivateAccount(ctx context.Context) error
	RevokeCertificate(ctx context.Context, cert *x509.Certificate, reason acme.CRLReasonCode) error
	RenewCertificate(ctx context.Context, oldCert *x509.Certificate, req *sdkacme.ACMECertificateRequest) (*x509.Certificate, error)
	EnrollDevice(ctx context.Context, config *sdkacme.ACMEEnrollmentConfig) (*sdkacme.ACMEEnrollmentResult, error)
	RequestEndorsementKeyCertificate(ctx context.Context, config *sdkacme.ACMEEnrollmentConfig) (*x509.Certificate, error)
	Close() error
}

// ACMEClientOptions carries the connection settings to the client
// constructor.
type ACMEClientOptions struct {
	DirectoryURL string
	Contact      string
	Signer       crypto.Signer
	TrustedRoots []string
	SystemRoots  bool
	Logger       *slog.Logger
}

// acmeClientTimeout bounds each HTTP request to the ACME server.
const acmeClientTimeout = 30 * time.Second

// NewACMEClient builds an sdk/go ACME client. The account DAO is in
// memory: the server finds the account again from the account key
// (RFC 8555 7.3.1), so callers keep no local state.
func NewACMEClient(opts ACMEClientOptions) (ACMEClient, error) {
	factory, err := sdkacme.NewACMEStorageFactoryFromKVStore(qrdbsdk.NewMemoryKVStore())
	if err != nil {
		return nil, fmt.Errorf("acme: account storage: %w", err)
	}
	accounts, err := factory.AccountDAO()
	if err != nil {
		return nil, fmt.Errorf("acme: account storage: %w", err)
	}
	client, err := sdkacme.NewACMEClient(&sdkacme.ACMEClientParams{
		AccountEmail:  opts.Contact,
		AccountSigner: opts.Signer,
		Logger:        opts.Logger,
		Storage:       accounts,
		Config: &sdkacme.ACMEClientConfig{
			DirectoryURL:   opts.DirectoryURL,
			TrustedRoots:   opts.TrustedRoots,
			SystemCertPool: opts.SystemRoots,
			Timeout:        acmeClientTimeout,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("acme: client: %w", err)
	}
	return client, nil
}

// LoadACMEAccountKey reads a PEM private key (PKCS#8, SEC 1 EC or PKCS#1).
// Errors name the file, never its content.
func LoadACMEAccountKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("acme: account key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("acme: account key %s: no PEM block", path)
	}
	var key any
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("acme: account key %s: unsupported or malformed %q block", path, block.Type)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("acme: account key %s: key cannot sign", path)
	}
	return signer, nil
}

// acmeRevocationReasons maps RFC 5280 5.3.1 reason names to codes.
var acmeRevocationReasons = map[string]acme.CRLReasonCode{
	"unspecified":          acme.CRLReasonUnspecified,
	"keyCompromise":        acme.CRLReasonKeyCompromise,
	"caCompromise":         acme.CRLReasonCACompromise,
	"affiliationChanged":   acme.CRLReasonAffiliationChanged,
	"superseded":           acme.CRLReasonSuperseded,
	"cessationOfOperation": acme.CRLReasonCessationOfOperation,
	"certificateHold":      acme.CRLReasonCertificateHold,
	"removeFromCRL":        acme.CRLReasonRemoveFromCRL,
	"privilegeWithdrawn":   acme.CRLReasonPrivilegeWithdrawn,
	"aACompromise":         acme.CRLReasonAACompromise,
}

// ParseACMERevocationReason accepts a reason name or its number (7 is
// unused in RFC 5280).
func ParseACMERevocationReason(s string) (acme.CRLReasonCode, error) {
	if code, ok := acmeRevocationReasons[s]; ok {
		return code, nil
	}
	n, err := strconv.Atoi(s)
	if err == nil && n >= int(acme.CRLReasonUnspecified) && n <= int(acme.CRLReasonAACompromise) && n != 7 {
		return acme.CRLReasonCode(n), nil
	}
	return 0, fmt.Errorf("acme: unknown revocation reason %q", s)
}

// LoadCertificatePEM reads the first certificate of a PEM file.
func LoadCertificatePEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("acme: certificate %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("acme: %s holds no PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("acme: certificate %s: %w", path, err)
	}
	return cert, nil
}
