package issuance

import (
	"context"
	"crypto"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/acme/linter"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// Request is one certificate to issue.
type Request struct {
	// CSR is the finalize request's certificate request (RFC 8555 §7.4).
	CSR *x509.CertificateRequest

	// Options are the CA sign options of the certificate: tenant, profile,
	// issuer and extensions. The Issuer sets Serial, Precertificate, Linter
	// and, when it is zero, NotBefore.
	Options ca.SignOptions

	// Actor and Resource name the requester and the order in audit events,
	// such as "account:12" and "order:34".
	Actor    string
	Resource string
}

// Result is an issued certificate and its precertificate.
type Result struct {
	// Precertificate is the RFC 6962 §3.1 precertificate.
	Precertificate *x509.Certificate

	// Certificate is the final certificate; the CA has stored it.
	Certificate *x509.Certificate
}

// CertificateSigner signs certificate requests; pkg/ca.CA is the one
// implementation, and stores every certificate it signs other than a
// precertificate.
type CertificateSigner interface {
	SignCSR(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error)
}

// SerialStorage reserves serial numbers (RFC 5280 §4.1.2.2) before anything
// is signed with them; pkg/ca.CA implements it over its serial store.
type SerialStorage interface {
	ReserveSerial(ctx context.Context) (*big.Int, error)
}

// KeyValidator refuses weak public keys; pkg/acme/goodkey.Validator
// implements it.
type KeyValidator interface {
	CheckKey(ctx context.Context, key crypto.PublicKey) error
}

// TransparencyLogs submits a precertificate and its issuing chain to every
// enabled Certificate Transparency log (RFC 6962 §4.2). *ct.CTPolicy
// implements it: the SCTs it returns are verified against each log's key
// (RFC 6962 §3.2), each failed log is named in Submission.Failures, and it
// returns an error when the verified SCTs do not meet its policy.
type TransparencyLogs interface {
	Submit(ctx context.Context, precertDER []byte, chain [][]byte, expiry time.Time) (*ct.Submission, error)
}

// IssuerChain returns the CA's PEM chain from its issuing certificate to its
// root; pkg/ca.CA implements it.
type IssuerChain interface {
	CABundle() ([]byte, error)
}

// CertificateLinter lints a DER certificate; pkg/acme/linter.Linter
// implements it. Lint returns an error when the certificate has a lint
// error or fatal, and the findings either way.
type CertificateLinter interface {
	Lint(der []byte) (*linter.Result, error)
}
