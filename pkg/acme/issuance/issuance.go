package issuance

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log/slog"
	"math/big"
	"slices"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/acme/linter"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Lint stages name the certificate a lint run checked, in logs and audit
// events.
const (
	stagePrecertificate = "precertificate"
	stageCertificate    = "certificate"
)

// Config holds an Issuer's dependencies; every field other than CT and Chain
// is required.
type Config struct {
	// Signer signs and stores the certificates.
	Signer CertificateSigner

	// Serials reserves each certificate's serial number.
	Serials SerialStorage

	// KeyValidator refuses weak public keys.
	KeyValidator KeyValidator

	// Linter lints each tbsCertificate before it is signed.
	Linter CertificateLinter

	// AuditLogger records precertificates, lint findings and Certificate
	// Transparency submissions.
	AuditLogger audit.AuditLogger

	// Logger logs lint findings and Certificate Transparency failures.
	Logger *slog.Logger

	// CT, when set, submits each precertificate to the enabled Certificate
	// Transparency logs and embeds their SCT list in the final certificate
	// (RFC 6962 §3.3). Nil leaves Certificate Transparency off; the
	// precertificate is then signed and linted but never submitted.
	CT TransparencyLogs

	// Chain supplies the issuing chain submitted with each precertificate
	// (RFC 6962 §4.2). It is required when CT is set.
	Chain IssuerChain
}

// Issuer issues ACME certificates through the CA: goodkey, a reserved
// serial, then a linted precertificate and a linted final certificate. It is
// safe for concurrent use when its dependencies are.
type Issuer struct {
	config Config
}

// New returns an Issuer, or ErrInvalidConfig naming the first missing
// dependency.
func New(config Config) (*Issuer, error) {
	missing := ""
	switch {
	case config.Signer == nil:
		missing = "Signer is required"
	case config.Serials == nil:
		missing = "Serials is required"
	case config.KeyValidator == nil:
		missing = "KeyValidator is required"
	case config.Linter == nil:
		missing = "Linter is required"
	case config.AuditLogger == nil:
		missing = "AuditLogger is required"
	case config.Logger == nil:
		missing = "Logger is required"
	case config.CT != nil && config.Chain == nil:
		missing = "Chain is required with CT"
	}
	if missing != "" {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: missing}
	}
	return &Issuer{config: config}, nil
}

// Issue issues the certificate req asks for (RFC 8555 §7.4 finalize).
//
// It refuses a weak public key with ErrBadPublicKey, then reserves a serial
// number (RFC 5280 §4.1.2.2) that the precertificate and the final
// certificate share (RFC 6962 §3.1). The CA lints each before signing it
// (CA/Browser Forum Baseline Requirements §4.3.1.2): a lint error or fatal
// refuses the certificate with an error matching ca.ErrLintFailed and
// linter.ErrRefused; a warning is logged and audited. The final certificate
// must match the precertificate apart from the poison and SCT list
// extensions, or Issue returns ErrTBSMismatch.
func (iss *Issuer) Issue(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.CSR == nil {
		return nil, ErrNilRequest
	}
	if err := iss.config.KeyValidator.CheckKey(ctx, req.CSR.PublicKey); err != nil {
		return nil, &errs.Joined{Lead: ErrBadPublicKey, Cause: err}
	}
	serial, err := iss.config.Serials.ReserveSerial(ctx)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSerialReservation, Cause: err}
	}

	opts := req.Options
	opts.Serial = serial
	if opts.NotBefore.IsZero() {
		// One notBefore for both signatures, so the precertificate and the
		// final certificate carry the same validity (RFC 6962 §3.1).
		opts.NotBefore = time.Now().UTC().Truncate(time.Second)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR.Raw})

	precertOpts := opts
	precertOpts.Precertificate = true
	precertOpts.Linter = iss.lintStage(ctx, req, stagePrecertificate)
	precert, err := iss.config.Signer.SignCSR(ctx, csrPEM, &precertOpts)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPrecertificate, Cause: err}
	}
	if err := iss.audit(ctx, req, audit.EventPrecertificateSigned, "sign", audit.ResultSuccess,
		map[string]interface{}{"serial": serial.Text(16)}); err != nil {
		return nil, err
	}

	if iss.config.CT != nil {
		// RFC 6962 §3.3: the final certificate embeds the SCTs the logs
		// issued for its precertificate, in a new slice so the request's
		// extensions are left as they were.
		sctList, err := iss.submitPrecertificate(ctx, req, &opts, precert)
		if err != nil {
			return nil, err
		}
		opts.ExtraExtensions = slices.Concat(opts.ExtraExtensions, []pkix.Extension{sctList})
	}

	opts.Linter = iss.lintStage(ctx, req, stageCertificate)
	cert, err := iss.config.Signer.SignCSR(ctx, csrPEM, &opts)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrCertificate, Cause: err}
	}
	if err := matchPrecertificate(precert.RawTBSCertificate, cert.RawTBSCertificate); err != nil {
		return nil, err
	}
	return &Result{Precertificate: precert, Certificate: cert}, nil
}

// submitPrecertificate submits the precertificate with its issuing chain to
// every enabled Certificate Transparency log (RFC 6962 §4.2) and returns the
// SCT list extension of the verified SCTs (RFC 6962 §3.3).
//
// A log that refuses the precertificate, times out or returns an SCT that
// fails verification (RFC 6962 §3.2) is logged and audited by name. Issuance
// proceeds while the verified SCTs still meet the CT policy (MinSCTs,
// MinOperators, RequireRFC6962Log), and fails with ErrCertificateTransparency,
// joined with every log's error, when they do not.
func (iss *Issuer) submitPrecertificate(ctx context.Context, req *Request, opts *ca.SignOptions,
	precert *x509.Certificate) (pkix.Extension, error) {
	serial := precert.SerialNumber.Text(16)
	chain, err := iss.issuingChain(opts)
	if err != nil {
		return pkix.Extension{}, err
	}

	submission, err := iss.config.CT.Submit(ctx, precert.Raw, chain, precert.NotAfter)
	if err != nil {
		iss.config.Logger.ErrorContext(ctx, "issuance: certificate transparency refused issuance",
			"resource", req.Resource, "serial", serial, "error", err)
		ctErr := &errs.Joined{Lead: ErrCertificateTransparency, Cause: err}
		if auditErr := iss.audit(ctx, req, audit.EventCertificateTransparency, "submit", audit.ResultFailure,
			map[string]interface{}{"serial": serial, "error": err.Error()}); auditErr != nil {
			return pkix.Extension{}, &errs.Joined{Lead: ctErr, Cause: auditErr}
		}
		return pkix.Extension{}, ctErr
	}

	failed := make([]string, 0, len(submission.Failures))
	for _, failure := range submission.Failures {
		iss.config.Logger.WarnContext(ctx, "issuance: certificate transparency log failed",
			"resource", req.Resource, "serial", serial, "log", failure.LogName, "error", failure.Cause)
		failed = append(failed, failure.Error())
	}
	if err := iss.audit(ctx, req, audit.EventCertificateTransparency, "submit", audit.ResultSuccess,
		map[string]interface{}{"serial": serial, "scts": len(submission.SCTs), "failed_logs": failed}); err != nil {
		return pkix.Extension{}, err
	}

	sctList, err := ct.MakeSCTListExtension(submission.SCTs)
	if err != nil {
		return pkix.Extension{}, &errs.Joined{Lead: ErrCertificateTransparency, Cause: err}
	}
	return sctList, nil
}

// issuingChain returns the DER chain RFC 6962 §4.2 add-pre-chain submits
// after the precertificate: the certificate of the CA that issued it first,
// then each certificate up to the root. A tenant signer's issuer certificate
// leads the CA bundle.
func (iss *Issuer) issuingChain(opts *ca.SignOptions) ([][]byte, error) {
	bundle, err := iss.config.Chain.CABundle()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrCertificateTransparency, Cause: err}
	}
	var chain [][]byte
	if opts.Signer != nil && opts.IssuerCert != nil {
		chain = append(chain, opts.IssuerCert.Raw)
	}
	for block, rest := pem.Decode(bundle); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" || slices.ContainsFunc(chain, func(der []byte) bool {
			return bytes.Equal(der, block.Bytes)
		}) {
			continue
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, &errs.Detail{Err: ErrCertificateTransparency, Detail: "the CA bundle holds no certificate"}
	}
	return chain, nil
}

// lintStage returns the ca.Linter the CA runs on the stage's lint
// certificate. It logs and audits warnings without refusing, and refuses on
// a lint error or fatal (CA/Browser Forum Baseline Requirements §4.3.1.2).
func (iss *Issuer) lintStage(ctx context.Context, req *Request, stage string) ca.Linter {
	return ca.LintFunc(func(der []byte) error {
		result, lintErr := iss.config.Linter.Lint(der)
		if lintErr != nil {
			details := map[string]interface{}{"stage": stage}
			if result != nil {
				details["errors"] = linter.Summary(result.Errors)
				details["warnings"] = linter.Summary(result.Warnings)
			}
			iss.config.Logger.ErrorContext(ctx, "issuance: lint refused certificate",
				"stage", stage, "resource", req.Resource, "error", lintErr)
			if err := iss.audit(ctx, req, audit.EventCertificateLinted, "lint", audit.ResultFailure, details); err != nil {
				return &errs.Joined{Lead: lintErr, Cause: err}
			}
			return lintErr
		}
		if result == nil || len(result.Warnings) == 0 {
			return nil
		}
		summary := linter.Summary(result.Warnings)
		iss.config.Logger.WarnContext(ctx, "issuance: lint warnings",
			"stage", stage, "resource", req.Resource, "warnings", summary)
		return iss.audit(ctx, req, audit.EventCertificateLinted, "lint", audit.ResultSuccess,
			map[string]interface{}{"stage": stage, "warnings": summary})
	})
}

// audit records one event, failing closed: an event that cannot be recorded
// stops the issuance.
func (iss *Issuer) audit(ctx context.Context, req *Request, event audit.EventType, action string,
	result audit.Result, details map[string]interface{}) error {
	if err := iss.config.AuditLogger.LogWithContext(ctx, event, req.Actor, req.Resource, action, result, details); err != nil {
		return &errs.Joined{Lead: ErrAudit, Cause: err}
	}
	return nil
}

// tbsCertificate is the RFC 5280 §4.1 TBSCertificate, with the fields the
// precertificate check compares kept as encoded.
type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	IssuerUniqueID     asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

// matchPrecertificate returns ErrTBSMismatch unless the precertificate and
// final tbsCertificates are equal once the poison and SCT list extensions
// are removed from both (RFC 6962 §3.1).
func matchPrecertificate(precertTBS, certTBS []byte) error {
	precert, err := stripCTExtensions(precertTBS)
	if err != nil {
		return err
	}
	cert, err := stripCTExtensions(certTBS)
	if err != nil {
		return err
	}
	if !bytes.Equal(precert, cert) {
		return ErrTBSMismatch
	}
	return nil
}

// stripCTExtensions re-encodes a tbsCertificate without the RFC 6962 §3.1
// poison and SCT list extensions.
func stripCTExtensions(der []byte) ([]byte, error) {
	var tbs tbsCertificate
	rest, err := asn1.Unmarshal(der, &tbs)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTBSMismatch, Cause: err}
	}
	if len(rest) != 0 {
		return nil, &errs.Detail{Err: ErrTBSMismatch, Detail: "trailing data after tbsCertificate"}
	}
	kept := tbs.Extensions[:0]
	for _, ext := range tbs.Extensions {
		if !ext.Id.Equal(ct.OIDPrecertPoison) && !ext.Id.Equal(ct.OIDSCTList) {
			kept = append(kept, ext)
		}
	}
	tbs.Extensions = kept
	encoded, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTBSMismatch, Cause: err}
	}
	return encoded, nil
}
