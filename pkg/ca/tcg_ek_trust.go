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

// Package ca implements TCG "TPM 2.0 Keys for Device Identity and
// Attestation" v1.10r9 §6.1.2 step 5b and §6.2.2 step 4b: before the CA
// issues an IAK or IDevID credential it verifies the requesting device's
// endorsement key certificate against a configured pool of TPM-manufacturer
// trust anchors, and that the certificate carries the tcg-kp-EKCertificate
// extended key usage (2.23.133.8.1). TPM2_ActivateCredential (driven
// elsewhere in this package) proves the requester holds the EK private key;
// it says nothing about whether the EK belongs to a genuine TPM, which is
// what this file establishes.
package ca

import (
	"crypto/x509"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// TCGConfig holds the CA's TCG TPM 2.0 Keys for Device Identity and
// Attestation settings: the pool of TPM-manufacturer trust anchors the CA
// verifies an endorsement key certificate against before issuing an IAK or
// IDevID credential (TPM 2.0 Keys for Device Identity and Attestation
// v1.10r9 §6.1.2 step 5b, §6.2.2 step 4b).
//
// A nil TCGConfig, or one naming no anchors, is not "skip the check" --
// every EK verification refuses with ErrTCGEKCertUntrusted until at least
// one trust anchor is configured. A CA that never issues TCG credentials can
// leave this unset.
type TCGConfig struct {
	// TrustAnchors configures the TPM-manufacturer root (and, when a
	// manufacturer's chain has one, intermediate -- see the doc comment on
	// ekRootPool) certificates trusted to anchor an EK certificate chain.
	// Reuses pkg/attestation/truststore.Config, the same trust-anchor
	// configuration shape pkg/config.AttestationConfig uses for the "tpm2"
	// attestation format: both ultimately anchor a TPM manufacturer's chain,
	// even though this check runs at a different moment (credential
	// issuance) than attestation-quote verification does.
	TrustAnchors *truststore.Config `yaml:"trust-anchors,omitempty" json:"trust_anchors,omitempty" mapstructure:"trust-anchors"`
}

// ekRootPool loads the configured EK trust anchors as an x509.CertPool
// suitable for use as x509.VerifyOptions.Roots. evidence.StripEKCertificateQuirks is applied
// to every loaded certificate before it is pooled, so a manufacturer root
// with the same critical-SAN encoding quirk as the leaf still chains.
//
// A manufacturer whose EK certificates chain through an intermediate can
// concatenate both certificates into one PEM file named in
// TrustAnchors.ExternalRootPaths: x509.CertPool draws no distinction between
// a self-signed and a non-self-signed entry, so an intermediate placed here
// anchors a chain exactly as a root does.
//
// Returns ErrTCGEKCertUntrusted when c is nil, TrustAnchors is nil, or the
// configured anchors resolve to zero certificates: an EK chain check with no
// configured anchors is a refusal, not a pass.
func (c *TCGConfig) ekRootPool() (*x509.CertPool, error) {
	if c == nil || c.TrustAnchors == nil {
		return nil, &errs.Detail{Err: ErrTCGEKCertUntrusted, Detail: "no ek trust anchors configured"}
	}

	ts, err := truststore.New(c.TrustAnchors)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTCGEKCertUntrusted, Cause: err}
	}
	if ts.Count() == 0 {
		return nil, &errs.Detail{Err: ErrTCGEKCertUntrusted, Detail: "no ek trust anchors configured"}
	}

	pool := x509.NewCertPool()
	for _, root := range ts.Roots() {
		evidence.StripEKCertificateQuirks(root)
		pool.AddCert(root)
	}
	return pool, nil
}

// parseEKCertificateChain parses the endorsement key certificate carried in
// a TCG-CSR-IDEVID's EkCert field together with any intermediates
// concatenated after it, through the evidence primitive
// evidence.ParseEKCertificateChain. A failure is reported as
// ErrTCGInvalidEKCert with the primitive's error as its cause.
func parseEKCertificateChain(raw []byte) (*x509.Certificate, []*x509.Certificate, error) {
	leaf, intermediates, err := evidence.ParseEKCertificateChain(raw)
	if err != nil {
		return nil, nil, &errs.Joined{Lead: ErrTCGInvalidEKCert, Cause: err}
	}
	return leaf, intermediates, nil
}

// verifyEKCertificateChain verifies an endorsement key certificate's chain
// and its tcg-kp-EKCertificate extended key usage against the CA's
// configured pool of TPM-manufacturer trust anchors, per TPM 2.0 Keys for
// Device Identity and Attestation v1.10r9 §6.1.2 step 5b / §6.2.2 step 4b.
// The check itself is the evidence primitive evidence.VerifyEKCertificate;
// this method supplies the CA's anchors. requestIntermediates carries any
// additional certificates the request supplied alongside the leaf; it may be
// nil.
//
// Returns ErrTCGEKCertUntrusted, with the underlying cause wrapped, when the
// CA has no EK trust anchors configured, the chain does not verify, or the
// leaf lacks the required extended key usage. There is no path that skips
// the check: a CA without configured anchors refuses every EK certificate.
func (ca *CA) verifyEKCertificateChain(leaf *x509.Certificate, requestIntermediates []*x509.Certificate) error {
	if leaf == nil {
		return &errs.Detail{Err: ErrTCGInvalidEKCert, Detail: "nil ek certificate"}
	}

	var tcgConfig *TCGConfig
	if ca.config != nil {
		tcgConfig = ca.config.TCGConfig
	}

	roots, err := tcgConfig.ekRootPool()
	if err != nil {
		return err
	}

	if err := evidence.VerifyEKCertificate(leaf, requestIntermediates, evidence.EKCertificateOptions{Roots: roots}); err != nil {
		return &errs.Joined{Lead: ErrTCGEKCertUntrusted, Cause: err}
	}
	return nil
}
