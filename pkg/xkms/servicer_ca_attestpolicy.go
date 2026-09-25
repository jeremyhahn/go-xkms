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

package xkms

import (
	"crypto/x509"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
)

// Attestation invariant failures. These are not policy: they are the checks
// without which a signed certificate does not mean what it appears to mean.
var (
	// ErrAttestationKeyNotBound means the CSR asks the CA to certify a key the
	// attestation does not cover.
	//
	// This is the single most important check in the whole path. Without it,
	// anyone holding *any* genuine attestation chain -- and these are public,
	// they travel with every enrollment -- can present it beside a CSR for a
	// key they generated in software, and receive a certificate that appears
	// hardware-backed to every relying party that reads it.
	ErrAttestationKeyNotBound = errors.New("ca: the CSR key is not the attested key")

	// ErrAttestationStale means the evidence does not carry the challenge this
	// server issued, so it may be a recording of an earlier exchange.
	ErrAttestationStale = errors.New("ca: the attestation challenge does not match")

	// ErrAttestationUnbindableFormat means the format's evidence cannot be tied
	// to the key being certified by any mechanism this server implements, so
	// the certificate it would issue could not honestly claim hardware backing.
	ErrAttestationUnbindableFormat = errors.New("ca: attestation format cannot be bound to the CSR key")
)

// AllowUnboundAttestationFormats permits formats whose binding mechanism this
// server cannot check with the evidence a carrier supplies.
//
// Off by default, and it should stay off. A certificate issued through an
// unbound format asserts hardware backing the server did not establish: the
// chain shows that *some* hardware exists, not that it holds the key being
// certified. Turning this on states that the gap is accepted for a particular
// deployment, and every such issuance is logged at WARN.
func (s *XKMSService) AllowUnboundAttestationFormats(allow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowUnboundAttestation = allow
}

func (s *XKMSService) unboundAttestationAllowed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowUnboundAttestation
}

// enforceAttestationInvariants applies the format-agnostic gate to a CSR
// signing request.
//
// The gate itself lives in pkg/attestation so the TCG-CSR carrier answers to
// the same one. This function is only the adapter: it turns a SignCSRRequest
// into Evidence. Two carriers exist because the evidence formats are
// externally defined standards, but there is one place that decides whether
// evidence is good enough to sign.
func (s *XKMSService) enforceAttestationInvariants(
	format string,
	req *transport.SignCSRRequest,
	leaf *x509.Certificate,
) error {
	csr, err := parseCSRAny(req.CSRPEM)
	if err != nil {
		return &ErrOperationWrap{Sentinel: ErrAttestationKeyNotBound, Detail: "the CSR does not parse", Err: err}
	}
	// A CSR is self-signed by the key it names. An invalid signature means the
	// requester does not hold the private half, so binding it to attested
	// hardware would certify a key nobody demonstrated control of.
	if err := csr.CheckSignature(); err != nil {
		return &ErrOperationWrap{Sentinel: ErrAttestationKeyNotBound, Detail: "the CSR signature does not verify", Err: err}
	}

	// This carrier delivers a PKCS#10 alongside a certificate chain; it has no
	// way to carry TPM public areas, so a TPM-bound format cannot be checked
	// here. That is reported as unbindable rather than waved through.
	ev := &attestation.Evidence{
		Format:            format,
		Leaf:              leaf,
		SubjectSPKI:       csr.RawSubjectPublicKeyInfo,
		ExpectedChallenge: req.AttestationNonce,
	}

	err = attestation.VerifyInvariants(ev)
	switch {
	case err == nil:
		return nil

	case errors.Is(err, attestation.ErrBindingUnavailable):
		if !s.unboundAttestationAllowed() {
			slog.Warn("CSR attestation refused: binding cannot be checked",
				"format", format, "error", err)
			return &ErrOperationWrap{Sentinel: ErrAttestationUnbindableFormat, Err: err}
		}
		// Deliberately accepted, and said out loud every time.
		slog.Warn("issuing against an attestation whose key binding was NOT verified",
			"format", format,
			"reason", err.Error(),
			"consequence", "the certificate asserts hardware backing this server did not establish")
		return nil

	case errors.Is(err, attestation.ErrUnknownFormat):
		slog.Warn("CSR attestation refused: no profile for format", "format", format)
		return &ErrOperationWrap{Sentinel: ErrAttestationUnbindableFormat, Err: err}

	case errors.Is(err, attestation.ErrKeyNotBound):
		slog.Warn("CSR attestation refused: key not bound", "format", format, "error", err)
		return &ErrOperationWrap{Sentinel: ErrAttestationKeyNotBound, Err: err}

	case errors.Is(err, attestation.ErrStaleEvidence):
		slog.Warn("CSR attestation refused: challenge mismatch", "format", format)
		return &ErrOperationWrap{Sentinel: ErrAttestationStale, Err: err}

	default:
		return err
	}
}
