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

package ca

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"slices"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// OIDFleetAgent is tp-fleetAgent (1.3.6.1.4.1.29377.101.25), a private,
// non-critical extension (RFC 5280 §4.2) that marks a certificate as issued
// to a fleet agent. The issuer stamps it from the issuing call
// (SignOptions.FleetAgent) and never from a CSR: a CSR that requests it is
// refused with ErrFleetAgentClaimRequested.
//
// Its value is the DER encoding of NULL, as for id-pkix-ocsp-nocheck
// (RFC 6960 §4.2.2.2.1): the claim is the extension's presence.
//
//	FleetAgent ::= NULL
var OIDFleetAgent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 25}

// fleetAgentValue is the DER encoding of NULL, the only value tp-fleetAgent
// carries.
var fleetAgentValue = []byte{0x05, 0x00}

var (
	// ErrFleetAgentClaimRequested reports a CSR whose requested extensions
	// carry tp-fleetAgent. The claim is the issuer's to make, so the CA
	// refuses the request rather than copy or silently drop it.
	ErrFleetAgentClaimRequested = errors.New("ca: a CSR may not request the fleet agent claim")

	// ErrFleetAgentClaimReserved reports SignOptions.ExtraExtensions carrying
	// tp-fleetAgent. SignOptions.FleetAgent is the only way the claim
	// reaches a certificate.
	ErrFleetAgentClaimReserved = errors.New("ca: the fleet agent claim is stamped only by SignOptions.FleetAgent")

	// ErrFleetAgentClaimAbsent reports a certificate without tp-fleetAgent.
	ErrFleetAgentClaimAbsent = errors.New("ca: certificate carries no fleet agent claim")

	// ErrFleetAgentClaimMalformed reports a tp-fleetAgent extension that is
	// critical or not the DER encoding of NULL.
	ErrFleetAgentClaimMalformed = errors.New("ca: malformed fleet agent claim")

	// ErrFleetAgentClaimUntrusted reports a certificate that does not chain
	// to the roots the fleet agent claim was verified against: its claim is
	// not this CA's.
	ErrFleetAgentClaimUntrusted = errors.New("ca: fleet agent claim is not from a trusted issuer")
)

// fleetAgentExtension returns the tp-fleetAgent extension the issuer stamps.
func fleetAgentExtension() pkix.Extension {
	return pkix.Extension{Id: OIDFleetAgent, Value: bytes.Clone(fleetAgentValue)}
}

// checkCSRFleetAgentClaim refuses a CSR that requests tp-fleetAgent among the
// extensions of its PKCS#10 extensionRequest attribute (RFC 2986 §4.1,
// RFC 2985 §5.4.2).
func checkCSRFleetAgentClaim(csr *x509.CertificateRequest) error {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(OIDFleetAgent) {
			return ErrFleetAgentClaimRequested
		}
	}
	return nil
}

// stampFleetAgentClaim returns extra with tp-fleetAgent appended when
// fleetAgent is set. extra itself may never carry the extension:
// ErrFleetAgentClaimReserved.
func stampFleetAgentClaim(extra []pkix.Extension, fleetAgent bool) ([]pkix.Extension, error) {
	for _, ext := range extra {
		if ext.Id.Equal(OIDFleetAgent) {
			return nil, ErrFleetAgentClaimReserved
		}
	}
	if !fleetAgent {
		return extra, nil
	}
	stamped := make([]pkix.Extension, 0, len(extra)+1)
	stamped = append(stamped, extra...)
	return append(stamped, fleetAgentExtension()), nil
}

// VerifyFleetAgentClaim reports whether cert carries the fleet agent claim
// from an issuer the caller trusts. It returns nil only when cert chains to
// opts.Roots (RFC 5280 §6) and carries a well-formed, non-critical
// tp-fleetAgent extension. A certificate from another CA carrying the same
// extension fails with ErrFleetAgentClaimUntrusted: the extension is only as
// good as the issuer that signed it.
//
// opts.Roots is required, so the claim is never accepted from the system
// trust store; pass this CA's certificate (or bundle). opts.KeyUsages
// defaults to any extended key usage, since the claim concerns the issuer
// and not the key's purpose.
func VerifyFleetAgentClaim(cert *x509.Certificate, opts x509.VerifyOptions) error {
	if cert == nil {
		return &errs.Detail{Err: ErrFleetAgentClaimAbsent, Detail: "nil certificate"}
	}
	if opts.Roots == nil {
		return &errs.Detail{Err: ErrFleetAgentClaimUntrusted, Detail: "no trusted roots"}
	}

	// The claim's shape is checked first: x509.Verify refuses an unhandled
	// critical extension, which would otherwise hide a critical claim behind
	// a chain error. x509.ParseCertificate already refuses a certificate
	// that repeats an extension (RFC 5280 §4.2).
	index := slices.IndexFunc(cert.Extensions, func(ext pkix.Extension) bool {
		return ext.Id.Equal(OIDFleetAgent)
	})
	if index < 0 {
		return ErrFleetAgentClaimAbsent
	}
	claim := cert.Extensions[index]
	if claim.Critical {
		return &errs.Detail{Err: ErrFleetAgentClaimMalformed, Detail: "extension must not be critical"}
	}
	if !bytes.Equal(claim.Value, fleetAgentValue) {
		return &errs.Detail{Err: ErrFleetAgentClaimMalformed, Detail: "value must be NULL"}
	}

	if len(opts.KeyUsages) == 0 {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if _, err := cert.Verify(opts); err != nil {
		return &errs.Joined{Lead: ErrFleetAgentClaimUntrusted, Detail: "chain", Cause: err}
	}
	return nil
}
