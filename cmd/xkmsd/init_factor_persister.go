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

package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// This file is the qrdbsdk.AdminFactorPersister the init ceremony now plugs
// into pkg/init.AdminEnrollmentConfig.Persister: it projects the enrollment
// pkg/init/admin_enrollment.go's EnrollAdminFactors already produced (driving
// the real CTAP2 / PIV / mTLS hardware ceremony) onto the wire shape the
// running xkmsd's own auth-factor add path uses
// (pkg/xkms/servicer_authfactor.go, qrdbtransport.UserAuthFactorClient), and
// writes it through the SAME client -- backed by the durable node's
// UserAuthFactorServicer -- so a factor enrolled at init authenticates
// against the identical record the running server reads at login.
//
// Factor.Enroll is pure (pkg/factor/{mtls,piv,fido2}/factor.go): it drives
// the hardware and returns public credential material, writing nothing. This
// is the seam that gives that material a durable home.

// Persister error types.
var (
	// ErrFactorPersistFailed is returned when the durable factor store refuses
	// or fails to write an enrolled factor.
	ErrFactorPersistFailed = errors.New("init: failed to persist admin factor")
)

// FactorConversionError reports that an enrollment result could not be
// projected onto the durable factor store's wire shape -- the enrollment
// itself succeeded (the operator's hardware produced a credential), but the
// record needed to persist it was missing or malformed.
type FactorConversionError struct {
	// Factor names the admin factor being converted.
	Factor string
	// Reason describes what is missing or malformed.
	Reason string
	// Err is the underlying cause, when one exists.
	Err error
}

// Error implements error.
func (e *FactorConversionError) Error() string {
	msg := "init: converting " + e.Factor + " enrollment: " + e.Reason
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap exposes the underlying cause.
func (e *FactorConversionError) Unwrap() error { return e.Err }

// UnsupportedPersistFactorError reports an admin factor this persister has no
// conversion for. New admin factors must ship a conversion in the same
// change that adds them to qrdb's EnrollableAdminFactors, per the project's
// no-partial-backend policy.
type UnsupportedPersistFactorError struct {
	Factor string
}

// Error implements error.
func (e *UnsupportedPersistFactorError) Error() string {
	return "init: no durable-store conversion for admin factor " + e.Factor
}

// nodeFactorPersister implements qrdbsdk.AdminFactorPersister against the
// durable node's user-side auth-factor client, for one fixed administrator
// userID resolved by first-boot.
type nodeFactorPersister struct {
	client qrdbtransport.UserAuthFactorClient
	userID uint64
}

var _ qrdbsdk.AdminFactorPersister = (*nodeFactorPersister)(nil)

// PersistAdminFactor implements qrdbsdk.AdminFactorPersister. It is called
// once per factor, immediately after that factor enrolls and before the next
// one starts (see qrdbsdk.EnrollAdminFactors), so a failure here halfway
// through a multi-factor plan leaves the earlier factors both enrolled and
// persisted -- never enrolled and lost.
func (p *nodeFactorPersister) PersistAdminFactor(ctx context.Context, factor qrdbsdk.AdminFactor, enrollment *qrdbsdk.AuthFactorEnrollment) error {
	req, err := enrollmentToAuthFactor(p.userID, factor, enrollment)
	if err != nil {
		return err
	}
	if _, err := p.client.AddAuthFactor(ctx, req); err != nil {
		return &WrappedDetailError{Sentinel: ErrFactorPersistFailed, Detail: factor.String(), Err: err}
	}
	return nil
}

// enrollmentToAuthFactor projects one factor's qrdbsdk.AuthFactorEnrollment
// onto the qrdbtransport.AuthFactorAddRequest the durable factor store's Add
// path expects. The credential shape is type-specific and mirrors the
// convention pkg/xkms and cmd/xkmsctl's own auth-factor add flows already
// use, so a factor enrolled here resolves through the SAME login lookup as
// one enrolled at runtime:
//
//   - mtls: Credential is the SPKI SHA-256 thumbprint (base64url) qrdb uses
//     stack-wide as the mTLS identity -- renewal-stable because it covers only
//     the public key, and IDENTICAL to what cmd/xkmsctl's admin enrollment
//     path binds (see xkmsLoadCertCredentialAndMetadata).
//   - piv: Credential is SHA-256 of the enrolled certificate's DER
//     (qrdbsdk.CredentialKey), matching the PIV slot-cert convention
//     cmd/xkmsctl's --credential-hex documents; SPKICredential is the same
//     SPKI thumbprint digest as mtls, so a PIV certificate renewed with the
//     same keypair keeps resolving.
//   - fido2: Credential is the raw WebAuthn credential ID
//     (base64url-decoded from Metadata["credential_id"], written by
//     pkg/factor/fido2's CTAP2 ceremony) -- qrdb's own lookup index hashes it,
//     so the stored Credential must be the raw, un-hashed identifier.
func enrollmentToAuthFactor(userID uint64, factor qrdbsdk.AdminFactor, enrollment *qrdbsdk.AuthFactorEnrollment) (*qrdbtransport.AuthFactorAddRequest, error) {
	name := factor.String()
	if enrollment == nil {
		return nil, &FactorConversionError{Factor: name, Reason: "enrollment is nil"}
	}

	req := &qrdbtransport.AuthFactorAddRequest{
		UserID:    userID,
		Type:      name,
		Label:     "xkmsd init: " + name,
		Metadata:  enrollment.Metadata,
		CreatedBy: qrdbsdk.FactorCreatedByAdmin,
	}

	switch factor {
	case qrdbsdk.FactorMTLS:
		thumbprint := enrollment.Metadata["cert_spki_thumbprint"]
		if thumbprint == "" {
			return nil, &FactorConversionError{Factor: name, Reason: "enrollment metadata carries no cert_spki_thumbprint"}
		}
		req.Credential = []byte(thumbprint)

	case qrdbsdk.FactorPIV:
		cert, err := parsePEMCertificate(enrollment.PublicKey)
		if err != nil {
			return nil, &FactorConversionError{Factor: name, Reason: "parsing enrolled certificate", Err: err}
		}
		req.Credential = qrdbsdk.CredentialKey(cert.Raw)
		spki, err := base64.RawURLEncoding.DecodeString(qrdbsdk.ComputeSPKIThumbprint(cert))
		if err != nil {
			return nil, &FactorConversionError{Factor: name, Reason: "decoding SPKI thumbprint", Err: err}
		}
		req.SPKICredential = spki

	case qrdbsdk.FactorFIDO2:
		credentialID := enrollment.Metadata["credential_id"]
		if credentialID == "" {
			return nil, &FactorConversionError{Factor: name, Reason: "enrollment metadata carries no credential_id"}
		}
		raw, err := base64.RawURLEncoding.DecodeString(credentialID)
		if err != nil {
			return nil, &FactorConversionError{Factor: name, Reason: "decoding credential_id", Err: err}
		}
		req.Credential = raw

	default:
		return nil, &UnsupportedPersistFactorError{Factor: name}
	}

	return req, nil
}

// parsePEMCertificate decodes a single PEM-encoded certificate block.
func parsePEMCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}
