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

package peer

import "strconv"

// PolicyError reports a Policy that cannot be evaluated as written. It is
// the caller's configuration that is wrong, not the peer's evidence, so
// Verify returns it as an error rather than folding it into the Verdict.
type PolicyError struct {
	// Field is the Policy field at fault.
	Field string
	// Reason says what is wrong with it.
	Reason string
}

// Error implements error.
func (e *PolicyError) Error() string {
	return "peer: invalid policy: " + e.Field + ": " + e.Reason
}

// ContextError reports that the context was done before verification ran.
type ContextError struct {
	// Cause is the context's error.
	Cause error
}

// Error implements error.
func (e *ContextError) Error() string {
	return "peer: verification aborted: " + e.Cause.Error()
}

// Unwrap returns the context error so errors.Is(err, context.Canceled) holds.
func (e *ContextError) Unwrap() error { return e.Cause }

// ChannelBindingError reports that a TLS connection state cannot yield a
// channel binding: no state was supplied, or the connection does not support
// key material export (TLS 1.2 without the extended master secret).
type ChannelBindingError struct {
	// Reason says why the binding could not be derived.
	Reason string
	// Cause is the underlying error, when the TLS stack produced one.
	Cause error
}

// Error implements error.
func (e *ChannelBindingError) Error() string {
	msg := "peer: channel binding unavailable: " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the TLS stack's error, when there is one.
func (e *ChannelBindingError) Unwrap() error { return e.Cause }

// DevIDError reports a certificate that is not a usable TCG device
// credential: a device identity (IDevID/LDevID) or an attestation key
// (IAK/LAK). It is returned by VerifyIDevID and VerifyIAK.
//
// A certificate, unlike a body of attestation evidence, is present or it is
// not — there is no partial credential to render a verdict over — so these
// checks answer with a typed error rather than a Verdict, and every rejection
// names the credential class and the reason.
type DevIDError struct {
	// Credential is the class the certificate was checked against, "IDevID"
	// or "IAK".
	Credential string
	// Reason says which check the certificate failed.
	Reason string
	// Cause is the underlying error, when one produced this rejection (a
	// chain verification failure, an ASN.1 decoding failure).
	Cause error
}

// Error implements error.
func (e *DevIDError) Error() string {
	msg := "peer: " + e.Credential + " certificate rejected: " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying error, when there is one, so a caller can
// errors.As a chain failure to *x509.CertificateInvalidError or
// *x509.UnknownAuthorityError.
func (e *DevIDError) Unwrap() error { return e.Cause }

// DevIDPolicyError reports a DevIDPolicy that cannot be evaluated as written.
// As with *PolicyError it is the caller's configuration that is wrong, not the
// certificate, and the two are kept apart so a gate can tell a misconfigured
// verifier from a rejected device.
type DevIDPolicyError struct {
	// Field is the DevIDPolicy field at fault.
	Field string
	// Reason says what is wrong with it.
	Reason string
}

// Error implements error.
func (e *DevIDPolicyError) Error() string {
	return "peer: invalid DevID policy: " + e.Field + ": " + e.Reason
}

// FailureClassError reports text that does not name a FailureClass.
type FailureClassError struct {
	// Text is the value that was rejected.
	Text string
}

// Error implements error.
func (e *FailureClassError) Error() string {
	return "peer: unknown failure class " + strconv.Quote(e.Text)
}

// DeviceMismatchError reports a device identity credential and an attestation
// key credential that name different TPMs (VerifySameDevice). Unlike a
// *DevIDError, nothing is missing: both credentials are well formed and they
// disagree, which is what a relayed quote looks like.
type DeviceMismatchError struct {
	// Field is the TCG DevID §8.1 name that differs: "hardwareModuleName" or
	// "permanentIdentifier".
	Field string
}

func (e *DeviceMismatchError) Error() string {
	return "peer: identity and attestation credentials name different TPMs: " + e.Field + " differs"
}
