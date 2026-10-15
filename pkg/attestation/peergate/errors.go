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

package peergate

import "strconv"

// ConfigError reports a Collector, Verifier or DAOStore configuration that
// does not describe a working component. Construction refuses it rather than
// running a gate that could only ever refuse, or never refuse.
type ConfigError struct {
	// Field is the configuration field at fault.
	Field string
	// Reason says what is wrong with it.
	Reason string
	// Cause is the underlying error, when one produced this rejection.
	Cause error
}

func (e *ConfigError) Error() string {
	msg := "peergate: invalid configuration: " + e.Field + ": " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *ConfigError) Unwrap() error { return e.Cause }

// ModeError reports a gate mode that is not off, optional or required.
type ModeError struct {
	// Value is the mode as configured.
	Value string
}

func (e *ModeError) Error() string {
	return "peergate: unknown gate mode " + strconv.Quote(e.Value) + " (want off, optional or required)"
}

// PeerCertificateError reports a connection that carries no verified client
// certificate, so there is no peer to challenge or to collect evidence from.
type PeerCertificateError struct {
	// Reason says what the connection lacks.
	Reason string
}

func (e *PeerCertificateError) Error() string {
	return "peergate: no attestable peer: " + e.Reason
}

// ChallengeError reports evidence that does not answer an outstanding
// challenge for the submitting peer: none was issued, it expired, or the
// evidence carries a different nonce. The evidence is not stored.
type ChallengeError struct {
	// Reason says why the submission does not answer a challenge.
	Reason string
}

func (e *ChallengeError) Error() string {
	return "peergate: evidence does not answer a challenge: " + e.Reason
}

// AttestedPeerError reports a go-qrdb AttestedPeer the verifier cannot judge:
// no certificate, or a thumbprint that is not the certificate's.
type AttestedPeerError struct {
	// Reason says what is wrong with the peer description.
	Reason string
}

func (e *AttestedPeerError) Error() string {
	return "peergate: unusable attested peer: " + e.Reason
}

// CapacityError reports a store or collector already tracking its maximum
// number of peers. It refuses the new peer and keeps every existing one.
type CapacityError struct {
	// What is the bounded collection: "evidence" or "challenges".
	What string
	// Limit is the configured maximum.
	Limit int
}

func (e *CapacityError) Error() string {
	return "peergate: " + e.What + " capacity of " + strconv.Itoa(e.Limit) + " peers reached"
}

// StoreError reports an EvidenceStore operation that failed. The verifier
// refuses to decide on a store error and the gate then refuses the request.
type StoreError struct {
	// Op is the store operation: "get" or "put".
	Op string
	// Cause is the store's error.
	Cause error
}

func (e *StoreError) Error() string {
	return "peergate: evidence store " + e.Op + " failed: " + e.Cause.Error()
}

func (e *StoreError) Unwrap() error { return e.Cause }

// QuoteError reports a quote the quoting side could not turn into evidence.
type QuoteError struct {
	// Reason says which step failed.
	Reason string
	// Cause is the underlying error, when one produced this failure.
	Cause error
}

func (e *QuoteError) Error() string {
	msg := "peergate: quote failed: " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *QuoteError) Unwrap() error { return e.Cause }

// NonceError reports that the system random source could not produce a
// challenge nonce.
type NonceError struct {
	// Cause is the random source's error.
	Cause error
}

func (e *NonceError) Error() string {
	return "peergate: challenge nonce generation failed: " + e.Cause.Error()
}

func (e *NonceError) Unwrap() error { return e.Cause }
