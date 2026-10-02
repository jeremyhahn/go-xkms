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

package handlers

import (
	"fmt"
	"net/http"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// ErrAttestationIdentifierType is returned when an attestation challenge
// (enroll-01, endorse-01, device-attest-01) is asked to authorize an
// identifier type it cannot (go-xkms#828). Attestation never authorizes an
// "ip" identifier: a device's attested identity is not a network address, and
// mapping one to the other is the hole #828 closes. device-attest-01 further
// authorizes only a permanent-identifier, the one type its evidence can be
// compared with (pkg/acme/challenges/device-attest-01/identity.go).
type ErrAttestationIdentifierType struct {
	// Challenge is the attestation challenge type.
	Challenge string

	// Type is the authorization's identifier type.
	Type string
}

// Error implements the error interface.
func (e *ErrAttestationIdentifierType) Error() string {
	return fmt.Sprintf("handlers: %s cannot authorize a %q identifier", e.Challenge, e.Type)
}

// ErrIPIdentifierNotValidatable is returned by new-order when an "ip"
// identifier has no challenge type that could validate it in this server's
// configuration: attestation challenges never authorize ip (go-xkms#828) and
// the policy offers no other. It is the server declining the identifier, so
// it is answered as RFC 8555 section 6.7 rejectedIdentifier with 400, not as
// a server error.
type ErrIPIdentifierNotValidatable struct {
	// Value is the ip identifier value.
	Value string
}

// Error implements the error interface.
func (e *ErrIPIdentifierNotValidatable) Error() string {
	return fmt.Sprintf("handlers: no challenge type can validate ip identifier %q", e.Value)
}

// Problem returns the problem document sent to the client.
func (e *ErrIPIdentifierNotValidatable) Problem() *entities.Error {
	return entities.NewError(common.ErrTypeRejectedIdentifier,
		"No challenge type can validate an ip identifier on this server",
		http.StatusBadRequest, nil)
}

// ErrAttestingVerifierRequired is returned when an attestation challenge has
// no common.AttestingVerifier registered (go-xkms#828). A plain
// common.ChallengeVerifierFunc cannot report the identity it attested, so
// accepting one would authorize the order without comparing the attesting
// device with the order's identifier; the challenge is refused instead.
type ErrAttestingVerifierRequired struct {
	// Challenge is the attestation challenge type.
	Challenge string
}

// Error implements the error interface.
func (e *ErrAttestingVerifierRequired) Error() string {
	return fmt.Sprintf("handlers: %s has no attesting verifier registered; a verifier that cannot report the attested identity is refused", e.Challenge)
}

// ErrAttestationNoIdentity is returned when a common.AttestingVerifier
// reports success without an attested identity, breaking its contract. It is
// a defect in the verifier, never a client failure.
type ErrAttestationNoIdentity struct {
	// Challenge is the attestation challenge type.
	Challenge string
}

// Error implements the error interface.
func (e *ErrAttestationNoIdentity) Error() string {
	return fmt.Sprintf("handlers: %s verifier reported success with no attested identity", e.Challenge)
}

// ErrIdentityMismatch is returned when the identity an attestation challenge
// established is not the identifier the order authorizes (go-xkms#828). A
// valid attestation from device A must not authorize an order for device B.
// It carries both values for the server log; ChallengeHandler never sends
// them to the client.
type ErrIdentityMismatch struct {
	// Attested is the identity the verifier's evidence established.
	Attested string

	// Authorized is the authorization's identifier value.
	Authorized string
}

// Error implements the error interface.
func (e *ErrIdentityMismatch) Error() string {
	return fmt.Sprintf("handlers: attested identity %q does not authorize order identifier %q", e.Attested, e.Authorized)
}

// ErrDeviceAttestationNotFound is returned at finalization when a
// permanent-identifier order's authorization carries no validated
// device-attest-01 challenge with a persisted attestation record
// (go-xkms#789): a certificate request for this order type must never be
// signed without one, so its absence is refused rather than treated as a
// standard certificate.
type ErrDeviceAttestationNotFound struct {
	// OrderID is the order being finalized.
	OrderID uint64
}

// Error implements the error interface.
func (e *ErrDeviceAttestationNotFound) Error() string {
	return fmt.Sprintf("handlers: order %d has no validated device-attest-01 attestation to bind the certificate request to", e.OrderID)
}

// ErrOrderAuthorizationMissing is returned when an order references an
// authorization that storage does not hold -- after a partial restore or a
// replication fault. Finalization is refused: the checks that decide what an
// order is (a device-attest-01 order, an endorse-01 order) read the order's
// authorizations, and drawing them from an incomplete set would turn the
// missing record into permission.
type ErrOrderAuthorizationMissing struct {
	// OrderID is the order being finalized.
	OrderID uint64

	// AuthorizationID is the referenced authorization that was not found.
	AuthorizationID uint64
}

// Error implements the error interface.
func (e *ErrOrderAuthorizationMissing) Error() string {
	return fmt.Sprintf("handlers: order %d references authorization %d, which does not exist", e.OrderID, e.AuthorizationID)
}

// Problem returns the problem document sent to the client: the server's state
// is at fault, not the request, so it is a server error and names no identifier.
func (e *ErrOrderAuthorizationMissing) Problem() *entities.Error {
	return common.ServerInternal("Order authorization is missing")
}

// ErrFinalizeRequestNotPermitted is returned when a finalize request is not one
// the order's validated attestation challenge permits (go-xkms#789, #1392): an
// EK-certificate request for an order enroll-01 validated, a TCG-CSR-IDEVID for
// one endorse-01 validated, and so on. An endorse-01 order can become only an EK
// certificate, because EAB authorized the account for it and nothing proved the
// account holds the key.
type ErrFinalizeRequestNotPermitted struct {
	// OrderID is the order being finalized.
	OrderID uint64

	// Request names the finalize request that was refused.
	Request string

	// Required is the challenge type the request belongs to.
	Required string

	// Validated are the attestation challenge types that validated the order,
	// none if no attestation challenge did.
	Validated []string
}

// Error implements the error interface.
func (e *ErrFinalizeRequestNotPermitted) Error() string {
	if len(e.Validated) == 0 {
		return fmt.Sprintf("handlers: order %d was validated by no attestation challenge; a %s request needs %s", e.OrderID, e.Request, e.Required)
	}
	return fmt.Sprintf("handlers: order %d was validated by %s; a %s request needs only %s", e.OrderID, strings.Join(e.Validated, ", "), e.Request, e.Required)
}

// ErrEnrollActivationNotFound is returned at finalization when a TCG-CSR-IDEVID
// arrives for an order no enroll-01 challenge left an activation record on
// (go-xkms#1391): there is no activated endorsement key to compare it with, and
// a request that cannot be compared is refused, not signed.
type ErrEnrollActivationNotFound struct {
	// OrderID is the order being finalized.
	OrderID uint64
}

// Error implements the error interface.
func (e *ErrEnrollActivationNotFound) Error() string {
	return fmt.Sprintf("handlers: order %d has no enroll-01 credential activation to bind the TCG-CSR-IDEVID to", e.OrderID)
}

// ErrEnrollActivationMismatch is returned at finalization when a
// TCG-CSR-IDEVID is built around an endorsement key or attestation key other
// than the one an enroll-01 credential was activated for (go-xkms#1391).
type ErrEnrollActivationMismatch struct {
	// OrderID is the order being finalized.
	OrderID uint64

	// Subject names what differs: "endorsement key", "attestation key" or
	// "endorsement key certificate" when it could not be read.
	Subject string

	// Cause is why the subject could not be read, when that is the reason.
	Cause error
}

// Error implements the error interface.
func (e *ErrEnrollActivationMismatch) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("handlers: order %d: the TCG-CSR-IDEVID's %s cannot be read: %v", e.OrderID, e.Subject, e.Cause)
	}
	return fmt.Sprintf("handlers: order %d: the TCG-CSR-IDEVID's %s is not the one that passed enroll-01 credential activation", e.OrderID, e.Subject)
}

// Unwrap returns the cause, if any.
func (e *ErrEnrollActivationMismatch) Unwrap() error { return e.Cause }

// MapDAONotFound checks if the error is a DAO not-found error and returns
// the appropriate ACME error. Returns nil if the error is not a not-found
// error, indicating the caller should handle it differently.
func MapDAONotFound(err error, entityType string) *entities.Error {
	if !qrdbsdk.IsDAONotFound(err) {
		return nil
	}
	switch entityType {
	case "account":
		return common.AccountDoesNotExist("Account not found")
	case "order":
		return common.MalformedError("Order not found", nil)
	case "authorization":
		return common.MalformedError("Authorization not found", nil)
	case "challenge":
		return common.MalformedError("Challenge not found", nil)
	case "certificate":
		return common.MalformedError("Certificate not found", nil)
	case "nonce":
		return common.BadNonce("Nonce not found")
	case "eab":
		return common.Unauthorized("External account binding not found")
	case "tenant":
		return common.ServerInternal("Tenant not found")
	default:
		return common.ServerInternal("Entity not found: " + entityType)
	}
}
