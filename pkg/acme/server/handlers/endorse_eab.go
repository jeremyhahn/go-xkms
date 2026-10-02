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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// EAB authorization errors for endorse-01 challenges.
var (
	// ErrEndorseEABRequired is returned when EAB is required for endorse-01 but not present.
	ErrEndorseEABRequired = errors.New("handlers: external account binding required for endorse-01 challenge")

	// ErrEndorseEABNotFound is returned when the EAB binding cannot be found.
	ErrEndorseEABNotFound = errors.New("handlers: external account binding not found for account")

	// ErrEndorseEABInvalid is returned when the EAB binding is not valid.
	ErrEndorseEABInvalid = errors.New("handlers: external account binding is not valid")

	// ErrEndorseEABPurposeMismatch is returned when the EAB purpose is not "endorse-01".
	ErrEndorseEABPurposeMismatch = errors.New("handlers: external account binding purpose must be 'endorse-01'")

	// ErrEndorseEABDeviceMismatch is returned when the device identifier doesn't match EAB metadata.
	ErrEndorseEABDeviceMismatch = errors.New("handlers: device identifier does not match authorized device in EAB")

	// ErrEndorseEABDeviceIDRequired is returned when device ID validation is configured but no ID in metadata.
	ErrEndorseEABDeviceIDRequired = errors.New("handlers: device identifier required in EAB metadata but not found")

	// ErrEndorseEABKeyNotBound is returned when an endorse-01 External Account
	// Binding does not name the EK it authorizes -- neither the configured
	// device-id metadata key nor deviceInfo.ekPublicKeyHash. Such a binding
	// would authorize its account for ANY public key, and endorse-01 holds no
	// proof that the account holds the key it asks to have certified.
	ErrEndorseEABKeyNotBound = errors.New("handlers: external account binding does not bind an EK public key (set deviceInfo.ekPublicKeyHash)")

	// ErrEndorseEABKeyMismatch is returned when the EK an endorse-01 order asks
	// to certify is not the one the account's External Account Binding is bound to.
	ErrEndorseEABKeyMismatch = errors.New("handlers: EK public key does not match the key authorized by the external account binding")

	// ErrEndorseNoAuthorizedIdentity is returned by the endorse-01 verifier when
	// it is run without the identity the account's External Account Binding
	// authorized. endorse-01 attests nothing about the device, so with no
	// authorization to derive it from there is no identity to report.
	ErrEndorseNoAuthorizedIdentity = errors.New("handlers: endorse-01 has no EAB-authorized identity to attest")
)

// EndorseEABAuthorization contains the result of EAB authorization for endorse-01.
type EndorseEABAuthorization struct {
	// Binding is the external account binding associated with the account.
	Binding *entities.ExternalAccountBinding

	// Authorized indicates whether the request is authorized.
	Authorized bool

	// AuthorizedDeviceID is the device identifier from the EAB metadata (if configured).
	AuthorizedDeviceID string

	// ExternalAccountID is the reference to the external system's account.
	ExternalAccountID string

	// AuthorizedIdentity is the EK identifier the EAB policy authorized, which
	// is what endorse-01 reports as the attested identity (go-xkms#1392). It is
	// the value the binding's device-id metadata holds, or, for a binding
	// bound by deviceInfo.ekPublicKeyHash, the identifier whose hash the
	// binding names. It is never read from the request alone.
	AuthorizedIdentity string

	// Unauthenticated is true when EAB was not required, so nothing authorized
	// the identifier and AuthorizedIdentity is the request's own. This is the
	// operator's explicit opt-out; the handler logs every use of it.
	Unauthenticated bool
}

// EndorseEABValidator validates EAB authorization for endorse-01 challenges.
type EndorseEABValidator struct {
	eabDAO          qrdbsdk.GenericDAO[*entities.ExternalAccountBinding]
	deviceIDMetaKey string
	requireEAB      bool
}

// NewEndorseEABValidator creates a new validator for endorse-01 EAB authorization.
func NewEndorseEABValidator(
	eabDAO qrdbsdk.GenericDAO[*entities.ExternalAccountBinding],
	requireEAB bool,
	deviceIDMetaKey string,
) *EndorseEABValidator {
	return &EndorseEABValidator{
		eabDAO:          eabDAO,
		deviceIDMetaKey: deviceIDMetaKey,
		requireEAB:      requireEAB,
	}
}

// ValidateEndorseAuthorization validates that an account is authorized to perform
// endorse-01 challenges based on its EAB binding.
//
// If EAB is not required (requireEAB=false), this returns an authorized result
// with no binding information, marked Unauthenticated: the operator has chosen
// to let any account obtain an EK certificate for any public key.
//
// If EAB is required:
//   - The account must have been registered with EAB
//   - The EAB binding must be in "used" status (bound to the account)
//   - The binding must name the EK it authorizes (go-xkms#1392): by the
//     device-id metadata key when deviceIDMetaKey is configured, and/or by
//     deviceInfo.ekPublicKeyHash (SHA-256 of the EK's PKIX DER, hex). A binding
//     that names neither is ErrEndorseEABKeyNotBound, because it would
//     authorize its account for any key.
//   - The device identifier must be that EK
//
// Parameters:
//   - ctx: Context for the operation
//   - account: The ACME account attempting the endorse-01 challenge
//   - deviceIdentifier: The device identifier from the authorization (e.g., EK public key hash)
//
// Returns:
//   - EndorseEABAuthorization with authorization result
//   - error if validation fails
func (v *EndorseEABValidator) ValidateEndorseAuthorization(
	ctx context.Context,
	account *entities.ACMEAccount,
	deviceIdentifier string,
) (*EndorseEABAuthorization, error) {

	// If EAB is not required, allow all endorse-01 challenges. Nothing
	// authorized the identifier, so the result says so.
	if !v.requireEAB {
		return &EndorseEABAuthorization{
			Authorized:         true,
			AuthorizedIdentity: deviceIdentifier,
			Unauthenticated:    true,
		}, nil
	}

	// EAB is required - check if account has EAB binding reference
	if account.ExternalAccountBinding == nil {
		return nil, ErrEndorseEABRequired
	}

	// Extract the EAB key identifier from the account's binding reference
	eabKID, err := extractEABKeyID(account.ExternalAccountBinding)
	if err != nil {
		return nil, caerrors.MalformedError("invalid EAB binding: %v", err)
	}

	if eabKID == "" {
		return nil, ErrEndorseEABRequired
	}

	// Look up the full EAB binding by key identifier
	binding, err := v.eabDAO.Get(ctx, entities.StringToEntityID(eabKID))
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, ErrEndorseEABNotFound
		}
		return nil, caerrors.StorageFailureError("failed to retrieve EAB binding: %v", err)
	}

	// Verify the binding is in "used" status and bound to this account
	if binding.Status != entities.EABStatusUsed {
		return nil, caerrors.UnauthorizedError(
			"EAB binding status is %s, expected %s", binding.Status, entities.EABStatusUsed)
	}

	if binding.AccountID != account.ID {
		return nil, caerrors.UnauthorizedError("EAB binding is not associated with this account")
	}

	// Verify the EAB purpose is "endorse-01"
	// Per implementation plan: server validates EAB.Purpose == "endorse-01"
	if binding.Purpose != entities.EABPurposeEndorse01 {
		return nil, caerrors.UnauthorizedError(
			"EAB binding purpose is %q, expected %q", binding.Purpose, entities.EABPurposeEndorse01)
	}

	result := &EndorseEABAuthorization{
		Binding:           binding,
		Authorized:        true,
		ExternalAccountID: binding.ExternalAccountID,
	}

	// If device ID metadata key is configured, validate device authorization
	if v.deviceIDMetaKey != "" {
		if binding.Metadata == nil {
			return nil, ErrEndorseEABDeviceIDRequired
		}

		authorizedDeviceID, exists := binding.Metadata[v.deviceIDMetaKey]
		if !exists || authorizedDeviceID == "" {
			return nil, ErrEndorseEABDeviceIDRequired
		}

		result.AuthorizedDeviceID = authorizedDeviceID

		// Compare device identifiers (case-insensitive for hex values)
		if !deviceIDMatches(deviceIdentifier, authorizedDeviceID) {
			return nil, caerrors.UnauthorizedError(
				"device identifier mismatch: expected %s, got %s", authorizedDeviceID, deviceIdentifier)
		}
		result.AuthorizedIdentity = authorizedDeviceID
	}

	// deviceInfo.ekPublicKeyHash binds the EK too. It needs no configuration,
	// so an operator who registers a device through the admin API binds its key
	// without setting a metadata key.
	if binding.DeviceInfo != nil && binding.DeviceInfo.EKPublicKeyHash != "" {
		if !ekIdentifierHashMatches(deviceIdentifier, binding.DeviceInfo.EKPublicKeyHash) {
			return nil, ErrEndorseEABKeyMismatch
		}
		if result.AuthorizedIdentity == "" {
			result.AuthorizedIdentity = deviceIdentifier
		}
	}

	if result.AuthorizedIdentity == "" {
		return nil, ErrEndorseEABKeyNotBound
	}
	return result, nil
}

// ekHashPrefix is the optional algorithm prefix an EAB's ekPublicKeyHash may
// carry ("sha256:<hex>", the form the admin API reference shows).
const ekHashPrefix = "sha256:"

// ekIdentifierHashMatches reports whether wantHash is the SHA-256 of the PKIX
// DER public key an endorse-01 identifier carries (base64url of the DER), in
// hex, with or without the "sha256:" prefix. An identifier that does not
// decode matches nothing.
func ekIdentifierHashMatches(identifier, wantHash string) bool {
	der, err := base64.RawURLEncoding.DecodeString(identifier)
	if err != nil {
		return false
	}
	want := strings.TrimSpace(wantHash)
	if len(want) >= len(ekHashPrefix) && strings.EqualFold(want[:len(ekHashPrefix)], ekHashPrefix) {
		want = want[len(ekHashPrefix):]
	}
	digest := sha256.Sum256(der)
	return strings.EqualFold(want, hex.EncodeToString(digest[:]))
}

// BoundTPMManufacturer returns the TCG TPM manufacturer code the account's
// external account binding authorizes for endorse-01, or the empty string
// when the account has no binding or its binding names no manufacturer.
//
// An endorse-01 device asserts its manufacturer code itself. When an operator
// registered the device with a code, the device may assert only that one, so
// this is consulted whether or not EAB is required for endorse-01.
//
// Returns ErrEndorseEABNotFound when the account names a binding that does not
// exist, and ErrEndorseEABInvalid when the binding belongs to another account.
func (v *EndorseEABValidator) BoundTPMManufacturer(
	ctx context.Context,
	account *entities.ACMEAccount,
) (string, error) {

	if account.ExternalAccountBinding == nil {
		return "", nil
	}
	eabKID, err := extractEABKeyID(account.ExternalAccountBinding)
	if err != nil {
		return "", caerrors.MalformedError("invalid EAB binding: %v", err)
	}
	if eabKID == "" {
		return "", nil
	}

	binding, err := v.eabDAO.Get(ctx, entities.StringToEntityID(eabKID))
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return "", ErrEndorseEABNotFound
		}
		return "", caerrors.StorageFailureError("failed to retrieve EAB binding: %v", err)
	}
	if binding.AccountID != account.ID {
		return "", ErrEndorseEABInvalid
	}
	if binding.DeviceInfo == nil {
		return "", nil
	}
	return binding.DeviceInfo.TPMManufacturer, nil
}

// extractEABKeyID extracts the key identifier from an account's EAB binding reference.
// The account stores EAB as interface{} which may be a map or struct.
func extractEABKeyID(eabRef interface{}) (string, error) {
	if eabRef == nil {
		return "", nil
	}

	// Try direct string (might be just the KID)
	if kid, ok := eabRef.(string); ok {
		return kid, nil
	}

	// Try map[string]interface{}
	if m, ok := eabRef.(map[string]interface{}); ok {
		if kid, exists := m["kid"]; exists {
			if kidStr, ok := kid.(string); ok {
				return kidStr, nil
			}
		}
		// Try protected header extraction
		if protected, exists := m["protected"]; exists {
			return extractKIDFromProtected(protected)
		}
	}

	// Try JSON marshaling and re-parsing
	data, err := json.Marshal(eabRef)
	if err != nil {
		return "", caerrors.SerializationFailureError("failed to marshal EAB reference: %v", err)
	}

	var eabMap map[string]interface{}
	if err := json.Unmarshal(data, &eabMap); err != nil {
		return "", caerrors.SerializationFailureError("failed to unmarshal EAB reference: %v", err)
	}

	if kid, exists := eabMap["kid"]; exists {
		if kidStr, ok := kid.(string); ok {
			return kidStr, nil
		}
	}

	return "", caerrors.MalformedError("unable to extract key identifier from EAB reference")
}

// extractKIDFromProtected extracts the KID from a base64url-encoded protected header.
func extractKIDFromProtected(protected interface{}) (string, error) {
	protectedStr, ok := protected.(string)
	if !ok {
		return "", caerrors.MalformedError("protected header is not a string")
	}

	// Decode base64url
	decoded, err := base64.RawURLEncoding.DecodeString(protectedStr)
	if err != nil {
		return "", caerrors.MalformedError("failed to decode protected header: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return "", caerrors.SerializationFailureError("failed to unmarshal protected header: %v", err)
	}

	if kid, exists := header["kid"]; exists {
		if kidStr, ok := kid.(string); ok {
			return kidStr, nil
		}
	}

	return "", caerrors.MalformedError("kid not found in protected header")
}

// deviceIDMatches compares two device identifiers.
// Comparison is case-insensitive to handle hex-encoded values.
func deviceIDMatches(actual, expected string) bool {
	// Normalize by trimming whitespace and converting to lowercase
	actual = strings.TrimSpace(strings.ToLower(actual))
	expected = strings.TrimSpace(strings.ToLower(expected))
	return actual == expected
}

// NewEndorseVerifier returns the endorse-01 common.AttestingVerifier
// (go-xkms#828, go-xkms#1392).
//
// endorse-01 attests nothing about the device. An EK is decrypt-only, the server
// holds no proof that the account holds the key it asks to have certified, and
// no exchange with the device takes place. What authorizes the request is the
// account's External Account Binding, which ChallengeHandler validates before
// this verifier runs and hands over as AttestationChallenge.AuthorizedIdentity.
// The identity reported is that: the EK the EAB policy authorized, not the
// identifier of the order being checked. ChallengeHandler then compares it with
// the order's identifier, so an account bound to one EK cannot obtain a
// certificate for another.
//
// With no authorized identity -- the verifier run by something other than
// ChallengeHandler -- there is nothing to report and the challenge is refused
// (ErrEndorseNoAuthorizedIdentity), never answered with the order's own
// identifier.
//
// A MakeCredential proof of possession is not added: it needs the server to
// reach the device (the order's identifier is an EK, not an address, so there
// is nothing to dial; see go-xkms#828) or a second request on the challenge,
// and either changes the protocol.
func NewEndorseVerifier() common.AttestingVerifier {
	return common.AttestingVerifierFunc(func(
		_ *net.Resolver,
		_ common.CertificateAuthority,
		challenge common.AttestationChallenge,
	) (*common.AttestedIdentity, error) {
		if challenge.AuthorizedIdentity == "" {
			return nil, ErrEndorseNoAuthorizedIdentity
		}
		return &common.AttestedIdentity{Identifier: challenge.AuthorizedIdentity}, nil
	})
}

// IsEndorseChallengeType returns true if the challenge type is endorse-01.
func IsEndorseChallengeType(challengeType string) bool {
	return challengeType == "endorse-01"
}
