// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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
// with no binding information.
//
// If EAB is required:
//   - The account must have been registered with EAB
//   - The EAB binding must be in "used" status (bound to the account)
//   - If deviceIDMetaKey is configured, the device identifier must match
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

	// If EAB is not required, allow all endorse-01 challenges
	if !v.requireEAB {
		return &EndorseEABAuthorization{
			Authorized: true,
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
	}

	return result, nil
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

// IsEndorseChallengeType returns true if the challenge type is endorse-01.
func IsEndorseChallengeType(challengeType string) bool {
	baseType, _, _ := parseChallengeAsDynamicPortAssignment(challengeType)
	return baseType == "endorse-01"
}
