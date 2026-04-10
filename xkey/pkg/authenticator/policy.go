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

package authenticator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// PolicyFields are the SO-controlled fields within AuthenticatorState
// that are covered by the HMAC integrity tag. Changes to these fields
// outside of SO operations are detected as tampering.
//
// Fields are serialized to JSON with deterministic key ordering (Go's
// encoding/json produces sorted struct fields) for canonical HMAC input.
type PolicyFields struct {
	// MinPINLength is the minimum PIN length in characters.
	MinPINLength int `json:"minPINLength"`

	// MaxPINRetries is the maximum PIN attempts before lockout.
	MaxPINRetries int `json:"maxPINRetries"`

	// SOPINMaxRetries is the maximum SO PIN attempts before lockout.
	SOPINMaxRetries int `json:"soPINMaxRetries"`

	// AlwaysUV indicates if user verification is always required.
	AlwaysUV bool `json:"alwaysUV"`

	// MaxCredentials is the maximum number of credentials to store.
	MaxCredentials int `json:"maxCredentials"`

	// MaxResidentCredentials is the maximum number of discoverable credentials.
	MaxResidentCredentials int `json:"maxResidentCredentials"`

	// EnableCredentialManagement indicates if credential management commands are enabled.
	EnableCredentialManagement bool `json:"enableCredentialManagement"`

	// EnableEnterpriseAttestation indicates if enterprise attestation is enabled.
	EnableEnterpriseAttestation bool `json:"enableEnterpriseAttestation"`

	// Transports is the configured transport list for GetInfo.
	Transports []string `json:"transports,omitempty"`
}

// ExtractPolicyFields extracts the HMAC-covered policy fields from the
// authenticator configuration. These are the SO-controlled parameters
// that affect the authenticator's security posture.
func ExtractPolicyFields(cfg *Config) *PolicyFields {
	soPINMaxRetries := DefaultSOPINMaxRetries
	return &PolicyFields{
		MinPINLength:                cfg.PINMinLength,
		MaxPINRetries:               cfg.PINMaxRetries,
		SOPINMaxRetries:             soPINMaxRetries,
		AlwaysUV:                    cfg.AlwaysUV,
		MaxCredentials:              cfg.MaxCredentials,
		MaxResidentCredentials:      cfg.MaxResidentCredentials,
		EnableCredentialManagement:  cfg.EnableCredentialManagement,
		EnableEnterpriseAttestation: cfg.EnableEnterpriseAttestation,
		Transports:                  cfg.Transports,
	}
}

// Canonical returns a deterministic JSON serialization of the policy fields
// suitable for HMAC computation. Go's encoding/json produces deterministic
// output for structs with fixed field order, making this suitable for
// cryptographic use.
func (pf *PolicyFields) Canonical() ([]byte, error) {
	if pf == nil {
		return nil, ErrPolicySignFailed
	}
	data, err := json.Marshal(pf)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicySignFailed, err)
	}
	return data, nil
}

// PolicyIntegrityProvider computes and verifies HMAC integrity tags over
// canonical policy data. Implementations include software (HMAC-SHA256),
// TPM2 (hardware-resident key), and PKCS#11 (HSM-resident key).
type PolicyIntegrityProvider interface {
	// Sign computes an HMAC tag over the canonical policy data.
	Sign(canonical []byte) ([]byte, error)

	// Verify checks the HMAC tag against the canonical policy data.
	// Returns ErrPolicyTampered if the tag does not match.
	// Returns other errors for infrastructure failures.
	Verify(canonical, tag []byte) error
}

// SoftwarePolicyProvider uses HMAC-SHA256 with a provided key for policy
// integrity. This is suitable for development and testing environments.
// For production, use TPM2PolicyProvider or PKCS11PolicyProvider which
// protect the HMAC key in hardware.
type SoftwarePolicyProvider struct {
	key []byte
}

// NewSoftwarePolicyProvider creates a software-based policy integrity provider.
// The key must be at least 32 bytes and should be derived from a secure source
// such as an attestation key or SO PIN-derived material.
//
// Returns ErrPolicyKeyTooShort if the key is less than 32 bytes.
func NewSoftwarePolicyProvider(key []byte) (*SoftwarePolicyProvider, error) {
	if len(key) < 32 {
		return nil, ErrPolicyKeyTooShort
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &SoftwarePolicyProvider{key: keyCopy}, nil
}

// Sign computes an HMAC-SHA256 tag over the canonical policy data.
func (p *SoftwarePolicyProvider) Sign(canonical []byte) ([]byte, error) {
	if canonical == nil {
		return nil, ErrPolicySignFailed
	}
	mac := hmac.New(sha256.New, p.key)
	if _, err := mac.Write(canonical); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicySignFailed, err)
	}
	return mac.Sum(nil), nil
}

// Verify checks the HMAC-SHA256 tag against the canonical policy data.
// Uses constant-time comparison to prevent timing side channels.
// Returns ErrPolicyTampered if the tag does not match.
func (p *SoftwarePolicyProvider) Verify(canonical, tag []byte) error {
	if canonical == nil || tag == nil {
		return ErrPolicyVerifyFailed
	}
	mac := hmac.New(sha256.New, p.key)
	if _, err := mac.Write(canonical); err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyVerifyFailed, err)
	}
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, tag) {
		return ErrPolicyTampered
	}
	return nil
}

// PolicyMismatch describes a single field that differs between the signed
// policy snapshot and the current configuration values.
type PolicyMismatch struct {
	// Field is the JSON field name that differs.
	Field string `json:"field"`

	// Expected is the value from the signed policy snapshot.
	Expected interface{} `json:"expected"`

	// Actual is the current value from the configuration.
	Actual interface{} `json:"actual"`
}

// PolicyDiagnostics reports the result of policy integrity verification.
// When verification fails, Mismatches identifies which specific fields
// were modified, aiding in incident response.
type PolicyDiagnostics struct {
	// Valid indicates whether the policy HMAC verification passed.
	Valid bool `json:"valid"`

	// Mismatches lists fields that differ between the signed snapshot
	// and the current configuration. Empty when Valid is true.
	Mismatches []PolicyMismatch `json:"mismatches,omitempty"`
}

// PolicyManager handles policy integrity verification and signing.
// It bridges the authenticator configuration, state, and the integrity
// provider to ensure SO-controlled policy fields are tamper-detected.
type PolicyManager struct {
	config   *Config
	provider PolicyIntegrityProvider
}

// NewPolicyManager creates a new PolicyManager with the given configuration
// and integrity provider.
func NewPolicyManager(config *Config, provider PolicyIntegrityProvider) *PolicyManager {
	return &PolicyManager{
		config:   config,
		provider: provider,
	}
}

// Verify checks the HMAC tag stored in state against the current policy fields.
// Returns PolicyDiagnostics including any mismatched fields.
//
// Returns ErrPolicyHMACMissing if no HMAC tag exists in state.
// Returns ErrPolicyTampered if the HMAC does not match, with diagnostics
// identifying which fields differ.
// Returns other errors for infrastructure failures (no diagnostics).
func (pm *PolicyManager) Verify(state *AuthenticatorState) (*PolicyDiagnostics, error) {
	if len(state.PolicyHMACTag) == 0 {
		return nil, ErrPolicyHMACMissing
	}

	current := ExtractPolicyFields(pm.config)
	canonical, err := current.Canonical()
	if err != nil {
		return nil, err
	}

	if err := pm.provider.Verify(canonical, state.PolicyHMACTag); err != nil {
		// Distinguish tamper detection from infrastructure failure.
		// ErrPolicyTampered means the HMAC didn't match (config was modified).
		// Other errors indicate provider-level failures (e.g., HSM unavailable).
		if errors.Is(err, ErrPolicyTampered) {
			diag := &PolicyDiagnostics{Valid: false}
			diag.Mismatches = computeMismatches(current, state.SignedPolicyFields)
			return diag, ErrPolicyTampered
		}
		// Infrastructure failure: propagate error without diagnostics
		return nil, err
	}

	return &PolicyDiagnostics{Valid: true}, nil
}

// Sign computes the HMAC tag for the current policy fields and stores
// it in the state. This is called when SO installs or modifies policy.
func (pm *PolicyManager) Sign(state *AuthenticatorState) error {
	current := ExtractPolicyFields(pm.config)
	canonical, err := current.Canonical()
	if err != nil {
		return err
	}

	tag, err := pm.provider.Sign(canonical)
	if err != nil {
		return err
	}

	state.PolicyHMACTag = tag
	state.SignedPolicyFields = current
	return nil
}

// computeMismatches compares current policy fields against the signed
// policy snapshot and returns a list of fields that differ. This provides
// detailed diagnostics for tamper detection incident response.
func computeMismatches(current, signed *PolicyFields) []PolicyMismatch {
	if signed == nil {
		return nil
	}

	var mismatches []PolicyMismatch

	if current.MinPINLength != signed.MinPINLength {
		mismatches = append(mismatches, PolicyMismatch{
			Field:    "minPINLength",
			Expected: signed.MinPINLength,
			Actual:   current.MinPINLength,
		})
	}
	if current.MaxPINRetries != signed.MaxPINRetries {
		mismatches = append(mismatches, PolicyMismatch{
			Field:    "maxPINRetries",
			Expected: signed.MaxPINRetries,
			Actual:   current.MaxPINRetries,
		})
	}
	if current.SOPINMaxRetries != signed.SOPINMaxRetries {
		mismatches = append(mismatches, PolicyMismatch{
			Field:    "soPINMaxRetries",
			Expected: signed.SOPINMaxRetries,
			Actual:   current.SOPINMaxRetries,
		})
	}
	if current.AlwaysUV != signed.AlwaysUV {
		mismatches = append(mismatches, PolicyMismatch{
			Field:    "alwaysUV",
			Expected: signed.AlwaysUV,
			Actual:   current.AlwaysUV,
		})
	}
	if current.MaxCredentials != signed.MaxCredentials {
		mismatches = append(mismatches, PolicyMismatch{
			Field:    "maxCredentials",
			Expected: signed.MaxCredentials,
			Actual:   current.MaxCredentials,
		})
	}
	if current.MaxResidentCredentials != signed.MaxResidentCredentials {
		mismatches = append(mismatches, PolicyMismatch{
			Field:    "maxResidentCredentials",
			Expected: signed.MaxResidentCredentials,
			Actual:   current.MaxResidentCredentials,
		})
	}
	if current.EnableCredentialManagement != signed.EnableCredentialManagement {
		mismatches = append(mismatches, PolicyMismatch{
			Field:    "enableCredentialManagement",
			Expected: signed.EnableCredentialManagement,
			Actual:   current.EnableCredentialManagement,
		})
	}
	if current.EnableEnterpriseAttestation != signed.EnableEnterpriseAttestation {
		mismatches = append(mismatches, PolicyMismatch{
			Field:    "enableEnterpriseAttestation",
			Expected: signed.EnableEnterpriseAttestation,
			Actual:   current.EnableEnterpriseAttestation,
		})
	}
	if !slicesEqual(current.Transports, signed.Transports) {
		mismatches = append(mismatches, PolicyMismatch{
			Field:    "transports",
			Expected: signed.Transports,
			Actual:   current.Transports,
		})
	}

	return mismatches
}

// slicesEqual compares two string slices for equality.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
