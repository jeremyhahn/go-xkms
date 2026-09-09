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

package config

import "errors"

// PolicyState says how far a VerifiedPolicy may be relied on.
type PolicyState uint8

const (
	// PolicyUnsealed means the config directory carries no HMAC file. This is
	// personal mode: the policy section is the user's own file and there is
	// no enterprise plane to authenticate, so a consumer treats the section
	// as the user's settings.
	PolicyUnsealed PolicyState = iota

	// PolicySealedVerified means the config directory carries an HMAC file
	// and the policy section verifies under the SO PIN. The section is
	// authenticated enterprise policy and may be honoured in both
	// directions, the permissive one included.
	PolicySealedVerified
)

// String returns the state's name for logs and error text.
func (s PolicyState) String() string {
	switch s {
	case PolicyUnsealed:
		return "unsealed"
	case PolicySealedVerified:
		return "sealed-verified"
	default:
		return "unknown"
	}
}

// VerifiedPolicy is a policy section together with how much it may be
// trusted. It is the only way a consumer should obtain enterprise policy:
// a *Config read straight from disk carries whatever the file says, and in
// a sealed deployment that is a value any local user could have written.
type VerifiedPolicy struct {
	Policy PolicySection
	State  PolicyState
}

// LoadVerifiedPolicy returns cfg's policy section with its verification
// state, failing closed whenever the section is sealed but cannot be
// authenticated.
//
// The states are exhaustive over what a consumer may do:
//
//   - No HMAC file in configDir: PolicyUnsealed. The section is returned as
//     read, because in personal mode it is the user's own file.
//   - HMAC file present and the section verifies under soPIN:
//     PolicySealedVerified. The section is authenticated enterprise policy.
//   - HMAC file present and anything else — soPIN empty, the file unreadable
//     or malformed, or the HMAC not matching — ErrPolicyUnverifiable, joined
//     with the cause (ErrPolicySOPINRequired, ErrPolicyHMACLoadFailed,
//     ErrPolicyHMACMismatch). No policy is returned with the error, so an
//     unverified sealed section cannot be consumed by accident.
//
// The third case is deliberately an error rather than a state. A sealed
// section that cannot be verified is a value any local user may have written,
// and the whole point of sealing is that such a value grants nothing (#118).
// A consumer that reaches it either refuses the operation or falls back to
// DefaultPolicy, which is the secure configuration; it never reads the file.
func LoadVerifiedPolicy(cfg *Config, configDir string, soPIN string) (*VerifiedPolicy, error) {
	if cfg == nil {
		return nil, errors.Join(ErrConfigInvalid, errors.New("config is nil"))
	}

	if !IsEnterpriseMode(configDir) {
		return &VerifiedPolicy{Policy: cfg.Policy, State: PolicyUnsealed}, nil
	}

	if soPIN == "" {
		return nil, errors.Join(ErrPolicyUnverifiable, ErrPolicySOPINRequired)
	}

	verified, err := VerifyPolicyHMAC(&cfg.Policy, PolicyHMACPath(configDir), soPIN)
	if err != nil {
		return nil, errors.Join(ErrPolicyUnverifiable, err)
	}
	if !verified {
		return nil, errors.Join(ErrPolicyUnverifiable, ErrPolicyHMACMismatch)
	}

	return &VerifiedPolicy{Policy: cfg.Policy, State: PolicySealedVerified}, nil
}
