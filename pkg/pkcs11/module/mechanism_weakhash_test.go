// Copyright (C) 2025 go-xkms authors
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License as published
//    by the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html

package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// C10: a SHA-1 signature mechanism must not advertise CKF_SIGN when weak-hash
// signing is not allowed — advertising a signing capability the weak-hash
// policy then refuses is the advertise-but-fail split. Verification of legacy
// signatures stays valid (SP 800-131A scopes the prohibition to generation), so
// CKF_VERIFY is retained and the mechanism is still discoverable.

func TestSHA1SignatureMechanism_WithholdsSignFlagByDefault(t *testing.T) {
	// Default policy (env unset): weak-hash signing is refused.
	t.Setenv(weakHashSigningEnvVar, "")

	for _, mech := range []MechanismType{CKM_SHA1_RSA_PKCS, CKM_ECDSA_SHA1} {
		desc := GetMechanismDescriptor(mech)
		require.NotNil(t, desc, "the mechanism stays discoverable for verification")
		assert.Zero(t, desc.Flags&CKF_SIGN,
			"%s must not advertise CKF_SIGN while weak-hash signing is refused", desc.Name)
		assert.NotZero(t, desc.Flags&CKF_VERIFY,
			"%s must keep CKF_VERIFY: verifying a legacy SHA-1 signature stays valid", desc.Name)
	}

	// The advertised C_GetMechanismInfo projection agrees with the *Init view.
	info := defaultMechanismInfo()
	if sha1rsa, ok := info[CKM_SHA1_RSA_PKCS]; ok {
		assert.Zero(t, sha1rsa.Flags&CKF_SIGN,
			"C_GetMechanismInfo must not advertise CKF_SIGN for CKM_SHA1_RSA_PKCS by default")
	}
}

func TestSHA1SignatureMechanism_AdvertisesSignWhenWeakHashAllowed(t *testing.T) {
	t.Setenv(weakHashSigningEnvVar, "true")

	for _, mech := range []MechanismType{CKM_SHA1_RSA_PKCS, CKM_ECDSA_SHA1} {
		desc := GetMechanismDescriptor(mech)
		require.NotNil(t, desc)
		assert.NotZero(t, desc.Flags&CKF_SIGN,
			"%s must advertise CKF_SIGN once the operator opts into weak-hash signing", desc.Name)
	}
}

// The registry entry itself is never mutated by the effective-flags copy, so a
// second reader under a different policy still sees the raw capability.
func TestEffectiveMechanismFlags_DoesNotMutateRegistry(t *testing.T) {
	raw := mechanismRegistry[CKM_SHA1_RSA_PKCS].Flags

	t.Setenv(weakHashSigningEnvVar, "")
	_ = GetMechanismDescriptor(CKM_SHA1_RSA_PKCS)

	assert.Equal(t, raw, mechanismRegistry[CKM_SHA1_RSA_PKCS].Flags,
		"GetMechanismDescriptor must return an adjusted copy, never mutate the shared registry entry")
}
