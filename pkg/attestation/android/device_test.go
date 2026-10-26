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

package android

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTestDenied = errors.New("test: application denied")

// packageMatcher allows exactly one package name.
type packageMatcher string

func (m packageMatcher) Match(appID *AttestationApplicationID) (string, string, error) {
	if appID == nil {
		return "", "", errTestDenied
	}
	for _, pkg := range appID.Packages {
		if pkg.Name == string(m) {
			return pkg.Name, "", nil
		}
	}
	return "", "", errTestDenied
}

func lockedVerifiedDescription() *KeyDescription {
	return &KeyDescription{TeeEnforced: AuthorizationList{
		Origin:      OriginGenerated,
		Purpose:     []int{PurposeVerify, PurposeSign},
		RootOfTrust: &RootOfTrust{DeviceLocked: true, VerifiedBootState: VerifiedBootVerified},
	}}
}

func TestDeviceVerifyOptions_RequestTheHardwareBar(t *testing.T) {
	pool := x509.NewCertPool()

	opts := DeviceVerifyOptions(pool)

	assert.Same(t, pool, opts.TrustedRoots, "the chain must be verified against the caller's pool")
	assert.Nil(t, opts.ExpectedNonce, "a persistent key carries its genesis challenge, never the live nonce (#129)")
	assert.Equal(t, SecurityLevelTrustedEnvironment, opts.MinSecurityLevel)
	assert.True(t, opts.VerifyBootState)
}

func TestRequireAttestedBootState_Succeeds(t *testing.T) {
	desc := lockedVerifiedDescription()

	rot, err := RequireAttestedBootState(desc)

	require.NoError(t, err)
	assert.Same(t, desc.TeeEnforced.RootOfTrust, rot)
}

func TestRequireAttestedBootState_Refuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		rot  *RootOfTrust
		want error
	}{
		{name: "no root of trust", rot: nil, want: ErrNoRootOfTrust},
		{name: "bootloader unlocked", rot: &RootOfTrust{VerifiedBootState: VerifiedBootVerified}, want: ErrBootloaderUnlocked},
		{name: "self-signed boot", rot: &RootOfTrust{DeviceLocked: true, VerifiedBootState: VerifiedBootSelfSigned}, want: ErrUnverifiedBoot},
		{name: "unverified boot", rot: &RootOfTrust{DeviceLocked: true, VerifiedBootState: VerifiedBootUnverified}, want: ErrUnverifiedBoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			desc := &KeyDescription{TeeEnforced: AuthorizationList{RootOfTrust: tc.rot}}

			rot, err := RequireAttestedBootState(desc)

			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, rot)
		})
	}

	t.Run("root of trust only in softwareEnforced", func(t *testing.T) {
		desc := &KeyDescription{SoftwareEnforced: AuthorizationList{
			RootOfTrust: &RootOfTrust{DeviceLocked: true, VerifiedBootState: VerifiedBootVerified},
		}}

		_, err := RequireAttestedBootState(desc)

		require.ErrorIs(t, err, ErrNoRootOfTrust)
	})

	t.Run("nil description", func(t *testing.T) {
		_, err := RequireAttestedBootState(nil)
		require.ErrorIs(t, err, ErrNilKeyDescription)
	})
}

func TestRequireAttestedKeyOrigin_Succeeds(t *testing.T) {
	require.NoError(t, RequireAttestedKeyOrigin(lockedVerifiedDescription()))
}

func TestRequireAttestedKeyOrigin_Refuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		desc *KeyDescription
		want error
	}{
		{
			name: "origin imported",
			desc: &KeyDescription{TeeEnforced: AuthorizationList{Origin: OriginImported, Purpose: []int{PurposeSign}}},
			want: ErrKeyOriginNotGenerated,
		},
		{
			name: "purpose without sign",
			desc: &KeyDescription{TeeEnforced: AuthorizationList{Origin: OriginGenerated, Purpose: []int{PurposeVerify}}},
			want: ErrKeyPurposeNotSign,
		},
		{
			name: "no hardware-enforced claim at all",
			desc: &KeyDescription{TeeEnforced: AuthorizationList{Origin: OriginUnknown}},
			want: ErrKeyOriginNotGenerated,
		},
		{
			name: "claim present only in softwareEnforced",
			desc: &KeyDescription{
				TeeEnforced:      AuthorizationList{Origin: OriginUnknown},
				SoftwareEnforced: AuthorizationList{Origin: OriginGenerated, Purpose: []int{PurposeSign}},
			},
			want: ErrKeyOriginNotGenerated,
		},
		{name: "nil description", desc: nil, want: ErrNilKeyDescription},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, RequireAttestedKeyOrigin(tc.desc), tc.want)
		})
	}
}

func TestRequireAttestedPerUseUserVerification_Succeeds(t *testing.T) {
	for name, authType := range map[string]int{
		"device credential (1)":           UserAuthTypePassword,
		"biometric (2)":                   UserAuthTypeFingerprint,
		"biometric or the credential (3)": UserAuthTypePassword | UserAuthTypeFingerprint,
	} {
		t.Run(name, func(t *testing.T) {
			desc := &KeyDescription{TeeEnforced: AuthorizationList{UserAuthType: authType}}
			require.NoError(t, RequireAttestedPerUseUserVerification(desc))
		})
	}
}

func TestRequireAttestedPerUseUserVerification_Refuses(t *testing.T) {
	biometric := AuthorizationList{UserAuthType: UserAuthTypeFingerprint}
	with := func(edit func(*AuthorizationList)) AuthorizationList {
		list := biometric
		edit(&list)
		return list
	}

	for _, tc := range []struct {
		name string
		desc *KeyDescription
		want error
	}{
		{
			name: "noAuthRequired in teeEnforced",
			desc: &KeyDescription{TeeEnforced: with(func(l *AuthorizationList) { l.NoAuthRequired = true })},
			want: ErrKeyNoAuthRequired,
		},
		{
			name: "noAuthRequired in softwareEnforced",
			desc: &KeyDescription{TeeEnforced: biometric, SoftwareEnforced: AuthorizationList{NoAuthRequired: true}},
			want: ErrKeyNoAuthRequired,
		},
		{
			name: "no userAuthType claim",
			desc: &KeyDescription{TeeEnforced: AuthorizationList{}},
			want: ErrKeyUserAuthTypeNotUserVerification,
		},
		{
			name: "a bit beyond the credential and the biometric",
			desc: &KeyDescription{TeeEnforced: with(func(l *AuthorizationList) { l.UserAuthType = 4 })},
			want: ErrKeyUserAuthTypeNotUserVerification,
		},
		{
			name: "the biometric with an unknown bit",
			desc: &KeyDescription{TeeEnforced: with(func(l *AuthorizationList) { l.UserAuthType = UserAuthTypeFingerprint | 4 })},
			want: ErrKeyUserAuthTypeNotUserVerification,
		},
		{
			name: "any authenticator type (0xFFFFFFFF)",
			desc: &KeyDescription{TeeEnforced: with(func(l *AuthorizationList) { l.UserAuthType = 0xFFFFFFFF })},
			want: ErrKeyUserAuthTypeNotUserVerification,
		},
		{
			name: "biometric claimed only in softwareEnforced",
			desc: &KeyDescription{SoftwareEnforced: biometric},
			want: ErrKeyUserAuthTypeNotUserVerification,
		},
		{
			name: "nonzero authTimeout",
			desc: &KeyDescription{TeeEnforced: with(func(l *AuthorizationList) { l.HasAuthTimeout, l.AuthTimeout = true, 30 })},
			want: ErrKeyAuthTimeout,
		},
		{
			name: "authTimeout present as zero",
			desc: &KeyDescription{TeeEnforced: with(func(l *AuthorizationList) { l.HasAuthTimeout = true })},
			want: ErrKeyAuthTimeout,
		},
		{
			name: "allowWhileOnBody",
			desc: &KeyDescription{TeeEnforced: with(func(l *AuthorizationList) { l.AllowWhileOnBody = true })},
			want: ErrKeyAllowWhileOnBody,
		},
		{name: "nil description", desc: nil, want: ErrNilKeyDescription},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, RequireAttestedPerUseUserVerification(tc.desc), tc.want)
		})
	}
}

func TestRequireAttestedApplication_Succeeds(t *testing.T) {
	desc := &KeyDescription{}
	desc.SoftwareEnforced.AttestationApplicationID = &AttestationApplicationID{
		Packages: []AttestationPackageInfo{{Name: "com.example.app"}},
	}

	require.NoError(t, RequireAttestedApplication(desc, packageMatcher("com.example.app")))
}

func TestRequireAttestedApplication_Refuses(t *testing.T) {
	t.Run("matcher refuses", func(t *testing.T) {
		err := RequireAttestedApplication(&KeyDescription{}, packageMatcher("com.example.app"))

		require.ErrorIs(t, err, ErrApplicationRefused)
		require.ErrorIs(t, err, errTestDenied, "the matcher's own reason must survive")
	})

	t.Run("nil matcher", func(t *testing.T) {
		require.ErrorIs(t, RequireAttestedApplication(&KeyDescription{}, nil), ErrNilApplicationMatcher)
	})

	t.Run("nil description", func(t *testing.T) {
		require.ErrorIs(t, RequireAttestedApplication(nil, packageMatcher("com.example.app")), ErrNilKeyDescription)
	})
}

func TestKeyDescriptionAttestedApplication_PrefersSoftwareEnforced(t *testing.T) {
	sw := &AttestationApplicationID{Packages: []AttestationPackageInfo{{Name: "com.example.sw"}}}
	tee := &AttestationApplicationID{Packages: []AttestationPackageInfo{{Name: "com.example.tee"}}}

	desc := &KeyDescription{}
	desc.SoftwareEnforced.AttestationApplicationID = sw
	desc.TeeEnforced.AttestationApplicationID = tee
	assert.Same(t, sw, desc.AttestedApplication())

	desc.SoftwareEnforced.AttestationApplicationID = nil
	assert.Same(t, tee, desc.AttestedApplication())

	desc.TeeEnforced.AttestationApplicationID = nil
	assert.Nil(t, desc.AttestedApplication())

	var none *KeyDescription
	assert.Nil(t, none.AttestedApplication())
}
