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

package pairing

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const appPolicyDigest = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

// attestedApp is the attestationApplicationId a genuine build presents.
func attestedApp(t *testing.T, pkg, digestHex string) *xkms.AndroidAttestationApplicationID {
	t.Helper()
	digest, err := hex.DecodeString(digestHex)
	require.NoError(t, err)
	return &xkms.AndroidAttestationApplicationID{
		Packages:         []xkms.AndroidAttestationPackageInfo{{Name: pkg, Version: 1}},
		SignatureDigests: [][]byte{digest},
	}
}

// pinnedPolicy allow-lists testPackage signed by appPolicyDigest only.
func pinnedPolicy() ApplicationPolicy {
	return ApplicationPolicy{AllowedApplications: []AllowedApplication{{
		PackageName:    testPackage,
		SigningDigests: []string{appPolicyDigest},
	}}}
}

func TestApplicationPolicy_AcceptsAPinnedBuild(t *testing.T) {
	pkg, digest, err := pinnedPolicy().Match(attestedApp(t, testPackage, appPolicyDigest))
	require.NoError(t, err)
	assert.Equal(t, testPackage, pkg)
	assert.Equal(t, appPolicyDigest, digest)
}

func TestApplicationPolicy_DigestComparisonIgnoresCaseAndSpace(t *testing.T) {
	policy := ApplicationPolicy{AllowedApplications: []AllowedApplication{{
		PackageName:    testPackage,
		SigningDigests: []string{"  " + strings.ToUpper(appPolicyDigest) + " "},
	}}}

	_, digest, err := policy.Match(attestedApp(t, testPackage, appPolicyDigest))
	require.NoError(t, err)
	assert.Equal(t, appPolicyDigest, digest)
}

func TestApplicationPolicy_RefusesARebuildSignedWithAnotherKey(t *testing.T) {
	// The package name is trivially forgeable -- anybody can build an APK
	// claiming it. The signing digest is what makes it an identity.
	_, _, err := pinnedPolicy().Match(attestedApp(t, testPackage, "00"+appPolicyDigest[2:]))
	assert.ErrorIs(t, err, ErrApplicationDenied)
}

func TestApplicationPolicy_RefusesAnUnlistedPackage(t *testing.T) {
	_, _, err := pinnedPolicy().Match(attestedApp(t, "com.example.other", appPolicyDigest))
	assert.ErrorIs(t, err, ErrApplicationDenied)
}

func TestApplicationPolicy_PackageNamesAreCaseSensitive(t *testing.T) {
	// Android package names are case-sensitive: a differently cased name is a
	// different application, not a spelling of this one.
	_, _, err := pinnedPolicy().Match(attestedApp(t, strings.ToUpper(testPackage), appPolicyDigest))
	assert.ErrorIs(t, err, ErrApplicationDenied)
}

func TestApplicationPolicy_RefusesEvidenceNamingNoApplication(t *testing.T) {
	_, _, err := pinnedPolicy().Match(nil)
	assert.ErrorIs(t, err, ErrApplicationDenied)

	_, _, err = pinnedPolicy().Match(&xkms.AndroidAttestationApplicationID{})
	assert.ErrorIs(t, err, ErrApplicationDenied)
}

func TestApplicationPolicy_RefusesEveryApplicationWhenUnconfigured(t *testing.T) {
	var policy ApplicationPolicy
	assert.False(t, policy.Configured())

	_, _, err := policy.Match(attestedApp(t, testPackage, appPolicyDigest))
	assert.ErrorIs(t, err, ErrApplicationPolicyUnconfigured)
	assert.ErrorIs(t, err, xkms.ErrAndroidNilApplicationMatcher,
		"the library's sentinel is the one contract for an unconfigured policy (#1721)")
	assert.False(t, errors.Is(err, ErrApplicationDenied),
		"an unconfigured policy is a setup problem, not a verdict on the device")
}

func TestApplicationPolicy_UnpinnedEntryNeedsExplicitOptIn(t *testing.T) {
	policy := ApplicationPolicy{AllowedApplications: []AllowedApplication{{PackageName: testPackage}}}
	app := attestedApp(t, testPackage, appPolicyDigest)

	_, _, err := policy.Match(app)
	require.ErrorIs(t, err, ErrApplicationDenied)
	assert.Contains(t, err.Error(), "allow_unpinned_signatures")

	policy.AllowUnpinnedSignatures = true
	pkg, digest, err := policy.Match(app)
	require.NoError(t, err)
	assert.Equal(t, testPackage, pkg)
	assert.Equal(t, appPolicyDigest, digest)
}

func TestApplicationPolicy_ConsidersEveryEntryForAPackage(t *testing.T) {
	// A release and a debug signer listed as two entries for one package: the
	// second must still be reachable after the first fails to match.
	policy := ApplicationPolicy{AllowedApplications: []AllowedApplication{
		{PackageName: testPackage, SigningDigests: []string{"00" + appPolicyDigest[2:]}},
		{PackageName: testPackage, SigningDigests: []string{appPolicyDigest}},
	}}

	_, digest, err := policy.Match(attestedApp(t, testPackage, appPolicyDigest))
	require.NoError(t, err)
	assert.Equal(t, appPolicyDigest, digest)
}

func TestApplicationPolicy_YAMLShape(t *testing.T) {
	const doc = `
allowed_applications:
  - package_name: com.automatethethings.xkey
    signing_digests:
      - ` + appPolicyDigest + `
allow_unpinned_signatures: true
`
	var policy ApplicationPolicy
	require.NoError(t, yaml.Unmarshal([]byte(doc), &policy))
	require.Len(t, policy.AllowedApplications, 1)
	assert.Equal(t, testPackage, policy.AllowedApplications[0].PackageName)
	assert.Equal(t, []string{appPolicyDigest}, policy.AllowedApplications[0].SigningDigests)
	assert.True(t, policy.AllowUnpinnedSignatures)

	var bad ApplicationPolicy
	assert.Error(t, yaml.Unmarshal([]byte("allowed_applications: not-a-list"), &bad))
}
