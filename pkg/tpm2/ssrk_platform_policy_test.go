package tpm2

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The shared SRK never carries a platform policy. The tests below cover the two
// halves of that invariant: the configuration cannot ask for one, and nothing
// built from a configuration produces one.
//
// The Platform SRK is the platform-bound storage parent, and it takes its
// policy from PlatformSRKConfig alone. That is asserted here too, because it is
// the property that has to survive the SSRK losing the flag: before this
// change the Platform SRK inherited the flag from the SSRK configuration, so
// deleting it without moving the source of truth would have silently
// un-bound the one SRK that is supposed to be bound.

const ssrkYAMLWithPlatformPolicy = `
ssrk:
  handle: 0x81000001
  algorithm: RSA
  platform-policy: true
  rsa:
    keysize: 2048
`

func TestSRKConfigYAMLRejectsPlatformPolicy(t *testing.T) {
	var config Config
	err := yaml.Unmarshal([]byte(ssrkYAMLWithPlatformPolicy), &config)

	require.Error(t, err, "an ssrk section asking for a platform policy must be rejected")

	var policyErr *SSRKPlatformPolicyError
	require.ErrorAs(t, err, &policyErr)
	assert.Equal(t, "yaml", policyErr.Format)
	assert.Equal(t, "platform-policy", policyErr.Key)
	assert.True(t, errors.Is(err, ErrSSRKPlatformPolicy))
	assert.Contains(t, err.Error(), "platform-srk.platform-policy",
		"the error must name the setting that does bind to the platform")

	// yaml.v3 allocates the section before handing it to the unmarshaler, so
	// the pointer survives; what must not survive is any of its content.
	require.NotNil(t, config.SSRK)
	assert.Zero(t, *config.SSRK,
		"a rejected ssrk section must not leave a usable SRK configuration behind")
}

func TestSRKConfigYAMLAcceptsAbsentAndExplicitFalsePlatformPolicy(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "absent",
			yaml: "ssrk:\n  handle: 0x81000001\n  algorithm: RSA\n  rsa:\n    keysize: 2048\n",
		},
		{
			name: "explicit false",
			yaml: "ssrk:\n  handle: 0x81000001\n  algorithm: RSA\n  platform-policy: false\n  rsa:\n    keysize: 2048\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var config Config
			require.NoError(t, yaml.Unmarshal([]byte(tc.yaml), &config))

			require.NotNil(t, config.SSRK)
			assert.Equal(t, uint32(0x81000001), config.SSRK.Handle,
				"the remaining fields must decode normally")
			assert.Equal(t, "RSA", config.SSRK.KeyAlgorithm)
			require.NotNil(t, config.SSRK.RSAConfig)
			assert.Equal(t, 2048, config.SSRK.RSAConfig.KeySize)
		})
	}
}

func TestSRKConfigYAMLReportsMalformedSection(t *testing.T) {
	// A scalar where a mapping belongs is a plain decode error, not a policy
	// error: the custom unmarshaler must not swallow ordinary YAML faults.
	var config Config
	err := yaml.Unmarshal([]byte("ssrk: not-a-mapping\n"), &config)

	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSSRKPlatformPolicy))
}

func TestSRKConfigJSONRejectsPlatformPolicy(t *testing.T) {
	tests := []struct {
		name string
		json string
		key  string
	}{
		{
			name: "current spelling",
			json: `{"handle":2164260865,"algorithm":"RSA","platform_policy":true}`,
			key:  "platform_policy",
		},
		{
			name: "legacy spelling",
			json: `{"handle":2164260865,"algorithm":"RSA","_platform_policy":true}`,
			key:  "_platform_policy",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var config SRKConfig
			err := json.Unmarshal([]byte(tc.json), &config)

			require.Error(t, err)
			var policyErr *SSRKPlatformPolicyError
			require.ErrorAs(t, err, &policyErr)
			assert.Equal(t, "json", policyErr.Format)
			assert.Equal(t, tc.key, policyErr.Key)
			assert.True(t, errors.Is(err, ErrSSRKPlatformPolicy))

			assert.Zero(t, config.Handle,
				"a rejected object must not be partially applied")
		})
	}
}

func TestSRKConfigJSONAcceptsFalsePlatformPolicy(t *testing.T) {
	var config SRKConfig
	require.NoError(t, json.Unmarshal(
		[]byte(`{"handle":2164260865,"algorithm":"RSA","platform_policy":false}`), &config))

	assert.Equal(t, uint32(0x81000001), config.Handle)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
}

func TestSRKConfigJSONReportsMalformedObject(t *testing.T) {
	var config SRKConfig
	err := json.Unmarshal([]byte(`{"handle":"not-a-number"}`), &config)

	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSSRKPlatformPolicy))
}

func TestSSRKPlatformPolicyErrorNamesTheOffendingKey(t *testing.T) {
	err := &SSRKPlatformPolicyError{Format: "yaml", Key: "platform-policy"}

	assert.Contains(t, err.Error(), `yaml key "platform-policy"`)
	assert.Equal(t, ErrSSRKPlatformPolicy, err.Unwrap())
}

func TestDefaultConfigSSRKCarriesNoPlatformPolicy(t *testing.T) {
	require.NotNil(t, DefaultConfig.SSRK)

	attrs, err := SRKAttributesFromConfig(*DefaultConfig.SSRK)
	require.NoError(t, err)
	assert.False(t, attrs.PlatformPolicy,
		"the shipped default must not ask for a platform policy on the shared SRK")
	assert.Empty(t, attrs.TPMAttributes.Template.AuthPolicy.Buffer)

	require.NotNil(t, DefaultConfig.PlatformSRK)
	assert.True(t, DefaultConfig.PlatformSRK.PlatformPolicy,
		"the platform SRK keeps its platform binding")
}

// TestBuildSRKAttrsFromConfigTakesPolicyFromPlatformSRK proves the Platform
// SRK's platform binding comes from PlatformSRKConfig and from nowhere else.
// The SSRK section supplies only algorithm and key parameters.
func TestBuildSRKAttrsFromConfigTakesPolicyFromPlatformSRK(t *testing.T) {
	ssrk := &SRKConfig{
		Handle:       0x81000001,
		KeyAlgorithm: x509.RSA.String(),
		RSAConfig:    &store.RSAConfig{KeySize: 2048},
	}

	tests := []struct {
		name           string
		platformSRK    *PlatformSRKConfig
		ssrk           *SRKConfig
		expectPolicy   bool
		expectedHandle uint32
	}{
		{
			name:           "platform policy enabled",
			platformSRK:    &PlatformSRKConfig{SRKHandle: 0x81000002, PlatformPolicy: true},
			ssrk:           ssrk,
			expectPolicy:   true,
			expectedHandle: 0x81000002,
		},
		{
			name:           "platform policy disabled",
			platformSRK:    &PlatformSRKConfig{SRKHandle: 0x81000002, PlatformPolicy: false},
			ssrk:           ssrk,
			expectPolicy:   false,
			expectedHandle: 0x81000002,
		},
		{
			name:           "no platform SRK section falls back to the default handle",
			platformSRK:    nil,
			ssrk:           ssrk,
			expectPolicy:   false,
			expectedHandle: tpSRKIndex,
		},
		{
			name:           "no ssrk section still honours the platform policy",
			platformSRK:    &PlatformSRKConfig{SRKHandle: 0x81000002, PlatformPolicy: true},
			ssrk:           nil,
			expectPolicy:   true,
			expectedHandle: 0x81000002,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := PlatformSRKAttributesFromConfig(&Config{
				PlatformSRK: tc.platformSRK,
				SSRK:        tc.ssrk,
			})
			require.NoError(t, err)

			assert.Equal(t, tc.expectPolicy, attrs.PlatformPolicy)
			assert.Equal(t, tpm2.TPMHandle(tc.expectedHandle), attrs.TPMAttributes.Handle)
			assert.False(t, attrs.TPMAttributes.Template.ObjectAttributes.NoDA,
				"the PIN-verification SRK must remain under dictionary attack protection")
		})
	}
}

func TestBuildSRKAttrsFromConfigRejectsUnusableSSRK(t *testing.T) {
	attrs, err := PlatformSRKAttributesFromConfig(&Config{
		PlatformSRK: &PlatformSRKConfig{SRKHandle: 0x81000002, PlatformPolicy: true},
		SSRK:        &SRKConfig{Handle: 0x81000001, KeyAlgorithm: "INVALID"},
	})

	require.Error(t, err, "an unparseable key algorithm must not yield attributes")
	assert.Nil(t, attrs)
}

// TestPlatformSRKAttributesFromConfig_HierarchyAuthNeverFromConfig proves the
// Platform SRK's owner-hierarchy authorization is never read from
// configuration -- not the SSRK's, and not PlatformSRKConfig's, which has no
// such field to read. The Security Officer PIN, when an operator has set
// one, reaches TPM2_CreatePrimary only as the soPIN argument threaded
// through Initialize/EnrollPlatformSRK at the moment of the operation. No SO
// PIN means the attributes carry empty hierarchy auth, matching the TCG
// factory-default owner-hierarchy state.
func TestPlatformSRKAttributesFromConfig_HierarchyAuthNeverFromConfig(t *testing.T) {
	ssrk := &SRKConfig{
		Handle:        0x81000001,
		KeyAlgorithm:  x509.RSA.String(),
		HierarchyAuth: types.NewLiteralSecretValue([]byte("ssrk-only-secret")),
		RSAConfig:     &store.RSAConfig{KeySize: 2048},
	}

	attrs, err := PlatformSRKAttributesFromConfig(&Config{
		PlatformSRK: &PlatformSRKConfig{SRKHandle: 0x81000002},
		SSRK:        ssrk,
	})
	require.NoError(t, err)
	assert.Nil(t, attrs.TPMAttributes.HierarchyAuth,
		"the SSRK's hierarchy auth must never be borrowed for the Platform SRK, and PlatformSRKConfig carries no hierarchy-auth field of its own")
}
