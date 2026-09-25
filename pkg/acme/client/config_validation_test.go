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

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateConfig_Valid(t *testing.T) {
	cfg := validConfig()
	err := cfg.Validate()
	require.NoError(t, err)
}

// TestValidateConfig_Nil proves Validate rejects a nil receiver with a typed
// error instead of panicking: WithConfig(nil) is a caller error New must
// fail closed on (go-xkms#938).
func TestValidateConfig_Nil(t *testing.T) {
	var cfg *TrustedCAConfig
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

func TestValidateConfig_InvalidACME(t *testing.T) {
	cfg := validConfig()
	cfg.ACME.HTTPSAddr = ""
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acme.https_addr")
}

func TestValidateConfig_InvalidCA(t *testing.T) {
	cfg := validConfig()
	cfg.CA.DefaultKeyAlgorithm = "INVALID"
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.default_key_algorithm")
}

func TestValidateConfig_InvalidAdmin(t *testing.T) {
	cfg := validConfig()
	cfg.Admin.Enabled = true
	cfg.Admin.HTTPSAddr = ""
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin.https_addr")
}

func TestValidateConfig_InvalidMultiTenant(t *testing.T) {
	cfg := validConfig()
	cfg.MultiTenant.Enabled = true
	cfg.MultiTenant.DefaultTenantID = ""
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multi_tenant.default_tenant_id")
}

// --- ACMEConfig ---

func TestValidateACMEConfig_Valid(t *testing.T) {
	acme := validACMEConfig()
	err := acme.Validate()
	require.NoError(t, err)
}

func TestValidateACMEConfig_MissingHTTPSAddr(t *testing.T) {
	acme := validACMEConfig()
	acme.HTTPSAddr = ""
	err := acme.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acme.https_addr is required")
}

// TestValidateACMEConfig_ExternalURLOptional verifies that Validate accepts a
// config with no ExternalURL: TrustedCA.Serve derives an origin from the
// listen address in that case (go-xkms#140), so requiring it unconditionally
// here would refuse a construction path Serve legitimately supports
// (go-xkms#938).
func TestValidateACMEConfig_ExternalURLOptional(t *testing.T) {
	acme := validACMEConfig()
	acme.ExternalURL = ""
	err := acme.Validate()
	require.NoError(t, err)
}

func TestValidateACMEConfig_ExternalURLNotHTTPS(t *testing.T) {
	acme := validACMEConfig()
	acme.ExternalURL = "http://acme.example.com"
	err := acme.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https scheme")
}

func TestValidateACMEConfig_ExternalURLNoHost(t *testing.T) {
	acme := validACMEConfig()
	acme.ExternalURL = "https://"
	err := acme.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must include a host")
}

func TestValidateACMEConfig_ExternalURLInvalid(t *testing.T) {
	acme := validACMEConfig()
	acme.ExternalURL = "://not-a-url"
	err := acme.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "external_url")
}

func TestValidateACMEConfig_MissingCAIdentifiers(t *testing.T) {
	acme := validACMEConfig()
	acme.CAIdentifiers = nil
	err := acme.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acme.ca_identifiers is required")
}

func TestValidateACMEConfig_InvalidTLS(t *testing.T) {
	acme := validACMEConfig()
	acme.TLS.MinVersion = "1.2"
	err := acme.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls.min_version")
}

// --- TLSConfig ---

func TestValidateTLSConfig_Valid(t *testing.T) {
	tls := TCATLSConfig{MinVersion: "1.3", MaxVersion: "1.3"}
	err := tls.Validate()
	require.NoError(t, err)
}

func TestValidateTLSConfig_ValidEmpty(t *testing.T) {
	tls := TCATLSConfig{}
	err := tls.Validate()
	require.NoError(t, err)
}

func TestValidateTLSConfig_InvalidMinVersion(t *testing.T) {
	tls := TCATLSConfig{MinVersion: "1.2", MaxVersion: "1.3"}
	err := tls.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls.min_version")
	assert.Contains(t, err.Error(), "1.2")
}

func TestValidateTLSConfig_InvalidMaxVersion(t *testing.T) {
	tls := TCATLSConfig{MinVersion: "1.3", MaxVersion: "1.2"}
	err := tls.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls.max_version")
	assert.Contains(t, err.Error(), "1.2")
}

// --- CAConfig ---

func TestValidateCAConfig_Valid(t *testing.T) {
	ca := validCAConfig()
	err := ca.Validate()
	require.NoError(t, err)
}

func TestValidateCAConfig_AllKeyAlgorithms(t *testing.T) {
	algorithms := []string{
		"RSA-2048", "RSA-3072", "RSA-4096",
		"ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
		"Ed25519",
	}
	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			ca := validCAConfig()
			ca.DefaultKeyAlgorithm = alg
			err := ca.Validate()
			require.NoError(t, err)
		})
	}
}

func TestValidateCAConfig_MissingKeyAlgorithm(t *testing.T) {
	ca := validCAConfig()
	ca.DefaultKeyAlgorithm = ""
	err := ca.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.default_key_algorithm is required")
}

func TestValidateCAConfig_InvalidKeyAlgorithm(t *testing.T) {
	ca := validCAConfig()
	ca.DefaultKeyAlgorithm = "BLOWFISH-128"
	err := ca.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.default_key_algorithm")
	assert.Contains(t, err.Error(), "BLOWFISH-128")
}

func TestValidateCAConfig_MissingSignatureAlgorithm(t *testing.T) {
	ca := validCAConfig()
	ca.DefaultSignatureAlgorithm = ""
	err := ca.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.default_signature_algorithm is required")
}

func TestValidateCAConfig_InvalidSignatureAlgorithm(t *testing.T) {
	ca := validCAConfig()
	ca.DefaultSignatureAlgorithm = "MD5-RSA"
	err := ca.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.default_signature_algorithm")
	assert.Contains(t, err.Error(), "MD5-RSA")
}

func TestValidateCAConfig_ValidityTooLow(t *testing.T) {
	ca := validCAConfig()
	ca.CertificateValidityDays = 0
	err := ca.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.certificate_validity_days")
}

func TestValidateCAConfig_ValidityTooHigh(t *testing.T) {
	ca := validCAConfig()
	ca.CertificateValidityDays = 10951
	err := ca.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.certificate_validity_days")
}

func TestValidateCAConfig_ValidityBoundary(t *testing.T) {
	// Min boundary: 1 day
	ca := validCAConfig()
	ca.CertificateValidityDays = 1
	require.NoError(t, ca.Validate())

	// Max boundary: 10950 days
	ca.CertificateValidityDays = 10950
	require.NoError(t, ca.Validate())
}

// --- AdminConfig ---

func TestValidateAdminConfig_ValidEnabled(t *testing.T) {
	admin := AdminConfig{
		Enabled:   true,
		HTTPSAddr: ":9443",
		TLS:       TCATLSConfig{MinVersion: "1.3", MaxVersion: "1.3"},
	}
	err := admin.Validate()
	require.NoError(t, err)
}

func TestValidateAdminConfig_DisabledSkipsValidation(t *testing.T) {
	admin := AdminConfig{
		Enabled:   false,
		HTTPSAddr: "", // would be invalid if enabled
	}
	err := admin.Validate()
	require.NoError(t, err)
}

func TestValidateAdminConfig_EnabledMissingAddr(t *testing.T) {
	admin := AdminConfig{
		Enabled:   true,
		HTTPSAddr: "",
	}
	err := admin.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin.https_addr")
}

func TestValidateAdminConfig_EnabledInvalidTLS(t *testing.T) {
	admin := AdminConfig{
		Enabled:   true,
		HTTPSAddr: ":9443",
		TLS:       TCATLSConfig{MinVersion: "1.0"},
	}
	err := admin.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls.min_version")
}

// --- MultiTenantConfig ---

func TestValidateMultiTenantConfig_ValidEnabled(t *testing.T) {
	mt := MultiTenantConfig{
		Enabled:         true,
		DefaultTenantID: "my-tenant",
	}
	err := mt.Validate()
	require.NoError(t, err)
}

func TestValidateMultiTenantConfig_DisabledSkipsValidation(t *testing.T) {
	mt := MultiTenantConfig{
		Enabled:         false,
		DefaultTenantID: "", // would be invalid if enabled
	}
	err := mt.Validate()
	require.NoError(t, err)
}

func TestValidateMultiTenantConfig_EnabledMissingTenantID(t *testing.T) {
	mt := MultiTenantConfig{
		Enabled:         true,
		DefaultTenantID: "",
	}
	err := mt.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multi_tenant.default_tenant_id")
}

// --- helpers ---

func validACMEConfig() TCAACMEConfig {
	return TCAACMEConfig{
		HTTPSAddr:     ":8443",
		ExternalURL:   "https://acme.example.com",
		CAIdentifiers: []string{"ca.example.com"},
		TLS:           TCATLSConfig{MinVersion: "1.3", MaxVersion: "1.3"},
	}
}

func validCAConfig() CAConfig {
	return CAConfig{
		DefaultKeyAlgorithm:       "ECDSA-P256",
		DefaultSignatureAlgorithm: "SHA256-ECDSA",
		CertificateValidityDays:   365,
	}
}

func validConfig() *TrustedCAConfig {
	return &TrustedCAConfig{
		ACME: validACMEConfig(),
		CA:   validCAConfig(),
		Admin: AdminConfig{
			Enabled:   false,
			HTTPSAddr: ":9443",
			TLS:       TCATLSConfig{MinVersion: "1.3", MaxVersion: "1.3"},
		},
		MultiTenant: MultiTenantConfig{
			Enabled:         false,
			DefaultTenantID: "default",
		},
	}
}
