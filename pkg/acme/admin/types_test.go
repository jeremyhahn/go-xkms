//go:build codec_json

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

package admin

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmstypes "github.com/jeremyhahn/go-xkms/pkg/types"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestConfig_JSONSerialization(t *testing.T) {
	config := Config{
		Enabled:    true,
		ListenAddr: ":8443",
		TLSEnabled: true,
		TLSCert:    "/path/to/cert.pem",
		TLSKey:     "/path/to/key.pem",
	}

	data, err := json.Marshal(config)
	require.NoError(t, err)

	var decoded Config
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, config.Enabled, decoded.Enabled)
	assert.Equal(t, config.ListenAddr, decoded.ListenAddr)
	assert.Equal(t, config.TLSEnabled, decoded.TLSEnabled)
}

func TestProblemDetail_JSONSerialization(t *testing.T) {
	problem := ProblemDetail{
		Type:   "urn:trusted-ca:error:not-found",
		Title:  "Not Found",
		Detail: "Resource not found",
		Status: 404,
	}

	data, err := json.Marshal(problem)
	require.NoError(t, err)

	var decoded ProblemDetail
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, problem.Type, decoded.Type)
	assert.Equal(t, problem.Title, decoded.Title)
	assert.Equal(t, problem.Detail, decoded.Detail)
	assert.Equal(t, problem.Status, decoded.Status)
}

func TestListResponse_JSONSerialization(t *testing.T) {
	resp := ListResponse{
		Items:   []string{"a", "b", "c"},
		Total:   100,
		Page:    1,
		PerPage: 20,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded ListResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp.Total, decoded.Total)
	assert.Equal(t, resp.Page, decoded.Page)
	assert.Equal(t, resp.PerPage, decoded.PerPage)
	assert.NotNil(t, decoded.Items)
}

func TestPagination_JSONSerialization(t *testing.T) {
	pagination := Pagination{
		Page:    5,
		PerPage: 50,
		Total:   250,
	}

	data, err := json.Marshal(pagination)
	require.NoError(t, err)

	var decoded Pagination
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, pagination.Page, decoded.Page)
	assert.Equal(t, pagination.PerPage, decoded.PerPage)
	assert.Equal(t, pagination.Total, decoded.Total)
}

func TestCertificateInfo_JSONSerialization(t *testing.T) {
	now := time.Now()
	certInfo := CertificateInfo{
		SerialNumber: "123456789",
		Subject:      "CN=example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		Status:       "valid",
		IssuedAt:     now,
		CertURL:      "https://ca.example.com/cert/123456789",
	}

	data, err := json.Marshal(certInfo)
	require.NoError(t, err)

	var decoded CertificateInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, certInfo.SerialNumber, decoded.SerialNumber)
	assert.Equal(t, certInfo.Subject, decoded.Subject)
	assert.Equal(t, certInfo.Status, decoded.Status)
}

func TestAccountInfo_JSONSerialization(t *testing.T) {
	now := time.Now()
	accountInfo := AccountInfo{
		ID:                   1,
		Status:               "valid",
		Contact:              []string{"mailto:admin@example.com"},
		CreatedAt:            now,
		TermsOfServiceAgreed: true,
		OrdersURL:            "https://ca.example.com/account/1/orders",
		OrderCount:           5,
	}

	data, err := json.Marshal(accountInfo)
	require.NoError(t, err)

	var decoded AccountInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, accountInfo.ID, decoded.ID)
	assert.Equal(t, accountInfo.Status, decoded.Status)
	assert.Equal(t, accountInfo.Contact, decoded.Contact)
	assert.Equal(t, accountInfo.OrderCount, decoded.OrderCount)
}

func TestOrderInfo_JSONSerialization(t *testing.T) {
	now := time.Now()
	orderInfo := OrderInfo{
		ID:          1,
		AccountID:   10,
		Status:      "pending",
		Identifiers: []string{"example.com", "www.example.com"},
		NotBefore:   now.Format(time.RFC3339),
		NotAfter:    now.Add(90 * 24 * time.Hour).Format(time.RFC3339),
		Expires:     now.Add(24 * time.Hour).Format(time.RFC3339),
		Certificate: "https://ca.example.com/cert/123",
		CreatedAt:   now,
	}

	data, err := json.Marshal(orderInfo)
	require.NoError(t, err)

	var decoded OrderInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, orderInfo.ID, decoded.ID)
	assert.Equal(t, orderInfo.AccountID, decoded.AccountID)
	assert.Equal(t, orderInfo.Status, decoded.Status)
	assert.Equal(t, orderInfo.Identifiers, decoded.Identifiers)
}

func TestCAStatus_JSONSerialization(t *testing.T) {
	now := time.Now()
	caStatus := CAStatus{
		Identity:       "test-ca",
		Initialized:    true,
		Version:        "1.0.0",
		StartedAt:      now,
		KeyAlgorithm:   "RSA-2048",
		SignatureAlgo:  "SHA256-RSA",
		RootCA:         "Test Root CA",
		IntermediateCA: "Test Intermediate CA",
		Keys: []KeyInfo{
			{
				Algorithm:          "RSA",
				SignatureAlgorithm: "SHA256-RSAPSS",
				Store:              "software",
				KeySize:            2048,
				Default:            true,
			},
			{
				Algorithm:          "ECDSA",
				SignatureAlgorithm: "ECDSAWithSHA256",
				Store:              "tpm2",
				Curve:              "P-256",
				Default:            false,
			},
		},
	}

	data, err := json.Marshal(caStatus)
	require.NoError(t, err)

	var decoded CAStatus
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, caStatus.Identity, decoded.Identity)
	assert.Equal(t, caStatus.Initialized, decoded.Initialized)
	assert.Equal(t, caStatus.Version, decoded.Version)
	assert.Equal(t, caStatus.RootCA, decoded.RootCA)
	assert.Equal(t, caStatus.IntermediateCA, decoded.IntermediateCA)

	// Verify keys round-trip
	require.Len(t, decoded.Keys, 2)
	assert.Equal(t, "RSA", decoded.Keys[0].Algorithm)
	assert.Equal(t, 2048, decoded.Keys[0].KeySize)
	assert.True(t, decoded.Keys[0].Default)
	assert.Equal(t, "ECDSA", decoded.Keys[1].Algorithm)
	assert.Equal(t, "P-256", decoded.Keys[1].Curve)
	assert.False(t, decoded.Keys[1].Default)
}

func TestCAStats_JSONSerialization(t *testing.T) {
	stats := CAStats{
		TotalCertificates:   100,
		ValidCertificates:   85,
		RevokedCertificates: 10,
		ExpiredCertificates: 5,
		TotalAccounts:       50,
		ActiveAccounts:      45,
		TotalOrders:         120,
		PendingOrders:       10,
		CompletedOrders:     100,
	}

	data, err := json.Marshal(stats)
	require.NoError(t, err)

	var decoded CAStats
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, stats.TotalCertificates, decoded.TotalCertificates)
	assert.Equal(t, stats.ValidCertificates, decoded.ValidCertificates)
	assert.Equal(t, stats.RevokedCertificates, decoded.RevokedCertificates)
	assert.Equal(t, stats.TotalAccounts, decoded.TotalAccounts)
}

func TestAuditLog_JSONSerialization(t *testing.T) {
	now := time.Now()
	auditLog := AuditLog{
		ID:        1,
		Timestamp: now,
		Actor:     "admin@example.com",
		Action:    "revoke_certificate",
		Resource:  "cert/123456789",
		Details:   "Certificate revoked due to key compromise",
		Success:   true,
	}

	data, err := json.Marshal(auditLog)
	require.NoError(t, err)

	var decoded AuditLog
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, auditLog.ID, decoded.ID)
	assert.Equal(t, auditLog.Actor, decoded.Actor)
	assert.Equal(t, auditLog.Action, decoded.Action)
	assert.Equal(t, auditLog.Success, decoded.Success)
}

func TestRevokeRequest_JSONSerialization(t *testing.T) {
	req := RevokeRequest{
		Reason: "keyCompromise",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded RevokeRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Reason, decoded.Reason)
}

func TestListCertificatesRequest_JSONSerialization(t *testing.T) {
	req := ListCertificatesRequest{
		Page:        2,
		PerPage:     50,
		Status:      "valid",
		Subject:     "example.com",
		ExpiresDays: 30,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ListCertificatesRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Page, decoded.Page)
	assert.Equal(t, req.PerPage, decoded.PerPage)
	assert.Equal(t, req.Status, decoded.Status)
	assert.Equal(t, req.Subject, decoded.Subject)
	assert.Equal(t, req.ExpiresDays, decoded.ExpiresDays)
}

func TestListAccountsRequest_JSONSerialization(t *testing.T) {
	req := ListAccountsRequest{
		Page:    3,
		PerPage: 25,
		Status:  "valid",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ListAccountsRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Page, decoded.Page)
	assert.Equal(t, req.PerPage, decoded.PerPage)
	assert.Equal(t, req.Status, decoded.Status)
}

func TestListOrdersRequest_JSONSerialization(t *testing.T) {
	req := ListOrdersRequest{
		Page:      1,
		PerPage:   20,
		AccountID: 42,
		Status:    "pending",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ListOrdersRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Page, decoded.Page)
	assert.Equal(t, req.PerPage, decoded.PerPage)
	assert.Equal(t, req.AccountID, decoded.AccountID)
	assert.Equal(t, req.Status, decoded.Status)
}

func TestListAuditLogsRequest_JSONSerialization(t *testing.T) {
	now := time.Now()
	req := ListAuditLogsRequest{
		Page:      1,
		PerPage:   50,
		StartTime: now.Add(-24 * time.Hour),
		EndTime:   now,
		Actor:     "admin@example.com",
		Action:    "revoke_certificate",
		Resource:  "cert/123",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ListAuditLogsRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Page, decoded.Page)
	assert.Equal(t, req.PerPage, decoded.PerPage)
	assert.Equal(t, req.Actor, decoded.Actor)
	assert.Equal(t, req.Action, decoded.Action)
	assert.Equal(t, req.Resource, decoded.Resource)
}

func TestErrorTypes(t *testing.T) {
	// Test that error constants are defined and unique
	errors := []error{
		ErrUnauthorized,
		ErrForbidden,
		ErrInvalidAPIKey,
		ErrInsufficientPrivileges,
		ErrInvalidRequest,
		ErrCertificateNotFound,
		ErrAccountNotFound,
		ErrOrderNotFound,
		ErrRevocationFailed,
	}

	// Ensure all errors have messages
	for _, err := range errors {
		assert.NotEmpty(t, err.Error())
	}

	// Ensure errors are distinct
	assert.NotEqual(t, ErrUnauthorized, ErrForbidden)
	assert.NotEqual(t, ErrCertificateNotFound, ErrAccountNotFound)
	assert.NotEqual(t, ErrAccountNotFound, ErrOrderNotFound)
}

func TestConfig_DefaultValues(t *testing.T) {
	config := Config{
		Enabled:    false,
		ListenAddr: "",
		TLSEnabled: false,
	}

	assert.False(t, config.Enabled)
	assert.Empty(t, config.ListenAddr)
	assert.False(t, config.TLSEnabled)
}

func TestCertificateInfo_OptionalFields(t *testing.T) {
	now := time.Now()
	certInfo := CertificateInfo{
		SerialNumber: "123",
		Subject:      "CN=test",
		Issuer:       "CN=CA",
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		Status:       "valid",
		IssuedAt:     now,
		// CertURL is optional
	}

	data, err := json.Marshal(certInfo)
	require.NoError(t, err)

	// Verify CertURL is omitted when empty
	assert.NotContains(t, string(data), "cert_url")
}

func TestAccountInfo_EmptyContact(t *testing.T) {
	accountInfo := AccountInfo{
		ID:                   1,
		Status:               "valid",
		Contact:              []string{}, // Empty contact list
		CreatedAt:            time.Now(),
		TermsOfServiceAgreed: false,
		OrdersURL:            "https://example.com/orders",
		OrderCount:           0,
	}

	data, err := json.Marshal(accountInfo)
	require.NoError(t, err)

	var decoded AccountInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.Contact)
	assert.False(t, decoded.TermsOfServiceAgreed)
	assert.Equal(t, 0, decoded.OrderCount)
}

func TestOrderInfo_EmptyOptionalFields(t *testing.T) {
	orderInfo := OrderInfo{
		ID:          1,
		AccountID:   10,
		Status:      "pending",
		Identifiers: []string{"example.com"},
		CreatedAt:   time.Now(),
		// NotBefore, NotAfter, Expires, Certificate are optional
	}

	data, err := json.Marshal(orderInfo)
	require.NoError(t, err)

	var decoded OrderInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.NotBefore)
	assert.Empty(t, decoded.NotAfter)
	assert.Empty(t, decoded.Expires)
	assert.Empty(t, decoded.Certificate)
}

func TestCAStatus_WithoutIntermediateCA(t *testing.T) {
	caStatus := CAStatus{
		Identity:      "test-ca",
		Initialized:   true,
		Version:       "1.0.0",
		StartedAt:     time.Now(),
		KeyAlgorithm:  "RSA-2048",
		SignatureAlgo: "SHA256-RSA",
		RootCA:        "Test Root CA",
		// IntermediateCA is optional
	}

	data, err := json.Marshal(caStatus)
	require.NoError(t, err)

	var decoded CAStatus
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.IntermediateCA)
}

func TestCAStatus_WithoutKeys(t *testing.T) {
	caStatus := CAStatus{
		Identity:      "test-ca",
		Initialized:   true,
		Version:       "1.0.0",
		StartedAt:     time.Now(),
		KeyAlgorithm:  "ECDSA",
		SignatureAlgo: "ECDSAWithSHA256",
		RootCA:        "Test Root CA",
		// Keys is optional (omitempty)
	}

	data, err := json.Marshal(caStatus)
	require.NoError(t, err)

	// Keys should be omitted from JSON when nil
	assert.NotContains(t, string(data), `"keys"`)

	var decoded CAStatus
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Nil(t, decoded.Keys)
}

func TestKeyInfo_JSONSerialization(t *testing.T) {
	tests := []struct {
		name    string
		key     KeyInfo
		checkFn func(t *testing.T, data []byte, decoded KeyInfo)
	}{
		{
			name: "ECDSA key with curve",
			key: KeyInfo{
				Algorithm:          "ECDSA",
				SignatureAlgorithm: "ECDSAWithSHA256",
				Store:              "software",
				Curve:              "P-256",
				Default:            true,
			},
			checkFn: func(t *testing.T, data []byte, decoded KeyInfo) {
				assert.Equal(t, "ECDSA", decoded.Algorithm)
				assert.Equal(t, "P-256", decoded.Curve)
				assert.Equal(t, 0, decoded.KeySize) // zero omitted
				assert.True(t, decoded.Default)
				assert.NotContains(t, string(data), `"key_size"`)
			},
		},
		{
			name: "RSA key with key size",
			key: KeyInfo{
				Algorithm:          "RSA",
				SignatureAlgorithm: "SHA256-RSAPSS",
				Store:              "tpm2",
				KeySize:            4096,
				Default:            false,
			},
			checkFn: func(t *testing.T, data []byte, decoded KeyInfo) {
				assert.Equal(t, "RSA", decoded.Algorithm)
				assert.Equal(t, 4096, decoded.KeySize)
				assert.Empty(t, decoded.Curve) // zero omitted
				assert.False(t, decoded.Default)
				assert.NotContains(t, string(data), `"curve"`)
			},
		},
		{
			name: "Ed25519 key with no size or curve",
			key: KeyInfo{
				Algorithm:          "Ed25519",
				SignatureAlgorithm: "Ed25519",
				Store:              "software",
				Default:            false,
			},
			checkFn: func(t *testing.T, data []byte, decoded KeyInfo) {
				assert.Equal(t, "Ed25519", decoded.Algorithm)
				assert.Equal(t, 0, decoded.KeySize)
				assert.Empty(t, decoded.Curve)
				assert.NotContains(t, string(data), `"key_size"`)
				assert.NotContains(t, string(data), `"curve"`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.key)
			require.NoError(t, err)

			var decoded KeyInfo
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			tt.checkFn(t, data, decoded)
		})
	}
}

func TestKeyInfoFromKeyConfig_ECDSASoftware(t *testing.T) {
	kc := &xkmssdk.KeyConfig{
		KeyAlgorithm:       "ECDSA",
		SignatureAlgorithm: "ECDSAWithSHA256",
		StoreType:          "software",
		ECCConfig:          &xkmstypes.ECCConfig{Curve: "P-256"},
	}

	ki := KeyInfoFromKeyConfig(kc, true)

	assert.Equal(t, "ECDSA", ki.Algorithm)
	assert.Equal(t, "ECDSAWithSHA256", ki.SignatureAlgorithm)
	assert.Equal(t, "software", ki.Store)
	assert.Equal(t, "P-256", ki.Curve)
	assert.Equal(t, 0, ki.KeySize)
	assert.True(t, ki.Default)
}

func TestKeyInfoFromKeyConfig_RSATPM2(t *testing.T) {
	kc := &xkmssdk.KeyConfig{
		KeyAlgorithm:       "RSA",
		SignatureAlgorithm: "SHA256-RSAPSS",
		StoreType:          "tpm2",
		RSAConfig:          &xkmstypes.RSAConfig{KeySize: 2048},
	}

	ki := KeyInfoFromKeyConfig(kc, false)

	assert.Equal(t, "RSA", ki.Algorithm)
	assert.Equal(t, "SHA256-RSAPSS", ki.SignatureAlgorithm)
	assert.Equal(t, "tpm2", ki.Store)
	assert.Equal(t, 2048, ki.KeySize)
	assert.Empty(t, ki.Curve)
	assert.False(t, ki.Default)
}

func TestKeyInfoFromKeyConfig_Ed25519(t *testing.T) {
	kc := &xkmssdk.KeyConfig{
		KeyAlgorithm:       "Ed25519",
		SignatureAlgorithm: "Ed25519",
		StoreType:          "software",
	}

	ki := KeyInfoFromKeyConfig(kc, false)

	assert.Equal(t, "Ed25519", ki.Algorithm)
	assert.Equal(t, "Ed25519", ki.SignatureAlgorithm)
	assert.Equal(t, "software", ki.Store)
	assert.Equal(t, 0, ki.KeySize)
	assert.Empty(t, ki.Curve)
	assert.False(t, ki.Default)
}

func TestKeyInfoFromKeyConfig_NilSubConfigs(t *testing.T) {
	// KeyConfig with no RSAConfig or ECCConfig (e.g., Ed25519)
	kc := &xkmssdk.KeyConfig{
		KeyAlgorithm:       "Ed25519",
		SignatureAlgorithm: "Ed25519",
		StoreType:          "pkcs11",
		RSAConfig:          nil,
		ECCConfig:          nil,
	}

	ki := KeyInfoFromKeyConfig(kc, true)

	assert.Equal(t, "Ed25519", ki.Algorithm)
	assert.Equal(t, "pkcs11", ki.Store)
	assert.Equal(t, 0, ki.KeySize)
	assert.Empty(t, ki.Curve)
	assert.True(t, ki.Default)
}

func TestTenantRootCAInfo_WithKeys(t *testing.T) {
	now := time.Now()
	info := TenantRootCAInfo{
		CommonName:   "Tenant Root CA",
		SerialNumber: "123456",
		KeyAlgorithm: "ECDSA",
		Keys: []KeyInfo{
			{
				Algorithm:          "ECDSA",
				SignatureAlgorithm: "ECDSAWithSHA256",
				Store:              "software",
				Curve:              "P-256",
				Default:            true,
			},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(10, 0, 0),
		Status:    "active",
		CreatedAt: now,
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var decoded TenantRootCAInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Keys, 1)
	assert.Equal(t, "ECDSA", decoded.Keys[0].Algorithm)
	assert.Equal(t, "P-256", decoded.Keys[0].Curve)
}

func TestTenantIntCAInfo_WithKeys(t *testing.T) {
	now := time.Now()
	info := TenantIntCAInfo{
		ID:           "int-ca-1",
		CommonName:   "Tenant Intermediate CA",
		SerialNumber: "789012",
		ParentType:   "tenant",
		Purpose:      "general",
		KeyAlgorithm: "RSA",
		Keys: []KeyInfo{
			{
				Algorithm:          "RSA",
				SignatureAlgorithm: "SHA256-RSAPSS",
				Store:              "tpm2",
				KeySize:            2048,
				Default:            true,
			},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(5, 0, 0),
		Status:    "active",
		CreatedAt: now,
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var decoded TenantIntCAInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Keys, 1)
	assert.Equal(t, "RSA", decoded.Keys[0].Algorithm)
	assert.Equal(t, 2048, decoded.Keys[0].KeySize)
}

func TestTenantRootCAInfo_WithoutKeys(t *testing.T) {
	now := time.Now()
	info := TenantRootCAInfo{
		CommonName:   "Tenant Root CA",
		KeyAlgorithm: "ECDSA",
		NotBefore:    now,
		NotAfter:     now.AddDate(10, 0, 0),
		Status:       "active",
		CreatedAt:    now,
		// Keys is nil
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	// Keys should be omitted
	assert.NotContains(t, string(data), `"keys"`)
}
