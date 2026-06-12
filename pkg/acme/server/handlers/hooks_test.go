//go:build codec_json

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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOrderFinalizeHookRegistry(t *testing.T) {
	registry := NewOrderFinalizeHookRegistry()
	require.NotNil(t, registry)
	assert.Equal(t, 0, registry.Count())
}

func TestOrderFinalizeHookRegistry_Register(t *testing.T) {
	registry := NewOrderFinalizeHookRegistry()

	// Register a hook
	hook := func(ctx *OrderFinalizeHookContext) error {
		return nil
	}
	registry.Register(hook)

	assert.Equal(t, 1, registry.Count())

	// Register another hook
	registry.Register(hook)
	assert.Equal(t, 2, registry.Count())
}

func TestOrderFinalizeHookRegistry_Execute_Success(t *testing.T) {
	registry := NewOrderFinalizeHookRegistry()

	// Track execution order
	executed := []int{}

	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		executed = append(executed, 1)
		return nil
	})
	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		executed = append(executed, 2)
		return nil
	})
	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		executed = append(executed, 3)
		return nil
	})

	hookCtx := &OrderFinalizeHookContext{
		Context: context.Background(),
		Order:   &entities.ACMEOrder{ID: 1},
	}

	err := registry.Execute(hookCtx)
	require.NoError(t, err)

	// Verify all hooks executed in order
	assert.Equal(t, []int{1, 2, 3}, executed)
}

func TestOrderFinalizeHookRegistry_Execute_Error(t *testing.T) {
	registry := NewOrderFinalizeHookRegistry()

	executed := []int{}
	testErr := errors.New("hook error")

	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		executed = append(executed, 1)
		return nil
	})
	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		executed = append(executed, 2)
		return testErr
	})
	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		executed = append(executed, 3)
		return nil
	})

	hookCtx := &OrderFinalizeHookContext{
		Context: context.Background(),
		Order:   &entities.ACMEOrder{ID: 1},
	}

	err := registry.Execute(hookCtx)
	require.Error(t, err)
	assert.Equal(t, testErr, err)

	// Verify execution stopped at second hook
	assert.Equal(t, []int{1, 2}, executed)
}

func TestOrderFinalizeHookRegistry_Execute_Empty(t *testing.T) {
	registry := NewOrderFinalizeHookRegistry()

	hookCtx := &OrderFinalizeHookContext{
		Context: context.Background(),
		Order:   &entities.ACMEOrder{ID: 1},
	}

	err := registry.Execute(hookCtx)
	require.NoError(t, err)
}

func TestOrderFinalizeHookRegistry_Count(t *testing.T) {
	registry := NewOrderFinalizeHookRegistry()
	assert.Equal(t, 0, registry.Count())

	for i := 0; i < 5; i++ {
		registry.Register(func(ctx *OrderFinalizeHookContext) error { return nil })
		assert.Equal(t, i+1, registry.Count())
	}
}

func TestOrderFinalizeHookContext_Fields(t *testing.T) {
	// Test that all context fields can be populated
	ctx := context.Background()
	order := &entities.ACMEOrder{
		ID:     123,
		Status: "valid",
	}
	cert := &x509.Certificate{
		SerialNumber: nil,
	}
	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	csr := &x509.CertificateRequest{}
	clientIP := "192.168.1.1"

	hookCtx := &OrderFinalizeHookContext{
		Context:        ctx,
		Order:          order,
		Certificate:    cert,
		CertificatePEM: certPEM,
		CSR:            csr,
		ClientIP:       clientIP,
		IsTCGCSR:       false,
		TCGData:        nil,
	}

	assert.Equal(t, ctx, hookCtx.Context)
	assert.Equal(t, order, hookCtx.Order)
	assert.Equal(t, cert, hookCtx.Certificate)
	assert.Equal(t, certPEM, hookCtx.CertificatePEM)
	assert.Equal(t, csr, hookCtx.CSR)
	assert.Equal(t, clientIP, hookCtx.ClientIP)
	assert.False(t, hookCtx.IsTCGCSR)
	assert.Nil(t, hookCtx.TCGData)
}

func TestOrderFinalizeHookContext_WithTCGData(t *testing.T) {
	tcgData := &TCGEnrollmentData{
		ProductModel:         "TestModel",
		ProductSerial:        "ABC123",
		PermanentIdentifier:  "device-001",
		EKCertificate:        &x509.Certificate{},
		IAKCertificateDER:    []byte("iak-cert"),
		IDevIDCertificateDER: []byte("idevid-cert"),
		AttestationPublicKey: []byte("attest-pubkey"),
		SigningPublicKey:     []byte("signing-pubkey"),
		EventLog:             []byte("event-log"),
	}

	hookCtx := &OrderFinalizeHookContext{
		Context:  context.Background(),
		Order:    &entities.ACMEOrder{ID: 1},
		IsTCGCSR: true,
		TCGData:  tcgData,
	}

	assert.True(t, hookCtx.IsTCGCSR)
	require.NotNil(t, hookCtx.TCGData)
	assert.Equal(t, "TestModel", hookCtx.TCGData.ProductModel)
	assert.Equal(t, "ABC123", hookCtx.TCGData.ProductSerial)
	assert.Equal(t, "device-001", hookCtx.TCGData.PermanentIdentifier)
	assert.NotNil(t, hookCtx.TCGData.EKCertificate)
	assert.Equal(t, []byte("iak-cert"), hookCtx.TCGData.IAKCertificateDER)
	assert.Equal(t, []byte("idevid-cert"), hookCtx.TCGData.IDevIDCertificateDER)
	assert.Equal(t, []byte("attest-pubkey"), hookCtx.TCGData.AttestationPublicKey)
	assert.Equal(t, []byte("signing-pubkey"), hookCtx.TCGData.SigningPublicKey)
	assert.Equal(t, []byte("event-log"), hookCtx.TCGData.EventLog)
}

func TestOrderFinalizeHook_CanAccessContextData(t *testing.T) {
	registry := NewOrderFinalizeHookRegistry()

	var capturedOrder *entities.ACMEOrder
	var capturedIP string

	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		capturedOrder = ctx.Order
		capturedIP = ctx.ClientIP
		return nil
	})

	hookCtx := &OrderFinalizeHookContext{
		Context:  context.Background(),
		Order:    &entities.ACMEOrder{ID: 42, Status: "valid"},
		ClientIP: "10.0.0.1",
	}

	err := registry.Execute(hookCtx)
	require.NoError(t, err)

	assert.NotNil(t, capturedOrder)
	assert.Equal(t, uint64(42), capturedOrder.ID)
	assert.Equal(t, "valid", capturedOrder.Status)
	assert.Equal(t, "10.0.0.1", capturedIP)
}

func TestOrderFinalizeHook_MultipleHooksModifyData(t *testing.T) {
	registry := NewOrderFinalizeHookRegistry()

	// Simulate hooks that check/modify shared state
	sharedData := make(map[string]bool)

	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		sharedData["hook1"] = true
		return nil
	})
	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		// Second hook can verify first hook ran
		if !sharedData["hook1"] {
			return errors.New("hook1 should have run first")
		}
		sharedData["hook2"] = true
		return nil
	})

	hookCtx := &OrderFinalizeHookContext{
		Context: context.Background(),
		Order:   &entities.ACMEOrder{ID: 1},
	}

	err := registry.Execute(hookCtx)
	require.NoError(t, err)

	assert.True(t, sharedData["hook1"])
	assert.True(t, sharedData["hook2"])
}

func TestTCGEnrollmentData_AllFields(t *testing.T) {
	// Test that TCGEnrollmentData struct can hold all expected data
	ekCert := &x509.Certificate{}

	data := TCGEnrollmentData{
		ProductModel:         "Model-X",
		ProductSerial:        "SN12345",
		PermanentIdentifier:  "perm-id-abc",
		EKCertificate:        ekCert,
		IAKCertificateDER:    []byte{1, 2, 3},
		IDevIDCertificateDER: []byte{4, 5, 6},
		AttestationPublicKey: []byte{7, 8, 9},
		SigningPublicKey:     []byte{10, 11, 12},
		EventLog:             []byte{13, 14, 15},
		ProdCaData:           []byte{16, 17, 18, 19, 20},
	}

	assert.Equal(t, "Model-X", data.ProductModel)
	assert.Equal(t, "SN12345", data.ProductSerial)
	assert.Equal(t, "perm-id-abc", data.PermanentIdentifier)
	assert.Same(t, ekCert, data.EKCertificate)
	assert.Equal(t, []byte{1, 2, 3}, data.IAKCertificateDER)
	assert.Equal(t, []byte{4, 5, 6}, data.IDevIDCertificateDER)
	assert.Equal(t, []byte{7, 8, 9}, data.AttestationPublicKey)
	assert.Equal(t, []byte{10, 11, 12}, data.SigningPublicKey)
	assert.Equal(t, []byte{13, 14, 15}, data.EventLog)
	assert.Equal(t, []byte{16, 17, 18, 19, 20}, data.ProdCaData)
}

func TestTCGEnrollmentData_WithProdCaData(t *testing.T) {
	// Test ProdCaData field specifically for attestation data transport
	// ProdCaData carries Quote + PCRs from client to server during TCG enrollment

	// Simulate packed ProdCaData structure (version + sizes + payload)
	// Version: 0x00000001, QuotedSz: 4, SignatureSz: 4, NonceSz: 4, PCRsSz: 4
	prodCaData := []byte{
		0x00, 0x00, 0x00, 0x01, // Version = 1
		0x00, 0x00, 0x00, 0x04, // QuotedSz = 4
		0x00, 0x00, 0x00, 0x04, // SignatureSz = 4
		0x00, 0x00, 0x00, 0x04, // NonceSz = 4
		0x00, 0x00, 0x00, 0x04, // PCRsSz = 4
		'Q', 'U', 'O', 'T', // Quoted data
		'S', 'I', 'G', 'N', // Signature
		'N', 'O', 'N', 'C', // Nonce
		'P', 'C', 'R', 'S', // PCRs
	}

	data := TCGEnrollmentData{
		ProductModel:  "TestDevice",
		ProductSerial: "SN001",
		EventLog:      []byte("event-log-data"),
		ProdCaData:    prodCaData,
	}

	assert.NotNil(t, data.ProdCaData)
	assert.Equal(t, 36, len(data.ProdCaData)) // 20 byte header + 16 byte payload
	assert.Equal(t, prodCaData, data.ProdCaData)
}

func TestOrderFinalizeHookContext_WithProdCaData(t *testing.T) {
	// Test that ProdCaData is properly passed through hook context
	prodCaData := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	tcgData := &TCGEnrollmentData{
		ProductModel:  "TestModel",
		ProductSerial: "ABC123",
		EventLog:      []byte("event-log"),
		ProdCaData:    prodCaData,
	}

	hookCtx := &OrderFinalizeHookContext{
		Context:  context.Background(),
		Order:    &entities.ACMEOrder{ID: 1},
		IsTCGCSR: true,
		TCGData:  tcgData,
	}

	assert.True(t, hookCtx.IsTCGCSR)
	require.NotNil(t, hookCtx.TCGData)
	assert.Equal(t, prodCaData, hookCtx.TCGData.ProdCaData)
	assert.Equal(t, 20, len(hookCtx.TCGData.ProdCaData))
}

func TestOrderFinalizeHook_AccessProdCaData(t *testing.T) {
	// Test that hooks can access ProdCaData from context
	registry := NewOrderFinalizeHookRegistry()

	var capturedProdCaData []byte

	registry.Register(func(ctx *OrderFinalizeHookContext) error {
		if ctx.TCGData != nil {
			capturedProdCaData = ctx.TCGData.ProdCaData
		}
		return nil
	})

	prodCaData := []byte{0x00, 0x00, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF}

	hookCtx := &OrderFinalizeHookContext{
		Context:  context.Background(),
		Order:    &entities.ACMEOrder{ID: 42},
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			ProductModel:  "Device",
			ProductSerial: "001",
			ProdCaData:    prodCaData,
		},
	}

	err := registry.Execute(hookCtx)
	require.NoError(t, err)

	assert.Equal(t, prodCaData, capturedProdCaData)
}

// =============================================================================
// Pre-Issuance Hook Tests
// =============================================================================

func TestNewPreIssuanceHookRegistry(t *testing.T) {
	registry := NewPreIssuanceHookRegistry()
	require.NotNil(t, registry)
	assert.Equal(t, 0, registry.Count())
}

func TestPreIssuanceHookRegistry_Register(t *testing.T) {
	registry := NewPreIssuanceHookRegistry()

	// Register a hook
	hook := func(ctx *PreIssuanceHookContext) error {
		return nil
	}
	registry.Register(hook)

	assert.Equal(t, 1, registry.Count())

	// Register another hook
	registry.Register(hook)
	assert.Equal(t, 2, registry.Count())
}

func TestPreIssuanceHookRegistry_Execute_Success(t *testing.T) {
	registry := NewPreIssuanceHookRegistry()

	// Track execution order
	executed := []int{}

	registry.Register(func(ctx *PreIssuanceHookContext) error {
		executed = append(executed, 1)
		return nil
	})
	registry.Register(func(ctx *PreIssuanceHookContext) error {
		executed = append(executed, 2)
		return nil
	})
	registry.Register(func(ctx *PreIssuanceHookContext) error {
		executed = append(executed, 3)
		return nil
	})

	hookCtx := &PreIssuanceHookContext{
		Context: context.Background(),
		Order:   &entities.ACMEOrder{ID: 1},
	}

	err := registry.Execute(hookCtx)
	require.NoError(t, err)

	// Verify all hooks executed in order
	assert.Equal(t, []int{1, 2, 3}, executed)
}

func TestPreIssuanceHookRegistry_Execute_Error(t *testing.T) {
	registry := NewPreIssuanceHookRegistry()

	executed := []int{}
	testErr := errors.New("pre-issuance hook error")

	registry.Register(func(ctx *PreIssuanceHookContext) error {
		executed = append(executed, 1)
		return nil
	})
	registry.Register(func(ctx *PreIssuanceHookContext) error {
		executed = append(executed, 2)
		return testErr
	})
	registry.Register(func(ctx *PreIssuanceHookContext) error {
		executed = append(executed, 3)
		return nil
	})

	hookCtx := &PreIssuanceHookContext{
		Context: context.Background(),
		Order:   &entities.ACMEOrder{ID: 1},
	}

	err := registry.Execute(hookCtx)
	require.Error(t, err)
	assert.Equal(t, testErr, err)

	// Verify execution stopped at second hook (short-circuit on error)
	assert.Equal(t, []int{1, 2}, executed)
}

func TestPreIssuanceHookRegistry_Execute_Empty(t *testing.T) {
	registry := NewPreIssuanceHookRegistry()

	hookCtx := &PreIssuanceHookContext{
		Context: context.Background(),
		Order:   &entities.ACMEOrder{ID: 1},
	}

	err := registry.Execute(hookCtx)
	require.NoError(t, err)
}

func TestPreIssuanceHookContext_Fields(t *testing.T) {
	// Test that all context fields can be populated
	ctx := context.Background()
	order := &entities.ACMEOrder{
		ID:     123,
		Status: "processing",
	}
	csr := &x509.CertificateRequest{}
	clientIP := "192.168.1.1"

	complianceConfig := &ComplianceConfig{
		Enabled:          true,
		CustomPolicyPath: "/etc/compliance/policy.rego",
	}

	hookCtx := &PreIssuanceHookContext{
		Context:          ctx,
		Order:            order,
		CSR:              csr,
		ClientIP:         clientIP,
		IsTCGCSR:         false,
		TCGData:          nil,
		ComplianceConfig: complianceConfig,
	}

	assert.Equal(t, ctx, hookCtx.Context)
	assert.Equal(t, order, hookCtx.Order)
	assert.Equal(t, csr, hookCtx.CSR)
	assert.Equal(t, clientIP, hookCtx.ClientIP)
	assert.False(t, hookCtx.IsTCGCSR)
	assert.Nil(t, hookCtx.TCGData)
	assert.NotNil(t, hookCtx.ComplianceConfig)
	assert.True(t, hookCtx.ComplianceConfig.Enabled)
	assert.Equal(t, "/etc/compliance/policy.rego", hookCtx.ComplianceConfig.CustomPolicyPath)
}

func TestPreIssuanceHookContext_WithTCGData(t *testing.T) {
	tcgData := &TCGEnrollmentData{
		ProductModel:         "TestModel",
		ProductSerial:        "ABC123",
		PermanentIdentifier:  "device-001",
		EKCertificate:        &x509.Certificate{},
		AttestationPublicKey: []byte("attest-pubkey"),
		SigningPublicKey:     []byte("signing-pubkey"),
		EventLog:             []byte("event-log"),
		ProdCaData:           []byte("prod-ca-data"),
	}

	hookCtx := &PreIssuanceHookContext{
		Context:  context.Background(),
		Order:    &entities.ACMEOrder{ID: 1},
		IsTCGCSR: true,
		TCGData:  tcgData,
	}

	assert.True(t, hookCtx.IsTCGCSR)
	require.NotNil(t, hookCtx.TCGData)
	assert.Equal(t, "TestModel", hookCtx.TCGData.ProductModel)
	assert.Equal(t, "ABC123", hookCtx.TCGData.ProductSerial)
	assert.Equal(t, "device-001", hookCtx.TCGData.PermanentIdentifier)
	assert.NotNil(t, hookCtx.TCGData.EKCertificate)
	assert.Equal(t, []byte("attest-pubkey"), hookCtx.TCGData.AttestationPublicKey)
	assert.Equal(t, []byte("signing-pubkey"), hookCtx.TCGData.SigningPublicKey)
	assert.Equal(t, []byte("event-log"), hookCtx.TCGData.EventLog)
	assert.Equal(t, []byte("prod-ca-data"), hookCtx.TCGData.ProdCaData)
}

func TestPreIssuanceHookContext_WithComplianceData(t *testing.T) {
	complianceData := &ComplianceData{
		ScanType:     "trivy",
		Report:       []byte(`{"Results": []}`),
		Signature:    []byte("signature"),
		SignatureAlg: "ECDSA-P256-SHA256",
	}

	hookCtx := &PreIssuanceHookContext{
		Context:        context.Background(),
		Order:          &entities.ACMEOrder{ID: 1},
		IsTCGCSR:       true,
		ComplianceData: complianceData,
	}

	require.NotNil(t, hookCtx.ComplianceData)
	assert.Equal(t, "trivy", hookCtx.ComplianceData.ScanType)
	assert.Equal(t, json.RawMessage(`{"Results": []}`), hookCtx.ComplianceData.Report)
	assert.Equal(t, []byte("signature"), hookCtx.ComplianceData.Signature)
	assert.Equal(t, "ECDSA-P256-SHA256", hookCtx.ComplianceData.SignatureAlg)
}

func TestResolveComplianceConfig_NilGlobal(t *testing.T) {
	result := entities.ResolveComplianceConfig(nil, nil)
	assert.Nil(t, result)
}

func TestResolveComplianceConfig_GlobalEnforce(t *testing.T) {
	global := &entities.GlobalComplianceConfig{
		ComplianceConfig: entities.ComplianceConfig{
			Enabled:          true,
			CustomPolicyPath: "/etc/global/policy.rego",
		},
		Enforce: true,
	}

	tenant := &entities.TenantSettings{
		ComplianceConfig: &entities.ComplianceConfig{
			Enabled: false, // Tenant disables compliance
		},
	}

	// With enforce=true, global config should be used even though tenant has config
	result := entities.ResolveComplianceConfig(global, tenant)
	require.NotNil(t, result)
	assert.True(t, result.Enabled) // Global's enabled=true should win
	assert.Equal(t, "/etc/global/policy.rego", result.CustomPolicyPath)
}

func TestResolveComplianceConfig_TenantOverride(t *testing.T) {
	global := &entities.GlobalComplianceConfig{
		ComplianceConfig: entities.ComplianceConfig{
			Enabled:          true,
			CustomPolicyPath: "/etc/global/policy.rego",
		},
		Enforce: false, // Allow tenant override
	}

	tenant := &entities.TenantSettings{
		ComplianceConfig: &entities.ComplianceConfig{
			Enabled:          true,
			CustomPolicyPath: "/etc/tenant/policy.rego",
		},
	}

	// With enforce=false, tenant config should be used
	result := entities.ResolveComplianceConfig(global, tenant)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, "/etc/tenant/policy.rego", result.CustomPolicyPath) // Tenant's config
}

func TestResolveComplianceConfig_GlobalFallback(t *testing.T) {
	global := &entities.GlobalComplianceConfig{
		ComplianceConfig: entities.ComplianceConfig{
			Enabled:          true,
			CustomPolicyPath: "/etc/fallback/policy.rego",
		},
		Enforce: false,
	}

	// Tenant has no compliance config - should fall back to global
	tenant := &entities.TenantSettings{}

	result := entities.ResolveComplianceConfig(global, tenant)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
	assert.Equal(t, "/etc/fallback/policy.rego", result.CustomPolicyPath) // Global fallback
}

func TestResolveComplianceConfig_NilTenant(t *testing.T) {
	global := &entities.GlobalComplianceConfig{
		ComplianceConfig: entities.ComplianceConfig{
			Enabled: true,
		},
		Enforce: false,
	}

	// Nil tenant settings - should fall back to global
	result := entities.ResolveComplianceConfig(global, nil)
	require.NotNil(t, result)
	assert.True(t, result.Enabled)
}

// =============================================================================
// Pre-Sign Extension Hook Tests
// =============================================================================

func TestNewOrderPreSignHookRegistry(t *testing.T) {
	registry := NewOrderPreSignHookRegistry()
	require.NotNil(t, registry)
	assert.Equal(t, 0, registry.Count())
}

func TestOrderPreSignHookRegistry_Register(t *testing.T) {
	registry := NewOrderPreSignHookRegistry()

	hook := func(ctx *OrderPreSignHookContext) ([]pkix.Extension, error) {
		return nil, nil
	}
	registry.Register(hook)
	assert.Equal(t, 1, registry.Count())

	registry.Register(hook)
	assert.Equal(t, 2, registry.Count())
}

func TestOrderPreSignHookRegistry_Execute_ReturnsExtensions(t *testing.T) {
	registry := NewOrderPreSignHookRegistry()

	ext1 := pkix.Extension{Id: []int{1, 3, 6, 1, 4, 1, 29377, 101, 21}, Value: []byte("zone-a")}
	ext2 := pkix.Extension{Id: []int{1, 3, 6, 1, 4, 1, 29377, 101, 22}, Value: []byte("zone-b")}

	registry.Register(func(ctx *OrderPreSignHookContext) ([]pkix.Extension, error) {
		return []pkix.Extension{ext1}, nil
	})
	registry.Register(func(ctx *OrderPreSignHookContext) ([]pkix.Extension, error) {
		return []pkix.Extension{ext2}, nil
	})

	hookCtx := &OrderPreSignHookContext{
		Context:  context.Background(),
		Order:    &entities.ACMEOrder{ID: 1},
		IsTCGCSR: false,
	}

	exts, err := registry.Execute(hookCtx)
	require.NoError(t, err)
	require.Len(t, exts, 2)
	assert.Equal(t, ext1, exts[0])
	assert.Equal(t, ext2, exts[1])
}

func TestOrderPreSignHookRegistry_Execute_NoHooks(t *testing.T) {
	registry := NewOrderPreSignHookRegistry()

	hookCtx := &OrderPreSignHookContext{
		Context: context.Background(),
		Order:   &entities.ACMEOrder{ID: 1},
	}

	exts, err := registry.Execute(hookCtx)
	require.NoError(t, err)
	assert.Empty(t, exts)
}

func TestOrderPreSignHookRegistry_Execute_HookReturnsNilSlice(t *testing.T) {
	registry := NewOrderPreSignHookRegistry()

	registry.Register(func(ctx *OrderPreSignHookContext) ([]pkix.Extension, error) {
		return nil, nil
	})

	hookCtx := &OrderPreSignHookContext{
		Context: context.Background(),
		Order:   &entities.ACMEOrder{ID: 1},
	}

	exts, err := registry.Execute(hookCtx)
	require.NoError(t, err)
	assert.Empty(t, exts)
}

func TestOrderPreSignHookRegistry_Execute_ErrorAborts(t *testing.T) {
	registry := NewOrderPreSignHookRegistry()

	executed := []int{}
	hookErr := errors.New("zone resolution failed")

	registry.Register(func(ctx *OrderPreSignHookContext) ([]pkix.Extension, error) {
		executed = append(executed, 1)
		return nil, nil
	})
	registry.Register(func(ctx *OrderPreSignHookContext) ([]pkix.Extension, error) {
		executed = append(executed, 2)
		return nil, hookErr
	})
	registry.Register(func(ctx *OrderPreSignHookContext) ([]pkix.Extension, error) {
		executed = append(executed, 3)
		return nil, nil
	})

	hookCtx := &OrderPreSignHookContext{
		Context: context.Background(),
		Order:   &entities.ACMEOrder{ID: 1},
	}

	exts, err := registry.Execute(hookCtx)
	require.Error(t, err)
	assert.Nil(t, exts)
	assert.Equal(t, []int{1, 2}, executed)

	var preSignErr ErrPreSignHookFailed
	require.ErrorAs(t, err, &preSignErr)
	assert.Equal(t, hookErr, preSignErr.Cause)
}

func TestErrPreSignHookFailed_Error(t *testing.T) {
	cause := errors.New("root cause")
	e := ErrPreSignHookFailed{Cause: cause}
	assert.Contains(t, e.Error(), "pre-sign hook failed")
	assert.Contains(t, e.Error(), "root cause")
	assert.Equal(t, cause, e.Unwrap())
}

func TestOrderPreSignHookContext_CSRPath(t *testing.T) {
	csr := &x509.CertificateRequest{}
	hookCtx := &OrderPreSignHookContext{
		Context:  context.Background(),
		Order:    &entities.ACMEOrder{ID: 42},
		CSR:      csr,
		ClientIP: "10.0.0.1",
		IsTCGCSR: false,
	}

	assert.Equal(t, uint64(42), hookCtx.Order.ID)
	assert.Same(t, csr, hookCtx.CSR)
	assert.Equal(t, "10.0.0.1", hookCtx.ClientIP)
	assert.False(t, hookCtx.IsTCGCSR)
	assert.Nil(t, hookCtx.TCGData)
}

func TestOrderPreSignHookContext_TCGPath(t *testing.T) {
	tcgData := &TCGEnrollmentData{
		ProductModel:        "XYZ-4000",
		ProductSerial:       "SN-9999",
		PermanentIdentifier: "XYZ-4000-SN-9999",
	}

	hookCtx := &OrderPreSignHookContext{
		Context:  context.Background(),
		Order:    &entities.ACMEOrder{ID: 7},
		ClientIP: "192.168.0.5",
		IsTCGCSR: true,
		TCGData:  tcgData,
	}

	assert.True(t, hookCtx.IsTCGCSR)
	assert.Nil(t, hookCtx.CSR)
	require.NotNil(t, hookCtx.TCGData)
	assert.Equal(t, "XYZ-4000", hookCtx.TCGData.ProductModel)
	assert.Equal(t, "SN-9999", hookCtx.TCGData.ProductSerial)
}
