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
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock DNS service
type mockDNSService struct {
	registerFunc func(fqdn, ip string) error
	registered   map[string]string
}

func newMockDNSService() *mockDNSService {
	return &mockDNSService{
		registered: make(map[string]string),
	}
}

func (m *mockDNSService) Register(fqdn, ip string) error {
	if m.registerFunc != nil {
		return m.registerFunc(fqdn, ip)
	}
	m.registered[fqdn] = ip
	return nil
}

// Mock device service
type mockDeviceService struct {
	saveFunc func(device interface{}) error
	devices  []interface{}
}

func newMockDeviceService() *mockDeviceService {
	return &mockDeviceService{
		devices: make([]interface{}, 0),
	}
}

func (m *mockDeviceService) SaveDevice(device interface{}) error {
	if m.saveFunc != nil {
		return m.saveFunc(device)
	}
	m.devices = append(m.devices, device)
	return nil
}

// Mock notifier
type mockNotifier struct {
	sendFunc func(message string) error
	messages []string
}

func newMockNotifier() *mockNotifier {
	return &mockNotifier{
		messages: make([]string, 0),
	}
}

func (m *mockNotifier) Send(message string) error {
	if m.sendFunc != nil {
		return m.sendFunc(message)
	}
	m.messages = append(m.messages, message)
	return nil
}

// Mock audit logger
type mockAuditLogger struct {
	logFunc func(data map[string]interface{}) error
	logs    []map[string]interface{}
}

func newMockAuditLogger() *mockAuditLogger {
	return &mockAuditLogger{
		logs: make([]map[string]interface{}, 0),
	}
}

func (m *mockAuditLogger) LogCertificateIssuance(data map[string]interface{}) error {
	if m.logFunc != nil {
		return m.logFunc(data)
	}
	m.logs = append(m.logs, data)
	return nil
}

// Helper function to create test x509 certificate for hooks testing
func createHookTestX509Certificate(cn string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: cn,
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
}

// Helper function to create test hook context
func createTestHookContext(isTCG bool) *OrderFinalizeHookContext {
	now := time.Now()
	// Create certificate with 90 days validity (well under 1 year limit)
	validUntil := now.Add(90 * 24 * time.Hour)

	ctx := &OrderFinalizeHookContext{
		Context:        context.Background(),
		Certificate:    createHookTestX509Certificate("test.example.com", now, validUntil),
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		CSR:            &x509.CertificateRequest{},
		ClientIP:       "192.168.1.100",
		IsTCGCSR:       isTCG,
		Order: &entities.ACMEOrder{
			ID:     12345,
			Status: "valid",
		},
	}

	if isTCG {
		ctx.TCGData = &TCGEnrollmentData{
			ProductModel:        "ACME-TPM-Device",
			ProductSerial:       "SN123456789",
			PermanentIdentifier: "perm-id-123",
			EKCertificate:       createHookTestX509Certificate("EK", now, validUntil),
			EventLog:            make([]byte, 200), // Larger than minimum required
		}
	}

	return ctx
}

func TestExampleDNSRegistrationHook_TCGEnrollment(t *testing.T) {
	dnsService := newMockDNSService()
	hook := ExampleDNSRegistrationHook(dnsService, "internal.example.com")

	ctx := createTestHookContext(true)
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, dnsService.registered, 1)

	expectedFQDN := "ACME-TPM-Device-SN123456789.internal.example.com"
	assert.Equal(t, "192.168.1.100", dnsService.registered[expectedFQDN])
}

func TestExampleDNSRegistrationHook_TCGEnrollment_Error(t *testing.T) {
	expectedErr := errors.New("DNS registration failed")
	dnsService := newMockDNSService()
	dnsService.registerFunc = func(fqdn, ip string) error {
		return expectedErr
	}

	hook := ExampleDNSRegistrationHook(dnsService, "internal.example.com")

	ctx := createTestHookContext(true)
	err := hook(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to register DNS record")
	assert.Contains(t, err.Error(), expectedErr.Error())
}

func TestExampleDNSRegistrationHook_NonTCGEnrollment(t *testing.T) {
	dnsService := newMockDNSService()
	hook := ExampleDNSRegistrationHook(dnsService, "internal.example.com")

	ctx := createTestHookContext(false)
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, dnsService.registered, 0, "Should not register DNS for non-TCG enrollments")
}

func TestExampleDNSRegistrationHook_NoTCGData(t *testing.T) {
	dnsService := newMockDNSService()
	hook := ExampleDNSRegistrationHook(dnsService, "internal.example.com")

	ctx := createTestHookContext(true)
	ctx.TCGData = nil
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, dnsService.registered, 0, "Should not register DNS when TCGData is nil")
}

func TestExampleDeviceInventoryHook_TCGEnrollment(t *testing.T) {
	deviceService := newMockDeviceService()
	hook := ExampleDeviceInventoryHook(deviceService)

	ctx := createTestHookContext(true)
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, deviceService.devices, 1)

	device := deviceService.devices[0].(map[string]interface{})
	assert.Equal(t, uint64(12345), device["id"])
	assert.Equal(t, "ACME-TPM-Device", device["model"])
	assert.Equal(t, "SN123456789", device["serial"])
	assert.Equal(t, "perm-id-123", device["permanent_id"])
	assert.Equal(t, ctx.TCGData.EKCertificate, device["ek_cert"])
	assert.Equal(t, ctx.TCGData.EventLog, device["event_log"])
	assert.Equal(t, ctx.Certificate.NotBefore, device["enrolled_at"])
	assert.Equal(t, "192.168.1.100", device["client_ip"])
}

func TestExampleDeviceInventoryHook_TCGEnrollment_Error(t *testing.T) {
	expectedErr := errors.New("database save failed")
	deviceService := newMockDeviceService()
	deviceService.saveFunc = func(device interface{}) error {
		return expectedErr
	}

	hook := ExampleDeviceInventoryHook(deviceService)

	ctx := createTestHookContext(true)
	err := hook(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save device to inventory")
	assert.Contains(t, err.Error(), expectedErr.Error())
}

func TestExampleDeviceInventoryHook_NonTCGEnrollment(t *testing.T) {
	deviceService := newMockDeviceService()
	hook := ExampleDeviceInventoryHook(deviceService)

	ctx := createTestHookContext(false)
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, deviceService.devices, 0, "Should not save device for non-TCG enrollments")
}

func TestExampleDeviceInventoryHook_NoTCGData(t *testing.T) {
	deviceService := newMockDeviceService()
	hook := ExampleDeviceInventoryHook(deviceService)

	ctx := createTestHookContext(true)
	ctx.TCGData = nil
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, deviceService.devices, 0, "Should not save device when TCGData is nil")
}

func TestExampleNotificationHook_TCGEnrollment(t *testing.T) {
	notifier := newMockNotifier()
	hook := ExampleNotificationHook(notifier)

	ctx := createTestHookContext(true)
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, notifier.messages, 1)

	expectedMessage := "TPM device enrolled: ACME-TPM-Device-SN123456789 (Serial: 12345)"
	assert.Equal(t, expectedMessage, notifier.messages[0])
}

func TestExampleNotificationHook_NonTCGEnrollment(t *testing.T) {
	notifier := newMockNotifier()
	hook := ExampleNotificationHook(notifier)

	ctx := createTestHookContext(false)
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, notifier.messages, 1)

	expectedMessage := "Certificate issued: test.example.com (Serial: 12345)"
	assert.Equal(t, expectedMessage, notifier.messages[0])
}

func TestExampleNotificationHook_Error_DoesNotFail(t *testing.T) {
	expectedErr := errors.New("notification service down")
	notifier := newMockNotifier()
	notifier.sendFunc = func(message string) error {
		return expectedErr
	}

	hook := ExampleNotificationHook(notifier)

	ctx := createTestHookContext(true)
	err := hook(ctx)

	// Hook should not fail even if notification fails
	require.NoError(t, err)
}

func TestExampleNotificationHook_NoTCGData(t *testing.T) {
	notifier := newMockNotifier()
	hook := ExampleNotificationHook(notifier)

	ctx := createTestHookContext(true)
	ctx.TCGData = nil
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, notifier.messages, 1)

	// Should fall back to standard certificate message
	expectedMessage := "Certificate issued: test.example.com (Serial: 12345)"
	assert.Equal(t, expectedMessage, notifier.messages[0])
}

func TestExamplePolicyEnforcementHook_ValidTCGEnrollment(t *testing.T) {
	hook := ExamplePolicyEnforcementHook()

	ctx := createTestHookContext(true)
	err := hook(ctx)

	require.NoError(t, err, "Valid TCG enrollment should pass policy checks")
}

func TestExamplePolicyEnforcementHook_EventLogTooSmall(t *testing.T) {
	hook := ExamplePolicyEnforcementHook()

	ctx := createTestHookContext(true)
	ctx.TCGData.EventLog = make([]byte, 50) // Less than minimum 100
	err := hook(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy violation: event log too small")
}

func TestExamplePolicyEnforcementHook_InvalidProductModelPrefix(t *testing.T) {
	hook := ExamplePolicyEnforcementHook()

	ctx := createTestHookContext(true)
	ctx.TCGData.ProductModel = "WRONG-PREFIX-Device"
	err := hook(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy violation: invalid product model prefix")
}

func TestExamplePolicyEnforcementHook_ProductModelTooShort(t *testing.T) {
	hook := ExamplePolicyEnforcementHook()

	ctx := createTestHookContext(true)
	ctx.TCGData.ProductModel = "ACM" // Shorter than "ACME-" prefix
	err := hook(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy violation: invalid product model prefix")
}

func TestExamplePolicyEnforcementHook_CertificateValidityTooLong(t *testing.T) {
	hook := ExamplePolicyEnforcementHook()

	ctx := createTestHookContext(false)
	// Create certificate with validity > 1 year (8760 hours)
	now := time.Now()
	ctx.Certificate = createHookTestX509Certificate(
		"test.example.com",
		now,
		now.Add(400*24*time.Hour), // ~13 months
	)

	err := hook(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy violation: certificate validity exceeds 1 year")
}

func TestExamplePolicyEnforcementHook_NonTCGEnrollment(t *testing.T) {
	hook := ExamplePolicyEnforcementHook()

	ctx := createTestHookContext(false)
	err := hook(ctx)

	require.NoError(t, err, "Non-TCG enrollment with valid cert should pass")
}

func TestExamplePolicyEnforcementHook_NoTCGData(t *testing.T) {
	hook := ExamplePolicyEnforcementHook()

	ctx := createTestHookContext(true)
	ctx.TCGData = nil
	err := hook(ctx)

	require.NoError(t, err, "Should not enforce TCG policies when TCGData is nil")
}

func TestExampleLoggingHook_TCGEnrollment(t *testing.T) {
	auditLogger := newMockAuditLogger()
	hook := ExampleLoggingHook(auditLogger)

	ctx := createTestHookContext(true)
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, auditLogger.logs, 1)

	logData := auditLogger.logs[0]
	assert.Equal(t, ctx.Certificate.NotBefore, logData["timestamp"])
	assert.Equal(t, "12345", logData["serial_number"])
	assert.Equal(t, "test.example.com", logData["subject_cn"])
	assert.Equal(t, "Test CA", logData["issuer_cn"])
	assert.Equal(t, "192.168.1.100", logData["client_ip"])
	assert.Equal(t, true, logData["is_tcg_csr"])
	assert.Equal(t, "ACME-TPM-Device", logData["product_model"])
	assert.Equal(t, "SN123456789", logData["product_serial"])
	assert.Equal(t, "perm-id-123", logData["permanent_id"])
	assert.Equal(t, uint64(12345), logData["order_id"])
	assert.Equal(t, "valid", logData["order_status"])
}

func TestExampleLoggingHook_NonTCGEnrollment(t *testing.T) {
	auditLogger := newMockAuditLogger()
	hook := ExampleLoggingHook(auditLogger)

	ctx := createTestHookContext(false)
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, auditLogger.logs, 1)

	logData := auditLogger.logs[0]
	assert.Equal(t, ctx.Certificate.NotBefore, logData["timestamp"])
	assert.Equal(t, "12345", logData["serial_number"])
	assert.Equal(t, "test.example.com", logData["subject_cn"])
	assert.Equal(t, "Test CA", logData["issuer_cn"])
	assert.Equal(t, "192.168.1.100", logData["client_ip"])
	assert.Equal(t, false, logData["is_tcg_csr"])
	assert.Nil(t, logData["product_model"], "Should not have TCG data for non-TCG enrollment")
	assert.Equal(t, uint64(12345), logData["order_id"])
	assert.Equal(t, "valid", logData["order_status"])
}

func TestExampleLoggingHook_Error_DoesNotFail(t *testing.T) {
	expectedErr := errors.New("audit log write failed")
	auditLogger := newMockAuditLogger()
	auditLogger.logFunc = func(data map[string]interface{}) error {
		return expectedErr
	}

	hook := ExampleLoggingHook(auditLogger)

	ctx := createTestHookContext(true)
	err := hook(ctx)

	// Hook should not fail even if audit logging fails
	require.NoError(t, err)
}

func TestExampleLoggingHook_NoTCGData(t *testing.T) {
	auditLogger := newMockAuditLogger()
	hook := ExampleLoggingHook(auditLogger)

	ctx := createTestHookContext(true)
	ctx.TCGData = nil
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, auditLogger.logs, 1)

	logData := auditLogger.logs[0]
	assert.Nil(t, logData["product_model"], "Should not have TCG data when TCGData is nil")
	assert.Nil(t, logData["product_serial"], "Should not have TCG data when TCGData is nil")
}

func TestExampleLoggingHook_NoOrder(t *testing.T) {
	auditLogger := newMockAuditLogger()
	hook := ExampleLoggingHook(auditLogger)

	ctx := createTestHookContext(false)
	ctx.Order = nil
	err := hook(ctx)

	require.NoError(t, err)
	assert.Len(t, auditLogger.logs, 1)

	logData := auditLogger.logs[0]
	assert.Nil(t, logData["order_id"], "Should not have order data when Order is nil")
	assert.Nil(t, logData["order_status"], "Should not have order data when Order is nil")
}

// Integration test that demonstrates using multiple hooks together
func TestMultipleHooksIntegration(t *testing.T) {
	// Create mock services
	dnsService := newMockDNSService()
	deviceService := newMockDeviceService()
	notifier := newMockNotifier()
	auditLogger := newMockAuditLogger()

	// Create hook registry
	registry := NewOrderFinalizeHookRegistry()
	registry.Register(ExampleDNSRegistrationHook(dnsService, "internal.example.com"))
	registry.Register(ExampleDeviceInventoryHook(deviceService))
	registry.Register(ExampleNotificationHook(notifier))
	registry.Register(ExamplePolicyEnforcementHook())
	registry.Register(ExampleLoggingHook(auditLogger))

	// Create test context
	ctx := createTestHookContext(true)

	// Execute all hooks
	err := registry.Execute(ctx)

	// Verify all hooks executed successfully
	require.NoError(t, err)
	assert.Len(t, dnsService.registered, 1, "DNS hook should have registered")
	assert.Len(t, deviceService.devices, 1, "Device inventory hook should have saved device")
	assert.Len(t, notifier.messages, 1, "Notification hook should have sent message")
	assert.Len(t, auditLogger.logs, 1, "Logging hook should have logged")
}

// Test that hook execution stops on first error
func TestMultipleHooks_StopsOnError(t *testing.T) {
	// Create services where device service will fail
	dnsService := newMockDNSService()
	deviceService := newMockDeviceService()
	deviceService.saveFunc = func(device interface{}) error {
		return errors.New("database error")
	}
	notifier := newMockNotifier()

	// Create hook registry in order: DNS, Device (fails), Notification
	registry := NewOrderFinalizeHookRegistry()
	registry.Register(ExampleDNSRegistrationHook(dnsService, "internal.example.com"))
	registry.Register(ExampleDeviceInventoryHook(deviceService))
	registry.Register(ExampleNotificationHook(notifier))

	ctx := createTestHookContext(true)
	err := registry.Execute(ctx)

	// Verify execution stopped at failing hook
	require.Error(t, err)
	assert.Len(t, dnsService.registered, 1, "First hook should have executed")
	assert.Len(t, notifier.messages, 0, "Subsequent hooks should not execute after error")
}
