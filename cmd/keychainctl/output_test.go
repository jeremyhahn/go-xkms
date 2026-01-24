// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestNewPrinter(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	if printer == nil {
		t.Fatal("expected non-nil printer")
	}

	if printer.format != OutputFormatJSON {
		t.Errorf("expected format %s, got %s", OutputFormatJSON, printer.format)
	}
}

func TestPrintBackendList_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	backends := []string{"memory", "tpm2", "pkcs11"}
	err := printer.PrintBackendList(backends)
	if err != nil {
		t.Fatalf("PrintBackendList failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	backendsList, ok := result["backends"].([]interface{})
	if !ok {
		t.Fatal("expected backends array")
	}

	if len(backendsList) != 3 {
		t.Errorf("expected 3 backends, got %d", len(backendsList))
	}
}

func TestPrintBackendList_Text(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	backends := []string{"memory", "tpm2"}
	err := printer.PrintBackendList(backends)
	if err != nil {
		t.Fatalf("PrintBackendList failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "memory") {
		t.Error("expected output to contain 'memory'")
	}
	if !strings.Contains(output, "tpm2") {
		t.Error("expected output to contain 'tpm2'")
	}
}

func TestPrintBackendList_Table(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	backends := []string{"memory"}
	err := printer.PrintBackendList(backends)
	if err != nil {
		t.Fatalf("PrintBackendList failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Available Backends") {
		t.Error("expected output to contain 'Available Backends'")
	}
}

func TestPrintBackendList_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("unknown", buf)

	err := printer.PrintBackendList([]string{"test"})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestPrintBackendInfo_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	caps := types.Capabilities{
		Keys:           true,
		HardwareBacked: true,
		Signing:        true,
		Decryption:     true,
		KeyRotation:    false,
	}

	err := printer.PrintBackendInfo("tpm2", caps)
	if err != nil {
		t.Fatalf("PrintBackendInfo failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["backend"] != "tpm2" {
		t.Errorf("expected backend 'tpm2', got %v", result["backend"])
	}
}

func TestPrintBackendInfo_Text(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	caps := types.Capabilities{
		Keys:           true,
		HardwareBacked: true,
	}

	err := printer.PrintBackendInfo("memory", caps)
	if err != nil {
		t.Fatalf("PrintBackendInfo failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Backend: memory") {
		t.Error("expected output to contain 'Backend: memory'")
	}
	if !strings.Contains(output, "Capabilities") {
		t.Error("expected output to contain 'Capabilities'")
	}
}

func TestPrintKeyList_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	keys := []*types.KeyAttributes{
		{CN: "key1", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.RSA, StoreType: types.StoreSoftware},
		{CN: "key2", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.ECDSA, StoreType: types.StoreTPM2},
	}

	err := printer.PrintKeyList(keys)
	if err != nil {
		t.Fatalf("PrintKeyList failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	keysList, ok := result["keys"].([]interface{})
	if !ok {
		t.Fatal("expected keys array")
	}

	if len(keysList) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keysList))
	}
}

func TestPrintKeyList_Table_Empty(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	err := printer.PrintKeyList([]*types.KeyAttributes{})
	if err != nil {
		t.Fatalf("PrintKeyList failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No keys found") {
		t.Error("expected 'No keys found' message")
	}
}

func TestPrintKeyList_Table_WithKeys(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	keys := []*types.KeyAttributes{
		{CN: "test-key", KeyType: types.KeyTypeSigning, KeyAlgorithm: x509.RSA, StoreType: types.StoreSoftware},
	}

	err := printer.PrintKeyList(keys)
	if err != nil {
		t.Fatalf("PrintKeyList failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "CN") {
		t.Error("expected table header")
	}
	if !strings.Contains(output, "test-key") {
		t.Error("expected key name in output")
	}
}

func TestPrintKeyList_Text(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	keys := []*types.KeyAttributes{
		{CN: "my-key", KeyAlgorithm: x509.ECDSA, KeyType: types.KeyTypeSigning},
	}

	err := printer.PrintKeyList(keys)
	if err != nil {
		t.Fatalf("PrintKeyList failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Keys:") {
		t.Error("expected 'Keys:' header")
	}
	if !strings.Contains(output, "my-key") {
		t.Error("expected key name in output")
	}
}

func TestPrintKeyInfo_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	key := &types.KeyAttributes{
		CN:           "test-key",
		KeyType:      types.KeyTypeSigning,
		KeyAlgorithm: x509.RSA,
		StoreType:    types.StoreSoftware,
		Hash:         crypto.SHA256,
		Partition:    "default",
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	err := printer.PrintKeyInfo(key)
	if err != nil {
		t.Fatalf("PrintKeyInfo failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["cn"] != "test-key" {
		t.Errorf("expected cn 'test-key', got %v", result["cn"])
	}
	if result["partition"] != "default" {
		t.Errorf("expected partition 'default', got %v", result["partition"])
	}
}

func TestPrintKeyInfo_Text_WithECC(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	key := &types.KeyAttributes{
		CN:           "ecc-key",
		KeyType:      types.KeyTypeSigning,
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.StoreSoftware,
		Hash:         crypto.SHA256,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	err := printer.PrintKeyInfo(key)
	if err != nil {
		t.Fatalf("PrintKeyInfo failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ECC Curve") {
		t.Error("expected ECC Curve in output")
	}
	if !strings.Contains(output, "P-256") {
		t.Error("expected P-256 curve in output")
	}
}

func TestPrintSuccess_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	err := printer.PrintSuccess("Operation completed")
	if err != nil {
		t.Fatalf("PrintSuccess failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["status"] != "success" {
		t.Errorf("expected status 'success', got %v", result["status"])
	}
	if result["message"] != "Operation completed" {
		t.Errorf("expected message 'Operation completed', got %v", result["message"])
	}
}

func TestPrintSuccess_Text(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	err := printer.PrintSuccess("Done!")
	if err != nil {
		t.Fatalf("PrintSuccess failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Done!") {
		t.Error("expected 'Done!' in output")
	}
}

func TestPrintError_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	err := printer.PrintError(errors.New("something went wrong"))
	if err != nil {
		t.Fatalf("PrintError failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["status"] != "error" {
		t.Errorf("expected status 'error', got %v", result["status"])
	}
	if result["error"] != "something went wrong" {
		t.Errorf("expected error message, got %v", result["error"])
	}
}

func TestPrintError_Text(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	err := printer.PrintError(errors.New("failed"))
	if err != nil {
		t.Fatalf("PrintError failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Error:") {
		t.Error("expected 'Error:' in output")
	}
}

func TestPrintSignature_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	err := printer.PrintSignature("dGVzdC1zaWduYXR1cmU=")
	if err != nil {
		t.Fatalf("PrintSignature failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["signature"] != "dGVzdC1zaWduYXR1cmU=" {
		t.Errorf("expected signature value")
	}
}

func TestPrintSignature_Text(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	err := printer.PrintSignature("base64sig")
	if err != nil {
		t.Fatalf("PrintSignature failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "base64sig") {
		t.Error("expected signature in output")
	}
}

func TestPrintDecryptedData(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	err := printer.PrintDecryptedData("plaintext-data")
	if err != nil {
		t.Fatalf("PrintDecryptedData failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["plaintext"] != "plaintext-data" {
		t.Errorf("expected plaintext data")
	}
}

func TestPrintEncryptedData_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	data := &types.EncryptedData{
		Ciphertext: []byte("encrypted"),
		Nonce:      []byte("nonce123"),
		Tag:        []byte("authtag"),
		Algorithm:  "AES-256-GCM",
	}

	err := printer.PrintEncryptedData(data)
	if err != nil {
		t.Fatalf("PrintEncryptedData failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["algorithm"] != "AES-256-GCM" {
		t.Errorf("expected algorithm 'AES-256-GCM', got %v", result["algorithm"])
	}
}

func TestPrintEncryptedData_Text(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	data := &types.EncryptedData{
		Ciphertext: []byte("encrypted"),
		Nonce:      []byte("nonce123"),
		Tag:        []byte("authtag"),
		Algorithm:  "AES-256-GCM",
	}

	err := printer.PrintEncryptedData(data)
	if err != nil {
		t.Fatalf("PrintEncryptedData failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Ciphertext:") {
		t.Error("expected 'Ciphertext:' in output")
	}
	if !strings.Contains(output, "Algorithm:") {
		t.Error("expected 'Algorithm:' in output")
	}
}

func TestPrintCertList_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	certIDs := []string{"cert1", "cert2", "cert3"}
	err := printer.PrintCertList(certIDs)
	if err != nil {
		t.Fatalf("PrintCertList failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	certs, ok := result["certificates"].([]interface{})
	if !ok {
		t.Fatal("expected certificates array")
	}
	if len(certs) != 3 {
		t.Errorf("expected 3 certs, got %d", len(certs))
	}
}

func TestPrintCertList_Table_Empty(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	err := printer.PrintCertList([]string{})
	if err != nil {
		t.Fatalf("PrintCertList failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No certificates found") {
		t.Error("expected 'No certificates found' message")
	}
}

func TestPrintCertExists_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	err := printer.PrintCertExists("my-key", true)
	if err != nil {
		t.Fatalf("PrintCertExists failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["key_id"] != "my-key" {
		t.Errorf("expected key_id 'my-key', got %v", result["key_id"])
	}
	if result["exists"] != true {
		t.Errorf("expected exists true")
	}
}

func TestPrintCertExists_Text(t *testing.T) {
	tests := []struct {
		name   string
		exists bool
		expect string
	}{
		{"exists", true, "Certificate exists"},
		{"not exists", false, "does not exist"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter("text", buf)

			err := printer.PrintCertExists("test-key", tt.exists)
			if err != nil {
				t.Fatalf("PrintCertExists failed: %v", err)
			}

			output := buf.String()
			if !strings.Contains(output, tt.expect) {
				t.Errorf("expected '%s' in output", tt.expect)
			}
		})
	}
}

func TestPrintMessage(t *testing.T) {
	tests := []struct {
		name   string
		format string
	}{
		{"json", "json"},
		{"text", "text"},
		{"table", "table"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			printer := NewPrinter(tt.format, buf)

			err := printer.PrintMessage("Hello World")
			if err != nil {
				t.Fatalf("PrintMessage failed: %v", err)
			}

			output := buf.String()
			if !strings.Contains(output, "Hello World") && !strings.Contains(output, "message") {
				t.Error("expected message in output")
			}
		})
	}
}

func TestPrintEncryptedAsym(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	err := printer.PrintEncryptedAsym("encrypted-ciphertext")
	if err != nil {
		t.Fatalf("PrintEncryptedAsym failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["ciphertext"] != "encrypted-ciphertext" {
		t.Errorf("expected ciphertext value")
	}
}

func TestPrintImportParameters_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	expiresAt := time.Now().Add(1 * time.Hour)
	params := &backend.ImportParameters{
		Algorithm:   "RSA_OAEP_SHA256",
		KeySpec:     "AES_256",
		ExpiresAt:   &expiresAt,
		ImportToken: []byte("token123"),
	}

	err := printer.PrintImportParameters(params)
	if err != nil {
		t.Fatalf("PrintImportParameters failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["algorithm"] != "RSA_OAEP_SHA256" {
		t.Errorf("expected algorithm 'RSA_OAEP_SHA256'")
	}
}

func TestPrintImportParameters_Text(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	params := &backend.ImportParameters{
		Algorithm: "RSA_OAEP_SHA256",
		KeySpec:   "AES_256",
	}

	err := printer.PrintImportParameters(params)
	if err != nil {
		t.Fatalf("PrintImportParameters failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Import Parameters") {
		t.Error("expected 'Import Parameters' header")
	}
	if !strings.Contains(output, "RSA_OAEP_SHA256") {
		t.Error("expected algorithm in output")
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short string", "abc", 10, "abc"},
		{"exact length", "abc", 3, "abc"},
		{"truncate", "abcdefghij", 5, "ab..."},
		{"very short max", "abcdefghij", 2, "ab"},
		{"empty", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncateString(%q, %d) = %q, expected %q", tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}

func TestPrintJSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	data := map[string]string{"key": "value"}
	err := printer.PrintJSON(data)
	if err != nil {
		t.Fatalf("PrintJSON failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("expected key 'value'")
	}
}

func TestPrintCertificate_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "test"},
		Issuer:       pkix.Name{CommonName: "issuer"},
		SerialNumber: big.NewInt(12345),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"example.com"},
	}

	err := printer.PrintCertificate(cert)
	if err != nil {
		t.Fatalf("PrintCertificate failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !strings.Contains(result["subject"].(string), "test") {
		t.Error("expected subject to contain 'test'")
	}
}

func TestPrintCertChain_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	chain := []*x509.Certificate{
		{
			Subject:      pkix.Name{CommonName: "leaf"},
			Issuer:       pkix.Name{CommonName: "intermediate"},
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		},
		{
			Subject:      pkix.Name{CommonName: "intermediate"},
			Issuer:       pkix.Name{CommonName: "root"},
			SerialNumber: big.NewInt(2),
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		},
	}

	err := printer.PrintCertChain(chain)
	if err != nil {
		t.Fatalf("PrintCertChain failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	chainResult, ok := result["chain"].([]interface{})
	if !ok {
		t.Fatal("expected chain array")
	}

	if len(chainResult) != 2 {
		t.Errorf("expected 2 certs in chain, got %d", len(chainResult))
	}
}

func TestPrintFIDO2Devices_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	devices := []fido2Device{
		{
			Path:         "/dev/hidraw0",
			VendorID:     0x1050,
			ProductID:    0x0407,
			Manufacturer: "Yubico",
			Product:      "YubiKey",
			Transport:    "hid",
		},
	}

	err := printer.PrintFIDO2Devices(devices)
	if err != nil {
		t.Fatalf("PrintFIDO2Devices failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	devicesList, ok := result["devices"].([]interface{})
	if !ok {
		t.Fatal("expected devices array")
	}

	if len(devicesList) != 1 {
		t.Errorf("expected 1 device, got %d", len(devicesList))
	}
}

func TestPrintFIDO2Devices_Table(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("table", buf)

	devices := []fido2Device{
		{
			Path:         "/dev/hidraw0",
			VendorID:     0x1050,
			ProductID:    0x0407,
			Manufacturer: "Yubico",
			Product:      "YubiKey",
		},
	}

	err := printer.PrintFIDO2Devices(devices)
	if err != nil {
		t.Fatalf("PrintFIDO2Devices failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "PATH") {
		t.Error("expected table header")
	}
	if !strings.Contains(output, "/dev/hidraw0") {
		t.Error("expected device path in output")
	}
}

func TestPrintFIDO2DeviceInfo_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	device := fido2Device{
		Path:         "/dev/hidraw0",
		VendorID:     0x1050,
		ProductID:    0x0407,
		Manufacturer: "Yubico",
		Product:      "YubiKey",
		SerialNumber: "12345678",
		Transport:    "hid",
	}

	err := printer.PrintFIDO2DeviceInfo(device)
	if err != nil {
		t.Fatalf("PrintFIDO2DeviceInfo failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["path"] != "/dev/hidraw0" {
		t.Errorf("expected path '/dev/hidraw0'")
	}
}

func TestPrintFIDO2Registration_JSON(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	result := &fido2EnrollmentResult{
		CredentialID: []byte("cred-id"),
		PublicKey:    []byte("pub-key"),
		AAGUID:       []byte("aaguid-data"),
		Salt:         []byte("salt-value"),
		User: fido2User{
			Name:        "user@example.com",
			DisplayName: "Test User",
		},
		RelyingParty: fido2RelyingParty{
			ID: "example.com",
		},
		Created: time.Now(),
	}

	err := printer.PrintFIDO2Registration(result)
	if err != nil {
		t.Fatalf("PrintFIDO2Registration failed: %v", err)
	}

	var jsonResult map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &jsonResult); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if jsonResult["user_name"] != "user@example.com" {
		t.Errorf("expected user_name 'user@example.com'")
	}
}

func TestPrintFIDO2Registration_Text(t *testing.T) {
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	result := &fido2EnrollmentResult{
		CredentialID: []byte("cred-id"),
		Salt:         []byte("salt-value"),
		User: fido2User{
			Name:        "user@example.com",
			DisplayName: "Test User",
		},
		RelyingParty: fido2RelyingParty{
			ID: "example.com",
		},
		Created: time.Now(),
	}

	err := printer.PrintFIDO2Registration(result)
	if err != nil {
		t.Fatalf("PrintFIDO2Registration failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Registration Successful") {
		t.Error("expected success message")
	}
	if !strings.Contains(output, "user@example.com") {
		t.Error("expected user name in output")
	}
}

func TestOutputFormatConstants(t *testing.T) {
	if OutputFormatText != "text" {
		t.Errorf("expected OutputFormatText to be 'text'")
	}
	if OutputFormatJSON != "json" {
		t.Errorf("expected OutputFormatJSON to be 'json'")
	}
	if OutputFormatTable != "table" {
		t.Errorf("expected OutputFormatTable to be 'table'")
	}
}
