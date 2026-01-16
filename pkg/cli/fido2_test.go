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

package cli

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestFIDO2Cmd_Exists(t *testing.T) {
	if fido2Cmd == nil {
		t.Fatal("fido2Cmd should not be nil")
	}
}

func TestFIDO2Cmd_Properties(t *testing.T) {
	if fido2Cmd.Use != "fido2" {
		t.Errorf("fido2Cmd.Use = %v, want fido2", fido2Cmd.Use)
	}

	if fido2Cmd.Short == "" {
		t.Error("fido2Cmd.Short should not be empty")
	}
}

func TestFIDO2Cmd_HasSubcommands(t *testing.T) {
	subcommands := fido2Cmd.Commands()

	expectedCmds := []string{
		"list-devices",
		"wait-device",
		"register",
		"authenticate",
		"info",
	}
	foundCmds := make(map[string]bool)

	for _, cmd := range subcommands {
		foundCmds[cmd.Name()] = true
	}

	for _, expected := range expectedCmds {
		if !foundCmds[expected] {
			t.Errorf("expected subcommand %q not found", expected)
		}
	}
}

func TestFIDO2ListDevicesCmd_Exists(t *testing.T) {
	if fido2ListDevicesCmd == nil {
		t.Fatal("fido2ListDevicesCmd should not be nil")
	}
}

func TestFIDO2ListDevicesCmd_Properties(t *testing.T) {
	if fido2ListDevicesCmd.Use != "list-devices" {
		t.Errorf("fido2ListDevicesCmd.Use = %v, want list-devices", fido2ListDevicesCmd.Use)
	}
}

func TestFIDO2WaitDeviceCmd_Exists(t *testing.T) {
	if fido2WaitDeviceCmd == nil {
		t.Fatal("fido2WaitDeviceCmd should not be nil")
	}
}

func TestFIDO2WaitDeviceCmd_HasFlags(t *testing.T) {
	flags := fido2WaitDeviceCmd.Flags()

	if flags.Lookup("timeout") == nil {
		t.Error("expected flag 'timeout' not found on fido2WaitDeviceCmd")
	}
}

func TestFIDO2RegisterCmd_Exists(t *testing.T) {
	if fido2RegisterCmd == nil {
		t.Fatal("fido2RegisterCmd should not be nil")
	}
}

func TestFIDO2RegisterCmd_Properties(t *testing.T) {
	if fido2RegisterCmd.Use != "register <username>" {
		t.Errorf("fido2RegisterCmd.Use = %v, want 'register <username>'", fido2RegisterCmd.Use)
	}
}

func TestFIDO2RegisterCmd_HasFlags(t *testing.T) {
	flags := fido2RegisterCmd.Flags()

	expectedFlags := []string{
		"rp-id",
		"rp-name",
		"display-name",
		"timeout",
		"device",
		"user-verification",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on fido2RegisterCmd", flag)
		}
	}
}

func TestFIDO2AuthenticateCmd_Exists(t *testing.T) {
	if fido2AuthenticateCmd == nil {
		t.Fatal("fido2AuthenticateCmd should not be nil")
	}
}

func TestFIDO2AuthenticateCmd_Properties(t *testing.T) {
	if fido2AuthenticateCmd.Use != "authenticate" {
		t.Errorf("fido2AuthenticateCmd.Use = %v, want authenticate", fido2AuthenticateCmd.Use)
	}
}

func TestFIDO2AuthenticateCmd_HasFlags(t *testing.T) {
	flags := fido2AuthenticateCmd.Flags()

	expectedFlags := []string{
		"credential-id",
		"salt",
		"rp-id",
		"timeout",
		"device",
		"user-verification",
		"hex",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on fido2AuthenticateCmd", flag)
		}
	}
}

func TestFIDO2InfoCmd_Exists(t *testing.T) {
	if fido2InfoCmd == nil {
		t.Fatal("fido2InfoCmd should not be nil")
	}
}

func TestFIDO2InfoCmd_HasFlags(t *testing.T) {
	flags := fido2InfoCmd.Flags()

	if flags.Lookup("device") == nil {
		t.Error("expected flag 'device' not found on fido2InfoCmd")
	}
}

func TestDecodeCredentialData_Base64(t *testing.T) {
	originalData := []byte("test credential data")
	encoded := base64.StdEncoding.EncodeToString(originalData)

	decoded, err := decodeCredentialData(encoded)
	if err != nil {
		t.Fatalf("decodeCredentialData failed: %v", err)
	}

	if string(decoded) != string(originalData) {
		t.Errorf("decoded = %v, want %v", decoded, originalData)
	}
}

func TestDecodeCredentialData_Base64URL(t *testing.T) {
	originalData := []byte("test credential data with special chars")
	encoded := base64.URLEncoding.EncodeToString(originalData)

	decoded, err := decodeCredentialData(encoded)
	if err != nil {
		t.Fatalf("decodeCredentialData failed: %v", err)
	}

	if string(decoded) != string(originalData) {
		t.Errorf("decoded = %v, want %v", decoded, originalData)
	}
}

func TestDecodeCredentialData_Hex(t *testing.T) {
	originalData := []byte("test hex data")
	encoded := hex.EncodeToString(originalData)

	decoded, err := decodeCredentialData(encoded)
	if err != nil {
		t.Fatalf("decodeCredentialData failed: %v", err)
	}

	if string(decoded) != string(originalData) {
		t.Errorf("decoded = %v, want %v", decoded, originalData)
	}
}

func TestDecodeCredentialData_Invalid(t *testing.T) {
	// Invalid data that's not valid base64 or hex
	invalidData := "not-valid-base64-or-hex!!!"

	_, err := decodeCredentialData(invalidData)
	if err == nil {
		t.Error("decodeCredentialData should return error for invalid data")
	}
}

func TestDecodeCredentialData_Empty(t *testing.T) {
	decoded, err := decodeCredentialData("")
	if err != nil {
		t.Fatalf("decodeCredentialData failed for empty string: %v", err)
	}

	if len(decoded) != 0 {
		t.Errorf("decoded length = %d, want 0", len(decoded))
	}
}

func TestFIDO2RegisterCmd_Arguments(t *testing.T) {
	// Verify command expects exactly one argument (username)
	if fido2RegisterCmd.Args == nil {
		t.Error("fido2RegisterCmd.Args should be set")
	}
}

func TestFIDO2RegisterCmd_FlagDefaults(t *testing.T) {
	flags := fido2RegisterCmd.Flags()

	rpIDFlag := flags.Lookup("rp-id")
	if rpIDFlag.DefValue != "go-keychain" {
		t.Errorf("rp-id default = %v, want go-keychain", rpIDFlag.DefValue)
	}

	rpNameFlag := flags.Lookup("rp-name")
	if rpNameFlag.DefValue != "Go Keychain" {
		t.Errorf("rp-name default = %v, want 'Go Keychain'", rpNameFlag.DefValue)
	}

	timeoutFlag := flags.Lookup("timeout")
	if timeoutFlag.DefValue != "30s" {
		t.Errorf("timeout default = %v, want 30s", timeoutFlag.DefValue)
	}
}

func TestFIDO2AuthenticateCmd_FlagDefaults(t *testing.T) {
	flags := fido2AuthenticateCmd.Flags()

	rpIDFlag := flags.Lookup("rp-id")
	if rpIDFlag.DefValue != "go-keychain" {
		t.Errorf("rp-id default = %v, want go-keychain", rpIDFlag.DefValue)
	}

	timeoutFlag := flags.Lookup("timeout")
	if timeoutFlag.DefValue != "30s" {
		t.Errorf("timeout default = %v, want 30s", timeoutFlag.DefValue)
	}
}

func TestFIDO2Device_Type(t *testing.T) {
	// Test fido2Device struct creation
	device := fido2Device{
		Path:         "/dev/hidraw0",
		VendorID:     0x1050,
		ProductID:    0x0407,
		Manufacturer: "Yubico",
		Product:      "YubiKey",
		SerialNumber: "12345",
		Transport:    "usb",
	}

	if device.Path != "/dev/hidraw0" {
		t.Error("device.Path not set correctly")
	}
	if device.VendorID != 0x1050 {
		t.Error("device.VendorID not set correctly")
	}
}

func TestFIDO2User_Type(t *testing.T) {
	// Test fido2User struct creation
	user := fido2User{
		ID:          []byte("user-id"),
		Name:        "test@example.com",
		DisplayName: "Test User",
		Icon:        "",
	}

	if user.Name != "test@example.com" {
		t.Error("user.Name not set correctly")
	}
	if user.DisplayName != "Test User" {
		t.Error("user.DisplayName not set correctly")
	}
}

func TestFIDO2RelyingParty_Type(t *testing.T) {
	// Test fido2RelyingParty struct creation
	rp := fido2RelyingParty{
		ID:   "example.com",
		Name: "Example",
		Icon: "",
	}

	if rp.ID != "example.com" {
		t.Error("rp.ID not set correctly")
	}
	if rp.Name != "Example" {
		t.Error("rp.Name not set correctly")
	}
}

func TestFIDO2EnrollmentResult_Type(t *testing.T) {
	// Test fido2EnrollmentResult struct creation
	result := &fido2EnrollmentResult{
		CredentialID: []byte("cred-id"),
		PublicKey:    []byte("pub-key"),
		AAGUID:       []byte("aaguid"),
		SignCount:    0,
		Salt:         []byte("salt"),
		User: fido2User{
			ID:   []byte("user-id"),
			Name: "test@example.com",
		},
		RelyingParty: fido2RelyingParty{
			ID:   "example.com",
			Name: "Example",
		},
	}

	if len(result.CredentialID) == 0 {
		t.Error("result.CredentialID should not be empty")
	}
	if len(result.PublicKey) == 0 {
		t.Error("result.PublicKey should not be empty")
	}
}

func TestFIDO2WaitDeviceCmd_TimeoutDefault(t *testing.T) {
	flags := fido2WaitDeviceCmd.Flags()

	timeoutFlag := flags.Lookup("timeout")
	if timeoutFlag.DefValue != "1m0s" {
		t.Errorf("timeout default = %v, want 1m0s", timeoutFlag.DefValue)
	}
}
