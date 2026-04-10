// Copyright (c) 2025 Jeremy Hahn
package services

import (
	"strings"
	"testing"
)

func TestTestBackendConnection_YubiKeyHandlerExists(t *testing.T) {
	svc := &AdminService{}
	result := svc.TestBackendConnection("yubikey", map[string]string{
		"library_path": "/usr/lib/x86_64-linux-gnu/libykcs11.so",
		"user_pin":     "123456",
		"slot_id":      "0",
	})
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if strings.Contains(result.Message, "not supported") {
		t.Errorf("yubikey backend type should have a connection test handler, got: %s", result.Message)
	}
}

func TestTestBackendConnection_YubiKeyMissingUserPIN(t *testing.T) {
	svc := &AdminService{}
	result := svc.TestBackendConnection("yubikey", map[string]string{
		"library_path": "/usr/lib/x86_64-linux-gnu/libykcs11.so",
	})
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Success {
		t.Error("expected failure when user_pin is missing")
	}
	if !strings.Contains(result.Message, "User PIN is required") {
		t.Errorf("expected 'User PIN is required' message, got: %s", result.Message)
	}
}
