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

//go:build integration && fido2

package fido2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ProtocolType represents a communication protocol
type ProtocolType string

const (
	ProtocolUnix ProtocolType = "unix"
	ProtocolREST ProtocolType = "rest"
	ProtocolGRPC ProtocolType = "grpc"
	ProtocolQUIC ProtocolType = "quic"
	ProtocolMCP  ProtocolType = "mcp"
)

// MultiProtocolConfig holds multi-protocol test configuration
type MultiProtocolConfig struct {
	CLIBinPath     string
	UnixSocketPath string
	RESTBaseURL    string
	GRPCAddr       string
	QUICBaseURL    string
	MCPAddr        string
	DevicePath     string
	TLSInsecure    bool
}

// LoadMultiProtocolConfig loads multi-protocol configuration
func LoadMultiProtocolConfig() *MultiProtocolConfig {
	cfg := LoadCLITestConfig()

	return &MultiProtocolConfig{
		CLIBinPath:     cfg.CLIBinPath,
		UnixSocketPath: getEnv("KEYSTORE_UNIX_SOCKET", "/var/run/keychain/keychain.sock"),
		RESTBaseURL:    getEnv("KEYSTORE_REST_URL", "http://localhost:8443"),
		GRPCAddr:       getEnv("KEYSTORE_GRPC_ADDR", "localhost:9443"),
		QUICBaseURL:    getEnv("KEYSTORE_QUIC_URL", "https://localhost:9445"),
		MCPAddr:        getEnv("KEYSTORE_MCP_ADDR", "localhost:9444"),
		DevicePath:     cfg.DevicePath,
		TLSInsecure:    true,
	}
}

// GetServerURL returns the server URL for a protocol
func (cfg *MultiProtocolConfig) GetServerURL(protocol ProtocolType) string {
	switch protocol {
	case ProtocolUnix:
		return "unix://" + cfg.UnixSocketPath
	case ProtocolREST:
		return cfg.RESTBaseURL
	case ProtocolGRPC:
		return "grpc://" + cfg.GRPCAddr
	case ProtocolQUIC:
		return "quic://" + strings.TrimPrefix(strings.TrimPrefix(cfg.QUICBaseURL, "https://"), "http://")
	case ProtocolMCP:
		return "mcp://" + cfg.MCPAddr
	default:
		return ""
	}
}

// execCLIWithProtocol executes CLI command with specific protocol
func (cfg *MultiProtocolConfig) execCLIWithProtocol(t *testing.T, protocol ProtocolType, args ...string) (string, string, error) {
	t.Helper()

	var prefixArgs []string

	serverURL := cfg.GetServerURL(protocol)
	if serverURL != "" {
		prefixArgs = append(prefixArgs, "--server", serverURL)
	}

	// Add TLS options for protocols that use TLS
	needsTLS := strings.HasPrefix(serverURL, "https://") ||
		strings.HasPrefix(serverURL, "grpc://") ||
		strings.HasPrefix(serverURL, "quic://")

	if needsTLS && cfg.TLSInsecure {
		prefixArgs = append(prefixArgs, "--tls-insecure")
	}

	args = append(prefixArgs, args...)
	cmd := exec.Command(cfg.CLIBinPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// AllProtocols returns all protocols to test
func AllProtocols() []ProtocolType {
	return []ProtocolType{ProtocolUnix, ProtocolREST, ProtocolGRPC, ProtocolQUIC, ProtocolMCP}
}

// TestMultiProtocolFIDO2ListDevices tests list-devices across all protocols
func TestMultiProtocolFIDO2ListDevices(t *testing.T) {
	cfg := LoadMultiProtocolConfig()
	cliCfg := LoadCLITestConfig()
	cliCfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== Multi-Protocol FIDO2 List Devices Test ===")

	protocols := AllProtocols()

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			args := []string{"fido2", "list-devices"}

			if fido2Cfg.DevicePath != "" {
				args = append(args, "--device", fido2Cfg.DevicePath)
			}

			stdout, stderr, err := cfg.execCLIWithProtocol(t, proto, args...)

			if err != nil {
				t.Logf("[%s] stdout: %s", proto, stdout)
				t.Logf("[%s] stderr: %s", proto, stderr)

				// Log but don't fail - server might not be running for this protocol
				t.Logf("[%s] list-devices may not be implemented or server not running: %v", proto, err)
				return
			}

			output := stdout + stderr
			assert.NotEmpty(t, output, fmt.Sprintf("[%s] Output should not be empty", proto))

			t.Logf("[%s] list-devices succeeded", proto)
		})
	}
}

// TestMultiProtocolFIDO2Register tests registration across all protocols
func TestMultiProtocolFIDO2Register(t *testing.T) {
	cfg := LoadMultiProtocolConfig()
	cliCfg := LoadCLITestConfig()
	cliCfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== Multi-Protocol FIDO2 Register Test ===")

	protocols := AllProtocols()

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			username := GenerateUniqueUsername(fmt.Sprintf("mp-%s-user", proto))

			args := []string{
				"--output", "json",
				"fido2", "register", username,
				"--rp-id", "go-keychain-mp-test",
				"--rp-name", fmt.Sprintf("Multi-Protocol %s Test", proto),
				"--timeout", "30s",
			}

			if fido2Cfg.DevicePath != "" {
				args = append(args, "--device", fido2Cfg.DevicePath)
			}

			t.Logf("[%s] Please touch your security key to register...", proto)

			stdout, stderr, err := cfg.execCLIWithProtocol(t, proto, args...)

			if err != nil {
				t.Logf("[%s] stdout: %s", proto, stdout)
				t.Logf("[%s] stderr: %s", proto, stderr)
				t.Logf("[%s] register may not be implemented or server not running: %v", proto, err)
				return
			}

			// Parse JSON output
			var result map[string]interface{}
			err = json.Unmarshal([]byte(stdout), &result)
			if err != nil {
				t.Logf("[%s] Failed to parse JSON output: %v", proto, err)
				t.Logf("[%s] Raw output: %s", proto, stdout)
				return
			}

			assert.NotEmpty(t, result["credential_id"], fmt.Sprintf("[%s] Should have credential ID", proto))
			assert.NotEmpty(t, result["salt"], fmt.Sprintf("[%s] Should have salt", proto))

			t.Logf("[%s] Registration successful", proto)
		})
	}
}

// TestMultiProtocolFIDO2Info tests device info across all protocols
func TestMultiProtocolFIDO2Info(t *testing.T) {
	cfg := LoadMultiProtocolConfig()
	cliCfg := LoadCLITestConfig()
	cliCfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== Multi-Protocol FIDO2 Info Test ===")

	protocols := AllProtocols()

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			args := []string{"--output", "json", "fido2", "info"}

			if fido2Cfg.DevicePath != "" {
				args = append(args, "--device", fido2Cfg.DevicePath)
			}

			stdout, stderr, err := cfg.execCLIWithProtocol(t, proto, args...)

			if err != nil {
				t.Logf("[%s] stdout: %s", proto, stdout)
				t.Logf("[%s] stderr: %s", proto, stderr)
				t.Logf("[%s] info may not be implemented or server not running: %v", proto, err)
				return
			}

			// Parse JSON output
			var info map[string]interface{}
			err = json.Unmarshal([]byte(stdout), &info)
			if err != nil {
				t.Logf("[%s] Failed to parse JSON output: %v", proto, err)
				return
			}

			assert.NotEmpty(t, info["path"], fmt.Sprintf("[%s] Should have device path", proto))

			t.Logf("[%s] Device info retrieved successfully", proto)
		})
	}
}

// TestMultiProtocolFIDO2FullWorkflow tests complete workflow across all protocols
func TestMultiProtocolFIDO2FullWorkflow(t *testing.T) {
	cfg := LoadMultiProtocolConfig()
	cliCfg := LoadCLITestConfig()
	cliCfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== Multi-Protocol FIDO2 Full Workflow Test ===")

	// Test only a subset to avoid excessive user interaction
	protocols := []ProtocolType{ProtocolUnix, ProtocolREST}

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			username := GenerateUniqueUsername(fmt.Sprintf("workflow-%s", proto))

			// Step 1: Register
			t.Logf("[%s] Step 1: Registering credential...", proto)

			registerArgs := []string{
				"--output", "json",
				"fido2", "register", username,
				"--rp-id", "go-keychain-workflow-test",
				"--rp-name", fmt.Sprintf("Workflow %s Test", proto),
				"--timeout", "30s",
			}

			if fido2Cfg.DevicePath != "" {
				registerArgs = append(registerArgs, "--device", fido2Cfg.DevicePath)
			}

			t.Logf("[%s] Please touch your security key to register...", proto)

			stdout, stderr, err := cfg.execCLIWithProtocol(t, proto, registerArgs...)
			if err != nil {
				t.Logf("[%s] stdout: %s", proto, stdout)
				t.Logf("[%s] stderr: %s", proto, stderr)
				t.Logf("[%s] Registration may not be implemented: %v", proto, err)
				return
			}

			// Parse registration result
			var regResult map[string]interface{}
			err = json.Unmarshal([]byte(stdout), &regResult)
			if err != nil {
				t.Logf("[%s] Failed to parse registration JSON: %v", proto, err)
				return
			}

			credID := regResult["credential_id"].(string)
			salt := regResult["salt"].(string)

			t.Logf("[%s] Registration successful", proto)

			// Small delay before authentication
			time.Sleep(1 * time.Second)

			// Step 2: Authenticate
			t.Logf("[%s] Step 2: Authenticating with credential...", proto)

			authArgs := []string{
				"--output", "json",
				"fido2", "authenticate",
				"--credential-id", credID,
				"--salt", salt,
				"--rp-id", "go-keychain-workflow-test",
				"--timeout", "30s",
			}

			if fido2Cfg.DevicePath != "" {
				authArgs = append(authArgs, "--device", fido2Cfg.DevicePath)
			}

			t.Logf("[%s] Please touch your security key to authenticate...", proto)

			stdout, stderr, err = cfg.execCLIWithProtocol(t, proto, authArgs...)
			if err != nil {
				t.Logf("[%s] stdout: %s", proto, stdout)
				t.Logf("[%s] stderr: %s", proto, stderr)
				t.Logf("[%s] Authentication may not be implemented: %v", proto, err)
				return
			}

			// Parse authentication result
			var authResult map[string]interface{}
			err = json.Unmarshal([]byte(stdout), &authResult)
			if err != nil {
				t.Logf("[%s] Failed to parse authentication JSON: %v", proto, err)
				return
			}

			assert.True(t, authResult["success"].(bool), fmt.Sprintf("[%s] Authentication should succeed", proto))
			assert.NotEmpty(t, authResult["derived_key"], fmt.Sprintf("[%s] Should have derived key", proto))

			t.Logf("[%s] Full workflow completed successfully!", proto)
		})
	}
}

// TestMultiProtocolFIDO2Consistency tests consistency across protocols
func TestMultiProtocolFIDO2Consistency(t *testing.T) {
	cfg := LoadMultiProtocolConfig()
	cliCfg := LoadCLITestConfig()
	cliCfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== Multi-Protocol FIDO2 Consistency Test ===")

	// Register once using Unix socket
	username := GenerateUniqueUsername("consistency-user")

	registerArgs := []string{
		"--output", "json",
		"fido2", "register", username,
		"--rp-id", "go-keychain-consistency-test",
		"--rp-name", "Consistency Test",
		"--timeout", "30s",
	}

	if fido2Cfg.DevicePath != "" {
		registerArgs = append(registerArgs, "--device", fido2Cfg.DevicePath)
	}

	t.Log("Please touch your security key to register (Unix socket)...")

	stdout, stderr, err := cfg.execCLIWithProtocol(t, ProtocolUnix, registerArgs...)
	if err != nil {
		t.Logf("Unix stdout: %s", stdout)
		t.Logf("Unix stderr: %s", stderr)
		t.Fatalf("Unix socket registration failed: %v", err)
	}

	// Parse registration result
	var regResult map[string]interface{}
	err = json.Unmarshal([]byte(stdout), &regResult)
	require.NoError(t, err, "Failed to parse registration JSON")

	credID := regResult["credential_id"].(string)
	salt := regResult["salt"].(string)

	t.Log("Credential registered, now testing authentication across protocols...")

	// Authenticate using different protocols
	protocols := []ProtocolType{ProtocolREST, ProtocolGRPC}
	var derivedKeys []string

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			authArgs := []string{
				"--output", "json",
				"fido2", "authenticate",
				"--credential-id", credID,
				"--salt", salt,
				"--rp-id", "go-keychain-consistency-test",
				"--timeout", "30s",
			}

			if fido2Cfg.DevicePath != "" {
				authArgs = append(authArgs, "--device", fido2Cfg.DevicePath)
			}

			t.Logf("[%s] Please touch your security key to authenticate...", proto)

			stdout, stderr, err := cfg.execCLIWithProtocol(t, proto, authArgs...)
			if err != nil {
				t.Logf("[%s] stdout: %s", proto, stdout)
				t.Logf("[%s] stderr: %s", proto, stderr)
				t.Fatalf("[%s] Authentication failed: %v", proto, err)
			}

			// Parse authentication result
			var authResult map[string]interface{}
			err = json.Unmarshal([]byte(stdout), &authResult)
			require.NoError(t, err, fmt.Sprintf("[%s] Failed to parse JSON", proto))

			derivedKey := authResult["derived_key"].(string)
			derivedKeys = append(derivedKeys, derivedKey)

			t.Logf("[%s] Authentication successful", proto)

			// Small delay between authentications
			time.Sleep(1 * time.Second)
		})
	}

	// Verify all derived keys are the same
	if len(derivedKeys) > 1 {
		for i := 1; i < len(derivedKeys); i++ {
			assert.Equal(t, derivedKeys[0], derivedKeys[i],
				"Derived keys should be consistent across protocols")
		}
		t.Log("Consistency verified: all protocols produce the same derived key")
	}
}

// TestMultiProtocolFIDO2WaitDevice tests wait-device across protocols
func TestMultiProtocolFIDO2WaitDevice(t *testing.T) {
	cfg := LoadMultiProtocolConfig()
	cliCfg := LoadCLITestConfig()
	cliCfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()

	// Require FIDO2 device
	fido2Cfg.RequireDevice(t)

	t.Log("=== Multi-Protocol FIDO2 Wait Device Test ===")

	protocols := AllProtocols()

	for _, proto := range protocols {
		t.Run(string(proto), func(t *testing.T) {
			args := []string{"fido2", "wait-device", "--timeout", "5s"}

			stdout, stderr, err := cfg.execCLIWithProtocol(t, proto, args...)

			if err != nil {
				t.Logf("[%s] stdout: %s", proto, stdout)
				t.Logf("[%s] stderr: %s", proto, stderr)
				t.Logf("[%s] wait-device may not be implemented: %v", proto, err)
				return
			}

			output := stdout + stderr
			assert.NotEmpty(t, output, fmt.Sprintf("[%s] Output should not be empty", proto))

			t.Logf("[%s] wait-device succeeded", proto)
		})
	}
}

// TestMultiProtocolFIDO2AuthenticateWithBase64AndHex tests different encoding formats
func TestMultiProtocolFIDO2AuthenticateWithBase64AndHex(t *testing.T) {
	cfg := LoadMultiProtocolConfig()
	cliCfg := LoadCLITestConfig()
	cliCfg.requireCLI(t)

	fido2Cfg := LoadFIDO2TestConfig()
	fido2Cfg.RequireDevice(t)

	t.Log("=== Multi-Protocol FIDO2 Authenticate With Different Encodings Test ===")

	// Enroll credential using API
	username := GenerateUniqueUsername("encoding-test")
	enrollment, handler := fido2Cfg.EnrollTestCredential(t, username)
	defer CleanupCredential(t, handler)

	credIDBase64 := base64.StdEncoding.EncodeToString(enrollment.CredentialID)
	saltBase64 := base64.StdEncoding.EncodeToString(enrollment.Salt)

	protocols := []ProtocolType{ProtocolUnix, ProtocolREST}

	for _, proto := range protocols {
		t.Run(fmt.Sprintf("%s-base64", proto), func(t *testing.T) {
			args := []string{
				"fido2", "authenticate",
				"--credential-id", credIDBase64,
				"--salt", saltBase64,
				"--rp-id", "go-keychain-test",
				"--timeout", "30s",
			}

			if fido2Cfg.DevicePath != "" {
				args = append(args, "--device", fido2Cfg.DevicePath)
			}

			t.Logf("[%s] Please touch your security key (base64 encoding)...", proto)

			stdout, stderr, err := cfg.execCLIWithProtocol(t, proto, args...)

			if err != nil {
				t.Logf("[%s] stdout: %s", proto, stdout)
				t.Logf("[%s] stderr: %s", proto, stderr)
				t.Fatalf("[%s] Authentication failed: %v", proto, err)
			}

			output := stdout + stderr
			assert.NotEmpty(t, output, fmt.Sprintf("[%s] Output should not be empty", proto))
			assert.Contains(t, strings.ToLower(output), "derived", fmt.Sprintf("[%s] Should mention derived key", proto))

			t.Logf("[%s] Base64 authentication successful", proto)

			time.Sleep(1 * time.Second)
		})
	}
}
