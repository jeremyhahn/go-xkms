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

package commands

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ProtocolType represents the communication protocol
type ProtocolType string

const (
	ProtocolUnix ProtocolType = "unix"
	ProtocolREST ProtocolType = "rest"
	ProtocolGRPC ProtocolType = "grpc"
	ProtocolQUIC ProtocolType = "quic"
	ProtocolMCP  ProtocolType = "mcp"
)

// AllProtocols returns all supported protocols
func AllProtocols() []ProtocolType {
	return []ProtocolType{ProtocolUnix, ProtocolREST, ProtocolGRPC, ProtocolQUIC, ProtocolMCP}
}

// CLIProtocols returns protocols supported by the CLI.
// MCP is excluded because it uses direct TCP with JSON-RPC 2.0, not HTTP-based URLs.
// MCP functionality is tested via direct MCPClient in mcp_comprehensive_test.go.
func CLIProtocols() []ProtocolType {
	return []ProtocolType{ProtocolUnix, ProtocolREST, ProtocolGRPC, ProtocolQUIC}
}

// TestRunner provides utilities for running CLI commands in tests
type TestRunner struct {
	CLIBinPath     string
	UnixSocketPath string
	RESTBaseURL    string
	GRPCAddr       string
	QUICBaseURL    string
	MCPAddr        string
	KeyDir         string
	Backend        string
	Timeout        time.Duration
	Verbose        bool
	TLSInsecure    bool
	TLSCACert      string
}

// NewTestRunner creates a new test runner with default configuration
func NewTestRunner() *TestRunner {
	projectRoot := getProjectRoot()
	defaultCLIPath := filepath.Join(projectRoot, "build", "bin", "keychain")

	return &TestRunner{
		CLIBinPath:     getEnv("KEYSTORE_CLI_BIN", defaultCLIPath),
		UnixSocketPath: getEnv("KEYSTORE_UNIX_SOCKET", "/var/run/keychain/keychain.sock"),
		RESTBaseURL:    getEnv("KEYSTORE_REST_URL", "http://localhost:8443"),
		GRPCAddr:       getEnv("KEYSTORE_GRPC_ADDR", "localhost:9443"),
		QUICBaseURL:    getEnv("KEYSTORE_QUIC_URL", "https://localhost:8444"),
		MCPAddr:        getEnv("KEYSTORE_MCP_ADDR", "localhost:9444"),
		KeyDir:         "",
		Backend:        "software",
		Timeout:        30 * time.Second,
		Verbose:        getEnv("VERBOSE", "") != "",
		TLSInsecure:    getEnv("KEYSTORE_TLS_INSECURE", "") != "",
		TLSCACert:      getEnv("KEYSTORE_TLS_CA", ""),
	}
}

// WithKeyDir sets a custom key directory
func (r *TestRunner) WithKeyDir(keyDir string) *TestRunner {
	r.KeyDir = keyDir
	return r
}

// WithBackend sets a custom backend
func (r *TestRunner) WithBackend(backend string) *TestRunner {
	r.Backend = backend
	return r
}

// WithTimeout sets a custom timeout
func (r *TestRunner) WithTimeout(timeout time.Duration) *TestRunner {
	r.Timeout = timeout
	return r
}

// GetServerURL returns the server URL for a protocol
func (r *TestRunner) GetServerURL(protocol ProtocolType) string {
	switch protocol {
	case ProtocolUnix:
		return "unix://" + r.UnixSocketPath
	case ProtocolREST:
		return r.RESTBaseURL
	case ProtocolGRPC:
		return "grpc://" + r.GRPCAddr
	case ProtocolQUIC:
		return "quic://" + strings.TrimPrefix(strings.TrimPrefix(r.QUICBaseURL, "https://"), "http://")
	case ProtocolMCP:
		return "mcp://" + r.MCPAddr
	default:
		return ""
	}
}

// IsCLIAvailable checks if the CLI binary is available
func (r *TestRunner) IsCLIAvailable(t *testing.T) bool {
	t.Helper()

	if _, err := os.Stat(r.CLIBinPath); os.IsNotExist(err) {
		return false
	}

	cmd := exec.Command(r.CLIBinPath, "version")
	return cmd.Run() == nil
}

// RequireCLI checks if CLI is available and skips the test if not.
// Integration tests should be run in Docker where CLI is built automatically.
// For local runs, use 'make build' to build the CLI first.
func (r *TestRunner) RequireCLI(t *testing.T) {
	t.Helper()

	if !r.IsCLIAvailable(t) {
		t.Skip("CLI binary not available. Run 'make build' for local testing or use 'make integration-test-cli' for Docker-based tests.")
	}
}

// RunCommand executes a CLI command and returns stdout, stderr, and error
func (r *TestRunner) RunCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()

	cmd := exec.Command(r.CLIBinPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if r.Verbose {
		t.Logf("Command: %s %s", r.CLIBinPath, strings.Join(args, " "))
		t.Logf("Stdout: %s", stdout.String())
		t.Logf("Stderr: %s", stderr.String())
	}

	return stdout.String(), stderr.String(), err
}

// RunCommandWithProtocol executes a CLI command with a specific protocol
func (r *TestRunner) RunCommandWithProtocol(t *testing.T, protocol ProtocolType, args ...string) (string, string, error) {
	t.Helper()

	// Build prefix args with server URL and TLS options
	prefixArgs := []string{}

	serverURL := r.GetServerURL(protocol)
	if serverURL != "" {
		prefixArgs = append(prefixArgs, "--server", serverURL)
	}

	// Add TLS options for protocols that use TLS (REST with HTTPS, gRPC, QUIC)
	needsTLS := protocol == ProtocolREST && strings.HasPrefix(r.RESTBaseURL, "https://") ||
		protocol == ProtocolGRPC ||
		protocol == ProtocolQUIC

	if needsTLS {
		if r.TLSInsecure {
			prefixArgs = append(prefixArgs, "--tls-insecure")
		}
		if r.TLSCACert != "" {
			prefixArgs = append(prefixArgs, "--tls-ca", r.TLSCACert)
		}
	}

	args = append(prefixArgs, args...)
	return r.RunCommand(t, args...)
}

// BuildCommandArgs builds the full argument list for a command definition
func (r *TestRunner) BuildCommandArgs(cmd CommandDefinition, overrides map[string]string) []string {
	args := make([]string, 0)

	// Add --local flag first if required (for FROST and other local-only commands)
	if cmd.RequiresLocal {
		args = append(args, "--local")
	}

	// Add key directory if required (before command for local mode)
	if cmd.RequiresKeyDir && r.KeyDir != "" {
		args = append(args, "--key-dir", r.KeyDir)
	}

	// Add command parts
	args = append(args, cmd.Command...)

	// Add backend if required
	if cmd.RequiresBackend && r.Backend != "" {
		args = append(args, "--backend", r.Backend)
	}

	// Add required positional args
	for _, arg := range cmd.RequiredArgs {
		if arg.IsPositional {
			value := arg.Value
			if override, ok := overrides[arg.Flag]; ok {
				value = override
			} else if override, ok := overrides[arg.Description]; ok {
				value = override
			}
			args = append(args, value)
		} else {
			value := arg.Value
			if override, ok := overrides[arg.Flag]; ok {
				value = override
			}
			args = append(args, "--"+arg.Flag, value)
		}
	}

	// Add optional args if provided in overrides
	for _, arg := range cmd.OptionalArgs {
		if value, ok := overrides[arg.Flag]; ok {
			if arg.Flag == "dealer" || arg.Flag == "local" {
				// Boolean flags
				args = append(args, "--"+arg.Flag)
			} else {
				args = append(args, "--"+arg.Flag, value)
			}
		} else if arg.Value != "" {
			// Use default value
			args = append(args, "--"+arg.Flag, arg.Value)
		}
	}

	return args
}

// ExecuteCommand runs a command definition and returns output
func (r *TestRunner) ExecuteCommand(t *testing.T, cmd CommandDefinition, overrides map[string]string) (string, string, error) {
	t.Helper()

	args := r.BuildCommandArgs(cmd, overrides)
	return r.RunCommand(t, args...)
}

// ExecuteCommandWithProtocol runs a command with a specific protocol
func (r *TestRunner) ExecuteCommandWithProtocol(t *testing.T, protocol ProtocolType, cmd CommandDefinition, overrides map[string]string) (string, string, error) {
	t.Helper()

	args := r.BuildCommandArgs(cmd, overrides)
	return r.RunCommandWithProtocol(t, protocol, args...)
}

// TestResult represents the result of running a command test
type TestResult struct {
	Command  CommandDefinition
	Protocol ProtocolType
	Stdout   string
	Stderr   string
	Error    error
	Duration time.Duration
	Passed   bool
	Message  string
}

// RunCommandTest runs a single command test and returns the result
func (r *TestRunner) RunCommandTest(t *testing.T, protocol ProtocolType, cmd CommandDefinition, overrides map[string]string) *TestResult {
	t.Helper()

	start := time.Now()
	stdout, stderr, err := r.ExecuteCommandWithProtocol(t, protocol, cmd, overrides)
	duration := time.Since(start)

	result := &TestResult{
		Command:  cmd,
		Protocol: protocol,
		Stdout:   stdout,
		Stderr:   stderr,
		Error:    err,
		Duration: duration,
		Passed:   err == nil,
		Message:  "",
	}

	if err != nil {
		result.Message = fmt.Sprintf("Command failed: %v", err)
	} else {
		// Check expected output
		for _, expected := range cmd.ExpectedOutputContains {
			if !strings.Contains(stdout+stderr, expected) {
				result.Passed = false
				result.Message = fmt.Sprintf("Output missing expected content: %s", expected)
				break
			}
		}
	}

	return result
}

// RunAllCommandsForProtocol runs all applicable commands for a protocol
func (r *TestRunner) RunAllCommandsForProtocol(t *testing.T, protocol ProtocolType, enabledTags []string) []*TestResult {
	t.Helper()

	var results []*TestResult

	// Generate unique key IDs for this test run to avoid conflicts
	runID := time.Now().UnixNano()
	keyIDs := map[string]string{
		"test-rsa-key":     fmt.Sprintf("test-rsa-key-%d", runID),
		"test-ecdsa-key":   fmt.Sprintf("test-ecdsa-key-%d", runID),
		"test-ed25519-key": fmt.Sprintf("test-ed25519-key-%d", runID),
		"test-key":         fmt.Sprintf("test-rsa-key-%d", runID), // Use RSA key for sign/verify/delete
		"frost-test-key":   fmt.Sprintf("frost-test-key-%d", runID),
		"frost-dealer-key": fmt.Sprintf("frost-dealer-key-%d", runID),
	}

	// Track signature from key-sign for use in key-verify
	var capturedSignature string

	for _, cmd := range AllCommands() {
		// Skip commands that require unavailable build tags
		if !r.commandTagsAvailable(cmd, enabledTags) {
			t.Logf("Skipping %s: requires build tags %v", cmd.Name, cmd.BuildTags)
			continue
		}

		// Skip commands that require prior setup (tested in workflow tests instead)
		if cmd.RequiresSetup {
			t.Logf("Skipping %s: requires prior setup (tested in workflow tests)", cmd.Name)
			continue
		}

		// Build overrides to replace hardcoded key IDs with unique ones
		overrides := make(map[string]string)
		for _, arg := range cmd.RequiredArgs {
			if arg.Description == "Key ID" {
				if uniqueID, ok := keyIDs[arg.Value]; ok {
					overrides[arg.Description] = uniqueID
				}
			}
		}

		// For key-verify, use the captured signature from key-sign
		if cmd.Name == "key-verify" && capturedSignature != "" {
			overrides["Signature"] = capturedSignature
		}

		// Skip server-required commands if testing version, etc.
		if !cmd.RequiresServer {
			result := r.RunCommandTest(t, protocol, cmd, overrides)
			results = append(results, result)
			continue
		}

		t.Run(cmd.Name, func(t *testing.T) {
			result := r.RunCommandTest(t, protocol, cmd, overrides)
			results = append(results, result)

			// Capture signature from key-sign output for use in key-verify
			if cmd.Name == "key-sign" && result.Passed {
				// The signature should be in the stdout, extract it
				sig := strings.TrimSpace(result.Stdout)
				if sig != "" {
					capturedSignature = sig
				}
			}

			if !result.Passed {
				t.Logf("Command %s failed: %s", cmd.Name, result.Message)
				t.Logf("Stdout: %s", result.Stdout)
				t.Logf("Stderr: %s", result.Stderr)
			}
		})
	}

	return results
}

// commandTagsAvailable checks if all required build tags are available
func (r *TestRunner) commandTagsAvailable(cmd CommandDefinition, enabledTags []string) bool {
	for _, requiredTag := range cmd.BuildTags {
		found := false
		for _, enabledTag := range enabledTags {
			if requiredTag == enabledTag {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Helper functions

func getProjectRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	// This file is in test/integration/api/commands/, so go up 4 levels
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "..")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// CreateTempKeyDir creates a temporary key directory for tests
func CreateTempKeyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

// GenerateUniqueKeyID generates a unique key ID for tests
func GenerateUniqueKeyID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}
