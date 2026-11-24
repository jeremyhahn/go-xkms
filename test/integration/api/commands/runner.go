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

package commands

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// ProtocolType represents the communication protocol
type ProtocolType string

const (
	ProtocolUnix     ProtocolType = "unix"
	ProtocolREST     ProtocolType = "rest"
	ProtocolGRPC     ProtocolType = "grpc"
	ProtocolQUIC     ProtocolType = "quic"
	ProtocolMCP      ProtocolType = "mcp"
	ProtocolEmbedded ProtocolType = "embedded"
)

// AllProtocols returns the protocols of the per-protocol command tests.
// The CLI matrix uses CLIProtocols, which also covers MCP.
func AllProtocols() []ProtocolType {
	return []ProtocolType{ProtocolUnix, ProtocolREST, ProtocolGRPC, ProtocolQUIC, ProtocolEmbedded}
}

// CLIProtocols returns every SDK transport the CLI matrix runs over
// (docs/SPEC.md row cli-protocol-matrix): the network transports, MCP
// (JSON-RPC 2.0 over TCP through the SDK MCP client transport) and embedded
// (in-process, --transport embedded).
func CLIProtocols() []ProtocolType {
	return []ProtocolType{ProtocolUnix, ProtocolREST, ProtocolGRPC, ProtocolQUIC, ProtocolMCP, ProtocolEmbedded}
}

// RemoteProtocols returns protocols that require a remote server connection.
// Excludes embedded mode which runs locally without a server.
// MCP is excluded due to SDK transport / server protocol mismatch (HTTP vs JSON-RPC).
func RemoteProtocols() []ProtocolType {
	return []ProtocolType{ProtocolUnix, ProtocolREST, ProtocolGRPC, ProtocolQUIC}
}

// LocalProtocols returns protocols that run locally without a server.
func LocalProtocols() []ProtocolType {
	return []ProtocolType{ProtocolEmbedded}
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
	TLSCACert      string
	// ClientCert, ClientKey and Token identify the caller on every remote
	// transport: the server refuses anonymous (adaptive) auth. The API stack
	// supplies the first-boot admin credential through KEYSTORE_TLS_CERT/KEY.
	ClientCert string
	ClientKey  string
	Token      string
}

// NewTestRunner creates a new test runner with default configuration
func NewTestRunner() *TestRunner {
	projectRoot := getProjectRoot()
	defaultCLIPath := filepath.Join(projectRoot, "build", "bin", "xkmsctl")

	return &TestRunner{
		CLIBinPath:     getEnv("KEYSTORE_CLI_BIN", defaultCLIPath),
		UnixSocketPath: getEnv("KEYSTORE_UNIX_SOCKET", "/var/run/xkms/xkms.sock"),
		RESTBaseURL:    getEnv("KEYSTORE_REST_URL", "http://localhost:8443"),
		GRPCAddr:       getEnv("KEYSTORE_GRPC_ADDR", "localhost:9443"),
		QUICBaseURL:    getEnv("KEYSTORE_QUIC_URL", "https://localhost:8444"),
		MCPAddr:        getEnv("KEYSTORE_MCP_ADDR", "localhost:9444"),
		KeyDir:         "",
		Backend:        "software",
		Timeout:        30 * time.Second,
		Verbose:        getEnv("VERBOSE", "") != "",
		TLSCACert:      getEnv("KEYSTORE_TLS_CA", "/etc/xkms/certs/ca.crt"),
		ClientCert:     getEnv("KEYSTORE_TLS_CERT", ""),
		ClientKey:      getEnv("KEYSTORE_TLS_KEY", ""),
		Token:          getEnv("KEYSTORE_TOKEN", ""),
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

// GetServerURL returns the server URL for a protocol.
// Returns empty string for embedded protocol (which uses --local flag instead).
func (r *TestRunner) GetServerURL(protocol ProtocolType) string {
	switch protocol {
	case ProtocolUnix:
		return "unix://" + r.UnixSocketPath
	case ProtocolREST:
		return r.RESTBaseURL
	case ProtocolGRPC:
		return "grpcs://" + r.GRPCAddr
	case ProtocolQUIC:
		return "quic://" + strings.TrimPrefix(strings.TrimPrefix(r.QUICBaseURL, "https://"), "http://")
	case ProtocolMCP:
		// The integration server serves MCP on its TLS listener (tls.enabled
		// in config.test.yaml); mcp:// would make the SDK speak plaintext.
		return "mcps://" + r.MCPAddr
	case ProtocolEmbedded:
		// Embedded mode uses --local flag, no server URL needed
		return ""
	default:
		return ""
	}
}

// IsEmbeddedProtocol returns true if the protocol is embedded (local) mode
func IsEmbeddedProtocol(protocol ProtocolType) bool {
	return protocol == ProtocolEmbedded
}

// IsRemoteProtocol returns true if the protocol requires a remote server
func IsRemoteProtocol(protocol ProtocolType) bool {
	return protocol != ProtocolEmbedded
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
// Integration tests run in Docker where CLI is built automatically.
func (r *TestRunner) RequireCLI(t *testing.T) {
	t.Helper()

	if !r.IsCLIAvailable(t) {
		t.Fatal("CLI binary not available. Run 'make build' for local testing or use 'make integration-test-cli' for Docker-based tests.")
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

	return r.RunCommand(t, r.protocolArgs(protocol, args)...)
}

// protocolArgs prefixes args with the flags that select protocol: the
// server URL and TLS CA for a network transport, or --transport embedded
// and the runner's key directory for embedded (each once: a RequiresLocal
// command already carries --transport embedded, a RequiresKeyDir one its
// --key-dir).
func (r *TestRunner) protocolArgs(protocol ProtocolType, args []string) []string {
	prefixArgs := []string{}

	if protocol == ProtocolEmbedded {
		if !slices.Contains(args, "--transport") {
			prefixArgs = append(prefixArgs, "--transport", "embedded")
		}
		if r.KeyDir != "" && !slices.Contains(args, "--key-dir") {
			prefixArgs = append(prefixArgs, "--key-dir", r.KeyDir)
		}
		return append(prefixArgs, args...)
	}

	serverURL := r.GetServerURL(protocol)
	if serverURL != "" {
		prefixArgs = append(prefixArgs, "--server", serverURL)
	}

	// Add TLS options for protocols that use TLS (REST with HTTPS, gRPC,
	// QUIC, MCP over mcps://).
	needsTLS := protocol == ProtocolREST && strings.HasPrefix(r.RESTBaseURL, "https://") ||
		protocol == ProtocolGRPC ||
		protocol == ProtocolQUIC ||
		protocol == ProtocolMCP

	if needsTLS && r.TLSCACert != "" {
		prefixArgs = append(prefixArgs, "--tls-ca", r.TLSCACert)
	}

	// Client credentials go to every remote transport; a value the
	// command already carries wins.
	for _, cred := range []struct{ flag, value string }{
		{"--tls-cert", r.ClientCert},
		{"--tls-key", r.ClientKey},
		{"--token", r.Token},
	} {
		if cred.value != "" && !slices.Contains(args, cred.flag) {
			prefixArgs = append(prefixArgs, cred.flag, cred.value)
		}
	}

	return append(prefixArgs, args...)
}

// BuildCommandArgs builds the full argument list for a command definition
func (r *TestRunner) BuildCommandArgs(cmd CommandDefinition, overrides map[string]string) []string {
	args := make([]string, 0)

	// Add --transport embedded first if required (for FROST and other embedded-only commands)
	if cmd.RequiresLocal {
		args = append(args, "--transport", "embedded")
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
	//
	// A boolean flag is emitted bare, and is emitted whether or not it appears
	// in the overrides: it carries no value, so an empty Value is the normal
	// case for one rather than a signal that it was left unset. The flag names
	// this used to test for -- "dealer" and "local" -- matched no command
	// definition in this package, so every boolean argument fell through to the
	// value-carrying branch and was either dropped or passed a value the flag
	// does not accept.
	for _, arg := range cmd.OptionalArgs {
		if arg.IsBoolean {
			args = append(args, "--"+arg.Flag)
			continue
		}
		if value, ok := overrides[arg.Flag]; ok {
			args = append(args, "--"+arg.Flag, value)
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
	keyIDs := uniqueKeyIDs(runID)

	// Track signature from key-sign for use in key-verify
	var capturedSignature string

	// Per-run work dir for file arguments, seeded with raw AES-256 material
	// for key wrap/import (#2321 slice f).
	workDir := t.TempDir()
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatalf("key material: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, MatrixKeyMaterialFile), material, 0o600); err != nil {
		t.Fatalf("write key material: %v", err)
	}

	// Commands that passed in this run; a SetupSteps command runs only after
	// all its steps passed.
	passed := map[string]bool{}

	for _, cmd := range AllCommands() {
		// Skip commands this cell cannot run, naming the reason
		if reason, skip := SkipReason(cmd, protocol, enabledTags); skip {
			t.Logf("Skipping (%s, %s) %s: %s", cmd.Category, protocol, cmd.Name, reason)
			continue
		}
		if step, ok := failedSetupStep(cmd, passed); ok {
			t.Logf("Skipping (%s, %s) %s: setup step %s did not pass", cmd.Category, protocol, cmd.Name, step)
			continue
		}

		overrides := commandOverrides(cmd, protocol, runID, keyIDs, workDir)

		// For key-verify, use the captured signature from key-sign
		if cmd.Name == "key-verify" && capturedSignature != "" {
			overrides["Signature"] = capturedSignature
		}

		// Skip server-required commands if testing version, etc.
		if !cmd.RequiresServer {
			result := r.RunCommandTest(t, protocol, cmd, overrides)
			results = append(results, result)
			passed[cmd.Name] = result.Passed
			continue
		}

		t.Run(cmd.Name, func(t *testing.T) {
			result := r.RunCommandTest(t, protocol, cmd, overrides)
			if reason, skip := unsupportedOnBackend(cmd, result); skip {
				t.Skipf("(%s, %s) %s: %s", cmd.Category, protocol, cmd.Name, reason)
			}
			results = append(results, result)
			passed[cmd.Name] = result.Passed

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

// commandOverrides builds the per-cell argument overrides for cmd: unique
// key IDs, a per-protocol CA common name and work-dir file paths.
func commandOverrides(cmd CommandDefinition, protocol ProtocolType, runID int64, keyIDs map[string]string, workDir string) map[string]string {
	overrides := make(map[string]string)
	for _, arg := range cmd.RequiredArgs {
		if arg.Description == "Key ID" {
			if uniqueID, ok := keyIDs[arg.Value]; ok {
				overrides[arg.Description] = uniqueID
			}
		}
		// Make CA issue CN unique per protocol+run to avoid "certificate
		// already exists". Including the protocol prevents collisions when two
		// RunAllCommandsForProtocol calls share a runID (coarse clock).
		if arg.Flag == "cn" && cmd.Category == CategoryCA {
			// BuildCommandArgs reads non-positional overrides by flag.
			overrides[arg.Flag] = fmt.Sprintf("%s-%s-%d", arg.Value, protocol, runID)
		}
		if strings.Contains(arg.Value, MatrixWorkDir) {
			key := arg.Flag
			if arg.IsPositional {
				key = arg.Description
			}
			overrides[key] = strings.ReplaceAll(arg.Value, MatrixWorkDir, workDir)
		}
	}
	// Create-chain identifiers get a per-transport name, keyed the way
	// BuildCommandArgs reads overrides (positional by description).
	names := perTransportNames(protocol, runID)
	for _, arg := range append(slices.Clone(cmd.RequiredArgs), cmd.OptionalArgs...) {
		name, ok := names[arg.Value]
		if !ok {
			continue
		}
		key := arg.Flag
		if arg.IsPositional {
			key = arg.Description
		}
		overrides[key] = name
	}
	return overrides
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

// uniqueKeyIDs maps each key identifier that appears literally in a command
// definition to a per-run unique one.
//
// The suite runs every command against every protocol in a single process, so a
// literal identifier is created by the first protocol and then collides on the
// remaining five with "key already exists". A command whose key ID is missing
// from this map therefore passes exactly once and fails five times, which reads
// as a protocol-specific defect rather than a test-fixture one.
//
// TestEveryKeyIDIsUniquified pins the correspondence, so a new command
// definition that forgets an entry fails in the unit suite rather than ten
// minutes into a container run.
func uniqueKeyIDs(runID int64) map[string]string {
	return map[string]string{
		"test-rsa-key":     fmt.Sprintf("test-rsa-key-%d", runID),
		"test-ecdsa-key":   fmt.Sprintf("test-ecdsa-key-%d", runID),
		"test-ed25519-key": fmt.Sprintf("test-ed25519-key-%d", runID),
		"test-key":         fmt.Sprintf("test-rsa-key-%d", runID), // Use RSA key for sign/verify/delete
		"frost-test-key":   fmt.Sprintf("frost-test-key-%d", runID),
		"frost-dealer-key": fmt.Sprintf("frost-dealer-key-%d", runID),

		"test-symmetric-exportable": fmt.Sprintf("test-symmetric-exportable-%d", runID),
		"test-symmetric-sensitive":  fmt.Sprintf("test-symmetric-sensitive-%d", runID),
		"test-import-key":           fmt.Sprintf("test-import-key-%d", runID),
	}
}

// perTransportNames maps each literal create-chain identifier (tenant,
// user, OIDC credential, backend credential) to a name unique to the
// protocol and run, so the chains of two transports never collide on the
// shared server. The email keeps its domain.
func perTransportNames(protocol ProtocolType, runID int64) map[string]string {
	names := map[string]string{
		"it-user@example.com": fmt.Sprintf("it-user-%s-%d@example.com", protocol, runID),
	}
	for _, base := range []string{"it-tenant", "it-user", "it-oidc", "it-credential"} {
		names[base] = fmt.Sprintf("%s-%s-%d", base, protocol, runID)
	}
	return names
}
