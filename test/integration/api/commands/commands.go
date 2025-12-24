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

// Package commands provides a centralized definition of all CLI commands
// for integration testing across all protocols. This ensures API parity
// between REST, gRPC, QUIC, MCP, and Unix socket interfaces.
package commands

// CommandCategory represents a category of commands
type CommandCategory string

const (
	CategoryBackend  CommandCategory = "backend"
	CategoryKey      CommandCategory = "key"
	CategoryCert     CommandCategory = "cert"
	CategoryTLS      CommandCategory = "tls"
	CategoryFrost    CommandCategory = "frost"
	CategoryFIDO2    CommandCategory = "fido2"
	CategoryUser     CommandCategory = "user"
	CategoryAdmin    CommandCategory = "admin"
	CategoryVersion  CommandCategory = "version"
	CategoryBackends CommandCategory = "backends"
)

// CommandDefinition defines a CLI command with its arguments and expected behavior
type CommandDefinition struct {
	// Name is the human-readable name of this command
	Name string

	// Category is the command category
	Category CommandCategory

	// Command is the CLI command parts (e.g., []string{"key", "generate"})
	Command []string

	// RequiredArgs are arguments that must be provided
	RequiredArgs []ArgDefinition

	// OptionalArgs are arguments that may be provided
	OptionalArgs []ArgDefinition

	// Description describes what this command does
	Description string

	// RequiresBackend indicates if this command needs a backend parameter
	RequiresBackend bool

	// RequiresKeyDir indicates if this command needs a key directory
	RequiresKeyDir bool

	// RequiresServer indicates if this command requires a server connection
	RequiresServer bool

	// RequiresLocal indicates if this command needs --local flag (no server connection)
	RequiresLocal bool

	// BuildTags are build tags required for this command (e.g., "frost")
	BuildTags []string

	// RequiresSetup indicates this command needs prior setup (e.g., key must exist)
	// Commands with RequiresSetup=true are skipped in standalone tests but run in workflow tests
	RequiresSetup bool

	// ExpectedOutputContains are strings that should be in successful output
	ExpectedOutputContains []string
}

// ArgDefinition defines a command argument
type ArgDefinition struct {
	// Flag is the flag name (without --)
	Flag string

	// Value is the default/example value
	Value string

	// Description describes the argument
	Description string

	// IsPositional indicates if this is a positional argument
	IsPositional bool
}

// AllCommands returns all CLI commands for testing
func AllCommands() []CommandDefinition {
	return append(append(append(append(append(append(
		BackendCommands(),
		KeyCommands()...),
		CertCommands()...),
		TLSCommands()...),
		FrostCommands()...),
		FIDO2Commands()...),
		VersionCommands()...)
}

// VersionCommands returns version-related commands
func VersionCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:                   "version",
			Category:               CategoryVersion,
			Command:                []string{"version"},
			Description:            "Show version information",
			RequiresServer:         false,
			ExpectedOutputContains: []string{"version"},
		},
	}
}

// BackendCommands returns backend-related commands
func BackendCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:                   "backends-list",
			Category:               CategoryBackends,
			Command:                []string{"backends", "list"},
			Description:            "List available backends",
			RequiresServer:         true,
			ExpectedOutputContains: []string{"software"},
		},
	}
}

// KeyCommands returns key management commands
func KeyCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:            "key-generate-rsa",
			Category:        CategoryKey,
			Command:         []string{"key", "generate"},
			Description:     "Generate RSA signing key",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-rsa-key", Description: "Key ID", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "key-type", Value: "rsa", Description: "Key type"},
				{Flag: "key-algorithm", Value: "rsa", Description: "Algorithm"},
				{Flag: "key-size", Value: "2048", Description: "Key size"},
			},
		},
		{
			Name:            "key-generate-ecdsa",
			Category:        CategoryKey,
			Command:         []string{"key", "generate"},
			Description:     "Generate ECDSA signing key",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-ecdsa-key", Description: "Key ID", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "key-type", Value: "ecdsa", Description: "Key type"},
				{Flag: "key-algorithm", Value: "ecdsa", Description: "Algorithm"},
				{Flag: "curve", Value: "P-256", Description: "Curve"},
			},
		},
		{
			Name:            "key-generate-ed25519",
			Category:        CategoryKey,
			Command:         []string{"key", "generate"},
			Description:     "Generate Ed25519 signing key",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-ed25519-key", Description: "Key ID", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "key-type", Value: "ed25519", Description: "Key type"},
				{Flag: "key-algorithm", Value: "ed25519", Description: "Algorithm"},
			},
		},
		{
			Name:            "key-list",
			Category:        CategoryKey,
			Command:         []string{"key", "list"},
			Description:     "List keys in backend",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
		},
		{
			Name:            "key-info",
			Category:        CategoryKey,
			Command:         []string{"key", "info"},
			Description:     "Show key information",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-key", Description: "Key ID", IsPositional: true},
			},
		},
		{
			Name:            "key-sign",
			Category:        CategoryKey,
			Command:         []string{"key", "sign"},
			Description:     "Sign data with key",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-key", Description: "Key ID", IsPositional: true},
				{Flag: "", Value: "test data to sign", Description: "Data", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "hash", Value: "SHA-256", Description: "Hash algorithm"},
			},
		},
		{
			Name:            "key-verify",
			Category:        CategoryKey,
			Command:         []string{"key", "verify"},
			Description:     "Verify signature",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-key", Description: "Key ID", IsPositional: true},
				{Flag: "", Value: "test data to sign", Description: "Data", IsPositional: true},
				// Use valid base64 placeholder - will fail verification but won't cause decode error
				{Flag: "", Value: "dGVzdHNpZ25hdHVyZQ==", Description: "Signature", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "hash", Value: "SHA-256", Description: "Hash algorithm"},
			},
		},
		{
			Name:            "key-delete",
			Category:        CategoryKey,
			Command:         []string{"key", "delete"},
			Description:     "Delete a key",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-key", Description: "Key ID", IsPositional: true},
			},
		},
	}
}

// CertCommands returns certificate-related commands
func CertCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:            "cert-list",
			Category:        CategoryCert,
			Command:         []string{"cert", "list"},
			Description:     "List certificates",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
		},
		{
			Name:            "cert-info",
			Category:        CategoryCert,
			Command:         []string{"cert", "info"},
			Description:     "Show certificate information",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-key", Description: "Key ID", IsPositional: true},
			},
		},
	}
}

// TLSCommands returns TLS-related commands
func TLSCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:            "tls-cert",
			Category:        CategoryTLS,
			Command:         []string{"tls", "cert"},
			Description:     "Get TLS certificate bundle",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-key", Description: "Key ID", IsPositional: true},
			},
		},
	}
}

// FrostCommands returns FROST threshold signature commands
// NOTE: FROST commands are local-only operations that work directly with the FROST backend.
// They do not require server connections - they use local file storage for key packages.
// These command definitions are for testing the CLI argument parsing and local operations.
//
// Commands included:
// - frost-keygen-participant: Generate key for a single participant
// - frost-keygen-dealer: Generate all participant keys (trusted dealer mode)
// - frost-list: List all FROST keys
// - frost-info: Show FROST key details
// - frost-delete: Delete a FROST key
//
// Signing ceremony commands (round1, round2, aggregate, verify) are tested as
// workflow tests in frost_parity_test.go since they require coordinated state.
func FrostCommands() []CommandDefinition {
	return []CommandDefinition{
		// Keygen - Participant mode
		{
			Name:           "frost-keygen-participant",
			Category:       CategoryFrost,
			Command:        []string{"frost", "keygen"},
			Description:    "Generate FROST key (participant mode)",
			RequiresKeyDir: true,
			RequiresServer: false,
			RequiresLocal:  true,
			BuildTags:      []string{"frost"},
			RequiredArgs: []ArgDefinition{
				{Flag: "key-id", Value: "frost-test-key", Description: "Key ID"},
				{Flag: "threshold", Value: "2", Description: "Threshold"},
				{Flag: "total", Value: "3", Description: "Total participants"},
				{Flag: "participant-id", Value: "1", Description: "Participant ID"},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "algorithm", Value: "FROST-Ed25519-SHA512", Description: "Algorithm"},
			},
		},
		// Keygen - Dealer mode (generates all participant keys)
		{
			Name:           "frost-keygen-dealer",
			Category:       CategoryFrost,
			Command:        []string{"frost", "keygen"},
			Description:    "Generate FROST keys (dealer mode)",
			RequiresKeyDir: true,
			RequiresServer: false,
			RequiresLocal:  true,
			BuildTags:      []string{"frost"},
			RequiredArgs: []ArgDefinition{
				{Flag: "key-id", Value: "frost-dealer-key", Description: "Key ID"},
				{Flag: "threshold", Value: "2", Description: "Threshold"},
				{Flag: "total", Value: "3", Description: "Total participants"},
				{Flag: "export-dir", Value: "/tmp/frost-packages", Description: "Export directory"},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "algorithm", Value: "FROST-Ed25519-SHA512", Description: "Algorithm"},
				{Flag: "participants", Value: "alice,bob,charlie", Description: "Participant names"},
			},
		},
		// List keys
		{
			Name:           "frost-list",
			Category:       CategoryFrost,
			Command:        []string{"frost", "list"},
			Description:    "List FROST keys",
			RequiresKeyDir: true,
			RequiresServer: false,
			RequiresLocal:  true,
			BuildTags:      []string{"frost"},
		},
		// Info - show key details (requires key to exist first)
		{
			Name:           "frost-info",
			Category:       CategoryFrost,
			Command:        []string{"frost", "info"},
			Description:    "Show FROST key details",
			RequiresKeyDir: true,
			RequiresServer: false,
			RequiresLocal:  true,
			BuildTags:      []string{"frost"},
			RequiresSetup:  true, // Requires key to exist
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "frost-test-key", Description: "Key ID", IsPositional: true},
			},
		},
		// Delete key (requires key to exist first)
		{
			Name:           "frost-delete",
			Category:       CategoryFrost,
			Command:        []string{"frost", "delete"},
			Description:    "Delete FROST key",
			RequiresKeyDir: true,
			RequiresServer: false,
			RequiresLocal:  true,
			BuildTags:      []string{"frost"},
			RequiresSetup:  true, // Requires key to exist
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "frost-test-key", Description: "Key ID", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "force", Value: "", Description: "Skip confirmation"},
			},
		},
	}
}

// FIDO2Commands returns FIDO2/WebAuthn-related commands
// These commands interact with FIDO2 security keys (CanoKey, YubiKey, etc.)
func FIDO2Commands() []CommandDefinition {
	return []CommandDefinition{
		// List devices
		{
			Name:                   "fido2-list-devices",
			Category:               CategoryFIDO2,
			Command:                []string{"fido2", "list-devices"},
			Description:            "List connected FIDO2 security keys",
			RequiresServer:         false,
			RequiresLocal:          true,
			BuildTags:              []string{"fido2"},
			ExpectedOutputContains: []string{},
		},
		// Wait for device
		{
			Name:           "fido2-wait-device",
			Category:       CategoryFIDO2,
			Command:        []string{"fido2", "wait-device"},
			Description:    "Wait for a FIDO2 device to be connected",
			RequiresServer: false,
			RequiresLocal:  true,
			BuildTags:      []string{"fido2"},
			OptionalArgs: []ArgDefinition{
				{Flag: "timeout", Value: "30s", Description: "Timeout for device wait"},
			},
		},
		// Register credential
		{
			Name:           "fido2-register",
			Category:       CategoryFIDO2,
			Command:        []string{"fido2", "register"},
			Description:    "Register a new FIDO2 credential",
			RequiresServer: false,
			RequiresLocal:  true,
			BuildTags:      []string{"fido2"},
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "testuser", Description: "Username", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "rp-id", Value: "go-keychain.local", Description: "Relying party ID"},
				{Flag: "rp-name", Value: "Go Keychain Test", Description: "Relying party name"},
				{Flag: "display-name", Value: "Test User", Description: "User display name"},
				{Flag: "timeout", Value: "60s", Description: "User presence timeout"},
				{Flag: "device", Value: "", Description: "Specific device path"},
				{Flag: "user-verification", Value: "", Description: "Require PIN verification"},
			},
		},
		// Authenticate
		{
			Name:           "fido2-authenticate",
			Category:       CategoryFIDO2,
			Command:        []string{"fido2", "authenticate"},
			Description:    "Authenticate using a registered FIDO2 credential",
			RequiresServer: false,
			RequiresLocal:  true,
			BuildTags:      []string{"fido2"},
			RequiresSetup:  true, // Requires credential to be registered first
			RequiredArgs: []ArgDefinition{
				{Flag: "credential-id", Value: "", Description: "Credential ID from registration"},
				{Flag: "salt", Value: "", Description: "Salt from registration"},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "rp-id", Value: "go-keychain.local", Description: "Relying party ID"},
				{Flag: "timeout", Value: "60s", Description: "User presence timeout"},
				{Flag: "device", Value: "", Description: "Specific device path"},
				{Flag: "user-verification", Value: "", Description: "Require PIN verification"},
				{Flag: "hex", Value: "", Description: "Output in hex instead of base64"},
			},
		},
		// Device info
		{
			Name:           "fido2-info",
			Category:       CategoryFIDO2,
			Command:        []string{"fido2", "info"},
			Description:    "Show information about a connected FIDO2 device",
			RequiresServer: false,
			RequiresLocal:  true,
			BuildTags:      []string{"fido2"},
			OptionalArgs: []ArgDefinition{
				{Flag: "device", Value: "", Description: "Specific device path"},
			},
		},
	}
}

// CommandsByCategory returns commands filtered by category
func CommandsByCategory(category CommandCategory) []CommandDefinition {
	var result []CommandDefinition
	for _, cmd := range AllCommands() {
		if cmd.Category == category {
			result = append(result, cmd)
		}
	}
	return result
}

// CommandsRequiringBuildTag returns commands that require a specific build tag
func CommandsRequiringBuildTag(tag string) []CommandDefinition {
	var result []CommandDefinition
	for _, cmd := range AllCommands() {
		for _, t := range cmd.BuildTags {
			if t == tag {
				result = append(result, cmd)
				break
			}
		}
	}
	return result
}

// CommandsWithoutBuildTags returns commands that don't require special build tags
func CommandsWithoutBuildTags() []CommandDefinition {
	var result []CommandDefinition
	for _, cmd := range AllCommands() {
		if len(cmd.BuildTags) == 0 {
			result = append(result, cmd)
		}
	}
	return result
}
