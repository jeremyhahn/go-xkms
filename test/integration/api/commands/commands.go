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

	// BuildTags are build tags required for this command (e.g., "frost")
	BuildTags []string

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
	return append(append(append(append(append(
		BackendCommands(),
		KeyCommands()...),
		CertCommands()...),
		TLSCommands()...),
		FrostCommands()...),
		VersionCommands()...)
}

// VersionCommands returns version-related commands
func VersionCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:           "version",
			Category:       CategoryVersion,
			Command:        []string{"version"},
			Description:    "Show version information",
			RequiresServer: false,
			ExpectedOutputContains: []string{"version"},
		},
	}
}

// BackendCommands returns backend-related commands
func BackendCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:           "backends-list",
			Category:       CategoryBackends,
			Command:        []string{"backends", "list"},
			Description:    "List available backends",
			RequiresServer: true,
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
func FrostCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:           "frost-list",
			Category:       CategoryFrost,
			Command:        []string{"frost", "list"},
			Description:    "List FROST keys",
			RequiresKeyDir: true,
			RequiresServer: false, // FROST commands are local-only
			BuildTags:      []string{"frost"},
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
