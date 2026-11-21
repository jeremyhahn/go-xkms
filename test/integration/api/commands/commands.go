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

// Package commands provides a centralized definition of all CLI commands
// for integration testing across all protocols. This ensures API parity
// between REST, gRPC, QUIC, MCP, and Unix socket interfaces.
package commands

import "slices"

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
	CategoryACME     CommandCategory = "acme"
	CategoryVersion  CommandCategory = "version"
	CategoryBackends CommandCategory = "backends"
	CategorySealing  CommandCategory = "sealing"
	CategoryCA       CommandCategory = "ca"
	CategoryPolicy   CommandCategory = "policy"

	CategoryTenant     CommandCategory = "tenant"
	CategoryAuth       CommandCategory = "auth"
	CategoryCredential CommandCategory = "credential"
	CategoryOIDC       CommandCategory = "oidc"
	CategoryPassword   CommandCategory = "password"
	CategoryPIN        CommandCategory = "pin"
	CategoryPIV        CommandCategory = "piv"
	CategoryPlatform   CommandCategory = "platform"
	CategoryServer     CommandCategory = "server"
	CategoryAlgorithms CommandCategory = "algorithms"
	CategoryCluster    CommandCategory = "cluster"
	CategoryRebalance  CommandCategory = "rebalance"
	CategoryBootstrap  CommandCategory = "bootstrap"
)

// Skip reasons shared by the account families (row #2321 slice c).
const (
	skipChain = "requires prior setup (workflow tests; later #2321 slices)"
	// skipFIDO2 names commands that need a FIDO2 authenticator touch.
	skipFIDO2 = "needs a FIDO2 authenticator (user presence); the compose stack has none"
	// skipNoOIDCProvider names oidc verbs that need a live identity provider.
	skipNoOIDCProvider = "needs an OIDC provider; the compose stack configures none"
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

	// Workflow names the ordered workflow test that runs this command with
	// its setup (e.g. platform put before get). The matrix counts it as a
	// run; the standalone run leaves it to that test.
	Workflow string

	// Transports, when set, are the only transports the command runs on;
	// every other cell is skipped with TransportSkip as the reason.
	Transports []ProtocolType

	// TransportSkip names why a transport outside Transports cannot run it.
	TransportSkip string

	// Unsupported, when set, is why no cell can run the command in the
	// integration environment (e.g. no DNS zone serving TLSA records).
	Unsupported string
	// SetupSteps names the commands (by Name) that set this command up. They
	// come earlier in AllCommands, so one ordered pass runs them first; a
	// RequiresSetup command with SetupSteps runs in the matrix and is skipped,
	// naming the step, only when a step did not pass in the same run.
	SetupSteps []string

	// SkipWhenOutputContains lists failure output that means the cell cannot
	// run on this backend (e.g. no attestation); the cell is then skipped with
	// SkipWhenReason instead of failing.
	SkipWhenOutputContains []string

	// SkipWhenReason is the skip reason logged for SkipWhenOutputContains.
	SkipWhenReason string

	// ExpectedOutputContains are strings that should be in successful output
	ExpectedOutputContains []string

	// Skip, when non-empty, is the reason the matrix skips this command on
	// every transport (e.g. the integration stack cannot serve it).
	Skip string
}

// MatrixWorkDir is the placeholder an argument value uses for the per-run
// working directory the runner creates; it holds MatrixKeyMaterialFile.
const MatrixWorkDir = "{{workdir}}"

// MatrixKeyMaterialFile is the raw AES-256 key material file the runner
// writes into MatrixWorkDir before the run, for key wrap and import.
const MatrixKeyMaterialFile = "key-material.bin"

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

	// IsBoolean marks a flag that takes no value, so the runner emits "--flag"
	// rather than "--flag <value>". Without it a boolean argument has to carry a
	// non-empty Value to be emitted at all, and that Value is then passed to a
	// flag that accepts none.
	IsBoolean bool
}

// AllCommands returns all CLI commands for testing
func AllCommands() []CommandDefinition {
	// Order matters: the standalone run executes commands in this order.
	return slices.Concat(
		BackendCommands(),
		KeyCommands(),
		CertCommands(),
		TLSCommands(),
		FrostCommands(),
		FIDO2Commands(),
		SealingCommands(),
		CACommands(),
		PolicyCommands(),
		ACMECommands(),
		AdminCommands(),
		VersionCommands(),
		TenantCommands(),
		UserCommands(),
		AuthCommands(),
		CredentialCommands(),
		OIDCCommands(),
		PasswordCommands(),
		PINCommands(),
		PIVCommands(),
		ServerCommands(),
		AlgorithmsCommands(),
		PlatformCommands(),
		ClusterCommands(),
		RebalanceCommands(),
		BootstrapCommands(),
	)
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
		// The protection flags are exercised here because they are the only key
		// attributes the CLI can set that change what the daemon will later
		// release. --exportable and --sensitive are independent: a sensitive key
		// may still be wrapped out under another key, but its plaintext is never
		// returned. Generating with both set proves the pair survives every
		// transport, which is where a field added to the request struct but not
		// mapped in one transport's handler would show up.
		{
			Name:            "key-generate-symmetric-exportable",
			Category:        CategoryKey,
			Command:         []string{"key", "generate"},
			Description:     "Generate an exportable symmetric key",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-symmetric-exportable", Description: "Key ID", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "key-type", Value: "symmetric", Description: "Key type"},
				{Flag: "key-size", Value: "256", Description: "Key size"},
				{Flag: "exportable", Value: "", Description: "Allow export", IsBoolean: true},
			},
		},
		{
			Name:            "key-generate-symmetric-sensitive",
			Category:        CategoryKey,
			Command:         []string{"key", "generate"},
			Description:     "Generate a sensitive symmetric key whose plaintext is never released",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-symmetric-sensitive", Description: "Key ID", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "key-type", Value: "symmetric", Description: "Key type"},
				{Flag: "key-size", Value: "256", Description: "Key size"},
				{Flag: "exportable", Value: "", Description: "Allow wrapping", IsBoolean: true},
				{Flag: "sensitive", Value: "", Description: "Never release plaintext", IsBoolean: true},
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
		// Lifecycle verbs (#2321 slice f) run between key-verify and
		// key-delete, so test-key still exists and the version verbs see the
		// versions key-rotate made.
		keyServerCommand("key-rotate", "Rotate a key to a new version", []string{"key", "rotate"},
			[]string{"key-generate-rsa"}, keyIDArg("test-key")),
		keyServerCommand("key-versions", "List the versions of a key", []string{"key", "versions"},
			[]string{"key-rotate"}, keyIDArg("test-key")),
		keyServerCommand("key-version-disable", "Disable key version 1", []string{"key", "version", "disable"},
			[]string{"key-rotate"}, keyIDArg("test-key"), versionArg("1")),
		keyServerCommand("key-version-enable", "Re-enable key version 1", []string{"key", "version", "enable"},
			[]string{"key-version-disable"}, keyIDArg("test-key"), versionArg("1")),
		keyServerCommand("key-version-disable-all", "Disable every version of a key", []string{"key", "version", "disable-all"},
			[]string{"key-rotate"}, keyIDArg("test-key")),
		keyServerCommand("key-version-enable-all", "Re-enable every version of a key", []string{"key", "version", "enable-all"},
			[]string{"key-version-disable-all"}, keyIDArg("test-key")),
		keyServerCommand("key-version-retire", "Retire key version 1", []string{"key", "version", "retire"},
			[]string{"key-version-enable-all"}, keyIDArg("test-key"), versionArg("1")),
		{
			Name:           "key-rotate-all",
			Category:       CategoryKey,
			Command:        []string{"key", "rotate-all"},
			Description:    "Rotate every key of the caller's tenant",
			RequiresServer: true,
			RequiresSetup:  true,
			SetupSteps:     []string{"key-generate-rsa"},
		},
		// Import path: the runner writes raw AES-256 material into the work
		// dir; get-import-params fetches the wrapping key, wrap seals the
		// material under it, unwrap opens it again and import stores it.
		keyServerCommand("key-get-import-params", "Fetch the wrapping key for an AES-256 import", []string{"key", "get-import-params"},
			nil, keyIDArg("test-import-key"),
			ArgDefinition{Flag: "key-algorithm", Value: "aes", Description: "Key algorithm"},
			ArgDefinition{Flag: "key-size", Value: "256", Description: "Key size"},
			ArgDefinition{Flag: "output", Value: MatrixWorkDir + "/import-params.json", Description: "Params output"}),
		keyServerCommand("key-wrap", "Wrap key material under the import parameters", []string{"key", "wrap"},
			[]string{"key-get-import-params"},
			fileArg(MatrixWorkDir+"/"+MatrixKeyMaterialFile, "Key material file"),
			fileArg(MatrixWorkDir+"/import-params.json", "Params file"),
			fileArg(MatrixWorkDir+"/wrapped.json", "Wrapped output file")),
		keyServerCommand("key-unwrap", "Unwrap the wrapped key material", []string{"key", "unwrap"},
			[]string{"key-wrap"},
			fileArg(MatrixWorkDir+"/wrapped.json", "Wrapped input file"),
			fileArg(MatrixWorkDir+"/import-params.json", "Params file"),
			fileArg(MatrixWorkDir+"/unwrapped.bin", "Unwrapped output file")),
		keyServerCommand("key-import", "Import the wrapped AES-256 key", []string{"key", "import"},
			[]string{"key-wrap"}, keyIDArg("test-import-key"),
			fileArg(MatrixWorkDir+"/wrapped.json", "Wrapped input file"),
			ArgDefinition{Flag: "key-type", Value: "aes", Description: "Key type"},
			ArgDefinition{Flag: "aes-key-size", Value: "256", Description: "AES key size"}),
		keyServerCommand("key-export", "Export an exportable key wrapped for transport", []string{"key", "export"},
			[]string{"key-generate-symmetric-exportable"}, keyIDArg("test-symmetric-exportable"),
			fileArg(MatrixWorkDir+"/exported.json", "Export output file")),
		func() CommandDefinition {
			def := keyServerCommand("key-attest", "Attest a key", []string{"key", "attest"},
				[]string{"key-generate-rsa"}, keyIDArg("test-key"))
			def.SkipWhenOutputContains = []string{"not supported", "unsupported", "does not support", "Unimplemented", "not implemented"}
			def.SkipWhenReason = "backend has no key attestation (tpm2/pkcs11 backends attest)"
			return def
		}(),
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

// keyServerCommand declares a key command that runs against the server's
// backend and key dir. A non-empty setup marks it RequiresSetup with those
// SetupSteps, which run earlier in the same pass.
func keyServerCommand(name, description string, command, setup []string, args ...ArgDefinition) CommandDefinition {
	return CommandDefinition{
		Name:            name,
		Category:        CategoryKey,
		Command:         command,
		Description:     description,
		RequiresBackend: true,
		RequiresKeyDir:  true,
		RequiresServer:  true,
		RequiresSetup:   len(setup) > 0,
		SetupSteps:      setup,
		RequiredArgs:    args,
	}
}

// keyIDArg is the positional key ID; the runner maps it to the run's unique ID.
func keyIDArg(id string) ArgDefinition {
	return ArgDefinition{Value: id, Description: "Key ID", IsPositional: true}
}

// versionArg is the positional key version number.
func versionArg(version string) ArgDefinition {
	return ArgDefinition{Value: version, Description: "Version", IsPositional: true}
}

// fileArg is a positional file path; description must be unique per command
// because the runner overrides positional values by description.
func fileArg(path, description string) ArgDefinition {
	return ArgDefinition{Value: path, Description: description, IsPositional: true}
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
			// Every package is encrypted to a participant recipient key
			// (--recipient), which `frost recipient` must create first:
			// exercised by frost_parity_test.go's dealer workflows.
			RequiresSetup: true,
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
// These commands interact with FIDO2 security keys (YubiKey, etc.)
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
			Skip:           skipFIDO2,
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
			Skip:           skipFIDO2,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "testuser", Description: "Username", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "rp-id", Value: "go-xkms.local", Description: "Relying party ID"},
				{Flag: "rp-name", Value: "Go xKMS Test", Description: "Relying party name"},
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
			Skip:           skipFIDO2,
			RequiresSetup:  true, // Requires credential to be registered first
			RequiredArgs: []ArgDefinition{
				{Flag: "credential-id", Value: "", Description: "Credential ID from registration"},
				{Flag: "salt", Value: "", Description: "Salt from registration"},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "rp-id", Value: "go-xkms.local", Description: "Relying party ID"},
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
			Skip:           skipFIDO2,
			OptionalArgs: []ArgDefinition{
				{Flag: "device", Value: "", Description: "Specific device path"},
			},
		},
	}
}

// SealingCommands returns sealing-related commands for data protection
// These commands use the backend's sealing mechanism to protect data
func SealingCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name:            "seal",
			Category:        CategorySealing,
			Command:         []string{"seal"},
			Description:     "Seal data using backend's sealing mechanism",
			RequiresBackend: true,
			RequiresServer:  true,
			RequiresSetup:   true, // Requires a key to be generated first
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "test-data-to-seal", Description: "Data to seal", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "key-id", Value: "", Description: "Key ID for sealing (required for software backend)"},
				{Flag: "aad", Value: "", Description: "Additional authenticated data"},
				{Flag: "output", Value: "", Description: "Output format (json/base64)"},
			},
		},
		{
			Name:            "unseal",
			Category:        CategorySealing,
			Command:         []string{"unseal"},
			Description:     "Unseal previously sealed data",
			RequiresBackend: true,
			RequiresServer:  true,
			RequiresSetup:   true, // Requires sealed data from seal operation
			RequiredArgs: []ArgDefinition{
				{Flag: "ciphertext", Value: "", Description: "Sealed ciphertext (base64)", IsPositional: false},
				{Flag: "nonce", Value: "", Description: "Nonce from seal operation", IsPositional: false},
				{Flag: "tag", Value: "", Description: "Authentication tag from seal operation", IsPositional: false},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "aad", Value: "", Description: "Additional authenticated data (must match seal)"},
			},
		},
		{
			Name:                   "can-seal",
			Category:               CategorySealing,
			Command:                []string{"can-seal"},
			Description:            "Check if backend supports sealing operations",
			RequiresBackend:        false, // Optional - checks default if not specified
			RequiresServer:         true,
			ExpectedOutputContains: []string{"can_seal"},
		},
	}
}

// PolicyCommands returns TPM policy management commands.
//
// These manage named TPM policies (pkg/tpmpolicy) through xkmsctl's
// "tpm policy" verb group, served on every transport. Every command but
// tpm-policy-create depends on the "it-tpm-policy" policy that command
// creates, so they carry RequiresSetup like the sealing workflow's
// unseal/can-seal above.
func PolicyCommands() []CommandDefinition {
	create := []string{"tpm-policy-create"}
	return []CommandDefinition{
		{
			Name:           "tpm-policy-create",
			Category:       CategoryPolicy,
			Command:        []string{"tpm", "policy", "create"},
			Description:    "Create a TPM policy over the live PCR values",
			RequiresServer: true,
			RequiredArgs: []ArgDefinition{
				{Flag: "", Value: "it-tpm-policy", Description: "Policy name", IsPositional: true},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "bank", Value: "sha256", Description: "PCR bank"},
				{Flag: "pcrs", Value: "23", Description: "Comma-separated PCR indices"},
			},
			ExpectedOutputContains: []string{"it-tpm-policy"},
		},
		expectPolicyName(policyCommand("tpm-policy-list", "List TPM policies", []string{"tpm", "policy", "list"}, create, false)),
		expectPolicyName(policyCommand("tpm-policy-get", "Show a TPM policy", []string{"tpm", "policy", "get"}, create, true)),
		policyCommand("tpm-policy-verify", "Compare a TPM policy with the live PCR values",
			[]string{"tpm", "policy", "verify"}, create, true),
		func() CommandDefinition {
			def := policyCommand("tpm-policy-describe", "Set a TPM policy's description",
				[]string{"tpm", "policy", "describe"}, create, true)
			def.RequiredArgs = append(def.RequiredArgs,
				ArgDefinition{Value: "integration matrix policy", Description: "Description text", IsPositional: true})
			return def
		}(),
		expectPolicyName(policyCommand("tpm-policy-objects", "List the objects bound to a TPM policy",
			[]string{"tpm", "policy", "objects"}, create, true)),
		policyCommand("tpm-policy-revoke", "Withdraw a TPM policy's approval",
			[]string{"tpm", "policy", "revoke"}, create, true),
		// update after revoke: it re-captures the PCRs and re-approves.
		expectPolicyName(policyCommand("tpm-policy-update", "Re-capture a TPM policy and re-approve it",
			[]string{"tpm", "policy", "update"}, []string{"tpm-policy-revoke"}, true)),
		policyCommand("tpm-policy-auto-unseal", "Mark a TPM policy as the auto-unseal barrier",
			[]string{"tpm", "policy", "auto-unseal"}, create, true),
		func() CommandDefinition {
			def := policyCommand("tpm-policy-auto-unseal-disable", "Clear the auto-unseal mark",
				[]string{"tpm", "policy", "auto-unseal"}, []string{"tpm-policy-auto-unseal"}, true)
			def.OptionalArgs = []ArgDefinition{{Flag: "disable", Description: "Clear the mark", IsBoolean: true}}
			return def
		}(),
		{
			// The ECDSA key survives KeyCommands (key-delete removes test-key).
			Name:            "key-policy",
			Category:        CategoryPolicy,
			Command:         []string{"key", "policy"},
			Description:     "Show the TPM policy a key is bound to",
			RequiresBackend: true,
			RequiresKeyDir:  true,
			RequiresServer:  true,
			RequiresSetup:   true,
			SetupSteps:      []string{"key-generate-ecdsa"},
			RequiredArgs:    []ArgDefinition{keyIDArg("test-ecdsa-key")},
		},
		policyCommand("tpm-authority-rotate", "Rotate the TPM policy authority key",
			[]string{"tpm", "authority", "rotate"}, create, false),
		// delete last: every verb above needs the policy.
		policyCommand("tpm-policy-delete", "Delete a TPM policy", []string{"tpm", "policy", "delete"}, create, true),
	}
}

// policyCommand declares a TPM policy command that runs after its setup
// steps; named commands take the policy name as their positional argument.
func policyCommand(name, description string, command, setup []string, named bool) CommandDefinition {
	def := CommandDefinition{
		Name:           name,
		Category:       CategoryPolicy,
		Command:        command,
		Description:    description,
		RequiresServer: true,
		RequiresSetup:  true,
		SetupSteps:     setup,
	}
	if named {
		def.RequiredArgs = []ArgDefinition{
			{Flag: "", Value: "it-tpm-policy", Description: "Policy name", IsPositional: true},
		}
	}
	return def
}

// expectPolicyName makes def pass only when its output names the policy.
func expectPolicyName(def CommandDefinition) CommandDefinition {
	def.ExpectedOutputContains = []string{"it-tpm-policy"}
	return def
}

// acmeNoAdminAPI is the skip reason of every acme cell: the integration
// compose stack runs no ACME server, so --acme-server has nothing to reach.
const acmeNoAdminAPI = "integration stack serves no ACME admin API (--acme-server); needs an ACME service in docker-compose.yml (#2321)"

// adminFirstUser is the skip reason of the mutating admin cells: the stack's
// adaptive auth is anonymous only until the first user exists, so admin
// create would lock every other suite out of the shared server.
const adminFirstUser = "admin create provisions the first user, which ends the stack's anonymous adaptive auth for every other suite; needs a dedicated stack with an mTLS operator cert (#2321)"

// acmeCmd builds one acme matrix entry, skipped with acmeNoAdminAPI.
func acmeCmd(name string, parts []string, desc string, positional ...ArgDefinition) CommandDefinition {
	return CommandDefinition{
		Name:           name,
		Category:       CategoryACME,
		Command:        parts,
		Description:    desc,
		RequiresServer: true,
		RequiredArgs: append([]ArgDefinition{
			{Flag: "acme-server", Value: "https://acme:8443", Description: "ACME admin API address"},
		}, positional...),
		Skip: acmeNoAdminAPI,
	}
}

// ACMECommands returns the acme family (cmd/xkmsctl/acme*.go). The chained
// cells (eab create -> get -> list -> delete, account/cert get on a seeded
// order) are RequiresSetup.
func ACMECommands() []CommandDefinition {
	account := ArgDefinition{Flag: "", Value: "it-acme-account", Description: "ACME account ID", IsPositional: true}
	serial := ArgDefinition{Flag: "", Value: "it-acme-serial", Description: "Certificate serial", IsPositional: true}
	eab := ArgDefinition{Flag: "", Value: "it-acme-eab", Description: "EAB key ID", IsPositional: true}

	cmds := []CommandDefinition{
		acmeCmd("acme-account-list", []string{"acme", "account", "list"}, "List ACME accounts"),
		acmeCmd("acme-account-get", []string{"acme", "account", "get"}, "Show an ACME account", account),
		acmeCmd("acme-account-disable", []string{"acme", "account", "disable"}, "Disable an ACME account", account),
		acmeCmd("acme-cert-list", []string{"acme", "cert", "list"}, "List ACME-issued certificates"),
		acmeCmd("acme-cert-get", []string{"acme", "cert", "get"}, "Show an ACME-issued certificate", serial),
		acmeCmd("acme-cert-revoke", []string{"acme", "cert", "revoke"}, "Revoke an ACME-issued certificate", serial),
		acmeCmd("acme-eab-create", []string{"acme", "eab", "create"}, "Create an EAB key"),
		acmeCmd("acme-eab-get", []string{"acme", "eab", "get"}, "Show an EAB key", eab),
		acmeCmd("acme-eab-list", []string{"acme", "eab", "list"}, "List EAB keys"),
		acmeCmd("acme-eab-delete", []string{"acme", "eab", "delete"}, "Delete an EAB key", eab),
		acmeCmd("acme-status", []string{"acme", "status"}, "Show ACME server status"),
		acmeCmd("acme-stats", []string{"acme", "stats"}, "Show ACME server statistics"),
	}
	for i := range cmds {
		switch cmds[i].Name {
		case "acme-account-get", "acme-account-disable", "acme-cert-get", "acme-cert-revoke",
			"acme-eab-get", "acme-eab-list", "acme-eab-delete":
			cmds[i].RequiresSetup = true
		}
	}

	gui := acmeCmd("acme-gui", []string{"acme", "gui"}, "Open the ACME admin GUI")
	gui.BuildTags = []string{"gui"}
	gui.Skip = "acme gui opens a Wails desktop window (-tags gui); no display in the integration stack"
	return append(cmds, gui)
}

// AdminCommands returns the admin family (cmd/xkmsctl/admin.go). list and
// status are read-only and run on every transport; the create -> get ->
// disable -> enable -> delete chain is skipped with adminFirstUser.
func AdminCommands() []CommandDefinition {
	user := ArgDefinition{Flag: "", Value: "it-admin", Description: "Admin username", IsPositional: true}
	chained := func(name, verb, desc string) CommandDefinition {
		return CommandDefinition{
			Name:           name,
			Category:       CategoryAdmin,
			Command:        []string{"admin", verb},
			Description:    desc,
			RequiresServer: true,
			RequiresSetup:  true,
			RequiredArgs:   []ArgDefinition{user},
			Skip:           adminFirstUser,
		}
	}

	create := chained("admin-create", "create", "Create an mTLS administrator")
	create.RequiresSetup = false
	create.RequiredArgs = append(create.RequiredArgs,
		ArgDefinition{Flag: "method", Value: "mtls", Description: "Enrollment method"},
		ArgDefinition{Flag: "cert-file", Value: "/etc/xkms/certs/operator.crt", Description: "Operator certificate"},
	)

	return []CommandDefinition{
		create,
		chained("admin-get", "get", "Show an administrator"),
		chained("admin-disable", "disable", "Disable an administrator"),
		chained("admin-enable", "enable", "Enable an administrator"),
		chained("admin-delete", "delete", "Delete an administrator"),
		{
			Name:           "admin-list",
			Category:       CategoryAdmin,
			Command:        []string{"admin", "list"},
			Description:    "List administrator accounts",
			RequiresServer: true,
		},
		{
			Name:           "admin-status",
			Category:       CategoryAdmin,
			Command:        []string{"admin", "status"},
			Description:    "Show administrator status",
			RequiresServer: true,
		},
	}
}

// pos is a positional argument of an account-family command.
func pos(value, description string) ArgDefinition {
	return ArgDefinition{Value: value, Description: description, IsPositional: true}
}

// TenantCommands returns the tenant family (cmd/xkmsctl/tenant.go). The
// create -> show -> update-* -> delete chain mutates one fixed tenant id, so
// it is RequiresSetup: running it on six transports against one server needs
// a per-transport id, which the runner does not derive yet.
func TenantCommands() []CommandDefinition {
	id := ArgDefinition{Flag: "id", Value: "it-tenant", Description: "Tenant ID"}
	return []CommandDefinition{
		{
			Name: "tenant-create", Category: CategoryTenant,
			Command:        []string{"tenant", "create"},
			Description:    "Create a tenant",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{id,
				{Flag: "name", Value: "IT tenant", Description: "Tenant display name"}},
			OptionalArgs: []ArgDefinition{{Flag: "isolation", Value: "prefix", Description: "Isolation mode"}},
		},
		{
			Name: "tenant-list", Category: CategoryTenant,
			Command:        []string{"tenant", "list"},
			Description:    "List tenants",
			RequiresServer: true,
		},
		{
			Name: "tenant-show", Category: CategoryTenant,
			Command:        []string{"tenant", "show"},
			Description:    "Show a tenant",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs:           []ArgDefinition{id},
			ExpectedOutputContains: []string{"it-tenant"},
		},
		{
			Name: "tenant-update-entitlements", Category: CategoryTenant,
			Command:        []string{"tenant", "update-entitlements"},
			Description:    "Update a tenant's entitlements",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{id,
				{Flag: "isolation-modes", Value: "prefix,barrier", Description: "Permitted isolation modes"}},
		},
		{
			Name: "tenant-update-quotas", Category: CategoryTenant,
			Command:        []string{"tenant", "update-quotas"},
			Description:    "Update a tenant's quotas",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{id,
				{Flag: "max-keys", Value: "100", Description: "Max keys"}},
		},
		{
			Name: "tenant-delete", Category: CategoryTenant,
			Command:        []string{"tenant", "delete"},
			Description:    "Delete a tenant",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{id},
		},
	}
}

// UserCommands returns the user family (cmd/xkmsctl/user.go, user_invite.go).
// The register -> get -> update -> disable -> enable -> delete chain is
// RequiresSetup for the same per-transport naming reason as the tenant chain.
func UserCommands() []CommandDefinition {
	user := pos("it-user", "Username")
	chain := func(name string, command []string, desc string, args ...ArgDefinition) CommandDefinition {
		return CommandDefinition{
			Name: name, Category: CategoryUser, Command: command, Description: desc,
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: append([]ArgDefinition{user}, args...),
		}
	}
	return []CommandDefinition{
		chain("user-register", []string{"user", "register"}, "Register a user",
			ArgDefinition{Flag: "email", Value: "it-user@example.com", Description: "Login email"},
			ArgDefinition{Flag: "role", Value: "user", Description: "User role"}),
		{
			Name: "user-login", Category: CategoryUser,
			Command:        []string{"user", "login"},
			Description:    "Log a user in with a FIDO2 authenticator",
			RequiresServer: true, Skip: skipFIDO2,
			RequiredArgs: []ArgDefinition{pos("it-user@example.com", "Login email")},
		},
		{
			Name: "user-list", Category: CategoryUser,
			Command:        []string{"user", "list"},
			Description:    "List users",
			RequiresServer: true,
		},
		chain("user-get", []string{"user", "get"}, "Show a user"),
		chain("user-update", []string{"user", "update"}, "Update a user",
			ArgDefinition{Flag: "enable", Description: "Enable the account", IsBoolean: true}),
		chain("user-disable", []string{"user", "disable"}, "Disable a user"),
		chain("user-enable", []string{"user", "enable"}, "Enable a user"),
		{
			Name: "user-status", Category: CategoryUser,
			Command:        []string{"user", "status"},
			Description:    "Show user setup status",
			RequiresServer: true,
		},
		chain("user-credentials", []string{"user", "credentials"}, "List a user's credentials"),
		chain("user-bind-cert", []string{"user", "bind-cert"}, "Bind a client certificate to a user",
			ArgDefinition{Flag: "thumbprint", Value: "abababababababababababababababababababababababababababababababab", Description: "SPKI SHA-256 thumbprint"},
			ArgDefinition{Flag: "not-after", Value: "4102444800", Description: "Binding expiry"}),
		chain("user-delete", []string{"user", "delete"}, "Delete a user"),
		{
			Name: "user-invite-redeem", Category: CategoryUser,
			Command:        []string{"user", "invite", "redeem"},
			Description:    "Redeem an invitation",
			RequiresServer: true,
			Skip:           "needs an issued invitation token and a FIDO2/PIV activation; " + skipFIDO2,
			RequiredArgs:   []ArgDefinition{pos("it-invite-token", "Invitation token")},
			OptionalArgs:   []ArgDefinition{{Flag: "tenant-id", Value: "system", Description: "Tenant ID"}},
		},
	}
}

// AuthCommands returns the auth family (cmd/xkmsctl/canonical.go,
// auth_factor_handlers.go). Every verb acts on a numeric user id and a bound
// factor, which need the seeded user and factor fixtures of the user chain.
func AuthCommands() []CommandDefinition {
	user := ArgDefinition{Flag: "user", Value: "1", Description: "Numeric user id"}
	factor := pos("it-factor", "Factor ID")
	def := func(name string, command []string, desc string, args ...ArgDefinition) CommandDefinition {
		return CommandDefinition{
			Name: name, Category: CategoryAuth, Command: command, Description: desc,
			RequiresServer: true, RequiresSetup: true, RequiredArgs: args,
		}
	}
	return []CommandDefinition{
		def("auth-login", []string{"auth", "login"}, "Log in with a bound factor",
			ArgDefinition{Flag: "method", Value: "mtls", Description: "Auth method"},
			ArgDefinition{Flag: "cert", Value: "it-user.pem", Description: "Certificate PEM path"}),
		def("auth-factor-list", []string{"auth", "factor", "list"}, "List a user's factors", user),
		def("auth-factor-add", []string{"auth", "factor", "add"}, "Add a factor", user,
			ArgDefinition{Flag: "type", Value: "fido2", Description: "Factor type"},
			ArgDefinition{Flag: "label", Value: "it-factor", Description: "Factor label"},
			ArgDefinition{Flag: "credential-hex", Value: "00ff", Description: "Credential bytes"}),
		def("auth-factor-rotate", []string{"auth", "factor", "rotate"}, "Rotate a factor", factor, user,
			ArgDefinition{Flag: "credential-hex", Value: "ff00", Description: "Credential bytes"}),
		def("auth-factor-relabel", []string{"auth", "factor", "relabel"}, "Relabel a factor", factor,
			ArgDefinition{Flag: "label", Value: "it-factor-2", Description: "New label"}),
		def("auth-factor-remove", []string{"auth", "factor", "remove"}, "Remove a factor", factor,
			ArgDefinition{Flag: "force", Description: "Allow removing the last factor", IsBoolean: true}),
	}
}

// CredentialCommands returns the credential family (cmd/xkmsctl/credential.go
// and the verbs augmentCanonicalCredentialCmd adds in canonical.go).
func CredentialCommands() []CommandDefinition {
	return []CommandDefinition{
		{
			Name: "credential-submit", Category: CategoryCredential,
			Command:        []string{"credential", "submit"},
			Description:    "Submit a backend credential",
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: []ArgDefinition{
				{Flag: "name", Value: "it-credential", Description: "Credential name"},
				{Flag: "value", Value: "it-secret", Description: "Credential value"},
			},
		},
		{
			Name: "credential-list", Category: CategoryCredential,
			Command:        []string{"credential", "list"},
			Description:    "List the credentials the server holds",
			RequiresServer: true,
		},
		{
			Name: "credential-strategy", Category: CategoryCredential,
			Command:        []string{"credential", "strategy"},
			Description:    "Show the configured credential strategy",
			RequiresServer: true,
		},
		{
			Name: "credential-rotate", Category: CategoryCredential,
			Command:        []string{"credential", "rotate"},
			Description:    "Rotate a backend credential",
			RequiresServer: true,
			Skip:           "the CLI verb is a stub that returns PendingCredentialBackendError",
		},
	}
}

// OIDCCommands returns the oidc family (cmd/xkmsctl/oidc.go). The stack has
// no identity provider, so the chain imports a static token
// (import -> get -> token -> delete); refresh and the browser login are skipped.
func OIDCCommands() []CommandDefinition {
	name := pos("it-oidc", "Credential name")
	chain := func(cmdName, verb, desc string, args ...ArgDefinition) CommandDefinition {
		return CommandDefinition{
			Name: cmdName, Category: CategoryOIDC, Command: []string{"oidc", verb}, Description: desc,
			RequiresServer: true, RequiresSetup: true,
			RequiredArgs: append([]ArgDefinition{name}, args...),
		}
	}
	return []CommandDefinition{
		{
			Name: "oidc-templates", Category: CategoryOIDC,
			Command:     []string{"oidc", "templates"},
			Description: "List the OIDC provider templates",
		},
		chain("oidc-create", "create", "Create an OIDC credential",
			ArgDefinition{Flag: "issuer", Value: "https://idp.example.com", Description: "Issuer URL"},
			ArgDefinition{Flag: "client-id", Value: "it-client", Description: "Client ID"},
			ArgDefinition{Flag: "token-endpoint", Value: "https://idp.example.com/token", Description: "Token endpoint"}),
		chain("oidc-import", "import", "Import a static token into a new OIDC credential",
			ArgDefinition{Flag: "create", Description: "Create the credential first", IsBoolean: true},
			ArgDefinition{Flag: "issuer", Value: "https://idp.example.com", Description: "Issuer URL"},
			ArgDefinition{Flag: "client-id", Value: "it-client", Description: "Client ID"},
			ArgDefinition{Flag: "token-endpoint", Value: "https://idp.example.com/token", Description: "Token endpoint"},
			ArgDefinition{Flag: "access-token", Value: "it-access-token", Description: "Access token"},
			ArgDefinition{Flag: "expires-at", Value: "2099-01-01T00:00:00Z", Description: "Token expiry"}),
		{
			Name: "oidc-list", Category: CategoryOIDC,
			Command:        []string{"oidc", "list"},
			Description:    "List OIDC credentials",
			RequiresServer: true,
		},
		chain("oidc-get", "get", "Show an OIDC credential"),
		chain("oidc-token", "token", "Print an OIDC credential's access token"),
		{
			Name: "oidc-refresh", Category: CategoryOIDC,
			Command:        []string{"oidc", "refresh"},
			Description:    "Refresh an OIDC credential",
			RequiresServer: true, Skip: skipNoOIDCProvider,
			RequiredArgs: []ArgDefinition{name},
		},
		{
			Name: "oidc-login", Category: CategoryOIDC,
			Command:        []string{"oidc", "login"},
			Description:    "Log in to an OIDC provider",
			RequiresServer: true,
			Skip:           "browser/device login flow with no headless path; " + skipNoOIDCProvider,
			RequiredArgs:   []ArgDefinition{name},
		},
		chain("oidc-delete", "delete", "Delete an OIDC credential"),
	}
}

// CACommands returns Certificate Authority commands
// These commands interact with the XKMS Certificate Authority for certificate lifecycle management.
// All CA commands require a server connection.
func CACommands() []CommandDefinition {
	return []CommandDefinition{
		// Bundle - get CA certificate bundle
		{
			Name:                   "ca-bundle",
			Category:               CategoryCA,
			Command:                []string{"ca", "bundle"},
			Description:            "Get CA certificate bundle in PEM format",
			RequiresServer:         true,
			ExpectedOutputContains: []string{"CERTIFICATE"},
		},
		// Certificate - get CA certificate info
		{
			Name:           "ca-certificate",
			Category:       CategoryCA,
			Command:        []string{"ca", "certificate"},
			Description:    "Get CA certificate info",
			RequiresServer: true,
			OptionalArgs: []ArgDefinition{
				{Flag: "identity", Value: "", Description: "CA identity/CN (empty for default CA)"},
			},
			ExpectedOutputContains: []string{"CA Certificate", "Subject"},
		},
		// Issue - issue a new certificate
		{
			Name:           "ca-issue",
			Category:       CategoryCA,
			Command:        []string{"ca", "issue"},
			Description:    "Issue a new certificate from the CA",
			RequiresServer: true,
			RequiredArgs: []ArgDefinition{
				{Flag: "cn", Value: "test.example.com", Description: "Common name for the certificate"},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "profile", Value: "server", Description: "Certificate profile"},
				{Flag: "org", Value: "Test Org", Description: "Organization name"},
				{Flag: "sans", Value: "DNS:test.example.com", Description: "Subject alternative names"},
				{Flag: "validity", Value: "365", Description: "Validity period in days"},
				{Flag: "algorithm", Value: "ecdsa-p256", Description: "Key algorithm"},
				{Flag: "output", Value: "", Description: "Output file for certificate PEM"},
			},
		},
		// Sign CSR - sign a certificate signing request
		{
			Name:           "ca-sign-csr",
			Category:       CategoryCA,
			Command:        []string{"ca", "sign-csr"},
			Description:    "Sign a Certificate Signing Request",
			RequiresServer: true,
			RequiresSetup:  true, // Requires a CSR file
			RequiredArgs: []ArgDefinition{
				{Flag: "csr", Value: "request.pem", Description: "Path to CSR PEM file"},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "profile", Value: "server", Description: "Certificate profile"},
				{Flag: "validity", Value: "365", Description: "Validity period in days"},
				{Flag: "output", Value: "", Description: "Output file for signed certificate PEM"},
			},
		},
		// Revoke - revoke a certificate
		{
			Name:           "ca-revoke",
			Category:       CategoryCA,
			Command:        []string{"ca", "revoke"},
			Description:    "Revoke a certificate by serial number",
			RequiresServer: true,
			RequiresSetup:  true, // Requires a valid serial number
			RequiredArgs: []ArgDefinition{
				{Flag: "serial", Value: "01AB23CD", Description: "Certificate serial number in hex"},
			},
			OptionalArgs: []ArgDefinition{
				{Flag: "reason", Value: "0", Description: "RFC 5280 revocation reason code"},
			},
		},
		// CRL - generate certificate revocation list
		{
			Name:           "ca-crl",
			Category:       CategoryCA,
			Command:        []string{"ca", "crl"},
			Description:    "Generate a Certificate Revocation List",
			RequiresServer: true,
			OptionalArgs: []ArgDefinition{
				{Flag: "output", Value: "", Description: "Output file for CRL PEM"},
			},
			ExpectedOutputContains: []string{"CRL"},
		},
		// Status - check certificate revocation status
		{
			Name:           "ca-status",
			Category:       CategoryCA,
			Command:        []string{"ca", "status"},
			Description:    "Check certificate revocation status",
			RequiresServer: true,
			RequiresSetup:  true, // Requires a valid serial number
			RequiredArgs: []ArgDefinition{
				{Flag: "serial", Value: "01AB23CD", Description: "Certificate serial number in hex"},
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
