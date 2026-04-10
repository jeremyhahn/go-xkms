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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
	"github.com/spf13/cobra"
)

// Auth command defaults.
const (
	defaultAuthStoragePath = "data/auth"
	defaultAuthTimeout     = 30 * time.Second
)

// Auth command errors.
var (
	// ErrAuthServerRequired indicates the --server flag is required.
	ErrAuthServerRequired = errors.New("auth: --server flag is required")

	// ErrAuthStorageCreationFailed indicates the storage backend could not be created.
	ErrAuthStorageCreationFailed = errors.New("auth: failed to create storage backend")

	// ErrAuthRegistryCreationFailed indicates the server registry could not be created.
	ErrAuthRegistryCreationFailed = errors.New("auth: failed to create server registry")

	// ErrAuthTokenStoreCreationFailed indicates the token store could not be created.
	ErrAuthTokenStoreCreationFailed = errors.New("auth: failed to create token store")

	// ErrAuthClientCreationFailed indicates the SDK client could not be created.
	ErrAuthClientCreationFailed = errors.New("auth: failed to create SDK client")

	// ErrAuthConnectFailed indicates the connection to the server failed.
	ErrAuthConnectFailed = errors.New("auth: failed to connect to server")

	// ErrAuthRegistrationFailed indicates the server registration failed.
	ErrAuthRegistrationFailed = errors.New("auth: failed to register server")

	// ErrAuthServerLookupFailed indicates the server lookup failed.
	ErrAuthServerLookupFailed = errors.New("auth: failed to look up server")

	// ErrAuthTokenLoadFailed indicates the token could not be loaded.
	ErrAuthTokenLoadFailed = errors.New("auth: failed to load token")

	// ErrAuthServerListFailed indicates listing servers failed.
	ErrAuthServerListFailed = errors.New("auth: failed to list servers")

	// ErrAuthTokenListFailed indicates listing tokens failed.
	ErrAuthTokenListFailed = errors.New("auth: failed to list tokens")
)

// authCmd is the parent command for server authentication management.
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage server authentication",
	Long: `Manage authentication with xkms servers.

The auth command provides subcommands for registering with servers,
authenticating via WebAuthn, and managing authentication tokens.

Server entries and JWT tokens are stored in the local xkey data directory
under the auth/ prefix. When a barrier is active, all auth data is
encrypted at rest.

Subcommands:
  register  Register with a new xkms server
  login     Authenticate to a registered server
  status    Show authentication status for all servers
  token     Print the current JWT token for a server

Examples:
  # Register with a server using SPKI pin for trust-on-first-use
  xkey auth register --server https://xkms.example.com:8443 --spki-pin abc123

  # Register with a setup token for pre-authorized enrollment
  xkey auth register --server https://xkms.example.com:8443 --setup-token TOKEN

  # Authenticate to a registered server
  xkey auth login --server https://xkms.example.com:8443

  # Show authentication status for all servers
  xkey auth status

  # Print the JWT token for a specific server
  xkey auth token --server https://xkms.example.com:8443`,
}

// authRegisterCmd registers with a new xkms server.
var authRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register with a new xkms server",
	Long: `Register with a new xkms server.

This command establishes a connection to the server, verifies its identity
using the provided SPKI pin or TLS certificate, and registers the server
in the local server registry. Future authentication commands use the stored
server entry for connection parameters.

Flags:
  --server      Server URL (required)
  --spki-pin    SPKI SHA-256 pin for certificate pinning (trust-on-first-use)
  --setup-token Pre-authorized enrollment token

Examples:
  # Register with SPKI pin
  xkey auth register --server https://xkms.example.com:8443 --spki-pin abc123

  # Register with setup token
  xkey auth register --server https://xkms.example.com:8443 --setup-token TOKEN`,
	RunE: runAuthRegister,
}

// authLoginCmd authenticates to a registered server.
var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate to a registered server",
	Long: `Authenticate to a registered server using WebAuthn.

This command loads the server entry from the registry, establishes a
connection, and performs WebAuthn authentication. On success, the resulting
JWT token is stored in the token store for subsequent API calls.

Flags:
  --server  Server URL (required)

Examples:
  # Login to a registered server
  xkey auth login --server https://xkms.example.com:8443`,
	RunE: runAuthLogin,
}

// authStatusCmd shows authentication status for all servers.
var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication status",
	Long: `Show authentication status for all registered servers.

Displays a table of registered servers with their connection status
and token validity. If --server is specified, shows status for only
that server.

Flags:
  --server  Filter to a specific server URL (optional)

Examples:
  # Show status for all servers
  xkey auth status

  # Show status for a specific server
  xkey auth status --server https://xkms.example.com:8443`,
	RunE: runAuthStatus,
}

// authTokenCmd prints the current JWT token for a server.
var authTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Print current JWT token for a server",
	Long: `Print the current JWT token for a registered server.

Outputs the raw JWT token to stdout, suitable for piping to other
commands or setting as an environment variable. Returns an error if
no token exists or the token has expired.

Flags:
  --server  Server URL (required)

Examples:
  # Print token to stdout
  xkey auth token --server https://xkms.example.com:8443

  # Use token in another command
  export XKMS_TOKEN=$(xkey auth token --server https://xkms.example.com:8443)`,
	RunE: runAuthToken,
}

func init() {
	// Register auth command with root
	RootCmd.AddCommand(authCmd)

	// Add subcommands
	authCmd.AddCommand(authRegisterCmd)
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authStatusCmd)
	authCmd.AddCommand(authTokenCmd)

	// Register command flags
	authRegisterCmd.Flags().String("server", "", "Server URL (required)")
	authRegisterCmd.Flags().String("spki-pin", "", "SPKI SHA-256 pin for certificate pinning")
	authRegisterCmd.Flags().String("setup-token", "", "Pre-authorized enrollment token")

	// Login command flags
	authLoginCmd.Flags().String("server", "", "Server URL (required)")

	// Status command flags
	authStatusCmd.Flags().String("server", "", "Filter to a specific server URL")

	// Token command flags
	authTokenCmd.Flags().String("server", "", "Server URL (required)")
}

// runAuthRegister executes the auth register command.
func runAuthRegister(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrAuthServerRequired
	}

	spkiPin, _ := cmd.Flags().GetString("spki-pin")
	setupToken, _ := cmd.Flags().GetString("setup-token")

	// Build SDK client options
	clientOpts := []xkms.Option{
		xkms.WithProtocol(xkms.ProtocolREST),
		xkms.WithAddress(serverURL),
	}
	if spkiPin != "" {
		clientOpts = append(clientOpts, xkms.WithSPKIPin(spkiPin))
	}
	if setupToken != "" {
		clientOpts = append(clientOpts, xkms.WithJWTToken(setupToken))
	}

	// Create SDK client
	client, err := xkms.NewWithOptions(clientOpts...)
	if err != nil {
		return errors.Join(ErrAuthClientCreationFailed, err)
	}
	defer func() { _ = client.Close() }()

	// Verify connection to the server
	ctx, cancel := context.WithTimeout(context.Background(), defaultAuthTimeout)
	defer cancel()

	logger.Info("connecting to server", slog.String("url", serverURL))

	if err := client.Connect(ctx); err != nil {
		return errors.Join(ErrAuthConnectFailed, err)
	}

	logger.Info("connected to server", slog.String("url", serverURL))

	// Open storage and create server registry
	registry, cleanup, err := openServerRegistry(logger)
	if err != nil {
		return err
	}
	defer cleanup()

	// Register the server entry
	entry := &serverregistry.ServerEntry{
		URL:      serverURL,
		Name:     serverURL,
		Protocol: serverregistry.ProtocolREST,
	}

	if err := registry.Register(ctx, entry); err != nil {
		if errors.Is(err, serverregistry.ErrServerExists) {
			fmt.Fprintf(os.Stderr, "Server already registered: %s\n", serverURL)
			fmt.Fprintf(os.Stderr, "Use 'xkey auth login' to authenticate.\n")
			return nil
		}
		return errors.Join(ErrAuthRegistrationFailed, err)
	}

	fmt.Printf("Server registered: %s\n", serverURL)

	// TODO: Full WebAuthn registration flow will be wired here.
	// The client.BeginRegistration/FinishRegistration calls will use
	// the local FIDO2 authenticator to create a credential on the server.
	fmt.Println("WebAuthn registration not yet implemented")

	return nil
}

// runAuthLogin executes the auth login command.
func runAuthLogin(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrAuthServerRequired
	}

	// Open server registry and look up the server
	registry, registryCleanup, err := openServerRegistry(logger)
	if err != nil {
		return err
	}
	defer registryCleanup()

	ctx, cancel := context.WithTimeout(context.Background(), defaultAuthTimeout)
	defer cancel()

	serverEntry, err := registry.Lookup(ctx, serverURL)
	if err != nil {
		return errors.Join(ErrAuthServerLookupFailed, err)
	}

	// Build SDK client for the registered server
	clientOpts := []xkms.Option{
		xkms.WithProtocol(xkms.ProtocolREST),
		xkms.WithAddress(serverEntry.URL),
	}

	client, err := xkms.NewWithOptions(clientOpts...)
	if err != nil {
		return errors.Join(ErrAuthClientCreationFailed, err)
	}
	defer func() { _ = client.Close() }()

	logger.Info("connecting to server", slog.String("url", serverEntry.URL))

	if err := client.Connect(ctx); err != nil {
		return errors.Join(ErrAuthConnectFailed, err)
	}

	logger.Info("connected to server", slog.String("url", serverEntry.URL))

	// TODO: Full WebAuthn authentication flow will be wired here.
	// The client.BeginAuthentication/FinishAuthentication calls will use
	// the local FIDO2 authenticator to perform assertion and receive a JWT.
	fmt.Println("WebAuthn login not yet implemented")

	// Update last connected time on the server entry
	if updateErr := registry.Update(ctx, serverEntry); updateErr != nil {
		logger.Warn("failed to update server last connected time",
			slog.String("url", serverEntry.URL),
			slog.Any("error", updateErr))
	}

	return nil
}

// runAuthStatus executes the auth status command.
func runAuthStatus(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	serverFilter, _ := cmd.Flags().GetString("server")

	// Open server registry
	registry, registryCleanup, err := openServerRegistry(logger)
	if err != nil {
		return err
	}
	defer registryCleanup()

	// Open token store
	tokens, tokenCleanup, err := openTokenStore(logger)
	if err != nil {
		return err
	}
	defer tokenCleanup()

	ctx := context.Background()

	// List servers
	servers, err := registry.List(ctx)
	if err != nil {
		return errors.Join(ErrAuthServerListFailed, err)
	}

	if len(servers) == 0 {
		fmt.Println("No servers registered.")
		fmt.Println("Use 'xkey auth register --server URL' to register a server.")
		return nil
	}

	fmt.Printf("Registered Servers (%d):\n\n", len(servers))

	for _, server := range servers {
		// Apply filter if specified
		if serverFilter != "" && server.URL != serverFilter {
			continue
		}

		fmt.Printf("  Server:         %s\n", server.URL)
		fmt.Printf("  Protocol:       %s\n", server.Protocol)
		fmt.Printf("  Registered:     %s\n", server.RegisteredAt.Format(time.RFC3339))

		if !server.LastConnectedAt.IsZero() {
			fmt.Printf("  Last Connected: %s\n", server.LastConnectedAt.Format(time.RFC3339))
		} else {
			fmt.Printf("  Last Connected: never\n")
		}

		// Check token status
		token, tokenErr := tokens.Load(ctx, server.URL)
		if tokenErr != nil {
			fmt.Printf("  Token:          none\n")
		} else if token.IsExpired() {
			fmt.Printf("  Token:          expired (was: %s, expired: %s)\n",
				token.Source, token.ExpiresAt.Format(time.RFC3339))
		} else {
			remaining := time.Until(token.ExpiresAt)
			fmt.Printf("  Token:          valid (%s, expires in %s)\n",
				token.Source, remaining.Truncate(time.Second))
		}

		if server.CAFingerprint != "" {
			fmt.Printf("  CA Fingerprint: %s\n", server.CAFingerprint)
		}

		fmt.Println()
	}

	return nil
}

// runAuthToken executes the auth token command.
func runAuthToken(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrAuthServerRequired
	}

	// Open token store
	tokens, cleanup, err := openTokenStore(logger)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx := context.Background()

	entry, err := tokens.Load(ctx, serverURL)
	if err != nil {
		return errors.Join(ErrAuthTokenLoadFailed, err)
	}

	if entry.IsExpired() {
		fmt.Fprintf(os.Stderr, "Warning: token expired at %s\n",
			entry.ExpiresAt.Format(time.RFC3339))
	}

	// Print raw token to stdout for piping
	fmt.Print(entry.Token)

	return nil
}

// authStoragePath returns the resolved path for auth data storage.
// It uses ~/.xkey/data/auth/ as the default location.
func authStoragePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".xkey", defaultAuthStoragePath), nil
}

// openServerRegistry creates a file-backed server registry.
// The returned cleanup function closes the registry and storage backend.
func openServerRegistry(logger *slog.Logger) (serverregistry.ServerRegistry, func(), error) {
	storagePath, err := authStoragePath()
	if err != nil {
		return nil, nil, errors.Join(ErrAuthStorageCreationFailed, err)
	}

	backend, err := filestorage.New(storagePath)
	if err != nil {
		return nil, nil, errors.Join(ErrAuthStorageCreationFailed, err)
	}

	registry, err := serverregistry.NewBackendServerRegistry(backend, "servers/")
	if err != nil {
		_ = backend.Close()
		return nil, nil, errors.Join(ErrAuthRegistryCreationFailed, err)
	}

	cleanup := func() {
		_ = registry.Close()
		_ = backend.Close()
	}

	logger.Debug("opened server registry", slog.String("path", storagePath))

	return registry, cleanup, nil
}

// openTokenStore creates a file-backed token store.
// The returned cleanup function closes the store and storage backend.
func openTokenStore(logger *slog.Logger) (tokenstore.TokenStore, func(), error) {
	storagePath, err := authStoragePath()
	if err != nil {
		return nil, nil, errors.Join(ErrAuthStorageCreationFailed, err)
	}

	backend, err := filestorage.New(storagePath)
	if err != nil {
		return nil, nil, errors.Join(ErrAuthStorageCreationFailed, err)
	}

	store, err := tokenstore.NewBackendTokenStore(backend, "tokens/")
	if err != nil {
		_ = backend.Close()
		return nil, nil, errors.Join(ErrAuthTokenStoreCreationFailed, err)
	}

	cleanup := func() {
		_ = store.Close()
		_ = backend.Close()
	}

	logger.Debug("opened token store", slog.String("path", storagePath))

	return store, cleanup, nil
}
