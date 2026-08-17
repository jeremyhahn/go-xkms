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
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
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

	// ErrAuthUsernameRequired indicates no username could be resolved for the
	// WebAuthn ceremony.
	ErrAuthUsernameRequired = errors.New("auth: --username is required (no account name could be derived from the environment)")

	// ErrAuthBeginRegistrationFailed indicates the server refused to start the
	// WebAuthn registration ceremony.
	ErrAuthBeginRegistrationFailed = errors.New("auth: server refused to begin WebAuthn registration")

	// ErrAuthFinishRegistrationFailed indicates the server rejected the
	// attestation produced by the authenticator.
	ErrAuthFinishRegistrationFailed = errors.New("auth: server refused to complete WebAuthn registration")

	// ErrAuthRegistrationRejected indicates the server completed the ceremony
	// but reported it unsuccessful.
	ErrAuthRegistrationRejected = errors.New("auth: server rejected the WebAuthn registration")

	// ErrAuthBeginAuthenticationFailed indicates the server refused to start
	// the WebAuthn authentication ceremony.
	ErrAuthBeginAuthenticationFailed = errors.New("auth: server refused to begin WebAuthn authentication")

	// ErrAuthFinishAuthenticationFailed indicates the server rejected the
	// assertion produced by the authenticator.
	ErrAuthFinishAuthenticationFailed = errors.New("auth: server refused to complete WebAuthn authentication")

	// ErrAuthLoginRejected indicates the server completed the ceremony but
	// reported the login unsuccessful.
	ErrAuthLoginRejected = errors.New("auth: server rejected the WebAuthn login")

	// ErrAuthNoToken indicates a successful login returned no JWT, leaving
	// nothing to store for subsequent API calls.
	ErrAuthNoToken = errors.New("auth: server accepted the login but issued no token")

	// ErrAuthTokenSaveFailed indicates the issued token could not be persisted.
	ErrAuthTokenSaveFailed = errors.New("auth: failed to store the issued token")
)

// AuthClientService is the subset of the SDK transport client the auth
// commands use: the connection lifecycle plus both WebAuthn ceremonies. It
// exists so tests can inject a server double.
type AuthClientService interface {
	Connect(ctx context.Context) error
	Close() error
	BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error)
	FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error)
	BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error)
	FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error)
}

// authClientFactory creates the transport client used by the auth commands.
// It is a package-level variable so tests can inject a server double.
var authClientFactory = defaultAuthClientFactory

// defaultAuthClientFactory builds the REST SDK client an xkms server serves
// its WebAuthn ceremony endpoints on. The SPKI pin implements
// trust-on-first-use certificate pinning; the setup token authorizes a
// pre-approved enrollment.
func defaultAuthClientFactory(serverURL, spkiPin, setupToken string) (AuthClientService, error) {
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

	client, err := xkms.NewWithOptions(clientOpts...)
	if err != nil {
		return nil, errors.Join(ErrAuthClientCreationFailed, err)
	}
	return client, nil
}

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
using the provided SPKI pin or TLS certificate, records the server in the
local server registry, and then enrolls a WebAuthn credential by running the
registration ceremony against the local FIDO2 authenticator.

The ceremony requires an attached CTAP2 authenticator - a security key, or
the xKey virtual authenticator started with "xkey fido2". Registration fails
if no authenticator can be opened; no credential is ever fabricated locally.

Flags:
  --server       Server URL (required)
  --spki-pin     SPKI SHA-256 pin for certificate pinning (trust-on-first-use)
  --setup-token  Pre-authorized enrollment token
  --username     Account name to enroll (default: current OS user)
  --display-name Human-readable account name (default: username)

Examples:
  # Register with SPKI pin
  xkey auth register --server https://xkms.example.com:8443 --spki-pin abc123

  # Register with setup token
  xkey auth register --server https://xkms.example.com:8443 --setup-token TOKEN

  # Enroll a specific account name
  xkey auth register --server https://xkms.example.com:8443 --username alice`,
	RunE: runAuthRegister,
}

// authLoginCmd authenticates to a registered server.
var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate to a registered server",
	Long: `Authenticate to a registered server using WebAuthn, or a PIV slot
certificate over mTLS with --piv.

WebAuthn (default): loads the server entry from the registry, establishes a
connection, and runs the WebAuthn assertion ceremony against the local FIDO2
authenticator. On success the issued JWT is stored in the token store for
subsequent API calls and printed by "xkey auth token". The ceremony requires
an attached CTAP2 authenticator - a security key, or the xKey virtual
authenticator started with "xkey fido2". Login fails if no authenticator can
be opened or the server rejects the assertion.

PIV (--piv): presents the certificate stored in the given PIV slot as the
TLS client certificate and signs the handshake with the slot's private key -
possession of the key IS the credential, so no username or authenticator
ceremony is involved. The server resolves the certificate's SPKI thumbprint
to an enrolled user and returns an access/refresh token pair, stored under
the same server entry "xkey auth token" reads. Only slots whose private key
this xkey process can reach work: keys generated with --backend software
exist only for the process that generated them (see "xkey piv generate");
--backend pkcs11 reaches a real, persistent hardware token.

Flags:
  --server    Server URL (required)
  --username  Account name to authenticate (default: current OS user)
  --piv       Authenticate with a PIV slot certificate over mTLS
  --slot      PIV slot to authenticate with (default: 9a, used with --piv)
  --backend   PIV key backend: software or pkcs11 (default: software, used with --piv)

Examples:
  # Login to a registered server
  xkey auth login --server https://xkms.example.com:8443

  # Login as a specific account
  xkey auth login --server https://xkms.example.com:8443 --username alice

  # Login with the PIV authentication slot (9a) certificate over mTLS
  xkey auth login --server https://xkms.example.com:8443 --piv

  # Login with a PKCS#11-backed PIV slot
  xkey auth login --server https://xkms.example.com:8443 --piv --slot 9c --backend pkcs11`,
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
	authRegisterCmd.Flags().String("username", "", "Account name to enroll (default: current OS user)")
	authRegisterCmd.Flags().String("display-name", "", "Human-readable account name (default: username)")

	// Login command flags
	authLoginCmd.Flags().String("server", "", "Server URL (required)")
	authLoginCmd.Flags().String("username", "", "Account name to authenticate (default: current OS user)")
	authLoginCmd.Flags().Bool("piv", false, "Authenticate with a PIV slot certificate over mTLS instead of WebAuthn")
	authLoginCmd.Flags().String("slot", string(PIVSlotAuthentication), "PIV slot to authenticate with (used with --piv)")
	authLoginCmd.Flags().String("backend", defaultPIVBackend, "PIV key backend: software or pkcs11 (used with --piv)")

	// Status command flags
	authStatusCmd.Flags().String("server", "", "Filter to a specific server URL")

	// Token command flags
	authTokenCmd.Flags().String("server", "", "Server URL (required)")
}

// runAuthRegister executes the auth register command: it records the server
// in the local registry and enrolls a WebAuthn credential on it using the
// local FIDO2 authenticator.
func runAuthRegister(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrAuthServerRequired
	}

	spkiPin, _ := cmd.Flags().GetString("spki-pin")
	setupToken, _ := cmd.Flags().GetString("setup-token")

	username, err := resolveAuthUsername(cmd)
	if err != nil {
		return err
	}
	displayName, _ := cmd.Flags().GetString("display-name")
	if displayName == "" {
		displayName = username
	}

	client, err := authClientFactory(serverURL, spkiPin, setupToken)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// Verify connection to the server.
	ctx, cancel := context.WithTimeout(context.Background(), defaultAuthTimeout)
	defer cancel()

	logger.Info("connecting to server", slog.String("url", serverURL))

	if err := client.Connect(ctx); err != nil {
		return errors.Join(ErrAuthConnectFailed, err)
	}

	logger.Info("connected to server", slog.String("url", serverURL))

	// Open storage and create server registry.
	registry, cleanup, err := openServerRegistry(logger)
	if err != nil {
		return err
	}
	defer cleanup()

	// Record the server entry. An already-registered server is not an error:
	// the operator asked to enroll a credential, so the ceremony still runs.
	// The SPKI pin persists as the entry's trust anchor so later sessions
	// (auth login / refresh / PIV) reach a server whose CA is not in the
	// system trust store — trust-on-first-use ends at registration, not at
	// every command.
	entry := &serverregistry.ServerEntry{
		URL:           serverURL,
		Name:          serverURL,
		CAFingerprint: spkiPin,
		Protocol:      serverregistry.ProtocolREST,
	}

	out := cmd.OutOrStdout()

	if err := registry.Register(ctx, entry); err != nil {
		if !errors.Is(err, serverregistry.ErrServerExists) {
			return errors.Join(ErrAuthRegistrationFailed, err)
		}
		_, _ = fmt.Fprintf(out, "Server already registered: %s\n", serverURL)
	} else {
		_, _ = fmt.Fprintf(out, "Server registered: %s\n", serverURL)
	}

	// WebAuthn registration ceremony.
	begin, err := client.BeginRegistration(ctx, &transport.BeginRegistrationRequest{
		Username:    username,
		DisplayName: displayName,
	})
	if err != nil {
		return errors.Join(ErrAuthBeginRegistrationFailed, err)
	}

	ceremony, err := webauthnCeremonyFactory()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := ceremony.Close(); closeErr != nil {
			logger.Warn("failed to close authenticator", slog.Any("error", closeErr))
		}
	}()

	_, _ = fmt.Fprintf(out, "Registering credential for %q - touch your authenticator...\n", username)

	attestation, err := ceremony.Register(ctx, []byte(begin.OptionsJSON), webauthnOrigin(serverURL))
	if err != nil {
		return err
	}

	finish, err := client.FinishRegistration(ctx, &transport.FinishRegistrationRequest{
		SessionID:       begin.SessionID,
		AttestationJSON: string(attestation),
	})
	if err != nil {
		return errors.Join(ErrAuthFinishRegistrationFailed, err)
	}
	if !finish.Success {
		return &DetailError{Err: ErrAuthRegistrationRejected, Detail: authServerDetail(finish.Message)}
	}

	_, _ = fmt.Fprintf(out, "Credential registered: %s\n", finish.CredentialID)

	// Some servers issue a session token alongside registration; keep it so
	// the operator does not have to log in again immediately.
	if finish.Token != "" {
		if err := storeAuthToken(ctx, logger, serverURL, finish.Token); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(out, "Token stored. Use 'xkey auth token --server "+serverURL+"' to print it.")
		return nil
	}

	_, _ = fmt.Fprintln(out, "Use 'xkey auth login --server "+serverURL+"' to obtain a token.")
	return nil
}

// runAuthLogin executes the auth login command: it performs the WebAuthn
// assertion ceremony against a registered server and stores the issued JWT.
// With --piv it instead authenticates over mTLS using a PIV slot
// certificate, via runAuthLoginPIV.
func runAuthLogin(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrAuthServerRequired
	}

	if piv, _ := cmd.Flags().GetBool("piv"); piv {
		return runAuthLoginPIV(cmd, logger, serverURL)
	}

	username, err := resolveAuthUsername(cmd)
	if err != nil {
		return err
	}

	// Open server registry and look up the server.
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

	// Reuse the trust anchor recorded at registration: without the stored
	// SPKI pin a server whose CA is outside the system trust store would
	// fail verification on every login after a successful TOFU registration.
	client, err := authClientFactory(serverEntry.URL, serverEntry.CAFingerprint, "")
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	logger.Info("connecting to server", slog.String("url", serverEntry.URL))

	if err := client.Connect(ctx); err != nil {
		return errors.Join(ErrAuthConnectFailed, err)
	}

	logger.Info("connected to server", slog.String("url", serverEntry.URL))

	// WebAuthn authentication ceremony.
	begin, err := client.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{Username: username})
	if err != nil {
		return errors.Join(ErrAuthBeginAuthenticationFailed, err)
	}

	ceremony, err := webauthnCeremonyFactory()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := ceremony.Close(); closeErr != nil {
			logger.Warn("failed to close authenticator", slog.Any("error", closeErr))
		}
	}()

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Authenticating as %q - touch your authenticator...\n", username)

	assertion, err := ceremony.Assert(ctx, []byte(begin.OptionsJSON), webauthnOrigin(serverEntry.URL))
	if err != nil {
		return err
	}

	finish, err := client.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{
		SessionID:     begin.SessionID,
		Username:      username,
		AssertionJSON: string(assertion),
	})
	if err != nil {
		return errors.Join(ErrAuthFinishAuthenticationFailed, err)
	}
	if !finish.Success {
		return &DetailError{Err: ErrAuthLoginRejected, Detail: authServerDetail(finish.Message)}
	}
	if finish.Token == "" {
		return ErrAuthNoToken
	}

	if err := storeAuthToken(ctx, logger, serverEntry.URL, finish.Token); err != nil {
		return err
	}

	// Record the successful connection on the server entry.
	serverEntry.LastConnectedAt = time.Now().UTC()
	if updateErr := registry.Update(ctx, serverEntry); updateErr != nil {
		logger.Warn("failed to update server last connected time",
			slog.String("url", serverEntry.URL),
			slog.Any("error", updateErr))
	}

	_, _ = fmt.Fprintf(out, "Authenticated to %s as %q. Token stored.\n", serverEntry.URL, username)
	return nil
}

// resolveAuthUsername returns the account name for a WebAuthn ceremony: the
// --username flag when given, otherwise the current operating system user.
func resolveAuthUsername(cmd *cobra.Command) (string, error) {
	username, _ := cmd.Flags().GetString("username")
	username = strings.TrimSpace(username)
	if username != "" {
		return username, nil
	}

	if current, err := user.Current(); err == nil && current.Username != "" {
		return current.Username, nil
	}
	if envUser := strings.TrimSpace(os.Getenv("USER")); envUser != "" {
		return envUser, nil
	}
	return "", ErrAuthUsernameRequired
}

// authServerDetail formats a server-supplied failure message as error detail.
func authServerDetail(message string) string {
	if message == "" {
		return ""
	}
	return ": " + message
}

// storeAuthToken persists a server-issued JWT in the token store, carrying
// over the expiry, issuer, and subject claims so "auth status" can report
// token validity without another round trip.
func storeAuthToken(ctx context.Context, logger *slog.Logger, serverURL, token string) error {
	tokens, cleanup, err := openTokenStore(logger)
	if err != nil {
		return err
	}
	defer cleanup()

	entry := &tokenstore.TokenEntry{
		ServerURL: serverURL,
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceFIDO2,
		Token:     token,
		IssuedAt:  time.Now().UTC(),
	}
	applyJWTClaims(entry, token)

	if err := tokens.Save(ctx, entry); err != nil {
		return errors.Join(ErrAuthTokenSaveFailed, err)
	}
	return nil
}

// applyJWTClaims copies the registered claims of a JWT onto a token entry.
// The token was just issued by the server this client authenticated to over
// a verified channel, so the claims are read without re-verifying the
// signature; they are metadata for local display only and never grant access.
// A token that is not a JWT simply leaves the metadata unset.
func applyJWTClaims(entry *tokenstore.TokenEntry, token string) {
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return
	}

	if expiry, err := parsed.Claims.GetExpirationTime(); err == nil && expiry != nil {
		entry.ExpiresAt = expiry.Time.UTC()
	}
	if issuedAt, err := parsed.Claims.GetIssuedAt(); err == nil && issuedAt != nil {
		entry.IssuedAt = issuedAt.Time.UTC()
	}
	if issuer, err := parsed.Claims.GetIssuer(); err == nil {
		entry.Issuer = issuer
	}
	if subject, err := parsed.Claims.GetSubject(); err == nil {
		entry.Subject = subject
	}
}

// runAuthStatus executes the auth status command.
func runAuthStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
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
		fmt.Fprintln(out, "No servers registered.")
		fmt.Fprintln(out, "Use 'xkey auth register --server URL' to register a server.")
		return nil
	}

	fmt.Fprintf(out, "Registered Servers (%d):\n\n", len(servers))

	for _, server := range servers {
		// Apply filter if specified
		if serverFilter != "" && server.URL != serverFilter {
			continue
		}

		fmt.Fprintf(out, "  Server:         %s\n", server.URL)
		fmt.Fprintf(out, "  Protocol:       %s\n", server.Protocol)
		fmt.Fprintf(out, "  Registered:     %s\n", server.RegisteredAt.Format(time.RFC3339))

		if !server.LastConnectedAt.IsZero() {
			fmt.Fprintf(out, "  Last Connected: %s\n", server.LastConnectedAt.Format(time.RFC3339))
		} else {
			fmt.Fprintf(out, "  Last Connected: never\n")
		}

		// Check token status
		token, tokenErr := tokens.Load(ctx, server.URL)
		if tokenErr != nil {
			fmt.Fprintf(out, "  Token:          none\n")
		} else if token.IsExpired() {
			fmt.Fprintf(out, "  Token:          expired (was: %s, expired: %s)\n",
				token.Source, token.ExpiresAt.Format(time.RFC3339))
		} else {
			remaining := time.Until(token.ExpiresAt)
			fmt.Fprintf(out, "  Token:          valid (%s, expires in %s)\n",
				token.Source, remaining.Truncate(time.Second))
		}
		if tokenErr == nil {
			if token.HasRefreshToken() {
				fmt.Fprintf(out, "  Refreshable:    yes (xkey auth refresh --server %s)\n", server.URL)
			} else {
				fmt.Fprintf(out, "  Refreshable:    no (re-run xkey auth login when it expires)\n")
			}
		}

		if server.CAFingerprint != "" {
			fmt.Fprintf(out, "  CA Fingerprint: %s\n", server.CAFingerprint)
		}

		fmt.Fprintln(out)
	}

	return nil
}

// runAuthToken executes the auth token command.
func runAuthToken(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
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
	fmt.Fprint(out, entry.Token)

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

	backend, err := xkms.NewFileStorageBackend(storagePath)
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

	backend, err := xkms.NewFileStorageBackend(storagePath)
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
