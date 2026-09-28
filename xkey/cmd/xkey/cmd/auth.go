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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	webauthnclient "github.com/jeremyhahn/go-xkms/sdk/go/webauthnclient"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
	"github.com/spf13/cobra"
)

// Auth command defaults.
const (
	defaultAuthStoragePath = "auth"
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

	// ErrAuthTLSCARead indicates the --tls-ca file could not be read.
	ErrAuthTLSCARead = errors.New("auth: failed to read the --tls-ca file")

	// ErrAuthTLSCAParse indicates the --tls-ca file held no PEM certificate.
	ErrAuthTLSCAParse = errors.New("auth: the --tls-ca file contains no PEM certificate")

	// ErrAuthTrustStoreRead indicates the xKey trust store could not be read
	// for TLS roots.
	ErrAuthTrustStoreRead = errors.New("auth: failed to read the trust store for TLS roots")

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

	// ErrAuthEmailRequired indicates no login key was supplied for the WebAuthn
	// ceremony. There is deliberately no environment-derived default: the
	// server resolves the account by its canonical email key, and an OS account
	// name is a different identifier that only looked equivalent while the two
	// were stored as one value.
	ErrAuthEmailRequired = errors.New("auth: --email is required: it is the canonical login key the server resolves the account by")

	// ErrAuthLoginKeyNotEmail indicates a login key that is not an email
	// address. The server resolves the account with GetUserByEmail, so a value
	// like an OS account name cannot match any principal — and against a
	// relying party with public registration enabled, that miss is a SIGN-UP
	// rather than an error.
	ErrAuthLoginKeyNotEmail = errors.New("auth: the login key must be an email address: the server resolves the account by its canonical email login key")

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

// authClientConfig carries everything the auth commands need to reach a
// server. It is a struct rather than a parameter list because the trust inputs
// (store, --tls-ca, --spki-pin) combine rather than exclude one another.
type authClientConfig struct {
	// ServerURL is the xkms server to connect to.
	ServerURL string

	// SPKIPin, when set, verifies the server's leaf key by its SPKI SHA-256
	// hash. With CA trust available it is additive; without any it is the
	// trust anchor (trust-on-first-use).
	SPKIPin string

	// SetupToken authorizes a pre-approved enrollment.
	SetupToken string

	// TLSCAFile is an extra PEM bundle to trust, for a CA the operator has
	// not added to the xKey trust store.
	TLSCAFile string
}

// defaultAuthClientFactory builds the REST SDK client an xkms server serves
// its WebAuthn ceremony endpoints on.
func defaultAuthClientFactory(cfg authClientConfig) (AuthClientService, error) {
	tlsCfg, err := buildAuthTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	clientOpts := []xkms.Option{
		xkms.WithProtocol(xkms.ProtocolREST),
		xkms.WithAddress(cfg.ServerURL),
	}
	if tlsCfg != nil {
		clientOpts = append(clientOpts, xkms.WithTLS(tlsCfg))
	} else if cfg.SPKIPin != "" {
		// No CA trust anywhere: the pin is the trust anchor, and the transport
		// builds the pinned config itself.
		clientOpts = append(clientOpts, xkms.WithSPKIPin(cfg.SPKIPin))
	}
	if cfg.SetupToken != "" {
		clientOpts = append(clientOpts, xkms.WithJWTToken(cfg.SetupToken))
	}

	client, err := xkms.NewWithOptions(clientOpts...)
	if err != nil {
		return nil, errors.Join(ErrAuthClientCreationFailed, err)
	}
	return client, nil
}

// buildAuthTLSConfig assembles the TLS configuration from the CA sources the
// operator has: the host's own roots, the xKey trust store that `xkey trust
// add` populates, and an explicit --tls-ca bundle. It returns nil to leave the
// connection on the SPKI-pin path.
//
// The trust store used to be ignored here entirely: `auth` built its config
// from the SPKI pin alone, so an operator who had correctly run `trust add`
// still could not connect, and the error named certificate trust rather than
// the fact that the store was never read (#250).
//
// A bare --spki-pin still means what it has always meant: the operator is
// bootstrapping trust for a server whose CA they do not have, and the pin is
// the trust anchor. Validating a chain against the ambient trust store as well
// would break every working trust-on-first-use invocation whose CA is not in
// it. A --tls-ca named on the same command line is different — the operator
// supplied that CA for this connection, so the chain is validated and the pin
// is checked on top of it.
func buildAuthTLSConfig(cfg authClientConfig) (*tls.Config, error) {
	if cfg.SPKIPin != "" && cfg.TLSCAFile == "" {
		return nil, nil
	}

	pool, err := authRootPool(cfg.TLSCAFile)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
	}
	if cfg.SPKIPin != "" {
		// Additive: the chain is validated against the pool first and the pin
		// is checked on top. A caller who named both must not silently lose
		// the pin because CA trust became available.
		tlsCfg.VerifyConnection = xkms.VerifySPKIPinnedConnection(cfg.SPKIPin)
	}
	return tlsCfg, nil
}

// authRootPool builds the root pool from the system roots, the xKey trust
// store and an optional PEM bundle. It returns nil when none of those
// contributed a certificate.
func authRootPool(caFile string) (*x509.CertPool, error) {
	var contributed bool

	pool, err := x509.SystemCertPool()
	if err != nil {
		// A host without a readable system store is not an error here: the
		// trust store and --tls-ca can still supply the anchors.
		pool = x509.NewCertPool()
	} else {
		contributed = true
	}

	storeCerts, err := authTrustStoreCertificates()
	if err != nil {
		return nil, err
	}
	for _, cert := range storeCerts {
		pool.AddCert(cert)
		contributed = true
	}

	if caFile != "" {
		pemData, readErr := os.ReadFile(caFile)
		if readErr != nil {
			return nil, &SentinelCauseError{Sentinel: ErrAuthTLSCARead, Cause: readErr}
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, ErrAuthTLSCAParse
		}
		contributed = true
	}

	if !contributed {
		return nil, nil
	}
	return pool, nil
}

// authTrustStoreCertificates returns the certificates in the xKey trust store
// that may anchor a TLS server chain. A store that has never been created is
// not an error — it is simply empty.
//
// It asks for TLSRoots rather than every certificate in the store. The store
// also holds TPM manufacturer roots, Android hardware attestation roots and
// IDevID issuers; those anchor DEVICE ATTESTATION chains, and a TLS session to
// a server is not one. Promoting them here would let a TPM vendor root
// authenticate an xkms server, which is a wider grant than the operator made
// when they imported it for attestation.
func authTrustStoreCertificates() (certs []*x509.Certificate, err error) {
	store, err := openTrustStore()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAuthTrustStoreRead, Cause: err}
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	certs, err = store.TLSRoots()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAuthTrustStoreRead, Cause: err}
	}
	return certs, nil
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

The WebAuthn register and login ceremonies resolve the account by its canonical
email login key, so they require --email. The PIV path does not: it authenticates
with a certificate and is resolved by its SPKI thumbprint.

Examples:
  # Register with a server using SPKI pin for trust-on-first-use
  xkey auth register --server https://xkms.example.com:8443 --spki-pin abc123 \
      --email alice@example.com

  # Register with a setup token for pre-authorized enrollment
  xkey auth register --server https://xkms.example.com:8443 --setup-token TOKEN \
      --email alice@example.com

  # Authenticate to a registered server
  xkey auth login --server https://xkms.example.com:8443 --email alice@example.com

  # Authenticate with a PIV certificate instead (no login key needed)
  xkey auth login --server https://xkms.example.com:8443 --piv --slot 9a

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

An authenticator with a CTAP2 PIN set - which is what the xKey setup wizard
produces - refuses the ceremony outright unless the request carries the PIN, so
supply it the way a browser would prompt for it. An authenticator with no PIN
configured needs none.

Note that --pin is the AUTHENTICATOR's PIN. It is unrelated to --spki-pin,
which is the server's public-key pin.

Flags:
  --server       Server URL (required)
  --spki-pin     SPKI SHA-256 pin for certificate pinning (trust-on-first-use)
  --setup-token  Pre-authorized enrollment token
  --email        Canonical login key to enroll (required)
  --display-name Human-readable account name (default: the login key)

` + pinUsage + `

Examples:
  # Register with SPKI pin
  xkey auth register --server https://xkms.example.com:8443 --spki-pin abc123 \
      --email alice@example.com

  # Register with setup token
  xkey auth register --server https://xkms.example.com:8443 --setup-token TOKEN \
      --email alice@example.com

  # Enroll against a PIN-protected authenticator, with no PIN in the process list
  printf '%s' "$PIN" | xkey auth register --pin-stdin \
      --server https://xkms.example.com:8443 --email alice@example.com

  # Enroll a specific account
  xkey auth register --server https://xkms.example.com:8443 --email alice@example.com`,
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

An authenticator with a CTAP2 PIN set refuses the assertion unless the request
carries the PIN, so the WebAuthn path takes the same PIN flags as "xkey unlock".
The PIV path takes none: possession of the slot key is the credential.

Flags:
  --server    Server URL (required)
  --email     Canonical login key to authenticate (required)
  --piv       Authenticate with a PIV slot certificate over mTLS
  --slot      PIV slot to authenticate with (default: 9a, used with --piv)
  --backend   PIV key backend: software or pkcs11 (default: software, used with --piv)

` + pinUsage + `

Examples:
  # Login to a registered server
  xkey auth login --server https://xkms.example.com:8443 --email alice@example.com

  # Login against a PIN-protected authenticator, with no PIN in the process list
  printf '%s' "$PIN" | xkey auth login --pin-stdin \
      --server https://xkms.example.com:8443 --email alice@example.com

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
	authRegisterCmd.Flags().String("spki-pin", "", "SPKI SHA-256 pin for certificate pinning (recorded on the server entry and reused by later runs)")
	authRegisterCmd.Flags().String("tls-ca", "", "PEM bundle of CA certificates to trust, in addition to the xKey trust store")
	authRegisterCmd.Flags().String("setup-token", "", "Pre-authorized enrollment token")
	authRegisterCmd.Flags().String("email", "", "Canonical email login key to enroll (required)")
	authRegisterCmd.Flags().String("display-name", "", "Human-readable account name (default: the login key)")
	addPINFlags(authRegisterCmd)

	// Login command flags
	authLoginCmd.Flags().String("server", "", "Server URL (required)")
	authLoginCmd.Flags().String("email", "", "Canonical email login key to authenticate (required)")
	authLoginCmd.Flags().Bool("piv", false, "Authenticate with a PIV slot certificate over mTLS instead of WebAuthn")
	authLoginCmd.Flags().String("tls-ca", "", "PEM bundle of CA certificates to trust, in addition to the xKey trust store")
	authLoginCmd.Flags().String("slot", string(PIVSlotAuthentication), "PIV slot to authenticate with (used with --piv)")
	authLoginCmd.Flags().String("backend", defaultPIVBackend, "PIV key backend: software or pkcs11 (used with --piv)")
	addPINFlags(authLoginCmd)

	// Status command flags
	authStatusCmd.Flags().String("server", "", "Filter to a specific server URL")

	// Token command flags
	authTokenCmd.Flags().String("server", "", "Server URL (required)")
}

// runAuthRegister executes the auth register command: it records the server
// in the local registry and enrolls a WebAuthn credential on it using the
// local FIDO2 authenticator.
func runAuthRegister(cmd *cobra.Command, args []string) (err error) {
	logger := slog.Default()

	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrAuthServerRequired
	}

	spkiPin, _ := cmd.Flags().GetString("spki-pin")
	setupToken, _ := cmd.Flags().GetString("setup-token")

	email, err := resolveAuthLoginKey(cmd)
	if err != nil {
		return err
	}
	displayName, _ := cmd.Flags().GetString("display-name")
	if displayName == "" {
		displayName = email
	}

	// Resolve the PIN before anything reaches the network: a --pin-stdin with
	// nothing on standard input is operator input to correct, and correcting
	// it should not first cost a server round trip or a half-finished
	// registration. An empty PIN is legitimate here — it is what an
	// authenticator with no PIN configured needs.
	pin, err := resolvePINInput(cmd)
	if err != nil {
		return err
	}
	ceremonyPIN, err := sealCeremonyPIN(pin)
	if err != nil {
		return err
	}

	tlsCAFile, _ := cmd.Flags().GetString("tls-ca")

	ctx, cancel := context.WithTimeout(context.Background(), defaultAuthTimeout)
	defer cancel()

	// Open the registry BEFORE connecting. A server that is already
	// registered carries the trust anchor recorded at its first registration,
	// and re-registering has to reuse it: `auth login` did, `auth register`
	// did not, so a second registration against a server whose CA is outside
	// the system trust store failed the handshake with the same x509 error
	// unless --spki-pin was passed again — even though `auth status` showed
	// the fingerprint on the entry (#250).
	registry, cleanup, err := openServerRegistry(logger)
	if err != nil {
		return err
	}
	defer cleanup()

	existing, lookupErr := registry.Lookup(ctx, serverURL)
	if lookupErr != nil && !errors.Is(lookupErr, serverregistry.ErrServerNotFound) {
		return errors.Join(ErrAuthServerLookupFailed, lookupErr)
	}
	if spkiPin == "" && existing != nil {
		spkiPin = existing.CAFingerprint
	}

	client, err := authClientFactory(authClientConfig{
		ServerURL:  serverURL,
		SPKIPin:    spkiPin,
		SetupToken: setupToken,
		TLSCAFile:  tlsCAFile,
	})
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	logger.Info("connecting to server", slog.String("url", serverURL))

	if err := client.Connect(ctx); err != nil {
		return errors.Join(ErrAuthConnectFailed, err)
	}

	logger.Info("connected to server", slog.String("url", serverURL))

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

	// WebAuthn registration ceremony against the account's email, the login
	// key the server resolves with GetUserByEmail.
	begin, err := client.BeginRegistration(ctx, &transport.BeginRegistrationRequest{
		Email:       email,
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

	_, _ = fmt.Fprintf(out, "Registering credential for %q - touch your authenticator...\n", email)

	attestation, err := ceremony.Register(ctx, CeremonyRequest{
		OptionsJSON: []byte(begin.OptionsJSON),
		Origin:      webauthnclient.OriginFromURL(serverURL),
		PIN:         ceremonyPIN,
	})
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

	// The email is already in scope, so print a command that actually runs:
	// login now requires the canonical login key, and guidance that omits it
	// dead-ends the operator right after a SUCCESSFUL registration.
	_, _ = fmt.Fprintln(out, "Use 'xkey auth login --server "+serverURL+" --email "+email+"' to obtain a token.")
	return nil
}

// runAuthLogin executes the auth login command: it performs the WebAuthn
// assertion ceremony against a registered server and stores the issued JWT.
// With --piv it instead authenticates over mTLS using a PIV slot
// certificate, via runAuthLoginPIV.
func runAuthLogin(cmd *cobra.Command, args []string) (err error) {
	logger := slog.Default()

	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrAuthServerRequired
	}

	// The PIV path presents a slot certificate over mTLS: possession of the
	// key is the credential, so it involves no authenticator ceremony and
	// takes no CTAP2 PIN. Branch before resolving one.
	if piv, _ := cmd.Flags().GetBool("piv"); piv {
		return runAuthLoginPIV(cmd, logger, serverURL)
	}

	email, err := resolveAuthLoginKey(cmd)
	if err != nil {
		return err
	}

	pin, err := resolvePINInput(cmd)
	if err != nil {
		return err
	}
	ceremonyPIN, err := sealCeremonyPIN(pin)
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
	// The trust store and --tls-ca apply here too, so a server registered by
	// pin can later be reached by CA trust and vice versa.
	tlsCAFile, _ := cmd.Flags().GetString("tls-ca")

	client, err := authClientFactory(authClientConfig{
		ServerURL: serverEntry.URL,
		SPKIPin:   serverEntry.CAFingerprint,
		TLSCAFile: tlsCAFile,
	})
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	logger.Info("connecting to server", slog.String("url", serverEntry.URL))

	if err := client.Connect(ctx); err != nil {
		return errors.Join(ErrAuthConnectFailed, err)
	}

	logger.Info("connected to server", slog.String("url", serverEntry.URL))

	// WebAuthn authentication ceremony against the account's email, the
	// login key the server resolves with GetUserByEmail.
	begin, err := client.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{Email: email})
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
	_, _ = fmt.Fprintf(out, "Authenticating as %q - touch your authenticator...\n", email)

	assertion, err := ceremony.Assert(ctx, CeremonyRequest{
		OptionsJSON: []byte(begin.OptionsJSON),
		Origin:      webauthnclient.OriginFromURL(serverEntry.URL),
		PIN:         ceremonyPIN,
	})
	if err != nil {
		return err
	}

	finish, err := client.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{
		SessionID:     begin.SessionID,
		Email:         email,
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

	_, _ = fmt.Fprintf(out, "Authenticated to %s as %q. Token stored.\n", serverEntry.URL, email)
	return nil
}

// resolveAuthLoginKey returns the canonical login key the server resolves a
// WebAuthn ceremony by: the --email flag.
//
// The server's ceremony takes an email — XKMSService.BeginRegistration and
// BeginAuthentication forward this value to GetUserByEmail — so this is the
// only identifier that can address a principal. There is no fallback to the
// current operating system user or to any other flag: an OS account name is
// never an email, so defaulting to it can only produce a lookup that misses.
// On a relying party with public registration enabled that miss is not even
// an error, it is a sign-up, and the credential is enrolled onto a second
// principal nobody created.
func resolveAuthLoginKey(cmd *cobra.Command) (string, error) {
	email := strings.TrimSpace(cmdFlagString(cmd, "email"))
	if email != "" {
		return validateLoginKey(email)
	}
	return "", ErrAuthEmailRequired
}

// validateLoginKey refuses a login key that is not an email address.
//
// The check is deliberately minimal — an address must PARSE and must be the bare
// address, not a display-name form, because the server stores this value
// verbatim as an index key and "Alice <a@b.com>" would become the key. Full
// RFC 5322 conformance is not the goal; distinguishing an email from an OS
// account name is.
func validateLoginKey(value string) (string, error) {
	addr, err := mail.ParseAddress(value)
	if err != nil || addr.Address != value {
		return "", ErrAuthLoginKeyNotEmail
	}
	return value, nil
}

// cmdFlagString reads a string flag, tolerating a command that does not define
// it. The auth commands are also constructed piecemeal by tests.
func cmdFlagString(cmd *cobra.Command, name string) string {
	value, _ := cmd.Flags().GetString(name)
	return value
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
		entry.ExpiresAt = expiry.UTC()
	}
	if issuedAt, err := parsed.Claims.GetIssuedAt(); err == nil && issuedAt != nil {
		entry.IssuedAt = issuedAt.UTC()
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
		_, _ = fmt.Fprintln(out, "No servers registered.")
		_, _ = fmt.Fprintln(out, "Use 'xkey auth register --server URL' to register a server.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Registered Servers (%d):\n\n", len(servers))

	for _, server := range servers {
		// Apply filter if specified
		if serverFilter != "" && server.URL != serverFilter {
			continue
		}

		_, _ = fmt.Fprintf(out, "  Server:         %s\n", server.URL)
		_, _ = fmt.Fprintf(out, "  Protocol:       %s\n", server.Protocol)
		_, _ = fmt.Fprintf(out, "  Registered:     %s\n", server.RegisteredAt.Format(time.RFC3339))

		if !server.LastConnectedAt.IsZero() {
			_, _ = fmt.Fprintf(out, "  Last Connected: %s\n", server.LastConnectedAt.Format(time.RFC3339))
		} else {
			_, _ = fmt.Fprintf(out, "  Last Connected: never\n")
		}

		// Check token status
		token, tokenErr := tokens.Load(ctx, server.URL)
		switch {
		case tokenErr != nil:
			_, _ = fmt.Fprintf(out, "  Token:          none\n")
		case token.IsExpired():
			_, _ = fmt.Fprintf(out, "  Token:          expired (was: %s, expired: %s)\n",
				token.Source, token.ExpiresAt.Format(time.RFC3339))
		default:
			remaining := time.Until(token.ExpiresAt)
			_, _ = fmt.Fprintf(out, "  Token:          valid (%s, expires in %s)\n",
				token.Source, remaining.Truncate(time.Second))
		}
		if tokenErr == nil {
			if token.HasRefreshToken() {
				_, _ = fmt.Fprintf(out, "  Refreshable:    yes (xkey auth refresh --server %s)\n", server.URL)
			} else {
				_, _ = fmt.Fprintf(out, "  Refreshable:    no (re-run xkey auth login when it expires)\n")
			}
		}

		if server.CAFingerprint != "" {
			_, _ = fmt.Fprintf(out, "  CA Fingerprint: %s\n", server.CAFingerprint)
		}

		_, _ = fmt.Fprintln(out)
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
	_, _ = fmt.Fprint(out, entry.Token)

	return nil
}

// authStoragePath returns the resolved path for auth data storage:
// <dataDir>/auth, with the data directory resolved through the CLI's
// single chain (featureDataDir). The storage backend creates the
// directory on open for every auth command, so one creating resolver
// serves both the login/register writers and the status/token readers.
func authStoragePath() (string, error) {
	return featureDataDir(defaultAuthStoragePath)
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
		return nil, nil, errors.Join(ErrAuthRegistryCreationFailed, err, backend.Close())
	}

	// cleanup's signature is func() -- there is no error return to the
	// caller's defer -- so a failure here is logged rather than dropped.
	cleanup := func() {
		if closeErr := registry.Close(); closeErr != nil {
			logger.Warn("failed to close server registry", slog.String("error", closeErr.Error()))
		}
		if closeErr := backend.Close(); closeErr != nil {
			logger.Warn("failed to close auth storage backend", slog.String("error", closeErr.Error()))
		}
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

	kvStore, err := xkms.NewKVStoreAdapter(backend)
	if err != nil {
		return nil, nil, errors.Join(ErrAuthTokenStoreCreationFailed, err, backend.Close())
	}

	store, err := tokenstore.NewDAOStore(kvStore)
	if err != nil {
		return nil, nil, errors.Join(ErrAuthTokenStoreCreationFailed, err, backend.Close())
	}

	// cleanup's signature is func() -- there is no error return to the
	// caller's defer -- so a failure here is logged rather than dropped.
	cleanup := func() {
		if closeErr := store.Close(); closeErr != nil {
			logger.Warn("failed to close auth token store", slog.String("error", closeErr.Error()))
		}
		if closeErr := backend.Close(); closeErr != nil {
			logger.Warn("failed to close auth storage backend", slog.String("error", closeErr.Error()))
		}
	}

	logger.Debug("opened token store", slog.String("path", storagePath))

	return store, cleanup, nil
}
