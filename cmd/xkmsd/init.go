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

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Init subcommand error types.
var (
	// ErrMissingSOPin is returned when the --so-pin flag is not provided.
	ErrMissingSOPin = errors.New("init: --so-pin is required")

	// ErrMissingUserPin is returned when the --user-pin flag is not provided.
	ErrMissingUserPin = errors.New("init: --user-pin is required")

	// ErrInvalidOfficerFormat is returned when an --so flag value does not
	// match the expected "username:/path/to/csr.pem" format.
	ErrInvalidOfficerFormat = errors.New("init: --so value must be username:/path/to/csr.pem")

	// ErrEmptyOfficerUsername is returned when the username portion of an
	// --so flag value is empty.
	ErrEmptyOfficerUsername = errors.New("init: officer username must not be empty")

	// ErrEmptyCSRPath is returned when the CSR path portion of an --so flag
	// value is empty.
	ErrEmptyCSRPath = errors.New("init: officer CSR path must not be empty")

	// ErrCSRFileNotFound is returned when a CSR file specified by --so does
	// not exist on disk.
	ErrCSRFileNotFound = errors.New("init: CSR file not found")

	// ErrCSRReadFailed is returned when a CSR file cannot be read.
	ErrCSRReadFailed = errors.New("init: failed to read CSR file")

	// ErrCSRDecodeFailed is returned when a CSR file does not contain valid
	// PEM data.
	ErrCSRDecodeFailed = errors.New("init: CSR file does not contain valid PEM data")

	// ErrCSRParseFailed is returned when a CSR file contains invalid
	// certificate request data.
	ErrCSRParseFailed = errors.New("init: failed to parse certificate request")

	// ErrCSRSignatureInvalid is returned when a CSR's self-signature does
	// not verify.
	ErrCSRSignatureInvalid = errors.New("init: CSR signature verification failed")

	// ErrConfigLoadFailed is returned when configuration loading fails.
	ErrConfigLoadFailed = errors.New("init: failed to load configuration")

	// ErrBarrierCreateFailed is returned when barrier creation fails.
	ErrBarrierCreateFailed = errors.New("init: failed to create barrier")

	// ErrPlatformStoreCreateFailed is returned when platform store creation fails.
	ErrPlatformStoreCreateFailed = errors.New("init: failed to create platform store")

	// ErrCredentialServiceCreateFailed is returned when credential service creation fails.
	ErrCredentialServiceCreateFailed = errors.New("init: failed to create credential service")

	// ErrCeremonyServiceCreateFailed is returned when ceremony service creation fails.
	ErrCeremonyServiceCreateFailed = errors.New("init: failed to create ceremony service")

	// ErrInvalidBarrierStrategy is returned when --barrier-strategy is not
	// one of the canonical values per
	// docs/08-bootstrap-auth-architecture.md §6.
	ErrInvalidBarrierStrategy = errors.New("init: --barrier-strategy must be one of passphrase, shamir, pkcs11, tpm2, awskms, gcpkms, azurekv, vault")

	// ErrShamirSharesRequired is returned when --barrier-strategy=shamir
	// but --shares is missing or invalid.
	ErrShamirSharesRequired = errors.New("init: --shares >= 2 is required when --barrier-strategy=shamir")

	// ErrShamirThresholdRequired is returned when
	// --barrier-strategy=shamir but --threshold is missing or invalid.
	ErrShamirThresholdRequired = errors.New("init: --threshold (2 <= threshold <= shares) is required when --barrier-strategy=shamir")

	// ErrSharesRequiresShamir is returned when --shares or --threshold
	// is supplied with a non-shamir barrier strategy.
	ErrSharesRequiresShamir = errors.New("init: --shares / --threshold are only valid when --barrier-strategy=shamir")

	// ErrPasskeyPINReadFailed is returned when --passkey-pin-stdin is set but
	// standard input cannot be read.
	ErrPasskeyPINReadFailed = errors.New("init: failed to read the passkey PIN from standard input")

	// ErrBarrierCredentialsFailed is returned when the SO PIN cannot be
	// moved into protected memory for the init-time barrier.
	ErrBarrierCredentialsFailed = errors.New("init: failed to build barrier credentials")
)

// validBarrierStrategies is the set of canonical --barrier-strategy
// values per docs/08-bootstrap-auth-architecture.md §2.
var validBarrierStrategies = map[string]struct{}{
	"passphrase": {},
	"shamir":     {},
	"pkcs11":     {},
	"tpm2":       {},
	"awskms":     {},
	"gcpkms":     {},
	"azurekv":    {},
	"vault":      {},
}

// stringSlice implements flag.Value for repeatable string flags.
type stringSlice []string

// String returns the comma-separated representation of the slice.
func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

// Set appends a value to the slice.
func (s *stringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

// initFlags holds the parsed init subcommand flags. The flag set is
// kept aligned with the canonical surface in
// docs/08-bootstrap-auth-architecture.md §6.
type initFlags struct {
	configPath         string
	soPin              string
	userPin            string
	barrierStrategy    string
	shares             int
	threshold          int
	officers           stringSlice
	credentialStrategy string
	dataDir            string
	hostname           string
	sans               string
	adminFactors       stringSlice
	passkeyDevice      string
	passkeyPINStdin    bool
}

// parseOfficerFlag parses a single "--so" flag value in the format
// "username:/path/to/csr.pem" and returns the username and CSR path.
func parseOfficerFlag(value string) (string, string, error) {
	idx := strings.Index(value, ":")
	if idx < 0 {
		return "", "", &WrappedDetailError{Sentinel: ErrInvalidOfficerFormat, Detail: strconv.Quote(value)}
	}

	username := strings.TrimSpace(value[:idx])
	csrPath := strings.TrimSpace(value[idx+1:])

	if username == "" {
		return "", "", &WrappedDetailError{Sentinel: ErrEmptyOfficerUsername, Detail: strconv.Quote(value)}
	}
	if csrPath == "" {
		return "", "", &WrappedDetailError{Sentinel: ErrEmptyCSRPath, Detail: strconv.Quote(value)}
	}

	return username, csrPath, nil
}

// readAndValidateCSR reads a PEM-encoded CSR file from disk, decodes it,
// parses the certificate request, and verifies its self-signature.
// Returns the raw PEM bytes on success.
func readAndValidateCSR(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &WrappedDetailError{Sentinel: ErrCSRFileNotFound, Detail: path}
		}
		return nil, &WrappedDetailError{Sentinel: ErrCSRReadFailed, Detail: path, Err: err}
	}
	if info.IsDir() {
		return nil, &WrappedDetailError{Sentinel: ErrCSRReadFailed, Detail: path + " is a directory"}
	}

	// #nosec G304 - CSR path is provided by admin during init ceremony
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedDetailError{Sentinel: ErrCSRReadFailed, Detail: path, Err: err}
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, &WrappedDetailError{Sentinel: ErrCSRDecodeFailed, Detail: path}
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, &WrappedDetailError{Sentinel: ErrCSRParseFailed, Detail: path, Err: err}
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, &WrappedDetailError{Sentinel: ErrCSRSignatureInvalid, Detail: path, Err: err}
	}

	return pemData, nil
}

// buildOfficerConfigs parses the --so flag values, reads and validates
// each CSR file, and returns the resulting officer configurations.
func buildOfficerConfigs(officerFlags []string) ([]initialize.OfficerConfig, error) {
	officers := make([]initialize.OfficerConfig, 0, len(officerFlags))
	for _, raw := range officerFlags {
		username, csrPath, err := parseOfficerFlag(raw)
		if err != nil {
			return nil, err
		}

		csrPEM, err := readAndValidateCSR(csrPath)
		if err != nil {
			return nil, err
		}

		officers = append(officers, initialize.OfficerConfig{
			Username: username,
			CSRPEM:   csrPEM,
		})
	}
	return officers, nil
}

// runInit implements the canonical "xkmsd init" subcommand. It
// resolves env-var fallbacks via the XKMS_* viper namespace, validates
// strategy-specific flag combinations, loads configuration, creates
// the barrier and credential service, and validates the ceremony
// configuration.
func runInit(args []string) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	flags, err := parseInitFlags(args)
	if err != nil {
		logger.Error("flag parsing failed", slog.Any("error", err))
		os.Exit(1)
	}

	resolveInitEnvFallbacks(flags)

	if err := validateInitFlags(flags); err != nil {
		logger.Error("validation failed", slog.Any("error", err))
		os.Exit(1)
	}

	// Load configuration if a config file is specified and exists.
	var cfg *config.Config
	if flags.configPath != "" {
		cfg, err = config.Load(flags.configPath)
		if err != nil {
			logger.Error("configuration load failed",
				slog.String("config", flags.configPath),
				slog.Any("error", err))
			os.Exit(1)
		}
		logger.Info("configuration loaded",
			slog.String("config", flags.configPath),
			slog.Any("backends", cfg.GetEnabledBackends()))
	}

	// Resolve credential strategy: flag overrides config, defaults to "barrier".
	credStrategy := resolveCredentialStrategy(flags, cfg)

	// Resolve data directory: flag overrides config, defaults to "/var/lib/xkms".
	dataDir := resolveDataDir(flags, cfg)

	// Resolve hostname: flag overrides config server host.
	hostname := resolveHostname(flags, cfg)

	// Create in-memory storage backend for the barrier and platform store.
	memBackend := storage.NewMemory()

	// Create barrier with the passphrase strategy. The strategy implementation
	// remains software-backed in this validation pass; the canonical
	// --barrier-strategy flag flows through to the ceremony layer where
	// it selects the correct sealing strategy at the SDK boundary.
	barrier, err := seal.NewBarrier(
		logger,
		memBackend,
		seal.BarrierConfig{
			RootKeyPath: "barrier/root-key",
		},
		seal.NewSoftwareStrategy(),
	)
	if err != nil {
		logger.Error("barrier creation failed", slog.Any("error", err))
		os.Exit(1)
	}

	// A freshly constructed barrier is SEALED. The ceremony stores the SO and
	// user PINs through the credential service, which for the "barrier"
	// strategy writes through this barrier — so it has to be initialized and
	// unsealed first, or every ceremony fails at the first credential write
	// with "barrier is sealed".
	//
	// The secret is the SO PIN: it is the credential the operator already has
	// to present to run this ceremony, so deriving the init barrier from it
	// introduces no new secret to manage. This barrier is backed by in-memory
	// storage and lives only for the duration of the command — the durable
	// artifacts are the CA bundle, SPKI pin, and admin bundle written to disk.
	barrierCreds, cerr := seal.CredentialsFor([]byte(flags.soPin))
	if cerr != nil {
		logger.Error("barrier credentials failed", slog.Any("error", &WrappedError{Sentinel: ErrBarrierCredentialsFailed, Err: cerr}))
		os.Exit(1)
	}
	if berr := barrier.Initialize(context.Background(), barrierCreds); berr != nil {
		logger.Error("barrier initialization failed", slog.Any("error", berr))
		exitInit(barrierCreds, nil, 1)
	}
	// Initialize may leave the barrier already unsealed; that is success, not
	// a failure to tolerate silently elsewhere.
	if berr := barrier.Unseal(context.Background(), barrierCreds); berr != nil && !errors.Is(berr, seal.ErrAlreadyUnsealed) {
		logger.Error("barrier unseal failed", slog.Any("error", berr))
		exitInit(barrierCreds, nil, 1)
	}

	// Create platform store backed by in-memory storage.
	platformStore, err := seal.NewPlatformStore(memBackend, logger)
	if err != nil {
		logger.Error("platform store creation failed", slog.Any("error", err))
		exitInit(barrierCreds, nil, 1)
	}

	// Create credential service.
	credService, err := credentials.New(
		&credentials.Config{Strategy: credStrategy},
		platformStore,
		barrier,
		logger,
	)
	if err != nil {
		logger.Error("credential service creation failed", slog.Any("error", err))
		exitInit(barrierCreds, nil, 1)
	}

	// Parse and validate officer CSR files for M-of-N mode.
	var officers []initialize.OfficerConfig
	if len(flags.officers) > 0 {
		officers, err = buildOfficerConfigs(flags.officers)
		if err != nil {
			logger.Error("officer CSR validation failed", slog.Any("error", err))
			exitInit(barrierCreds, nil, 1)
		}
	}

	// Build ceremony configuration.
	ceremonyCfg := &initialize.CeremonyConfig{
		SOPin:                  flags.soPin,
		UserPin:                flags.userPin,
		CredentialSealStrategy: credStrategy,
		Threshold:              flags.threshold,
		Officers:               officers,
		Hostname:               hostname,
		DataDir:                dataDir,
	}

	// Create the ceremony service. Constructor performs config validation,
	// surfacing structural errors before any state-mutating ceremony step.
	cs, err := initialize.NewCeremonyService(
		ceremonyCfg,
		barrier,
		credService,
		logger,
	)
	if err != nil {
		logger.Error("ceremony service creation failed", slog.Any("error", err))
		exitInit(barrierCreds, nil, 1)
	}

	// Print validated configuration summary.
	printInitSummary(ceremonyCfg, credStrategy, officers, flags)

	logger.Info("initialization configuration validated successfully",
		slog.String("hostname", hostname),
		slog.String("data_dir", dataDir),
		slog.String("credential_strategy", credStrategy),
		slog.String("barrier_strategy", flags.barrierStrategy),
		slog.Int("threshold", flags.threshold),
		slog.Int("shares", flags.shares),
		slog.Int("officers", len(officers)))

	// Execute the ceremony end-to-end: construct a software-backed CA in
	// the same in-memory tier the rest of init uses, run
	// CeremonyService.Initialize against it via the CAAdapter (built by
	// the wrapper at the qrdb boundary), and persist the durable
	// artifacts (CA bundle, SPKI pin).
	// Parse the requested login factors through the shared parser so
	// --admin-factor means the same thing here as in every other daemon in
	// the stack. A bad value fails before the ceremony touches anything.
	plan, planErr := qrdbsdk.ParseAdminFactors(flags.adminFactors)
	if planErr != nil {
		logger.Error("invalid --admin-factor", slog.Any("error", planErr))
		exitInit(barrierCreds, nil, 1)
	}

	passkeyPIN, pinErr := resolvePasskeyPIN(flags, os.Stdin)
	if pinErr != nil {
		logger.Error("passkey PIN unavailable", slog.Any("error", pinErr))
		exitInit(barrierCreds, nil, 1)
	}

	rpID, rpName := resolveRelyingParty(cfg, hostname)
	env := &ceremonyEnv{
		logger:           logger,
		hostname:         hostname,
		dataDir:          dataDir,
		enrollmentPlan:   plan,
		passkeyDevice:    flags.passkeyDevice,
		passkeyPIN:       passkeyPIN,
		relyingPartyID:   rpID,
		relyingPartyName: rpName,
		nodeCfg:          resolveInitNodeConfig(cfg, flags, dataDir),
		soPin:            []byte(flags.soPin),
	}

	// Open the authenticator only when a passkey is actually planned, so a
	// host with no FIDO2 support can still run an mTLS-only ceremony.
	if plan.Includes(qrdbsdk.FactorFIDO2) {
		handler, herr := pkgfido2.NewHandler(nil, pkgfido2.NewDefaultEnumerator())
		if herr != nil {
			logger.Error("FIDO2 subsystem unavailable", slog.Any("error", herr))
			exitInit(barrierCreds, env, 1)
		}
		env.fido2Handler = handler
	}

	// Refuse before the ceremony changes any state when a planned factor
	// cannot succeed. A missing security key costs one retry; discovering it
	// midway leaves an initialized barrier with a half-enrolled administrator.
	if pfErr := preflightAdminFactors(context.Background(), env); pfErr != nil {
		logger.Error("admin factor preflight failed", slog.Any("error", pfErr))
		exitInit(barrierCreds, env, 1)
	}
	result, err := executeCeremony(context.Background(), cs, env)
	if err != nil {
		logger.Error("ceremony execution failed", slog.Any("error", err))
		exitInit(barrierCreds, env, 1)
	}
	closeFIDO2Handler(env)
	barrierCreds.Secret.Destroy()

	printCeremonyOutcome(env, result)

	logger.Info("initialization ceremony completed",
		slog.String("state", string(result.State)),
		slog.String("spki_pin", result.SPKIPin),
		slog.Int("shares_generated", result.ShareCount))
}

// exitInit releases everything runInit holds and then terminates. Deferred
// cleanup does not run under os.Exit, so every exit after the barrier
// credential is built goes through here rather than calling os.Exit directly.
//
// This exists because the credential lives in PROTECTED MEMORY: a
// `defer barrierCreds.Secret.Destroy()` sat above eleven os.Exit paths and ran
// on none of them, leaving the SO PIN resident on every error exit -- the exact
// exposure moving credentials into an enclave was meant to close. One function
// that knows what must be released means a twelfth exit point releases it by
// construction instead of by remembering.
//
// env is nil for the exits that precede its construction; the credential is
// built earlier in runInit than the ceremony environment, so its lifetime
// spans and precedes env's.
func exitInit(creds seal.Credentials, env *ceremonyEnv, code int) {
	if creds.Secret != nil {
		creds.Secret.Destroy()
	}
	if env != nil {
		closeFIDO2Handler(env)
	}
	os.Exit(code)
}

// closeFIDO2Handler closes the ceremony's FIDO2 handler, if one was opened.
// Called explicitly at every runInit exit point (including os.Exit paths,
// where a deferred close would never run) rather than via defer.
func closeFIDO2Handler(env *ceremonyEnv) {
	if env.fido2Handler == nil {
		return
	}
	if err := env.fido2Handler.Close(); err != nil {
		env.logger.Warn("init: failed to close the FIDO2 handler", "error", err)
	}
}

// parseInitFlags creates and parses the init subcommand FlagSet.
func parseInitFlags(args []string) (*initFlags, error) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	flags := &initFlags{}

	// Help text documents the canonical XKMS_* env var bindings per
	// docs/08-bootstrap-auth-architecture.md §6.
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "Usage: xkmsd init [flags]")
		_, _ = fmt.Fprintln(fs.Output(), "")
		_, _ = fmt.Fprintln(fs.Output(), "Bootstrap an xkms server in one call. Canonical surface per")
		_, _ = fmt.Fprintln(fs.Output(), "docs/08-bootstrap-auth-architecture.md §6.")
		_, _ = fmt.Fprintln(fs.Output(), "")
		_, _ = fmt.Fprintln(fs.Output(), "Canonical environment variables (Viper-bound):")
		_, _ = fmt.Fprintln(fs.Output(), "  XKMS_SO_PIN              equivalent to --so-pin")
		_, _ = fmt.Fprintln(fs.Output(), "  XKMS_USER_PIN            equivalent to --user-pin")
		_, _ = fmt.Fprintln(fs.Output(), "  XKMS_BARRIER_STRATEGY    equivalent to --barrier-strategy")
		_, _ = fmt.Fprintln(fs.Output(), "  XKMS_SHARES              equivalent to --shares")
		_, _ = fmt.Fprintln(fs.Output(), "  XKMS_THRESHOLD           equivalent to --threshold")
		_, _ = fmt.Fprintln(fs.Output(), "  XKMS_HOSTNAME            equivalent to --hostname")
		_, _ = fmt.Fprintln(fs.Output(), "  XKMS_SANS                equivalent to --sans")
		_, _ = fmt.Fprintln(fs.Output(), "  XKMS_PASSKEY_PIN         FIDO2 authenticator PIN (prefer --passkey-pin-stdin)")
		_, _ = fmt.Fprintln(fs.Output(), "")
		_, _ = fmt.Fprintln(fs.Output(), "Flags:")
		fs.PrintDefaults()
	}

	fs.StringVar(&flags.configPath, "config", "/etc/xkms/xkmsd.yaml", "Path to configuration file")
	fs.StringVar(&flags.soPin, "so-pin", "",
		"Security Officer PIN (required, FIPS 140-3 / PCI-DSS v4 SO credential)")
	fs.StringVar(&flags.userPin, "user-pin", "",
		"User PIN (required, FIPS 140-3 / PCI-DSS v4 user credential)")
	fs.StringVar(&flags.barrierStrategy, "barrier-strategy", "passphrase",
		"Barrier sealing strategy: passphrase | shamir | pkcs11 | tpm2 | awskms | gcpkms | azurekv | vault")
	fs.IntVar(&flags.shares, "shares", 0,
		"Total Shamir shares (required when --barrier-strategy=shamir)")
	fs.IntVar(&flags.threshold, "threshold", 0,
		"Shamir M-of-N threshold (required when --barrier-strategy=shamir)")
	fs.Var(&flags.officers, "so",
		"SO officer in format username:/path/to/csr.pem (repeatable)")
	fs.StringVar(&flags.credentialStrategy, "credential-strategy", "",
		"Credential seal strategy (barrier, manual, tpm2, pkcs11, etc.)")
	fs.StringVar(&flags.dataDir, "data-dir", "", "Data directory for public artifacts")
	fs.StringVar(&flags.hostname, "hostname", "",
		"FQDN written into the admin/server certificate CN")
	fs.StringVar(&flags.sans, "sans", "",
		"Comma-separated additional DNS / IP SANs")
	fs.Var(&flags.adminFactors, "admin-factor",
		"Login factor to enroll for the administrator; repeatable or comma-separated ("+
			strings.Join(qrdbsdk.AdminFactorNames(), "|")+"). Defaults to mtls.")
	fs.StringVar(&flags.passkeyDevice, "passkey-device", "",
		"Select one FIDO2 authenticator when several are attached: a device path, "+
			"or part of the product, manufacturer, or serial number.")
	fs.BoolVar(&flags.passkeyPINStdin, "passkey-pin-stdin", false,
		"Read the FIDO2 authenticator's CTAP2 PIN from standard input. Required when "+
			"the key has a PIN set. There is deliberately no --passkey-pin flag: a PIN "+
			"on the command line is readable from /proc by every process on the host.")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return flags, nil
}

// resolveInitEnvFallbacks applies XKMS_* environment variable values
// for any canonical flag that was not explicitly set. Mirrors viper
// AutomaticEnv semantics with the XKMS_ prefix.
//
// The flag-package signature does not expose "was set"; we treat
// zero-values as "unset" for resolution, which is consistent with
// the canonical CLI surface.
func resolveInitEnvFallbacks(f *initFlags) {
	if f.soPin == "" {
		f.soPin = os.Getenv("XKMS_SO_PIN")
	}
	if f.userPin == "" {
		f.userPin = os.Getenv("XKMS_USER_PIN")
	}
	if v := os.Getenv("XKMS_BARRIER_STRATEGY"); v != "" {
		// Only override the default ("passphrase") with an explicit env value;
		// never clobber an operator's explicit non-default --barrier-strategy.
		if f.barrierStrategy == "passphrase" {
			f.barrierStrategy = v
		}
	}
	if f.shares == 0 {
		if v := os.Getenv("XKMS_SHARES"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				f.shares = n
			}
		}
	}
	if f.threshold == 0 {
		if v := os.Getenv("XKMS_THRESHOLD"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				f.threshold = n
			}
		}
	}
	if f.hostname == "" {
		f.hostname = os.Getenv("XKMS_HOSTNAME")
	}
	if f.sans == "" {
		f.sans = os.Getenv("XKMS_SANS")
	}
}

// resolvePasskeyPIN returns the CTAP2 PIN of the authenticator being
// enrolled, sealed into protected memory.
//
// --passkey-pin-stdin wins over XKMS_PASSKEY_PIN so an operator can override an
// inherited environment without unsetting it. There is no flag form on purpose:
// a PIN in argv is world-readable through /proc for the life of the process.
//
// A nil result is not an error. A key with no PIN configured enrolls without
// one, and a key that does have one refuses with a CTAP error that names the
// cause far more precisely than a guess here could.
func resolvePasskeyPIN(flags *initFlags, stdin io.Reader) (*secure.Secret, error) {
	var raw string
	if flags.passkeyPINStdin {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrPasskeyPINReadFailed, Err: err}
		}
		raw = strings.TrimRight(string(data), "\r\n")
	} else {
		raw = os.Getenv("XKMS_PASSKEY_PIN")
	}
	if raw == "" {
		return nil, nil
	}
	secret, err := secure.NewSecret([]byte(raw))
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrPasskeyPINReadFailed, Err: err}
	}
	return secret, nil
}

// validateInitFlags checks that all required flags are present and
// strategy-specific constraints are satisfied.
func validateInitFlags(flags *initFlags) error {
	if flags.soPin == "" {
		return ErrMissingSOPin
	}
	if flags.userPin == "" {
		return ErrMissingUserPin
	}
	if _, ok := validBarrierStrategies[flags.barrierStrategy]; !ok {
		return ErrInvalidBarrierStrategy
	}

	if flags.barrierStrategy == "shamir" {
		if flags.shares < 2 {
			return ErrShamirSharesRequired
		}
		if flags.threshold < 2 || flags.threshold > flags.shares {
			return ErrShamirThresholdRequired
		}
	} else if flags.shares != 0 || flags.threshold != 0 {
		return ErrSharesRequiresShamir
	}

	return nil
}

// resolveCredentialStrategy determines the credential seal strategy from
// flags and config, defaulting to "barrier".
func resolveCredentialStrategy(flags *initFlags, cfg *config.Config) string {
	if flags.credentialStrategy != "" {
		return flags.credentialStrategy
	}
	if cfg != nil && cfg.Credentials.SealStrategy != "" {
		return cfg.Credentials.SealStrategy
	}
	return "barrier"
}

// resolveDataDir determines the data directory from flags and config,
// defaulting to "/var/lib/xkms".
func resolveDataDir(flags *initFlags, cfg *config.Config) string {
	if flags.dataDir != "" {
		return flags.dataDir
	}
	if cfg != nil && cfg.Storage.Path != "" {
		return cfg.Storage.Path
	}
	return "/var/lib/xkms"
}

// resolveHostname determines the hostname from flags and config,
// defaulting to "localhost".
func resolveHostname(flags *initFlags, cfg *config.Config) string {
	if flags.hostname != "" {
		return flags.hostname
	}
	if cfg != nil && cfg.Server.Host != "" {
		return cfg.Server.Host
	}
	return "localhost"
}

// printInitSummary outputs a human-readable summary of the validated
// initialization configuration to stdout.
func printInitSummary(cfg *initialize.CeremonyConfig, credStrategy string, officers []initialize.OfficerConfig, flags *initFlags) {
	fmt.Println("=== xkmsd init: Configuration Summary ===")
	fmt.Println()
	fmt.Printf("  Hostname:             %s\n", cfg.Hostname)
	fmt.Printf("  Data Directory:       %s\n", cfg.DataDir)
	fmt.Printf("  Barrier Strategy:     %s\n", flags.barrierStrategy)
	fmt.Printf("  Credential Strategy:  %s\n", credStrategy)
	fmt.Printf("  SO PIN:               [provided]\n")
	fmt.Printf("  User PIN:             [provided]\n")
	if flags.barrierStrategy == "shamir" {
		fmt.Printf("  Shamir Mode:          %d-of-%d\n", flags.threshold, flags.shares)
	}
	fmt.Println()

	if cfg.Threshold >= 2 && len(officers) > 0 {
		fmt.Printf("  Mode:                 M-of-N (%d-of-%d)\n", cfg.Threshold, len(officers))
		fmt.Printf("  Officers:\n")
		for _, o := range officers {
			fmt.Printf("    - %s (CSR validated)\n", o.Username)
		}
	} else if flags.barrierStrategy != "shamir" {
		fmt.Printf("  Mode:                 Single Admin\n")
	}

	fmt.Println()
	fmt.Println("=== Validation Passed ===")
}

// resolveRelyingParty determines the WebAuthn relying party an enrolled
// passkey is scoped to.
//
// The configured rp_id wins; otherwise the ceremony hostname is used. Getting
// this wrong is silent: the credential enrolls cleanly and fails at every
// login, because the browser computes the RP ID from the URL bar and the
// server compares it to what was stored.
func resolveRelyingParty(cfg *config.Config, hostname string) (string, string) {
	// WebAuthn is an optional config section, so it is nil far more often than
	// it is populated — every config without a webauthn block reaches here.
	if cfg != nil && cfg.WebAuthn != nil && cfg.WebAuthn.RPID != "" {
		name := cfg.WebAuthn.RPDisplayName
		if name == "" {
			name = cfg.WebAuthn.RPID
		}
		return cfg.WebAuthn.RPID, name
	}
	return hostname, hostname
}
