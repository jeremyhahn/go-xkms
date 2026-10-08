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
	"errors"
	"flag"
	"fmt"
	"io"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"log/slog"
	"os"
	"strings"

	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Init subcommand error types.
var (
	// ErrMissingSOPin is returned when the --so-pin flag is not provided.
	ErrMissingSOPin = errors.New("init: --so-pin is required")

	// ErrConfigLoadFailed is returned when configuration loading fails.
	ErrConfigLoadFailed = errors.New("init: failed to load configuration")

	// ErrInvalidBarrierStrategy is returned when --barrier-strategy is not
	// one of the values the durable node's barrier can be initialized with
	// unattended. Shamir custody is not among them: holders are enrolled and
	// the quorum is run through go-qrdb's own barrier verbs.
	ErrInvalidBarrierStrategy = errors.New("init: --barrier-strategy must be one of passphrase, pkcs11, tpm2, awskms, gcpkms, azurekv, vault")

	// ErrPasskeyPINReadFailed is returned when --passkey-pin-stdin is set but
	// standard input cannot be read.
	ErrPasskeyPINReadFailed = errors.New("init: failed to read the passkey PIN from standard input")
)

// validBarrierStrategies is the set of --barrier-strategy values `xkmsd init`
// can complete unattended (docs/08-bootstrap-auth-architecture.md §2).
var validBarrierStrategies = map[string]struct{}{
	"passphrase": {},
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
	configPath      string
	soPin           string
	barrierStrategy string
	dataDir         string
	hostname        string
	sans            string
	adminFactors    stringSlice
	passkeyDevice   string
	passkeyPINStdin bool
}

// runInit implements the canonical "xkmsd init" subcommand: the single
// administrator bootstrap. It resolves env-var fallbacks via the XKMS_* viper
// namespace, validates the flag set, loads configuration, builds the CA the
// deployment trusts, persists its public artifacts (CA bundle and SPKI pin),
// opens the durable qrdb node, runs first-boot against it, and enrolls the
// administrator's login factors.
//
// Holder enrolment, Shamir custody and share claims are go-qrdb's own
// ceremony, served by the node; `xkmsd init` carries no copy of them.
//
// runInit reports its exit code as a return value rather than calling
// os.Exit directly, so it performs no process-wide teardown of its own --
// mirroring run() (main.go) and, like it, safe for tests to call directly.
// Only main, via runProcess, turns the returned code into a process exit.
func runInit(args []string) int {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	flags, err := parseInitFlags(args)
	if err != nil {
		logger.Error("flag parsing failed", slog.Any("error", err))
		return 1
	}

	resolveInitEnvFallbacks(flags)

	if err := validateInitFlags(flags); err != nil {
		logger.Error("validation failed", slog.Any("error", err))
		return 1
	}

	// Load configuration if a config file is specified and exists.
	var cfg *config.Config
	if flags.configPath != "" {
		cfg, err = config.Load(flags.configPath)
		if err != nil {
			logger.Error("configuration load failed",
				slog.String("config", flags.configPath),
				slog.Any("error", err))
			return 1
		}
		logger.Info("configuration loaded",
			slog.String("config", flags.configPath),
			slog.Any("backends", cfg.GetEnabledBackends()))
	}

	// Resolve data directory: flag overrides config, defaults to "/var/lib/xkms".
	dataDir := resolveDataDir(flags, cfg)

	// Resolve hostname: flag overrides config server host.
	hostname := resolveHostname(flags, cfg)

	printInitSummary(hostname, dataDir, flags)

	logger.Info("initialization configuration validated successfully",
		slog.String("hostname", hostname),
		slog.String("data_dir", dataDir),
		slog.String("barrier_strategy", flags.barrierStrategy))

	// Parse the requested login factors through the shared parser so
	// --admin-factor means the same thing here as in every other daemon in
	// the stack. A bad value fails before anything is changed.
	plan, planErr := qrdbsdk.ParseAdminFactors(flags.adminFactors)
	if planErr != nil {
		logger.Error("invalid --admin-factor", slog.Any("error", planErr))
		return 1
	}

	passkeyPIN, pinErr := resolvePasskeyPIN(context.Background(), flags, os.Stdin)
	if pinErr != nil {
		logger.Error("passkey PIN unavailable", slog.Any("error", pinErr))
		return 1
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
	// host with no FIDO2 support can still run an mTLS-only bootstrap.
	if plan.Includes(qrdbsdk.FactorFIDO2) {
		handler, herr := pkgfido2.NewHandler(nil, pkgfido2.NewDefaultEnumerator())
		if herr != nil {
			logger.Error("FIDO2 subsystem unavailable", slog.Any("error", herr))
			return exitInit(env, 1)
		}
		env.fido2Handler = handler
	}

	// Refuse before anything changes state when a planned factor cannot
	// succeed. A missing security key costs one retry; discovering it midway
	// leaves an initialized node with a half-enrolled administrator.
	if pfErr := preflightAdminFactors(context.Background(), env); pfErr != nil {
		logger.Error("admin factor preflight failed", slog.Any("error", pfErr))
		return exitInit(env, 1)
	}
	result, err := executeBootstrap(context.Background(), env)
	if err != nil {
		logger.Error("bootstrap execution failed", slog.Any("error", err))
		return exitInit(env, 1)
	}
	closeFIDO2Handler(env)

	printBootstrapOutcome(env, result)

	logger.Info("initialization completed",
		slog.String("spki_pin", result.SPKIPin))

	return 0
}

// exitInit releases everything runInit holds and returns the exit code to
// report. It exists so every exit point releases the authenticator handle by
// construction instead of by remembering: a `defer` above the early returns
// would not survive a path that exits the process directly. runInit itself
// performs no process-wide teardown -- callers propagate the returned code
// with `return exitInit(...)` -- so this function does not call os.Exit
// either; only main (via runProcess) does.
func exitInit(env *ceremonyEnv, code int) int {
	if env != nil {
		closeFIDO2Handler(env)
	}
	return code
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
		_, _ = fmt.Fprintln(fs.Output(), "Bootstrap the administrator of an xkms server in one call: the CA's")
		_, _ = fmt.Fprintln(fs.Output(), "public artifacts, the durable node's first boot, and the administrator's")
		_, _ = fmt.Fprintln(fs.Output(), "login factors. Holder enrolment and Shamir custody are go-qrdb's own")
		_, _ = fmt.Fprintln(fs.Output(), "ceremony, run against the node.")
		_, _ = fmt.Fprintln(fs.Output(), "")
		_, _ = fmt.Fprintln(fs.Output(), "Canonical environment variables (Viper-bound):")
		_, _ = fmt.Fprintln(fs.Output(), "  XKMS_SO_PIN              equivalent to --so-pin")
		_, _ = fmt.Fprintln(fs.Output(), "  XKMS_BARRIER_STRATEGY    equivalent to --barrier-strategy")
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
	fs.StringVar(&flags.barrierStrategy, "barrier-strategy", "passphrase",
		"Barrier sealing strategy: passphrase | pkcs11 | tpm2 | awskms | gcpkms | azurekv | vault")
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
	if v := os.Getenv("XKMS_BARRIER_STRATEGY"); v != "" {
		// Only override the default ("passphrase") with an explicit env value;
		// never clobber an operator's explicit non-default --barrier-strategy.
		if f.barrierStrategy == "passphrase" {
			f.barrierStrategy = v
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
func resolvePasskeyPIN(ctx context.Context, flags *initFlags, stdin io.Reader) (*secure.Secret, error) {
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
	secret, err := secure.NewSecret(ctx, []byte(raw))
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrPasskeyPINReadFailed, Err: err}
	}
	return secret, nil
}

// validateInitFlags checks that all required flags are present and the
// barrier strategy is one init can complete.
func validateInitFlags(flags *initFlags) error {
	if flags.soPin == "" {
		return ErrMissingSOPin
	}
	if _, ok := validBarrierStrategies[flags.barrierStrategy]; !ok {
		return ErrInvalidBarrierStrategy
	}
	return nil
}

// resolveDataDir determines the data directory from flags and config,
// defaulting to "/var/lib/xkms".
func resolveDataDir(flags *initFlags, cfg *config.Config) string {
	if flags.dataDir != "" {
		return flags.dataDir
	}
	if cfg != nil && cfg.Datastore.Path != "" {
		return cfg.Datastore.Path
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
func printInitSummary(hostname, dataDir string, flags *initFlags) {
	fmt.Println("=== xkmsd init: Configuration Summary ===")
	fmt.Println()
	fmt.Printf("  Hostname:             %s\n", hostname)
	fmt.Printf("  Data Directory:       %s\n", dataDir)
	fmt.Printf("  Barrier Strategy:     %s\n", flags.barrierStrategy)
	fmt.Printf("  SO PIN:               [provided]\n")
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
