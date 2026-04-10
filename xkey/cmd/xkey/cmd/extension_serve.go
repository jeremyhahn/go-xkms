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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpm2store "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// Extension serve command errors.
var (
	ErrServeBarrierPasswordRequired = errors.New("extension serve: barrier password required")
	ErrServeBarrierUnsealFailed     = errors.New("extension serve: barrier unseal failed")
	ErrServeIPCStartFailed          = errors.New("extension serve: IPC server start failed")
	ErrServeHomeResolveFailed       = errors.New("extension serve: home resolution failed")
	ErrServeStoreInitFailed         = errors.New("extension serve: store initialization failed")
	ErrServeLogFileOpenFailed       = errors.New("extension serve: log file open failed")
	ErrServePINManagerInitFailed    = errors.New("extension serve: PIN manager initialization failed")
	ErrServeTypePasswordUnsupported = errors.New("extension serve: type_password not supported in headless mode")
	ErrServeStrategyReadFailed      = errors.New("extension serve: failed to read barrier strategy from root key")
	ErrServeStrategyUnsupported     = errors.New("extension serve: barrier strategy not supported in headless mode")
	ErrServeTPMOpenFailed           = errors.New("extension serve: failed to open TPM for barrier strategy")
	ErrServeAuthenticatorInitFailed = errors.New("extension serve: authenticator initialization failed")
)

// extensionServeCmd starts the headless autofill IPC server.
var extensionServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run headless autofill IPC server",
	Long: `Start a production-grade headless IPC server for browser extension communication.

This command runs the autofill pipeline (credential search, TOTP generation, policy enforcement)
without requiring a desktop environment. It is designed for headless servers, SSH sessions,
and remote deployments where the GUI cannot run.

The server communicates with the browser extension via the same Unix socket IPC protocol
used by the GUI, ensuring full compatibility.

Examples:
  # Start with barrier encryption (production)
  xkey extension serve --barrier-password "my-secret"

  # Start with password from environment
  XKEY_BARRIER_PASSWORD=secret xkey extension serve

  # Start without barrier (development/testing)
  xkey extension serve --no-barrier

  # Custom socket path and log level
  xkey extension serve --socket /tmp/xkey.sock --log-level debug

  # Disable CTAP2 authentication (credentials returned without PIN/touch)
  xkey extension serve --no-barrier --no-auth

  # Disable extension pairing verification (testing only)
  xkey extension serve --no-barrier --no-pairing`,
	RunE: runExtensionServe,
}

func init() {
	extensionCmd.AddCommand(extensionServeCmd)

	extensionServeCmd.Flags().String("socket", "", "IPC Unix socket path (default: auto-detect)")
	extensionServeCmd.Flags().String("log-level", "info", "Log level (debug, info, warn, error)")
	extensionServeCmd.Flags().String("log-file", "", "Log file path (default: stderr)")
	extensionServeCmd.Flags().String("barrier-password", "", "Barrier password")
	extensionServeCmd.Flags().String("barrier-password-file", "", "Read barrier password from file (first line)")
	extensionServeCmd.Flags().Bool("no-barrier", false, "Skip barrier, use plain file storage (testing/development)")
	extensionServeCmd.Flags().Int("auto-lock-minutes", 15, "Inactivity lock timeout (0=disabled)")
	extensionServeCmd.Flags().String("pin-state", "", "PIN state directory path")
	extensionServeCmd.Flags().Bool("no-auth", false, "Disable CTAP2 authentication for autofill (credentials returned without PIN/touch)")
	extensionServeCmd.Flags().Bool("no-pairing", false, "Disable extension identity verification (testing only)")
}

// runExtensionServe is the entry point for the headless IPC server command.
func runExtensionServe(cmd *cobra.Command, _ []string) error {
	// 1. Resolve xKey home directory.
	home, err := xhome.Resolve()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrServeHomeResolveFailed, err)
	}

	// 2. Create logger.
	logger, logCloser, err := createServeLogger(cmd)
	if err != nil {
		return err
	}
	if logCloser != nil {
		defer logCloser.Close()
	}

	logger.Info("starting headless autofill IPC server",
		slog.String("home", home.Root))

	// 3. Ensure data directory exists.
	dataDir, err := home.EnsureDataDir()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrServeHomeResolveFailed, err)
	}

	// 4. Create services with nil stores (wired after barrier unseal).
	pinSvc := services.NewPINService()
	barrierSvc := services.NewBarrierService(home.Root, logger)
	barrierSvc.SetDataDir(dataDir)

	appLockSvc := services.NewAppLockService(pinSvc, barrierSvc)
	passwordSvc := services.NewStaticPasswordService(nil)
	oathSvc := services.NewOATHService(nil)

	auditLogger := audit.NewSlogLogger(logger)
	autofillSvc := services.NewAutoFillService(passwordSvc, oathSvc, appLockSvc, auditLogger, logger)

	noBarrier, _ := cmd.Flags().GetBool("no-barrier")

	// Track TPM closer for deferred cleanup.
	var tpmCloser io.Closer

	// 5. Initialize stores: barrier-encrypted or plain.
	if noBarrier {
		logger.Warn("running without barrier encryption (no-barrier mode)")
		if err := initPlainStores(dataDir, passwordSvc, oathSvc); err != nil {
			return fmt.Errorf("%w: %v", ErrServeStoreInitFailed, err)
		}
	} else {
		// Register post-unseal hook to wire encrypted stores.
		barrierSvc.SetPostUnsealHook(func() error {
			return initBarrierStores(barrierSvc, passwordSvc, oathSvc)
		})

		// Check if barrier is already initialized; if not, initialize it.
		sealInfo := barrierSvc.GetSealInfo()
		if !sealInfo.Initialized {
			password, pwErr := resolveBarrierPassword(cmd)
			if pwErr != nil {
				return pwErr
			}
			logger.Info("barrier not initialized, initializing with software strategy")
			if err := barrierSvc.Initialize(password, string(seal.StrategySoftware)); err != nil {
				return fmt.Errorf("%w: %v", ErrServeBarrierUnsealFailed, err)
			}
		} else {
			// Read the stored root key to determine which strategy was used
			// to seal the barrier. This drives which backend to initialize.
			strategy, err := readBarrierStrategy(dataDir)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrServeStrategyReadFailed, err)
			}

			logger.Info("barrier strategy detected from root key",
				slog.String("strategy", string(strategy)))

			switch strategy {
			case seal.StrategySoftware:
				// Software strategy: password required for Argon2id unseal.
				password, pwErr := resolveBarrierPassword(cmd)
				if pwErr != nil {
					return pwErr
				}
				if err := barrierSvc.Unseal(password, string(strategy)); err != nil {
					return fmt.Errorf("%w: %v", ErrServeBarrierUnsealFailed, err)
				}

			case seal.StrategyTPM2:
				// TPM2 strategy: open the TPM and register it, then unseal
				// without a password (the hardware protects the root key).
				sealer, closer := probeTPMSealer(logger, dataDir)
				if sealer == nil {
					return fmt.Errorf("%w: TPM device required for tpm2 barrier strategy", ErrServeTPMOpenFailed)
				}
				tpmCloser = closer
				barrierSvc.SetTPMSealerFunc(func() types.Sealer { return sealer })

				if err := barrierSvc.Unseal("", string(strategy)); err != nil {
					return fmt.Errorf("%w: %v", ErrServeBarrierUnsealFailed, err)
				}

			default:
				// Cloud KMS, PKCS#11, Shamir, etc. -- not yet supported in headless mode.
				return fmt.Errorf("%w: %s", ErrServeStrategyUnsupported, strategy)
			}
		}

		logger.Info("barrier unsealed successfully")
	}

	// Ensure TPM resources are released on exit.
	if tpmCloser != nil {
		defer tpmCloser.Close()
	}

	// 6. Initialize PIN manager.
	pinDir, _ := cmd.Flags().GetString("pin-state")
	if pinDir == "" {
		pinDir = filepath.Join(dataDir, "pin")
	}
	if err := os.MkdirAll(pinDir, 0700); err != nil {
		return fmt.Errorf("%w: %v", ErrServePINManagerInitFailed, err)
	}
	fileStore, err := filestorage.New(pinDir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrServePINManagerInitFailed, err)
	}
	hashConfig := pin.AutoDetectHashConfig()
	if epDir := config.ConfigDir(); epDir != "" && config.IsEnterpriseMode(epDir) {
		ucfg, loadErr := config.Load()
		if loadErr == nil && ucfg.Policy.PINMaxAttempts > 0 {
			logger.Info("enterprise PIN policy detected, lockout handled by hash backend",
				"policy_max_attempts", ucfg.Policy.PINMaxAttempts)
		}
	}
	pinBackend, err := pin.NewSoftwareBackend(fileStore, hashConfig)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrServePINManagerInitFailed, err)
	}
	pinBackendSvc := pin.NewService(pinBackend, logger)
	pinSvc.SetPINService(pinBackendSvc)

	// Lock for startup if user PIN is set.
	if pinBackendSvc.UserPINSet() {
		if !noBarrier {
			strategy, stratErr := readBarrierStrategy(dataDir)
			if stratErr == nil && strategy == seal.StrategyTPM2 {
				appLockSvc.LockForStartup()
				appLockSvc.AutoUnlock()
				logger.Info("app auto-unlocked: TPM2 auto-unseal succeeded")
			} else {
				appLockSvc.LockForStartup()
				if stratErr == nil {
					appLockSvc.SetBarrierStrategy(string(strategy))
				}
				logger.Info("app locked for startup: user PIN is set, unlock via IPC required")
			}
		} else {
			appLockSvc.LockForStartup()
			logger.Info("app locked for startup: user PIN is set (no-barrier mode), unlock via IPC required")
		}
	}

	// 7. Configure auto-lock timeout.
	autoLockMinutes, _ := cmd.Flags().GetInt("auto-lock-minutes")
	appLockSvc.SetAutoLockMinutes(autoLockMinutes)

	// 8. Enable the autofill service.
	if err := autofillSvc.SetEnabled(true); err != nil {
		return fmt.Errorf("%w: %v", ErrServeIPCStartFailed, err)
	}

	// 8a. Configure CTAP2 authentication.
	noAuth, _ := cmd.Flags().GetBool("no-auth")

	// 8b. Configure extension pairing verification.
	noPairing, _ := cmd.Flags().GetBool("no-pairing")

	// 8c. Apply enterprise policy overrides.
	cfgDir := config.ConfigDir()
	if config.IsEnterpriseMode(cfgDir) {
		ucfg, loadErr := config.Load()
		if loadErr == nil {
			pol := ucfg.Policy
			if !pol.ExtensionEnabled {
				return fmt.Errorf("%w: browser extension disabled by enterprise policy", ErrServeIPCStartFailed)
			}
			if pol.ExtensionRequirePairing && noPairing {
				logger.Warn("enterprise policy requires pairing, ignoring --no-pairing flag")
				noPairing = false
			}
			if pol.ExtensionRequireAuthentication && noAuth {
				logger.Warn("enterprise policy requires CTAP2 auth, ignoring --no-auth flag")
				noAuth = false
			}
			autofillSvc.SetEnterprisePolicy(&services.EnterpriseExtensionPolicy{
				Enabled:               pol.ExtensionEnabled,
				RequireAuthentication: pol.ExtensionRequireAuthentication,
				ForceAudit:            pol.ExtensionForceAudit,
				AllowedDomains:        pol.ExtensionAllowedDomains,
				BlockedDomains:        pol.ExtensionBlockedDomains,
				MaxFillsPerMinute:     pol.ExtensionMaxFillsPerMinute,
			})
		} else {
			logger.Warn("failed to load enterprise config for extension policy", "error", loadErr)
		}
	}

	if noAuth {
		logger.Warn("CTAP2 authentication DISABLED for autofill (--no-auth)")
		if err := autofillSvc.SetRequireAuthentication(false); err != nil {
			logger.Warn("failed to disable autofill authentication", "error", err)
		}
	} else {
		// Determine FIDO2 storage backend: barrier-backed or plain file.
		// When the barrier is active, use the barrier backend so headless mode
		// reads the same encrypted FIDO2 credentials as the GUI.
		var fido2Backend storage.Backend
		if !noBarrier {
			fido2Backend = barrierSvc.GetBackend()
			if fido2Backend == nil {
				logger.Warn("barrier backend not available for FIDO2 storage, falling back to file storage")
			}
		}
		if fido2Backend == nil {
			fido2Dir := filepath.Join(dataDir, "fido2")
			if err := os.MkdirAll(fido2Dir, 0700); err != nil {
				logger.Warn("failed to create FIDO2 directory", "error", err)
			} else {
				var fsErr error
				fido2Backend, fsErr = filestorage.New(fido2Dir)
				if fsErr != nil {
					logger.Warn("failed to create FIDO2 file storage", "error", fsErr)
				}
			}
		}

		if fido2Backend != nil {
			auth, authErr := initHeadlessAuthenticator(fido2Backend, pinSvc, logger)
			if authErr != nil {
				logger.Warn("failed to initialize authenticator, autofill will operate without CTAP2 auth",
					"error", authErr)
			} else {
				// Wire FIDO2 hash setter so PIN changes propagate to the authenticator.
				pinBackendSvc.SetFIDO2HashSetter(func(hash []byte) {
					auth.SetFIDO2PINHash(hash)
				})
				autofillSvc.SetAuthenticator(auth)
				logger.Info("CTAP2 authentication enabled for autofill")
			}
		}
	}

	if noPairing {
		logger.Warn("extension pairing verification DISABLED (--no-pairing)")
	}

	// 9. Build handler and start IPC server.
	handler := &headlessHandler{
		autofillSvc: autofillSvc,
		passwordSvc: passwordSvc,
		appLockSvc:  appLockSvc,
	}

	socketPath, _ := cmd.Flags().GetString("socket")
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

	server, err := ipc.NewServer(socketPath, handler, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrServeIPCStartFailed, err)
	}

	logger.Info("IPC server listening",
		slog.String("socket", server.SocketPath()))

	// 10. Wait for shutdown signal or parent context cancellation.
	// Using the command's context as parent allows tests to cancel via
	// cmd.ExecuteContext while still responding to OS signals in production.
	parentCtx := cmd.Context()
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := signal.NotifyContext(parentCtx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(ctx)
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received, stopping server")
	case err := <-serveErr:
		if err != nil && !errors.Is(err, ipc.ErrServerClosed) {
			logger.Error("IPC server error", "error", err)
		}
	}

	// 11. Graceful shutdown.
	if closeErr := server.Close(); closeErr != nil {
		logger.Error("IPC server close error", "error", closeErr)
	}

	if !noBarrier {
		if sealErr := barrierSvc.Seal(); sealErr != nil {
			logger.Error("barrier seal error", "error", sealErr)
		} else {
			logger.Info("barrier sealed")
		}
	}

	logger.Info("headless IPC server stopped")
	return nil
}

// initHeadlessAuthenticator creates a CTAP2 authenticator for the headless
// IPC server. It uses the provided storage backend (barrier-encrypted in
// production, plain file in development) matching the GUI's credential
// storage, and an AutoGrantHandler for user presence since terminal
// interaction is not available in headless mode.
func initHeadlessAuthenticator(backend storage.Backend, pinSvc *services.PINService, logger *slog.Logger) (*authenticator.Authenticator, error) {
	store, err := authenticator.NewBackendStorage(backend, "fido2/xkey/")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrServeAuthenticatorInitFailed, err)
	}

	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		Storage:                    store,
		AAGUID:                     [16]byte{0x78, 0x6B, 0x65, 0x79}, // "xkey"
		EnablePIN:                  true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		UserPresenceHandler:        authenticator.NewAutoGrantHandler(),
		Logger:                     logger,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrServeAuthenticatorInitFailed, err)
	}

	auth.SetPINVerifier(pinSvc)

	return auth, nil
}

// createServeLogger creates an slog.Logger based on command flags. If --log-file
// is set, the logger writes to that file; otherwise it writes to stderr.
func createServeLogger(cmd *cobra.Command) (*slog.Logger, io.Closer, error) {
	levelStr, _ := cmd.Flags().GetString("log-level")
	level := parseSlogLevel(levelStr)

	logFile, _ := cmd.Flags().GetString("log-file")
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrServeLogFileOpenFailed, err)
		}
		handler := slog.NewJSONHandler(f, &slog.HandlerOptions{Level: level})
		return slog.New(handler), f, nil
	}

	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(handler), nil, nil
}

// parseSlogLevel converts a string log level to an slog.Level.
func parseSlogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// resolveBarrierPassword resolves the barrier password from flags, file,
// environment variable, or interactive terminal prompt (in priority order).
func resolveBarrierPassword(cmd *cobra.Command) (string, error) {
	// 1. --barrier-password flag
	if pw, _ := cmd.Flags().GetString("barrier-password"); pw != "" {
		return pw, nil
	}

	// 2. --barrier-password-file flag
	if file, _ := cmd.Flags().GetString("barrier-password-file"); file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrServeBarrierPasswordRequired, err)
		}
		pw := strings.SplitN(string(data), "\n", 2)[0]
		return strings.TrimSpace(pw), nil
	}

	// 3. XKEY_BARRIER_PASSWORD environment variable
	if pw := os.Getenv("XKEY_BARRIER_PASSWORD"); pw != "" {
		return pw, nil
	}

	// 4. Interactive stdin prompt (only if terminal)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Barrier password: ")
		pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrServeBarrierPasswordRequired, err)
		}
		return string(pwBytes), nil
	}

	return "", ErrServeBarrierPasswordRequired
}

// initPlainStores creates plain (unencrypted) file-based stores for no-barrier
// mode. Paths match CLI defaults so data seeded via `xkey password add --store`
// and `xkey oath add --store` is visible to the headless server.
func initPlainStores(dataDir string, passwordSvc *services.StaticPasswordService, oathSvc *services.OATHService) error {
	// Password store: same as CLI default (data/staticpw subdirectory).
	pwBackend, err := filestorage.New(filepath.Join(dataDir, "staticpw"))
	if err != nil {
		return err
	}
	passwordSvc.SetStore(staticpw.NewStore(pwBackend))

	// OATH store: same as CLI default (data/oath.json file).
	oathStore, err := oath.NewFileStore(filepath.Join(dataDir, "oath.json"))
	if err != nil {
		return err
	}
	oathSvc.SetStore(oathStore)

	return nil
}

// initBarrierStores wires barrier-encrypted stores after a successful unseal.
func initBarrierStores(barrierSvc *services.BarrierService, passwordSvc *services.StaticPasswordService, oathSvc *services.OATHService) error {
	backend := barrierSvc.GetBackend()
	if backend == nil {
		return ErrServeStoreInitFailed
	}
	passwordSvc.SetStore(staticpw.NewStore(backend))

	oathStore, err := oath.NewBackendStore(backend, "oath/")
	if err != nil {
		return err
	}
	oathSvc.SetStore(oathStore)

	return nil
}

// headlessHandler implements ipc.Handler, ipc.AutofillHandler,
// ipc.PairingHandler, and ipc.UnlockHandler for the headless server mode.
// It delegates autofill operations to the AutoFillService and provides
// headless-appropriate responses for touch, status, and pairing requests.
type headlessHandler struct {
	autofillSvc *services.AutoFillService
	passwordSvc *services.StaticPasswordService
	appLockSvc  *services.AppLockService
}

// HandleTouch returns an OK response. In headless mode there is no physical
// touch device, so user presence is implicitly approved.
func (h *headlessHandler) HandleTouch() (*ipc.Response, error) {
	return ipc.OKResponse(ipc.ActionApprovedUP), nil
}

// HandleTypePassword returns an error because virtual keyboard input is not
// available in headless mode. Clients should use the autofill API instead.
func (h *headlessHandler) HandleTypePassword(_ string) (*ipc.Response, error) {
	return nil, ErrServeTypePasswordUnsupported
}

// HandleStatus returns the IPC server status including the headless mode
// indicator.
func (h *headlessHandler) HandleStatus() (*ipc.Response, error) {
	return &ipc.Response{
		Status: ipc.StatusOK,
		Action: ipc.ActionDaemonReady,
	}, nil
}

// HandleAutofillSearch implements ipc.AutofillHandler by delegating to AutoFillService.
func (h *headlessHandler) HandleAutofillSearch(domain string) (*ipc.AutofillResult, error) {
	return h.autofillSvc.HandleAutofillSearch(domain)
}

// HandleAutofillGet implements ipc.AutofillHandler by delegating to AutoFillService.
func (h *headlessHandler) HandleAutofillGet(id, challenge string) (*ipc.AutofillResult, error) {
	return h.autofillSvc.HandleAutofillGet(id, challenge)
}

// HandleAutofillTOTP implements ipc.AutofillHandler by delegating to AutoFillService.
func (h *headlessHandler) HandleAutofillTOTP(domain string) (*ipc.AutofillResult, error) {
	return h.autofillSvc.HandleAutofillTOTP(domain)
}

// HandleAutofillTOTPByID implements ipc.AutofillHandler by delegating to AutoFillService.
func (h *headlessHandler) HandleAutofillTOTPByID(id string) (*ipc.AutofillResult, error) {
	return h.autofillSvc.HandleAutofillTOTPByID(id)
}

// HandleAutofillStatus implements ipc.AutofillHandler by delegating to AutoFillService.
func (h *headlessHandler) HandleAutofillStatus() (*ipc.AutofillResult, error) {
	return h.autofillSvc.HandleAutofillStatus()
}

// HandleAutofillPolicy implements ipc.AutofillHandler by delegating to AutoFillService.
func (h *headlessHandler) HandleAutofillPolicy() (*ipc.AutofillResult, error) {
	return h.autofillSvc.HandleAutofillPolicy()
}

// HandleAutofillSave implements ipc.AutofillHandler by delegating to AutoFillService.
func (h *headlessHandler) HandleAutofillSave(domain, username, password, title string) (*ipc.AutofillResult, error) {
	return h.autofillSvc.HandleAutofillSave(domain, username, password, title)
}

// HandleAutofillIgnoreDomain implements ipc.AutofillHandler by delegating to AutoFillService.
func (h *headlessHandler) HandleAutofillIgnoreDomain(domain string) (*ipc.AutofillResult, error) {
	return h.autofillSvc.HandleAutofillIgnoreDomain(domain)
}

// HandleAutofillFocus implements ipc.AutofillHandler. In headless mode there
// is no window to focus, so this is a no-op that returns success.
func (h *headlessHandler) HandleAutofillFocus() (*ipc.AutofillResult, error) {
	return &ipc.AutofillResult{}, nil
}

// HandlePairingNotifyCode displays the pairing code on the terminal for the
// user to enter in the browser extension popup. In headless mode, this is the
// only way the user sees the code.
func (h *headlessHandler) HandlePairingNotifyCode(code, identityKey, origin string) error {
	fmt.Fprintf(os.Stderr, "\n"+
		"╔══════════════════════════════════════════╗\n"+
		"║       Browser Extension Pairing          ║\n"+
		"╠══════════════════════════════════════════╣\n"+
		"║                                          ║\n"+
		"║   Enter this code in the extension:      ║\n"+
		"║                                          ║\n"+
		"║            %s                        ║\n"+
		"║                                          ║\n"+
		"║   Origin: %-30s║\n"+
		"║                                          ║\n"+
		"╚══════════════════════════════════════════╝\n\n",
		code, origin)
	return nil
}

// HandlePairingCompleted logs that pairing completed successfully.
func (h *headlessHandler) HandlePairingCompleted(origin string) error {
	slog.Info("extension pairing completed", "origin", origin)
	fmt.Fprintf(os.Stderr, "Extension paired successfully (origin: %s)\n", origin)
	return nil
}

// HandleUnlock implements ipc.UnlockHandler by delegating to AppLockService.
func (h *headlessHandler) HandleUnlock(pin string) (*ipc.UnlockResult, error) {
	if h.appLockSvc == nil {
		return &ipc.UnlockResult{Success: false, Error: "app lock service not configured"}, nil
	}
	if err := h.appLockSvc.Unlock(pin); err != nil {
		return &ipc.UnlockResult{Success: false, Error: err.Error()}, nil
	}
	slog.Info("app unlocked via IPC")
	return &ipc.UnlockResult{Success: true}, nil
}

// readBarrierStrategy reads the sealed root key blob from disk and returns
// the strategy ID that was used to seal the barrier. This allows the serve
// command to initialize only the required sealer backend rather than probing
// all available hardware.
func readBarrierStrategy(dataDir string) (seal.StrategyID, error) {
	rootKeyPath := filepath.Join(dataDir, "barrier", "root_key")
	data, err := os.ReadFile(rootKeyPath)
	if err != nil {
		return "", fmt.Errorf("read root key: %w", err)
	}

	// Parse only the strategy field to minimize exposure to the sealed blob.
	var envelope struct {
		Strategy seal.StrategyID `json:"strategy"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", fmt.Errorf("parse root key: %w", err)
	}
	if envelope.Strategy == "" {
		return "", errors.New("root key missing strategy field")
	}
	return envelope.Strategy, nil
}

// probeTPMSealer attempts to open the system TPM for barrier unsealing.
// Returns (sealer, closer) if the TPM is available, or (nil, nil) if not.
// The caller must close the returned io.Closer when the TPM is no longer needed.
func probeTPMSealer(logger *slog.Logger, dataDir string) (types.Sealer, io.Closer) {
	const tpmDevice = "/dev/tpmrm0"
	if _, err := os.Stat(tpmDevice); err != nil {
		logger.Debug("TPM device not found, barrier TPM2 strategy unavailable",
			"device", tpmDevice)
		return nil, nil
	}

	tpmDataDir := filepath.Join(dataDir, "tpm")
	factory, err := tpm2store.NewStorageFactory(logger, tpmDataDir)
	if err != nil {
		logger.Warn("failed to create TPM storage factory", "error", err)
		return nil, nil
	}

	cfg := tpm2pkg.DefaultConfig
	cfg.Device = tpmDevice
	cfg.UseSimulator = false

	tpm, err := tpm2pkg.NewTPM2(&tpm2pkg.Params{
		Logger:    logger,
		Config:    &cfg,
		BlobStore: factory.BlobStore(),
		Backend:   factory.KeyBackend(),
	})
	if err != nil {
		logger.Warn("failed to open TPM", "error", err)
		factory.Close()
		return nil, nil
	}

	return tpm, tpm
}

// Compile-time interface satisfaction checks.
var _ ipc.Handler = (*headlessHandler)(nil)
var _ ipc.AutofillHandler = (*headlessHandler)(nil)
var _ ipc.PairingHandler = (*headlessHandler)(nil)
var _ ipc.UnlockHandler = (*headlessHandler)(nil)
