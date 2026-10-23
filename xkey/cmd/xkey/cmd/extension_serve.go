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

	"github.com/jeremyhahn/go-enclave"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
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
	ErrServeRootKeyMissingStrategy  = errors.New("extension serve: root key missing strategy field")

	// ErrServePolicyRefused indicates the config directory is sealed, an SO
	// PIN was supplied, and the policy section did not verify under it. The
	// server refuses to start rather than serve under a policy that may have
	// been edited; the cause (config.ErrPolicyUnverifiable joined with the
	// HMAC error) is reachable with errors.Is.
	ErrServePolicyRefused = errors.New("extension serve: sealed enterprise policy could not be verified")

	// ErrServeShamirStrategyUnavailable indicates the barrier's root key was
	// sealed with the shamir strategy, which reassembles the root key from
	// an M-of-N quorum of operator-held shares. A headless process has no
	// way to collect that quorum, so it is refused rather than left to hang
	// waiting for shares that will never arrive.
	ErrServeShamirStrategyUnavailable = errors.New("extension serve: shamir barrier strategy needs an operator quorum a headless process cannot collect; unseal interactively with 'xkey barrier unseal'")

	// ErrServeLocalAppAccessDisabled indicates the local app access setting
	// is off, so no process may open the IPC socket that would expose the
	// keys to other apps.
	ErrServeLocalAppAccessDisabled = errors.New("extension serve: local app access is off; enable it with 'xkey app-access enable' or in xKey Settings")
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

The server opens that socket only with local app access on; it refuses to
start otherwise. Turn it on with "xkey app-access enable".

Examples:
  # Start with barrier encryption (production)
  xkey extension serve --barrier-password-stdin < password.txt

  # Start with password from environment
  XKEY_BARRIER_PASSWORD=secret xkey extension serve

  # Honour a sealed enterprise policy (see below)
  XKEY_SO_PIN=... xkey extension serve

` + soPINUsage + `

  # Start without barrier (development/testing)
  xkey extension serve --no-barrier

  # Custom socket path and log level
  xkey extension serve --socket "$XDG_RUNTIME_DIR/xkey/xkey.sock" --log-level debug

  # Disable CTAP2 authentication (credentials returned without PIN/touch)
  xkey extension serve --no-barrier --no-auth

  # Disable extension pairing verification (testing only)
  xkey extension serve --no-barrier --no-pairing

  # Unseal a tpm2-strategy barrier against a specific device or the
  # in-process simulator (device selection follows the same
  # --tpm-device/--tpm-simulator/TPM_DEVICE_PATH priority as "xkey barrier")
  xkey extension serve --tpm-device /dev/tpm0
  xkey extension serve --tpm-simulator`,
	RunE: runExtensionServe,
}

func init() {
	extensionCmd.AddCommand(extensionServeCmd)

	extensionServeCmd.Flags().String("log-level", "info", "Log level (debug, info, warn, error)")
	extensionServeCmd.Flags().String("log-file", "", "Log file path (default: stderr)")
	addBarrierPasswordFlags(extensionServeCmd)
	extensionServeCmd.Flags().Bool("no-barrier", false, "Skip barrier, use plain file storage (testing/development)")
	extensionServeCmd.Flags().Int("auto-lock-minutes", 15, "Inactivity lock timeout (0=disabled)")
	extensionServeCmd.Flags().String("pin-state", "", "PIN state directory path")
	extensionServeCmd.Flags().Bool("no-auth", false, "Disable CTAP2 authentication for autofill (credentials returned without PIN/touch)")
	extensionServeCmd.Flags().Bool("no-pairing", false, "Disable extension identity verification (testing only)")
	addSOPINFlags(extensionServeCmd)
	extensionServeCmd.Flags().String("tpm-device", "",
		"TPM device path for the tpm2 barrier strategy (default: $TPM_DEVICE_PATH or /dev/tpmrm0)")
	extensionServeCmd.Flags().Bool("tpm-simulator", false,
		"Use the in-process TPM simulator instead of a hardware device (requires a simulator build)")
}

// runExtensionServe is the entry point for the headless IPC server command.
func runExtensionServe(cmd *cobra.Command, _ []string) error {
	// 0. Refuse before touching anything unless the user let other apps
	// use their keys.
	enabled, err := localAppAccessEnabled()
	if err != nil {
		return err
	}
	if !enabled {
		return ErrServeLocalAppAccessDisabled
	}

	// 1. Resolve xKey home directory.
	home, err := xhome.Resolve()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrServeHomeResolveFailed, Cause: err}
	}

	// 2. Create logger.
	logger, logCloser, err := createServeLogger(cmd)
	if err != nil {
		return err
	}
	if logCloser != nil {
		defer func() {
			if closeErr := logCloser.Close(); closeErr != nil {
				logger.Warn("failed to close log file", slog.String("error", closeErr.Error()))
			}
		}()
	}

	logger.Info("starting headless autofill IPC server",
		slog.String("home", home.Root))

	// 3. Ensure data directory exists.
	dataDir, err := home.EnsureDataDir()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrServeHomeResolveFailed, Cause: err}
	}

	// 4. Create services with nil stores (wired after barrier unseal).
	pinSvc := services.NewPINService()
	barrierSvc := services.NewBarrierService(home.Root, logger)
	barrierSvc.SetDataDir(dataDir)

	appLockSvc := services.NewAppLockService(pinSvc, barrierSvc)
	appLockSvc.SetDataDir(dataDir)
	pinSvc.SetAppLockService(appLockSvc)
	passwordSvc := services.NewStaticPasswordService(nil)
	oathSvc := services.NewOATHService(nil)

	auditLogger := audit.NewSlogLogger(logger)
	autofillSvc := services.NewAutoFillService(passwordSvc, oathSvc, appLockSvc, auditLogger, logger)

	noBarrier, _ := cmd.Flags().GetBool("no-barrier")

	// Track TPM and cloud KMS backend closers for deferred cleanup.
	var tpmCloser io.Closer
	var strategyCloser io.Closer

	// 5. Initialize stores: barrier-encrypted or plain.
	if noBarrier {
		logger.Warn("running without barrier encryption (no-barrier mode)")
		pwStore, err := initPlainStores(dataDir, passwordSvc, oathSvc)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrServeStoreInitFailed, Cause: err}
		}
		defer func() {
			if closeErr := pwStore.Close(); closeErr != nil {
				logger.Warn("failed to close the password store", slog.String("error", closeErr.Error()))
			}
		}()
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
			if err := barrierSvc.Initialize(password, string(xkms.StrategyPassphrase)); err != nil {
				return &SentinelCauseError{Sentinel: ErrServeBarrierUnsealFailed, Cause: err}
			}
		} else {
			// Read the stored root key to determine which strategy was used
			// to seal the barrier. This drives which backend to initialize.
			strategy, err := readBarrierStrategy(dataDir)
			if err != nil {
				return &SentinelCauseError{Sentinel: ErrServeStrategyReadFailed, Cause: err}
			}

			logger.Info("barrier strategy detected from root key",
				slog.String("strategy", string(strategy)))

			switch strategy {
			case xkms.StrategyPassphrase:
				// Software strategy: password required for Argon2id unseal.
				password, pwErr := resolveBarrierPassword(cmd)
				if pwErr != nil {
					return pwErr
				}
				if err := barrierSvc.Unseal(password, string(strategy)); err != nil {
					return &SentinelCauseError{Sentinel: ErrServeBarrierUnsealFailed, Cause: err}
				}

			case xkms.StrategyTPM2:
				// TPM2 strategy: try TPM-policy auto-unseal first (see
				// `xkey tpm policy auto-unseal`) -- it needs no password
				// because the TPM releases the barrier credential through
				// the auto-unseal policy's session. Fall back to a direct
				// TPM unseal (passwordless tpm2 barriers only) when no
				// auto-unseal policy is configured or the TPM refuses it.
				tpmDevice, _ := cmd.Flags().GetString("tpm-device")
				tpmSimulator, _ := cmd.Flags().GetBool("tpm-simulator")

				unsealed, autoCloser, autoErr := tryBarrierPolicyAutoUnseal(context.Background(), logger, barrierSvc, dataDir, strategy, tpmDevice, tpmSimulator)
				switch {
				case autoErr != nil:
					logger.Warn("barrier TPM-policy auto-unseal failed, falling back to direct TPM unseal", "error", autoErr)
				case unsealed:
					logger.Info("barrier auto-unsealed through the TPM auto-unseal policy")
				}

				if unsealed {
					tpmCloser = autoCloser
				} else {
					sealer, closer := probeTPMSealer(logger, dataDir, tpmDevice, tpmSimulator)
					if sealer == nil {
						return &DetailError{Err: ErrServeTPMOpenFailed, Detail: ": TPM device required for tpm2 barrier strategy"}
					}
					tpmCloser = closer
					barrierSvc.SetTPMSealerFunc(func() xkms.Sealer { return sealer })

					if err := barrierSvc.Unseal("", string(strategy)); err != nil {
						// The release below is deferred only once the barrier
						// is open, so a failed unseal releases the TPM here.
						if closer != nil {
							err = errors.Join(err, closer.Close())
						}
						return &SentinelCauseError{Sentinel: ErrServeBarrierUnsealFailed, Cause: err}
					}
				}

			case xkms.StrategyPKCS11:
				// The token PIN is released from the pre-barrier secret
				// store `xkey barrier init --strategy pkcs11` sealed it into,
				// under the TPM's platform PCR policy, so no human types it.
				tpmDevice, _ := cmd.Flags().GetString("tpm-device")
				tpmSimulator, _ := cmd.Flags().GetBool("tpm-simulator")
				closer, err := unsealWithExternalStrategy(barrierSvc, strategy, func() (xkms.SealingStrategy, io.Closer, error) {
					return pkcs11BarrierStrategy(context.Background(), dataDir, tpmDevice, tpmSimulator)
				})
				if err != nil {
					return err
				}
				strategyCloser = closer

			case xkms.StrategyShamir:
				return ErrServeShamirStrategyUnavailable

			case xkms.StrategyAWSKMS, xkms.StrategyGCPKMS, xkms.StrategyAzureKV, xkms.StrategyVault:
				// Cloud KMS strategies need no password and no per-request
				// secret: the backend (built from the xkey config persisted
				// by `xkey barrier init`) is the same one that sealed the
				// root key, and BuildCloudKMSStrategy resolves its wrapping
				// key deterministically by CN (go-xkms#757).
				closer, err := unsealWithExternalStrategy(barrierSvc, strategy, func() (xkms.SealingStrategy, io.Closer, error) {
					return cloudKMSBarrierStrategy(context.Background(), strategy, dataDir)
				})
				if err != nil {
					return err
				}
				strategyCloser = closer

			default:
				return &DetailError{Err: ErrServeStrategyUnsupported, Detail: fmt.Sprintf(": %s", strategy)}
			}
		}

		logger.Info("barrier unsealed successfully")
	}

	// Ensure TPM and barrier strategy backend resources are released on exit.
	if tpmCloser != nil {
		defer func() {
			if closeErr := tpmCloser.Close(); closeErr != nil {
				logger.Warn("failed to close TPM connection", slog.String("error", closeErr.Error()))
			}
		}()
	}
	if strategyCloser != nil {
		defer func() {
			if closeErr := strategyCloser.Close(); closeErr != nil {
				logger.Warn("failed to close the barrier strategy backend", slog.String("error", closeErr.Error()))
			}
		}()
	}

	// 6. Initialize PIN manager.
	//
	// The backend is resolved through the shared pinselect resolver (xkms.ResolvePINBackend) — the
	// same rule the xKey GUI and `xkey pin` use — instead of hard-coding
	// the software backend. A device whose PIN was set up through the
	// GUI's TPM2 wizard persists strategy=tpm2 beside the PIN state; this
	// daemon must authenticate against that same backend, or refuse to
	// start, rather than silently answering from a different store
	// (go-xkms#307).
	pinDir, _ := cmd.Flags().GetString("pin-state")
	if pinDir == "" {
		pinDir = filepath.Join(dataDir, "pin")
	}
	if err := os.MkdirAll(pinDir, 0700); err != nil {
		return &SentinelCauseError{Sentinel: ErrServePINManagerInitFailed, Cause: err}
	}

	pinTPMDevice, _ := cmd.Flags().GetString("tpm-device")
	pinTPMSimulator, _ := cmd.Flags().GetBool("tpm-simulator")

	persistedStrategy, loadErr := xkms.LoadPINStrategy(pinDir)
	persistedTPM2 := loadErr == nil && persistedStrategy == qrdbsdk.PINStrategyTPM2

	// Capture the TPM connection's closer (if PlatformAuth ends up opening
	// one) so it outlives Resolve: the daemon keeps using it for every
	// subsequent PIN verification, not just the one Resolve performs here.
	var pinTPMCloser io.Closer
	pinTPMProvider := xkms.NewPINTPMProvider(func() (xkms.PINPlatformKeyStoreProvider, error) {
		tpm, closer, err := openTPMModule(logger, dataDir, pinTPMDevice, pinTPMSimulator)
		if err != nil {
			return nil, err
		}
		pinTPMCloser = closer
		return tpm, nil
	}, persistedTPM2, logger)

	pinBackend, _, err := xkms.ResolvePINBackend(xkms.PINResolveConfig{
		PINDir: pinDir,
		Config: xkms.PINSelectConfig{
			TPM:      pinTPMProvider,
			Software: cliSoftwarePINProvider{pinDir: pinDir},
			Logger:   logger,
		},
	})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrServePINManagerInitFailed, Cause: err}
	}
	if pinTPMCloser != nil {
		defer func() {
			if closeErr := pinTPMCloser.Close(); closeErr != nil {
				logger.Warn("failed to close PIN manager TPM connection", slog.String("error", closeErr.Error()))
			}
		}()
	}
	pinBackendSvc := qrdbsdk.NewPINService(pinBackend, logger)
	pinSvc.SetPINService(pinBackendSvc)

	// Lock for startup if user PIN is set.
	if pinBackendSvc.UserPINSet() {
		if !noBarrier {
			strategy, stratErr := readBarrierStrategy(dataDir)
			if stratErr == nil && strategy == xkms.StrategyTPM2 {
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
		return &SentinelCauseError{Sentinel: ErrServeIPCStartFailed, Cause: err}
	}

	// 8a. Configure CTAP2 authentication.
	noAuth, _ := cmd.Flags().GetBool("no-auth")

	// 8b. Configure extension pairing verification.
	noPairing, _ := cmd.Flags().GetBool("no-pairing")

	// 8c. Apply enterprise policy overrides. The section is consulted only
	// through serveEnterprisePolicy, which never returns an unverified
	// sealed section (#118).
	pol, err := serveEnterprisePolicy(cmd, GetConfig(), config.ConfigDir(), logger)
	if err != nil {
		return err
	}
	if pol != nil {
		if !pol.ExtensionEnabled {
			return &DetailError{Err: ErrServeIPCStartFailed, Detail: ": browser extension disabled by enterprise policy"}
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
		var fido2Backend xkms.StorageBackend
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
				fido2Backend, fsErr = xkms.NewFileStorageBackend(fido2Dir)
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
				// Wire the same audit logger the autofill service uses, so
				// the authenticator's security events (OpPINSeeded,
				// OpFIDO2CredentialCreated) reach the same audit trail as
				// every other headless-daemon security event (#688).
				auth.SetAuditLogger(audit.NewFIDO2Logger(auditLogger))

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

	socketPath := resolvedSocketPath(cmd)

	server, err := ipc.NewServer(socketPath, handler, logger)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrServeIPCStartFailed, Cause: err}
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
func initHeadlessAuthenticator(backend xkms.StorageBackend, pinSvc *services.PINService, logger *slog.Logger) (*authenticator.Authenticator, error) {
	store, err := authenticator.NewBackendStorage(backend, "fido2/xkey/")
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrServeAuthenticatorInitFailed, Cause: err}
	}

	// The attestation format lives in the unified xkey config
	// (`fido2.attestation`), the same place the GUI and the CLI read it from.
	attestationFormat := authenticator.AttestationFormatNone
	if ucfg, cfgErr := config.Load(); cfgErr == nil && ucfg.FIDO2.Attestation != "" {
		attestationFormat = ucfg.FIDO2.Attestation
	}

	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		Storage: store,
		// One product, one AAGUID: authenticator.DefaultAAGUID is the single
		// definition every xkey entry point reports. A relying party allowlists
		// this value and, once attestation carries an x5c, the attestation
		// certificate vouches for it, so a per-entry-point value would make one
		// of them unallowlistable.
		AAGUID:                     authenticator.DefaultAAGUID,
		AttestationFormat:          attestationFormat,
		EnablePIN:                  true,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		UserPresenceHandler:        authenticator.NewAutoGrantHandler(),
		Logger:                     logger,
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrServeAuthenticatorInitFailed, Cause: err}
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
			return nil, nil, &SentinelCauseError{Sentinel: ErrServeLogFileOpenFailed, Cause: err}
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

// serveEnterprisePolicy resolves the enterprise plane for the headless server.
//
// It returns nil when the config directory is not sealed: personal mode has
// no enterprise plane and the user's own settings apply. In a sealed
// directory it returns the policy section only once it has verified under
// the SO PIN supplied through the SO PIN sources (soPINUsage). With no SO
// PIN supplied it returns config.DefaultPolicy — the secure configuration —
// and says so, because a daemon started by a user session has no SO at the
// keyboard and the sealed file is a value any local user could have written
// (#118). With an SO PIN supplied and a section that does not verify it
// returns ErrServePolicyRefused, and the server does not start.
func serveEnterprisePolicy(cmd *cobra.Command, unified *config.Config, configDir string, logger *slog.Logger) (*config.PolicySection, error) {
	if !config.IsEnterpriseMode(configDir) {
		return nil, nil
	}

	soPIN, err := resolveSOPINInput(cmd)
	if err != nil {
		return nil, err
	}
	if soPIN == "" {
		logger.Warn("sealed enterprise policy not consulted: no SO PIN supplied, applying the default policy",
			"config_dir", configDir,
			"hint", "supply the SO PIN (--so-pin-stdin or XKEY_SO_PIN) to honour the sealed policy")
		return config.DefaultPolicy(), nil
	}

	policy, err := config.LoadVerifiedPolicy(unified, configDir, soPIN)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrServePolicyRefused, Cause: err}
	}
	logger.Info("enterprise policy verified", "state", policy.State.String())
	return &policy.Policy, nil
}

// resolveBarrierPassword resolves the barrier password from
// --barrier-password-stdin, --barrier-password-file, the
// XKEY_BARRIER_PASSWORD environment variable, or an interactive terminal
// prompt (in priority order). There is no "--barrier-password" value flag
// (go-xkms#1209): a value on the command line is visible to every other
// process on the host via 'ps'.
func resolveBarrierPassword(cmd *cobra.Command) (string, error) {
	// 1. --barrier-password-stdin flag
	fromStdin, err := cmd.Flags().GetBool(barrierPasswordSource.stdinFlag)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrPINInputFlagsMissing, Cause: err}
	}
	if fromStdin {
		secret, err := barrierPasswordSource.resolveBytesFrom(true)
		if err != nil {
			return "", err
		}
		defer enclave.Wipe(secret)
		return string(secret), nil
	}

	// 2. --barrier-password-file flag
	if file, _ := cmd.Flags().GetString("barrier-password-file"); file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", &SentinelCauseError{Sentinel: ErrServeBarrierPasswordRequired, Cause: err}
		}
		pw := strings.SplitN(string(data), "\n", 2)[0]
		return strings.TrimSpace(pw), nil
	}

	// 3. XKEY_BARRIER_PASSWORD environment variable
	if pw := os.Getenv(barrierPasswordSource.envVar); pw != "" {
		return pw, nil
	}

	// 4. Interactive stdin prompt (only if terminal)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Barrier password: ")
		pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", &SentinelCauseError{Sentinel: ErrServeBarrierPasswordRequired, Cause: err}
		}
		return string(pwBytes), nil
	}

	return "", ErrServeBarrierPasswordRequired
}

// initPlainStores creates plain (unencrypted) file-based stores for no-barrier
// mode. Paths match CLI defaults so data seeded via `xkey password add --store`
// and `xkey oath add --store` is visible to the headless server. The caller
// owns the returned password store and closes it at shutdown.
func initPlainStores(dataDir string, passwordSvc *services.StaticPasswordService, oathSvc *services.OATHService) (io.Closer, error) {
	// Password store: same as CLI default (data/staticpw subdirectory).
	pwStore, err := openPasswordStore(filepath.Join(dataDir, "staticpw"))
	if err != nil {
		return nil, err
	}

	// OATH store: the CLI's store set, every backend partition beside
	// data/oath.json.
	oathStore, err := openOATHStores(nil, filepath.Join(dataDir, oathStoreFilename))
	if err != nil {
		return nil, errors.Join(err, pwStore.Close())
	}

	passwordSvc.SetStore(pwStore)
	oathSvc.SetStore(oathStore)
	return pwStore, nil
}

// initBarrierStores wires barrier-encrypted stores after a successful unseal.
func initBarrierStores(barrierSvc *services.BarrierService, passwordSvc *services.StaticPasswordService, oathSvc *services.OATHService) error {
	backend := barrierSvc.GetBackend()
	if backend == nil {
		return ErrServeStoreInitFailed
	}
	pwStore, err := staticpw.NewBackendStore(backend)
	if err != nil {
		return err
	}
	passwordSvc.SetStore(pwStore)

	oathStore, err := openOATHStores(backend, "")
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

// HandleStatus returns the IPC server status. When an app lock service is
// wired, the action carries the real lock state so a client can verify that
// the state an unlock reported is the state the daemon is actually in. Without
// one there is no lock to report and the daemon is simply ready.
func (h *headlessHandler) HandleStatus() (*ipc.Response, error) {
	action := ipc.ActionDaemonReady
	if h.appLockSvc != nil {
		action = ipc.ActionUnlocked
		if h.appLockSvc.IsLocked() {
			action = ipc.ActionLocked
		}
	}
	return &ipc.Response{
		Status: ipc.StatusOK,
		Action: action,
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

// HandleUnlock implements ipc.UnlockHandler by delegating to AppLockService,
// which verifies the resulting state and names what the PIN released.
func (h *headlessHandler) HandleUnlock(pin string) (*ipc.UnlockResult, error) {
	if h.appLockSvc == nil {
		return &ipc.UnlockResult{Success: false, Error: "app lock service not configured"}, nil
	}
	return h.appLockSvc.HandleUnlock(pin), nil
}

// readBarrierStrategy reads the sealed root key blob from disk and returns
// the strategy ID that was used to seal the barrier. This allows the serve
// command to initialize only the required sealer backend rather than probing
// all available hardware.
func readBarrierStrategy(dataDir string) (xkms.StrategyID, error) {
	data, err := loadBarrierRootKey(dataDir)
	if err != nil {
		return "", &WrappedError{Msg: "read root key", Err: err}
	}

	// Parse only the strategy field to minimize exposure to the sealed blob.
	var envelope struct {
		Strategy xkms.StrategyID `json:"strategy"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", &WrappedError{Msg: "parse root key", Err: err}
	}
	if envelope.Strategy == "" {
		return "", ErrServeRootKeyMissingStrategy
	}
	return envelope.Strategy, nil
}

// defaultBarrierTPMDevice is the TPM device path used when no --tpm-device flag
// or TPM_DEVICE_PATH environment variable is supplied.
const defaultBarrierTPMDevice = "/dev/tpmrm0"

// resolveTPMDevice resolves the TPM device path for the tpm2 barrier
// strategy. Priority: explicit device (e.g. a --tpm-device flag value) >
// TPM_DEVICE_PATH environment variable (matches the server-side behavior
// in pkg/config) > defaultBarrierTPMDevice.
func resolveTPMDevice(device string) string {
	if device != "" {
		return device
	}
	if envDevice := os.Getenv("TPM_DEVICE_PATH"); envDevice != "" {
		return envDevice
	}
	return defaultBarrierTPMDevice
}

// probeTPMModule attempts to open the TPM -- the hardware device at the
// resolved path, or the in-process simulator when useSimulator is true --
// for barrier unsealing. Returns (tpm, closer) if the TPM is available, or
// (nil, nil) if not. The caller must close the returned io.Closer when the
// TPM is no longer needed.
//
// It delegates to openTPMModule, the same TPM-opening primitive
// newPINTPMProvider uses for PIN backend resolution, so the barrier and
// PIN code paths never drift into different TPM configurations. It is the
// one place that tolerates "no TPM" as a non-error, nil result rather than
// propagating openTPMModule's error: probeTPMSealer (the barrier strategy
// view) and tryBarrierPolicyAutoUnseal (the PCR-policy auto-unseal view,
// barrier_auto_unseal.go) both need the full xkms.TrustedPlatformModule,
// not just the narrower Sealer method set, so they share this rather than
// each probing the TPM independently.
// unsealWithExternalStrategy builds the strategy that sealed the barrier's
// root key -- one the barrier service cannot assemble itself (pkcs11 or a
// cloud KMS) -- injects it and unseals with it. The returned closer releases
// the strategy's backend.
func unsealWithExternalStrategy(barrierSvc *services.BarrierService, id xkms.StrategyID, build func() (xkms.SealingStrategy, io.Closer, error)) (io.Closer, error) {
	strategy, closer, err := build()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrServeBarrierUnsealFailed, Cause: err}
	}
	barrierSvc.SetExternalStrategyFunc(func(_ string) (xkms.SealingStrategy, error) {
		return strategy, nil
	})
	if err := barrierSvc.Unseal("", string(id)); err != nil {
		if closer != nil {
			err = errors.Join(err, closer.Close())
		}
		return nil, &SentinelCauseError{Sentinel: ErrServeBarrierUnsealFailed, Cause: err}
	}
	return closer, nil
}

func probeTPMModule(logger *slog.Logger, dataDir, device string, useSimulator bool) (xkms.TrustedPlatformModule, io.Closer) {
	tpm, closer, err := openTPMModule(logger, dataDir, device, useSimulator)
	if err != nil {
		logger.Debug("TPM unavailable, barrier TPM2 strategy unavailable", "error", err)
		return nil, nil
	}
	return tpm, closer
}

// probeTPMSealer narrows probeTPMModule's result to the Sealer interface
// the barrier strategy needs; see probeTPMModule for the shared
// TPM-opening behaviour.
func probeTPMSealer(logger *slog.Logger, dataDir, device string, useSimulator bool) (xkms.Sealer, io.Closer) {
	return probeTPMModule(logger, dataDir, device, useSimulator)
}

// pkcs11BarrierStrategy and cloudKMSBarrierStrategy build the external
// strategies serve unseals a pkcs11 or cloud KMS barrier with. Tests replace
// them with in-process strategies; outside tests they are the HSM and cloud
// KMS builders.
var (
	pkcs11BarrierStrategy   = buildPKCS11BarrierStrategy
	cloudKMSBarrierStrategy = buildCloudKMSBarrierStrategy
)

// Compile-time interface satisfaction checks.
var _ ipc.Handler = (*headlessHandler)(nil)
var _ ipc.AutofillHandler = (*headlessHandler)(nil)
var _ ipc.PairingHandler = (*headlessHandler)(nil)
var _ ipc.UnlockHandler = (*headlessHandler)(nil)
