// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/secretservice"
)

// Secret Service command sentinel errors.
var (
	// ErrSecretServiceStartFailed is returned when the daemon cannot be
	// constructed or bound to the bus.
	ErrSecretServiceStartFailed = errors.New("secret-service: failed to start")

	// ErrSecretServiceUnlockFailed is returned when a configured
	// --barrier-password-file cannot be read at unlock time.
	ErrSecretServiceUnlockFailed = errors.New("secret-service: failed to resolve barrier password")
)

// secretServiceBus is the --bus flag for `xkey secret-service`.
var secretServiceBus string

// secretServiceCmd runs the org.freedesktop.secrets D-Bus daemon in the
// foreground, following the same start/signal/stop shape as `xkey agent
// start`. There is deliberately no separate stop/status pair (unlike
// `agent`): the daemon owns no shared enrollment state that a second process
// needs to inspect, so SIGINT/SIGTERM is the only shutdown path, same as
// `xkey extension serve`.
var secretServiceCmd = &cobra.Command{
	Use:   "secret-service",
	Short: "Run the freedesktop Secret Service daemon (org.freedesktop.secrets)",
	Long: `Run xkey as a freedesktop.org Secret Service provider, exposing the
static-password store to secret-tool, git-credential-libsecret, browsers and
any other org.freedesktop.Secret.Service client over D-Bus.

Every collection is a static-password folder and every item is a password
entry; there is exactly one lock behind all of them, the barrier itself
(see 'xkey barrier'). While the barrier is sealed, every collection reports
Locked=true and no method that would touch a secret succeeds -- they fail
with org.freedesktop.Secret.Error.IsLocked instead. A client's Service.Unlock
opens a Prompt that this command resolves the same way 'xkey barrier unseal'
does: --barrier-password, then --barrier-password-file, then
XKEY_BARRIER_PASSWORD, then (only on an interactive terminal) an
interactive password prompt.

FIPS 140 enforcement (GODEBUG=fips140=only or a GOFIPS140 build) narrows the
session encryption algorithms OpenSession offers to "plain" only: the
dh-ietf1024-sha256-aes128-cbc-pkcs7 algorithm's key derivation is not an
approved construction. This is safe because org.freedesktop.secrets is only
reachable over the local, kernel-mediated D-Bus session bus.

The barrier must already be initialized ('xkey barrier init'); this command
never initializes one.

Examples:
  # Run on the session bus, unsealing interactively on first Unlock
  xkey secret-service

  # Run with the barrier already unsealed at startup (piped password)
  echo "mypassword" | xkey secret-service --barrier-password-file /dev/stdin

  # Run on the system bus (requires a matching D-Bus policy file)
  xkey secret-service --bus system`,
	RunE: runSecretService,
}

func init() {
	RootCmd.AddCommand(secretServiceCmd)

	secretServiceCmd.Flags().StringVar(&secretServiceBus, "bus", "session", "D-Bus bus to own org.freedesktop.secrets on (session or system)")
	secretServiceCmd.Flags().StringVar(&barrierDataDir, "data-dir", "", "data directory for barrier storage (default: ~/.xkey/data)")
	secretServiceCmd.Flags().StringVar(&barrierStrategy, "strategy", "", "barrier seal strategy override (default: the strategy the barrier was initialized with)")
	secretServiceCmd.Flags().StringVar(&barrierTPMDevice, "tpm-device", "", "TPM device path for the tpm2 strategy (default: $TPM_DEVICE_PATH or /dev/tpmrm0)")
	secretServiceCmd.Flags().BoolVar(&barrierTPMSimulator, "tpm-simulator", false, "use the in-process TPM simulator instead of a hardware device (requires a simulator build)")
	secretServiceCmd.Flags().String("barrier-password", "", "barrier password used to unlock on demand (or XKEY_BARRIER_PASSWORD)")
	secretServiceCmd.Flags().String("barrier-password-file", "", "path to a file containing the barrier password")
}

func runSecretService(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	logger := slog.Default()

	dataDir, err := resolveBarrierDataDir()
	if err != nil {
		return err
	}
	if !barrierRootKeyExists(dataDir) {
		return &BarrierError{
			Operation: "check_initialized",
			Message:   "barrier not initialized, run 'xkey barrier init' first",
		}
	}

	barrier, closer, err := createBarrier(dataDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = barrier.Close()
		if closer != nil {
			_ = closer.Close()
		}
	}()

	backend := xkms.NewBarrierBackend(barrier)
	store := xkms.NewStaticPasswordStore(backend)

	config := secretservice.DefaultConfig()
	config.Bus = secretServiceBus

	daemon, err := secretservice.NewDaemon(store, barrier, config, logger)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecretServiceStartFailed, Cause: err}
	}
	daemon.SetUnlockFunc(secretServiceUnlockFunc(cmd))

	// Same chicken-and-egg the GUI's audit store solves the same way (see
	// pkg/gui/app.go): the barrier-backed store is not necessarily unsealed
	// yet, so the audit trail starts in-memory rather than blocking startup
	// on a password. It is process-lifetime only; xkmsd-backed persistent
	// audit is a separate, larger wiring this command does not attempt.
	auditStore, auditErr := audit.NewBackendStore(xkms.NewStorageMemory(), 10000, logger)
	if auditErr != nil {
		return &SentinelCauseError{Sentinel: ErrSecretServiceStartFailed, Cause: auditErr}
	}
	daemon.SetAuditLogger(auditStore)

	// Unseal immediately when a password was supplied up front, so the
	// daemon starts unlocked instead of forcing the first client through a
	// Prompt round-trip. Starting sealed is not an error: every collection
	// simply reports Locked=true until a client unlocks it.
	if password, pwErr := resolveSecretServicePassword(cmd); pwErr == nil && password != "" {
		creds, credErr := xkms.CredentialsFor([]byte(password))
		if credErr == nil {
			if unsealErr := barrier.Unseal(context.Background(), creds); unsealErr != nil {
				logger.Warn("secret-service: startup unseal failed, starting sealed", slog.String("error", unsealErr.Error()))
			}
			creds.Secret.Destroy()
		}
	}

	if err := daemon.Start(); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecretServiceStartFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Secret Service daemon started\n")
	_, _ = fmt.Fprintf(out, "  Bus:    %s\n", secretServiceBus)
	_, _ = fmt.Fprintf(out, "  Name:   %s\n", secretservice.BusName)
	_, _ = fmt.Fprintf(out, "  Sealed: %v\n", barrier.IsSealed())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		_, _ = fmt.Fprintln(out, "\nShutting down Secret Service daemon...")
	case <-ctx.Done():
	}

	return daemon.Stop()
}

// secretServiceUnlockFunc returns the secretservice.UnlockFunc this command
// registers on the daemon: it resolves a password the same way `xkey
// barrier unseal` does (flags, then XKEY_BARRIER_PASSWORD, then an
// interactive terminal prompt via readBarrierPassword) each time a client's
// Unlock drives a Prompt.
func secretServiceUnlockFunc(cmd *cobra.Command) secretservice.UnlockFunc {
	out := cmd.OutOrStdout()
	return func(ctx context.Context) (xkms.SealCredentials, error) {
		password, err := resolveSecretServicePassword(cmd)
		if err != nil {
			return xkms.SealCredentials{}, err
		}
		if password == "" {
			password, err = readBarrierPassword(out, "Enter barrier password to unlock the secret service: ")
			if err != nil {
				return xkms.SealCredentials{}, err
			}
		}
		return xkms.CredentialsFor([]byte(password))
	}
}

// resolveSecretServicePassword resolves the barrier password the same way
// `xkey barrier unseal` and the device commands do: --barrier-password,
// then --barrier-password-file, then XKEY_BARRIER_PASSWORD. An empty result
// with a nil error means "no password configured", not a failure: the
// caller falls back to an interactive prompt.
func resolveSecretServicePassword(cmd *cobra.Command) (string, error) {
	password, _ := cmd.Flags().GetString("barrier-password")
	if password == "" {
		if path, _ := cmd.Flags().GetString("barrier-password-file"); path != "" {
			raw, err := os.ReadFile(path)
			if err != nil {
				return "", &SentinelCauseError{Sentinel: ErrSecretServiceUnlockFailed, Cause: err}
			}
			password = strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
		}
	}
	if password == "" {
		password = os.Getenv("XKEY_BARRIER_PASSWORD")
	}
	return password, nil
}
