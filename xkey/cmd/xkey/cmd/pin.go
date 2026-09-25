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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pinstrategy"
)

const (
	// defaultPINStateSubdir is the subdirectory under the data dir
	// for PIN state persistence.
	defaultPINStateSubdir = "pin"
)

var (
	// pinDataDir is the --data-dir flag for pin commands.
	pinDataDir string

	// pinTPMDevice is the --tpm-device flag for pin commands: the device
	// path probed when the persisted governing strategy is tpm2. Device
	// selection follows the same --tpm-device/TPM_DEVICE_PATH priority as
	// "xkey barrier" and "xkey extension serve" (see resolveTPMDevice).
	pinTPMDevice string

	// pinTPMSimulator is the --tpm-simulator flag for pin commands.
	pinTPMSimulator bool

	// pinStdinMu guards pinStdin and pinStdinReader.
	pinStdinMu sync.Mutex

	// pinStdin is the source of piped PIN input. It is a variable so that
	// tests can substitute a deterministic reader; production always reads
	// os.Stdin.
	pinStdin io.Reader = os.Stdin

	// pinStdinReader is a shared buffered reader over pinStdin. It is
	// created lazily on first use to prevent multiple bufio.NewReader
	// instances from consuming data from the same underlying reader.
	pinStdinReader *bufio.Reader
)

// pinInputIsTerminal reports whether PIN input can be prompted for
// interactively. It is a variable so tests can exercise both the terminal
// and the piped-stdin branches.
var pinInputIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// setPINStdin points piped PIN input at r, discarding any data buffered
// from the previous source, and returns a function that restores the
// previous source. Only tests call it.
func setPINStdin(r io.Reader) func() {
	pinStdinMu.Lock()
	previous := pinStdin
	pinStdin = r
	pinStdinReader = nil
	pinStdinMu.Unlock()

	return func() {
		pinStdinMu.Lock()
		pinStdin = previous
		pinStdinReader = nil
		pinStdinMu.Unlock()
	}
}

// pinCmd is the parent command for PIN management operations.
var pinCmd = &cobra.Command{
	Use:   "pin",
	Short: "PIN management",
	Long: `Manage Security Officer (SO) and User PINs for xKey.

PINs provide authentication for sensitive operations. The SO PIN acts as
the master credential, while the User PIN is for day-to-day operations.
Both are hashed with Argon2id and persisted securely.

These are the host PIN service's credentials, under the data directory. The
virtual FIDO2 authenticator has its own Security Officer PIN, a separate
credential over separate state: see "xkey fido2 init-token".

Lockout protection automatically locks PINs after too many failed attempts
with configurable exponential backoff.

Commands:
  set-so          Set the Security Officer PIN (first-time)
  set-user        Set the User PIN (requires SO PIN)
  change-so       Change the SO PIN
  change-user     Change the User PIN
  verify          Verify a PIN
  status          Show PIN and lockout status
  reset-lockout   Reset lockout counter (requires SO PIN)

Examples:
  # Set the SO PIN for the first time
  xkey pin set-so

  # Set the user PIN (requires SO PIN)
  xkey pin set-user

  # Verify a user PIN
  xkey pin verify --type user

  # Show PIN status
  xkey pin status

  # Reset lockout after too many failed attempts
  xkey pin reset-lockout`,
}

func init() {
	RootCmd.AddCommand(pinCmd)

	// Add persistent flags available to all pin subcommands.
	pinCmd.PersistentFlags().StringVar(&pinDataDir, "data-dir", "",
		"data directory for PIN state (default: ~/.xkey/data)")
	pinCmd.PersistentFlags().StringVar(&pinTPMDevice, "tpm-device", "",
		"TPM device path probed when the governing PIN strategy is tpm2 (default: $TPM_DEVICE_PATH or /dev/tpmrm0)")
	pinCmd.PersistentFlags().BoolVar(&pinTPMSimulator, "tpm-simulator", false,
		"use the in-process TPM simulator instead of a hardware device (requires a simulator build)")
}

// getPINStdinReader returns the shared buffered reader for piped stdin.
func getPINStdinReader() *bufio.Reader {
	pinStdinMu.Lock()
	defer pinStdinMu.Unlock()
	if pinStdinReader == nil {
		pinStdinReader = bufio.NewReader(pinStdin)
	}
	return pinStdinReader
}

// resolvePINDataDir resolves the data directory for PIN state through the
// CLI's single resolution chain (see resolveDataDir).
// Priority: --data-dir flag > XKEY_DATA_DIR env > viper config > ~/.xkey/data
//
// The default is the same ~/.xkey/data every other subsystem uses. A
// private fallback here once dropped the `data` segment, so every pin
// subcommand read a phantom empty store beside the real one (issue #295).
func resolvePINDataDir() (string, error) {
	dataDir, err := resolveDataDir(pinDataDir)
	if err != nil {
		return "", &PINCommandError{
			Operation: "resolve_data_dir",
			Err:       err,
		}
	}
	return dataDir, nil
}

// resolvePINDataDirExisting resolves the same chain as resolvePINDataDir
// but never creates a directory. Commands that only consult existing PIN
// state (status, verify, change, reset-lockout) use it, so a read cannot
// manufacture the empty store that made issue #295 invisible.
func resolvePINDataDirExisting() (string, error) {
	dataDir, err := resolveDataDirExisting(pinDataDir)
	if err != nil {
		return "", &PINCommandError{
			Operation: "resolve_data_dir",
			Err:       err,
		}
	}
	return dataDir, nil
}

// pinStateDir returns the PIN state directory under the resolved data
// directory.
func pinStateDir(dataDir string) string {
	return filepath.Join(dataDir, defaultPINStateSubdir)
}

// createPINService creates a qrdbsdk.PINService backed by a SoftwareBackend
// using file-based storage from the resolved data directory, creating the
// PIN state directory if it does not exist. Only commands that legitimately
// initialize PIN state (set-so, set-user) call it; everything else opens
// the store with openPINService.
func createPINService(dataDir string) (*qrdbsdk.PINService, error) {
	pinDir := pinStateDir(dataDir)
	if err := os.MkdirAll(pinDir, 0700); err != nil {
		return nil, &PINCommandError{
			Operation: "create_pin_dir",
			Err:       err,
		}
	}
	return newPINService(dataDir)
}

// openPINService creates a qrdbsdk.PINService over an existing PIN state
// directory. When the directory does not exist it returns
// *PINStoreNotFoundError instead of fabricating a fresh store: an absent
// store is a distinct fact ("not initialized, or wrong data directory")
// that must never be reported as a confident "PIN not set".
func openPINService(dataDir string) (*qrdbsdk.PINService, error) {
	pinDir := pinStateDir(dataDir)
	info, err := os.Stat(pinDir)
	if err != nil || !info.IsDir() {
		return nil, &PINStoreNotFoundError{Dir: pinDir}
	}
	return newPINService(dataDir)
}

// cliSoftwarePINProvider persists software PIN state under pinDir and
// routes through the PIN adapter so the qrdb software backend observes
// the canonical pin.ErrNotFound on a fresh install rather than xkey's
// storage.ErrNotFound (which it would treat as a load failure).
type cliSoftwarePINProvider struct {
	pinDir string
}

// Storage implements xkms.PINSoftwareProvider.
func (p cliSoftwarePINProvider) Storage() (qrdbsdk.PINStorage, error) {
	fileStore, err := xkms.NewFileStorageBackend(p.pinDir)
	if err != nil {
		return nil, err
	}
	return xkms.NewPINStoreAdapter(fileStore)
}

// HashConfig implements xkms.PINSoftwareProvider.
func (p cliSoftwarePINProvider) HashConfig() qrdbsdk.PINHashConfig {
	return qrdbsdk.AutoDetectHashConfig()
}

// newPINService resolves the PIN backend that governs the PIN state under
// dataDir through the shared pinstrategy package — the same resolution
// rule the xKey GUI and the headless daemon use — and wires it into a
// qrdbsdk.PINService.
//
// A PIN store with no persisted strategy yet (a fresh install, or PIN
// state that predates this package) auto-selects hardware-first and
// persists the choice. A PIN store whose persisted strategy needs a
// provider unavailable in this build/host (a device set up through the
// GUI's TPM2 wizard, probed here without a TPM present) returns
// *pinstrategy.ProviderUnavailableError instead of silently answering
// from the software store: that silent fallback is the bug go-xkms#307
// reports.
func newPINService(dataDir string) (*qrdbsdk.PINService, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	pinDir := pinStateDir(dataDir)

	persisted, loadErr := pinstrategy.Load(pinDir)
	persistedTPM2 := loadErr == nil && persisted == qrdbsdk.PINStrategyTPM2

	backend, _, err := pinstrategy.Resolve(pinstrategy.Config{
		PINDir: pinDir,
		PINSelectConfig: xkms.PINSelectConfig{
			TPM:      newPINTPMProvider(logger, dataDir, pinTPMDevice, pinTPMSimulator, persistedTPM2),
			Software: cliSoftwarePINProvider{pinDir: pinDir},
			Logger:   logger,
		},
	})
	if err != nil {
		return nil, &PINCommandError{
			Operation: "create_service",
			Err:       err,
		}
	}

	return qrdbsdk.NewPINService(backend, logger), nil
}

// readPIN reads a PIN from terminal or piped stdin.
func readPIN(out io.Writer, prompt string) (string, error) {
	if pinInputIsTerminal() {
		_, _ = fmt.Fprint(out, prompt)
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(out)
		if err != nil {
			return "", &PINCommandError{Operation: "read_pin", Err: err}
		}
		if len(pinBytes) == 0 {
			return "", ErrPINCmdEmpty
		}
		return string(pinBytes), nil
	}

	// Read from piped stdin using the shared reader.
	return readLineFromPipedStdin()
}

// readAndConfirmPIN reads a PIN with confirmation.
func readAndConfirmPIN(out io.Writer, prompt string) (string, error) {
	if pinInputIsTerminal() {
		return readPINFromTerminal(out, prompt)
	}
	return readPINFromStdin()
}

// readPINFromTerminal reads and confirms a PIN from terminal.
func readPINFromTerminal(out io.Writer, prompt string) (string, error) {
	_, _ = fmt.Fprint(out, prompt)
	pin1, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(out)
	if err != nil {
		return "", &PINCommandError{Operation: "read_pin", Err: err}
	}

	_, _ = fmt.Fprint(out, "Confirm PIN: ")
	pin2, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(out)
	if err != nil {
		return "", &PINCommandError{Operation: "read_pin", Err: err}
	}

	if !bytes.Equal(pin1, pin2) {
		return "", ErrPINCmdMismatch
	}

	if len(pin1) == 0 {
		return "", ErrPINCmdEmpty
	}

	return string(pin1), nil
}

// readPINFromStdin reads and confirms a PIN from piped stdin using the
// shared reader.
func readPINFromStdin() (string, error) {
	pin1, err := readLineFromPipedStdin()
	if err != nil {
		return "", err
	}

	pin2, err := readLineFromPipedStdin()
	if err != nil {
		return "", err
	}

	if pin1 != pin2 {
		return "", ErrPINCmdMismatch
	}

	return pin1, nil
}

// readLineFromPipedStdin reads a single line from the shared piped stdin reader.
func readLineFromPipedStdin() (string, error) {
	reader := getPINStdinReader()
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", &PINCommandError{Operation: "read_pin", Err: err}
	}
	// Trim BOTH \n and a preceding \r: CRLF input (a Windows console, or a
	// CRLF file/here-doc piped in) would otherwise store a PIN with a
	// trailing carriage return that can never be re-entered from a
	// terminal — permanently locking the SO/user PIN.
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", ErrPINCmdEmpty
	}
	return line, nil
}
