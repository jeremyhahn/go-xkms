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
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

const (
	// defaultPINStateSubdir is the subdirectory under the data dir
	// for PIN state persistence.
	defaultPINStateSubdir = "pin"
)

var (
	// pinDataDir is the --data-dir flag for pin commands.
	pinDataDir string

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
		"data directory for PIN state (default: ~/.xkey)")
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

// resolvePINDataDir resolves the data directory for PIN state.
// Priority: --data-dir flag > XKEY_DATA_DIR env > viper config > ~/.xkey
func resolvePINDataDir() (string, error) {
	if pinDataDir != "" {
		return filepath.Clean(pinDataDir), nil
	}

	if envDir := os.Getenv("XKEY_DATA_DIR"); envDir != "" {
		return filepath.Clean(envDir), nil
	}

	if viperDir := viper.GetString("data_dir"); viperDir != "" {
		return filepath.Clean(viperDir), nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", &PINCommandError{
			Operation: "resolve_data_dir",
			Err:       err,
		}
	}
	return filepath.Join(homeDir, ".xkey"), nil
}

// createPINService creates a qrdbsdk.PINService backed by a SoftwareBackend using
// file-based storage from the resolved data directory.
func createPINService(dataDir string) (*qrdbsdk.PINService, error) {
	pinDir := filepath.Join(dataDir, defaultPINStateSubdir)
	if err := os.MkdirAll(pinDir, 0700); err != nil {
		return nil, &PINCommandError{
			Operation: "create_pin_dir",
			Err:       err,
		}
	}

	fileStore, err := xkms.NewFileStorageBackend(pinDir)
	if err != nil {
		return nil, &PINCommandError{
			Operation: "create_service",
			Err:       err,
		}
	}

	// Wrap the file storage in the PIN adapter so the qrdb software backend
	// observes the canonical pin.ErrNotFound on a fresh install rather than
	// xkey's storage.ErrNotFound (which it would treat as a load failure).
	pinStore, err := xkms.NewPINStoreAdapter(fileStore)
	if err != nil {
		return nil, &PINCommandError{
			Operation: "create_service",
			Err:       err,
		}
	}

	hashConfig := qrdbsdk.AutoDetectHashConfig()
	backend, err := qrdbsdk.NewSoftwareBackend(pinStore, hashConfig)
	if err != nil {
		return nil, &PINCommandError{
			Operation: "create_service",
			Err:       err,
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

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

	if string(pin1) != string(pin2) {
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
	if err != nil && err != io.EOF {
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
