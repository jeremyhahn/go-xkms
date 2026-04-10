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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

const (
	// defaultBarrierRootKeyPath is the storage key for the sealed root key blob.
	// This matches the GUI and extension serve paths for unified barrier access.
	defaultBarrierRootKeyPath = "barrier/root_key"
)

var (
	// barrierDataDir is the --data-dir flag for barrier commands.
	barrierDataDir string

	// barrierStrategy is the --strategy flag for barrier init.
	barrierStrategy string
)

// barrierCmd is the parent command for barrier seal/unseal operations.
var barrierCmd = &cobra.Command{
	Use:   "barrier",
	Short: "Barrier seal/unseal management",
	Long: `Manage the barrier that protects xKey secrets at rest.

The barrier uses AES-256-GCM to transparently encrypt all stored values.
A root key is generated during initialization and sealed using the best
available strategy (TPM2, PKCS#11, or software-based Argon2id).

Lifecycle:
  1. Initialize  - Generate a new root key and seal it
  2. Unseal       - Load and decrypt the root key, derive DEK
  3. Seal         - Zero the DEK and lock all operations

Commands:
  init      First-time barrier setup
  unseal    Unseal the barrier (requires password)
  seal      Seal the barrier (lock it)
  status    Show current barrier status

Examples:
  # Initialize the barrier
  xkey barrier init

  # Initialize with a specific strategy
  xkey barrier init --strategy software

  # Unseal the barrier
  xkey barrier unseal

  # Seal the barrier
  xkey barrier seal

  # Show barrier status
  xkey barrier status`,
}

func init() {
	RootCmd.AddCommand(barrierCmd)

	// Add persistent flags available to all barrier subcommands.
	barrierCmd.PersistentFlags().StringVar(&barrierDataDir, "data-dir", "",
		"data directory for barrier storage (default: ~/.xkey/data)")
}

// resolveBarrierDataDir resolves the data directory for barrier storage.
// Priority: --data-dir flag > XKEY_DATA_DIR env > viper config > ~/.xkey/data
// The default matches the GUI and extension serve paths for unified barrier access.
func resolveBarrierDataDir() (string, error) {
	if barrierDataDir != "" {
		return filepath.Clean(barrierDataDir), nil
	}

	if envDir := os.Getenv("XKEY_DATA_DIR"); envDir != "" {
		return filepath.Clean(envDir), nil
	}

	if viperDir := viper.GetString("data_dir"); viperDir != "" {
		return filepath.Clean(viperDir), nil
	}

	home, err := xhome.Resolve()
	if err != nil {
		return "", &BarrierError{
			Operation: "resolve_data_dir",
			Err:       err,
		}
	}
	return home.EnsureDataDir()
}

// createBarrier creates a Barrier instance from the resolved data directory
// and strategy preference. The dataDir is used directly as the storage root,
// matching the GUI and extension serve barrier layout.
func createBarrier(dataDir string) (*seal.Barrier, error) {
	backend, err := file.New(dataDir)
	if err != nil {
		return nil, &BarrierError{
			Operation: "create_storage",
			Err:       err,
		}
	}

	strategies := buildStrategies()
	if len(strategies) == 0 {
		return nil, &BarrierError{
			Operation: "create_barrier",
			Message:   "no sealing strategies available",
		}
	}

	config := seal.BarrierConfig{
		RootKeyPath: defaultBarrierRootKeyPath,
	}

	// If a strategy preference was specified, set the preference order.
	if barrierStrategy != "" {
		stratID := seal.StrategyID(barrierStrategy)
		config.PreferenceOrder = []seal.StrategyID{stratID}
	}

	barrier, err := seal.NewBarrier(
		slog.Default(),
		backend,
		config,
		strategies...,
	)
	if err != nil {
		return nil, &BarrierError{
			Operation: "create_barrier",
			Err:       err,
		}
	}

	return barrier, nil
}

// buildStrategies returns all available sealing strategies.
// Software strategy is always available as a fallback.
func buildStrategies() []seal.SealingStrategy {
	strategies := make([]seal.SealingStrategy, 0, 3)

	// Software strategy is always available.
	strategies = append(strategies, seal.NewSoftwareStrategy())

	return strategies
}

// readBarrierPassword reads a password from terminal or piped stdin.
func readBarrierPassword(out io.Writer, prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(out, prompt)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(out)
		if err != nil {
			return "", &BarrierError{Operation: "read_password", Err: err}
		}
		if len(password) == 0 {
			return "", ErrBarrierPasswordEmpty
		}
		return string(password), nil
	}

	// Read from piped stdin for automation.
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", &BarrierError{Operation: "read_password", Err: err}
	}
	password = strings.TrimSuffix(password, "\n")
	if password == "" {
		return "", ErrBarrierPasswordEmpty
	}
	return password, nil
}

// readAndConfirmBarrierPassword reads and confirms a password.
func readAndConfirmBarrierPassword(out io.Writer) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return readBarrierPasswordFromTerminal(out)
	}
	return readBarrierPasswordFromStdin(out)
}

// readBarrierPasswordFromTerminal reads password securely from terminal with
// confirmation.
func readBarrierPasswordFromTerminal(out io.Writer) (string, error) {
	fmt.Fprint(out, "Enter password: ")
	password1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", &BarrierError{Operation: "read_password", Err: err}
	}

	fmt.Fprint(out, "Confirm password: ")
	password2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", &BarrierError{Operation: "read_password", Err: err}
	}

	if string(password1) != string(password2) {
		return "", ErrBarrierPasswordConfirm
	}

	if len(password1) == 0 {
		return "", ErrBarrierPasswordEmpty
	}

	return string(password1), nil
}

// readBarrierPasswordFromStdin reads password from piped stdin for automation.
func readBarrierPasswordFromStdin(out io.Writer) (string, error) {
	reader := bufio.NewReader(os.Stdin)

	password1, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", &BarrierError{Operation: "read_password", Err: err}
	}
	password1 = strings.TrimSuffix(password1, "\n")

	password2, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", &BarrierError{Operation: "read_password", Err: err}
	}
	password2 = strings.TrimSuffix(password2, "\n")

	if password1 != password2 {
		return "", ErrBarrierPasswordConfirm
	}

	if password1 == "" {
		return "", ErrBarrierPasswordEmpty
	}

	return password1, nil
}

// barrierRootKeyExists checks if the barrier root key blob exists on disk
// by checking the file in the storage backend directory.
func barrierRootKeyExists(dataDir string) bool {
	keyPath := filepath.Join(dataDir, defaultBarrierRootKeyPath)
	_, err := os.Stat(keyPath)
	return err == nil
}
