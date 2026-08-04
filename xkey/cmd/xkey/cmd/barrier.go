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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
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

	// barrierTPMDevice is the --tpm-device flag for barrier commands. It
	// mirrors the `tpm` command group's --device flag so the tpm2 barrier
	// strategy can target a specific device or the in-process simulator.
	barrierTPMDevice string

	// barrierTPMSimulator is the --tpm-simulator flag for barrier commands.
	// It mirrors the `tpm` command group's --simulator flag.
	barrierTPMSimulator bool
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

  # Initialize with the tpm2 strategy against a specific device
  xkey barrier init --strategy tpm2 --tpm-device /dev/tpm0

  # Initialize with the tpm2 strategy against the in-process simulator
  # (development/testing only; requires a simulator build)
  xkey barrier init --strategy tpm2 --tpm-simulator

  # Unseal the barrier
  xkey barrier unseal

  # Seal the barrier
  xkey barrier seal

  # Show barrier status
  xkey barrier status

The tpm2 strategy's device selection follows this priority: the
--tpm-device/--tpm-simulator flags, then the TPM_DEVICE_PATH environment
variable, then /dev/tpmrm0.`,
}

func init() {
	RootCmd.AddCommand(barrierCmd)

	// Add persistent flags available to all barrier subcommands.
	barrierCmd.PersistentFlags().StringVar(&barrierDataDir, "data-dir", "",
		"data directory for barrier storage (default: ~/.xkey/data)")
	barrierCmd.PersistentFlags().StringVar(&barrierTPMDevice, "tpm-device", "",
		"TPM device path for the tpm2 strategy (default: $TPM_DEVICE_PATH or /dev/tpmrm0)")
	barrierCmd.PersistentFlags().BoolVar(&barrierTPMSimulator, "tpm-simulator", false,
		"Use the in-process TPM simulator instead of a hardware device (requires a simulator build)")
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

// strategyFlagToID maps the user-facing CLI strategy names to the canonical
// seal StrategyIDs. The CLI exposes "software" for the passphrase-protected
// Argon2id strategy to match the documented user experience.
var strategyFlagToID = map[string]xkms.StrategyID{
	"software": xkms.StrategyPassphrase,
	"tpm2":     xkms.StrategyTPM2,
	"pkcs11":   xkms.StrategyPKCS11,
}

// strategyIDToDisplay maps canonical seal StrategyIDs back to the
// user-facing CLI names. IDs without an entry display as themselves.
var strategyIDToDisplay = map[xkms.StrategyID]string{
	xkms.StrategyPassphrase: "software",
}

// strategyDisplayName returns the user-facing name for a strategy ID.
func strategyDisplayName(id xkms.StrategyID) string {
	if name, ok := strategyIDToDisplay[id]; ok {
		return name
	}
	return string(id)
}

// resolveBarrierStrategyID resolves the canonical strategy ID to use for the
// barrier. Priority:
//  1. The --strategy flag, mapped through strategyFlagToID.
//  2. The strategy recorded in an existing sealed root key blob.
//  3. Auto-detect: TPM 2.0 hardware when available, otherwise software.
//
// The hardware-first auto-detect matches the GUI's bestStrategy selection
// and the documented preference order (tpm2, pkcs11, software).
func resolveBarrierStrategyID(dataDir string) (xkms.StrategyID, error) {
	if barrierStrategy != "" {
		id, ok := strategyFlagToID[barrierStrategy]
		if !ok {
			return "", &BarrierError{
				Operation: "validate_strategy",
				Message:   fmt.Sprintf("unknown strategy %q, valid values: software, tpm2, pkcs11", barrierStrategy),
			}
		}
		return id, nil
	}

	if barrierRootKeyExists(dataDir) {
		id, err := readBarrierStrategy(dataDir)
		if err != nil {
			return "", &BarrierError{
				Operation: "read_strategy",
				Err:       err,
			}
		}
		return id, nil
	}

	// Auto-detect: prefer hardware-backed sealing when a TPM is present.
	if sealer, closer := probeTPMSealer(slog.Default(), dataDir, barrierTPMDevice, barrierTPMSimulator); sealer != nil {
		_ = closer.Close()
		return xkms.StrategyTPM2, nil
	}
	return xkms.StrategyPassphrase, nil
}

// assembleBarrierStrategy constructs the sealing strategy for the given
// canonical ID. When the strategy holds hardware resources (TPM), the
// returned io.Closer releases them; it is nil for software strategies.
func assembleBarrierStrategy(id xkms.StrategyID, dataDir string) (xkms.SealingStrategy, io.Closer, error) {
	switch id {
	case xkms.StrategyPassphrase:
		return xkms.NewSoftwareSealStrategy(), nil, nil
	case xkms.StrategyTPM2:
		sealer, closer := probeTPMSealer(slog.Default(), dataDir, barrierTPMDevice, barrierTPMSimulator)
		if sealer == nil {
			return nil, nil, &BarrierError{
				Operation: "assemble_strategy",
				Message:   "tpm2 strategy unavailable: no usable TPM 2.0 device",
			}
		}
		return xkms.NewTPM2Strategy(sealer, nil), closer, nil
	case xkms.StrategyPKCS11:
		return nil, nil, &BarrierError{
			Operation: "assemble_strategy",
			Message:   "pkcs11 strategy requires an HSM module configuration, which the CLI barrier does not support",
		}
	default:
		return nil, nil, &BarrierError{
			Operation: "assemble_strategy",
			Message:   fmt.Sprintf("unsupported strategy %q", id),
		}
	}
}

// createBarrier creates a Barrier instance from the resolved data directory
// and strategy preference. The dataDir is used directly as the storage root,
// matching the GUI and extension serve barrier layout.
//
// The returned io.Closer releases hardware resources held by the assembled
// strategy (e.g. the TPM transport) and may be nil for software strategies.
// Callers must close it after closing the barrier.
func createBarrier(dataDir string) (*xkms.Barrier, io.Closer, error) {
	backend, err := xkms.NewFileStorageBackend(dataDir)
	if err != nil {
		return nil, nil, &BarrierError{
			Operation: "create_storage",
			Err:       err,
		}
	}

	stratID, err := resolveBarrierStrategyID(dataDir)
	if err != nil {
		return nil, nil, err
	}

	strategy, closer, err := assembleBarrierStrategy(stratID, dataDir)
	if err != nil {
		return nil, nil, err
	}

	config := xkms.BarrierConfig{
		RootKeyPath:     defaultBarrierRootKeyPath,
		PreferenceOrder: []xkms.StrategyID{stratID},
	}

	barrier, err := xkms.NewBarrier(
		slog.Default(),
		backend,
		config,
		strategy,
	)
	if err != nil {
		if closer != nil {
			_ = closer.Close()
		}
		return nil, nil, &BarrierError{
			Operation: "create_barrier",
			Err:       err,
		}
	}

	return barrier, closer, nil
}

// readBarrierPassword reads a password from terminal or piped stdin.
func readBarrierPassword(out io.Writer, prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		_, _ = fmt.Fprint(out, prompt)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(out)
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
	_, _ = fmt.Fprint(out, "Enter password: ")
	password1, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(out)
	if err != nil {
		return "", &BarrierError{Operation: "read_password", Err: err}
	}

	_, _ = fmt.Fprint(out, "Confirm password: ")
	password2, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(out)
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
