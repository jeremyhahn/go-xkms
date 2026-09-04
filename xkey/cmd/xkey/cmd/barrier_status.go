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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

var (
	// barrierStatusJSON controls JSON output for barrier status.
	barrierStatusJSON bool
)

// barrierStatusInfo is the CLI-facing barrier status representation. The
// embedded stateSourceInfo names which authority answered: a live daemon
// reporting "Sealed" and a cold data directory reporting "Sealed" are
// different facts and must not render identically.
type barrierStatusInfo struct {
	Initialized    bool   `json:"initialized"`
	Sealed         bool   `json:"sealed"`
	Strategy       string `json:"strategy"`
	HardwareBacked bool   `json:"hardware_backed"`
	DataDir        string `json:"data_dir,omitempty"`
	RootKeyPath    string `json:"root_key_path,omitempty"`

	stateSourceInfo
}

// barrierStatusCmd shows the current barrier status.
var barrierStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show barrier status",
	Long: `Show the current state of the barrier.

Displays whether the barrier is initialized, sealed/unsealed, which
sealing strategy is in use, and whether it is hardware-backed.

The running daemon owns the barrier, so its seal state is read from the
daemon over the IPC socket when one is running. With no daemon running the
on-disk data directory is read instead, which can only ever report a sealed
barrier. The reported source names which one answered.

Examples:
  # Show barrier status (daemon when running, data directory otherwise)
  xkey barrier status

  # Require the running daemon
  xkey barrier status --source daemon

  # Inspect the on-disk data directory even while a daemon runs
  xkey barrier status --source disk

  # Show status as JSON
  xkey barrier status --json`,
	RunE: runBarrierStatus,
}

func init() {
	barrierStatusCmd.Flags().BoolVar(&barrierStatusJSON, "json", false,
		"output status as JSON")
	addStateSourceFlags(barrierStatusCmd, stateSelectorsLocal)

	barrierCmd.AddCommand(barrierStatusCmd)
}

func runBarrierStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	selection, err := stateSourceSelection(cmd, stateSelectorsLocal)
	if err != nil {
		return err
	}

	info, src, err := resolveBarrierStatus(cmd, selection)
	if err != nil {
		return err
	}
	info.stateSourceInfo = src.info()

	if barrierStatusJSON {
		return writeJSON(out, info)
	}

	if !info.Initialized {
		_, _ = fmt.Fprintln(out, "Barrier Status: Not Initialized")
		if info.DataDir != "" {
			_, _ = fmt.Fprintf(out, "  Data directory:  %s\n", info.DataDir)
		}
		_, _ = fmt.Fprintln(out, "\nRun 'xkey barrier init' to initialize the barrier.")
		_, _ = fmt.Fprintln(out)
		writeSource(out, src)
		return nil
	}

	_, _ = fmt.Fprintln(out, "Barrier Status:")
	_, _ = fmt.Fprintf(out, "  Initialized:      Yes\n")
	_, _ = fmt.Fprintf(out, "  State:            %s\n", sealedDisplay(info.Sealed))
	_, _ = fmt.Fprintf(out, "  Strategy:         %s\n", info.Strategy)
	_, _ = fmt.Fprintf(out, "  Hardware-backed:  %s\n", boolToYesNo(info.HardwareBacked))
	if info.DataDir != "" {
		_, _ = fmt.Fprintf(out, "  Data directory:   %s\n", info.DataDir)
	}
	_, _ = fmt.Fprintln(out)
	writeSource(out, src)

	return nil
}

// sealedDisplay renders the seal state.
func sealedDisplay(sealed bool) string {
	if sealed {
		return "Sealed"
	}
	return "Unsealed"
}

// resolveBarrierStatus asks the running daemon — which owns the barrier —
// and falls back to the on-disk data directory only when none can answer.
func resolveBarrierStatus(cmd *cobra.Command, selection string) (barrierStatusInfo, stateSource, error) {
	state, socketPath, answered, reason, err := askDaemon(cmd, selection,
		func(client *ipc.Client) (*ipc.BarrierStatusResult, error) {
			return client.StateBarrier()
		})
	if err != nil {
		return barrierStatusInfo{}, stateSource{}, err
	}
	if answered {
		return barrierStatusInfo{
			Initialized:    state.Initialized,
			Sealed:         state.Sealed,
			Strategy:       strategyDisplayName(xkms.StrategyID(state.Strategy)),
			HardwareBacked: state.HardwareBacked,
		}, daemonSource(socketPath), nil
	}

	info, dataDir, err := readBarrierStatusFromDisk()
	if err != nil {
		return barrierStatusInfo{}, stateSource{}, err
	}
	return info, diskSource(dataDir, reason), nil
}

// readBarrierStatusFromDisk reports what the on-disk data directory records.
// A barrier read this way is always sealed: nothing in this process has
// unsealed it. That is a true statement about the directory and a false one
// about a running device, which is why the source is always reported.
func readBarrierStatusFromDisk() (barrierStatusInfo, string, error) {
	dataDir, err := resolveBarrierDataDir()
	if err != nil {
		return barrierStatusInfo{}, "", err
	}

	info := barrierStatusInfo{
		DataDir:     dataDir,
		RootKeyPath: filepath.Join(dataDir, defaultBarrierRootKeyPath),
	}

	if !barrierRootKeyExists(dataDir) {
		info.Sealed = true
		return info, dataDir, nil
	}

	info.Initialized = true
	info.Sealed = true

	// The sealed root key blob records which strategy protects it.
	data, readErr := os.ReadFile(info.RootKeyPath)
	if readErr == nil {
		var sealed xkms.SealedRootKey
		if jsonErr := json.Unmarshal(data, &sealed); jsonErr == nil {
			info.Strategy = strategyDisplayName(sealed.Strategy)
		}
	}

	info.HardwareBacked = hardwareBackedStrategies[info.Strategy]

	return info, dataDir, nil
}

// hardwareBackedStrategies names the strategies that bind the root key to
// dedicated cryptographic hardware or an external key-management service.
var hardwareBackedStrategies = map[string]bool{
	"tpm2":    true,
	"pkcs11":  true,
	"awskms":  true,
	"gcpkms":  true,
	"azurekv": true,
	"vault":   true,
}

// writeJSON marshals the value as indented JSON and writes it to the writer.
func writeJSON(out io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return &BarrierError{
			Operation: "json_marshal",
			Err:       err,
		}
	}
	_, err = fmt.Fprintln(out, string(data))
	if err != nil {
		return &BarrierError{
			Operation: "write_output",
			Err:       err,
		}
	}
	return nil
}
