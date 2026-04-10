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

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/spf13/cobra"
)

var (
	// barrierStatusJSON controls JSON output for barrier status.
	barrierStatusJSON bool
)

// barrierStatusInfo is the CLI-facing barrier status representation.
type barrierStatusInfo struct {
	Initialized    bool   `json:"initialized"`
	Sealed         bool   `json:"sealed"`
	Strategy       string `json:"strategy"`
	HardwareBacked bool   `json:"hardware_backed"`
	DataDir        string `json:"data_dir"`
	RootKeyPath    string `json:"root_key_path"`
}

// barrierStatusCmd shows the current barrier status.
var barrierStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show barrier status",
	Long: `Show the current state of the barrier.

Displays whether the barrier is initialized, sealed/unsealed, which
sealing strategy is in use, and whether it is hardware-backed.

Examples:
  # Show barrier status
  xkey barrier status

  # Show status as JSON
  xkey barrier status --json`,
	RunE: runBarrierStatus,
}

func init() {
	barrierStatusCmd.Flags().BoolVar(&barrierStatusJSON, "json", false,
		"output status as JSON")

	barrierCmd.AddCommand(barrierStatusCmd)
}

func runBarrierStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// Resolve data directory.
	dataDir, err := resolveBarrierDataDir()
	if err != nil {
		return err
	}

	info := barrierStatusInfo{
		DataDir:     dataDir,
		RootKeyPath: filepath.Join(dataDir, defaultBarrierRootKeyPath),
	}

	// Check if initialized by looking for the root key file.
	if !barrierRootKeyExists(dataDir) {
		info.Initialized = false
		info.Sealed = true

		if barrierStatusJSON {
			return writeJSON(out, info)
		}

		fmt.Fprintln(out, "Barrier Status: Not Initialized")
		fmt.Fprintf(out, "  Data directory:  %s\n", dataDir)
		fmt.Fprintln(out, "\nRun 'xkey barrier init' to initialize the barrier.")
		return nil
	}

	info.Initialized = true

	// Try to read the sealed root key to determine strategy.
	rootKeyPath := filepath.Join(dataDir, defaultBarrierRootKeyPath)
	data, readErr := os.ReadFile(rootKeyPath)
	if readErr == nil {
		var sealed seal.SealedRootKey
		if jsonErr := json.Unmarshal(data, &sealed); jsonErr == nil {
			info.Strategy = string(sealed.Strategy)
		}
	}

	// Barrier starts in sealed state when freshly loaded.
	info.Sealed = true

	// Check if strategy is hardware-backed.
	hwBacked := map[string]bool{
		"tpm2":    true,
		"pkcs11":  true,
		"awskms":  true,
		"gcpkms":  true,
		"azurekv": true,
		"vault":   true,
	}
	info.HardwareBacked = hwBacked[info.Strategy]

	if barrierStatusJSON {
		return writeJSON(out, info)
	}

	sealedStr := "Sealed"
	if !info.Sealed {
		sealedStr = "Unsealed"
	}

	hwStr := "No"
	if info.HardwareBacked {
		hwStr = "Yes"
	}

	fmt.Fprintln(out, "Barrier Status:")
	fmt.Fprintf(out, "  Initialized:      Yes\n")
	fmt.Fprintf(out, "  State:            %s\n", sealedStr)
	fmt.Fprintf(out, "  Strategy:         %s\n", info.Strategy)
	fmt.Fprintf(out, "  Hardware-backed:  %s\n", hwStr)
	fmt.Fprintf(out, "  Data directory:   %s\n", dataDir)

	return nil
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
