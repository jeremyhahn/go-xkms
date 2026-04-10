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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
)

var (
	// pinVerifyType controls which PIN type to verify.
	pinVerifyType string
)

// pinVerifyCmd verifies a PIN.
var pinVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a PIN",
	Long: `Verify a Security Officer or User PIN.

Use the --type flag to select which PIN to verify. Defaults to "user".

Verification is subject to lockout protection. After too many failed
attempts, the PIN will be locked for a configurable duration.

Examples:
  # Verify user PIN (default)
  xkey pin verify

  # Verify SO PIN
  xkey pin verify --type so

  # Verify user PIN explicitly
  xkey pin verify --type user`,
	RunE: runPINVerify,
}

// pinVerifyHandler is a function that verifies a specific PIN type.
type pinVerifyHandler func(cmd *cobra.Command, svc *pin.Service) error

// pinVerifyHandlers maps PIN type strings to their verification handlers.
var pinVerifyHandlers = map[string]pinVerifyHandler{
	"so":   handleVerifySO,
	"user": handleVerifyUser,
}

func init() {
	pinVerifyCmd.Flags().StringVar(&pinVerifyType, "type", "user",
		"PIN type to verify: 'so' or 'user'")

	pinCmd.AddCommand(pinVerifyCmd)
}

func runPINVerify(cmd *cobra.Command, args []string) error {
	// Resolve data directory.
	dataDir, err := resolvePINDataDir()
	if err != nil {
		return err
	}

	// Create PIN service.
	svc, err := createPINService(dataDir)
	if err != nil {
		return err
	}

	// Dispatch to the appropriate handler.
	handler, ok := pinVerifyHandlers[pinVerifyType]
	if !ok {
		return ErrPINCmdInvalidType
	}

	return handler(cmd, svc)
}

func handleVerifySO(cmd *cobra.Command, svc *pin.Service) error {
	out := cmd.OutOrStdout()

	pinValue, err := readPIN(out, "Enter SO PIN: ")
	if err != nil {
		return err
	}

	if err := svc.VerifySOPIN(pinValue); err != nil {
		fmt.Fprintln(out, "SO PIN: INVALID")
		return &PINCommandError{
			Operation: "verify_so",
			Err:       err,
		}
	}

	fmt.Fprintln(out, "SO PIN: VALID")
	return nil
}

func handleVerifyUser(cmd *cobra.Command, svc *pin.Service) error {
	out := cmd.OutOrStdout()

	pinValue, err := readPIN(out, "Enter User PIN: ")
	if err != nil {
		return err
	}

	if err := svc.VerifyUserPIN(pinValue); err != nil {
		fmt.Fprintln(out, "User PIN: INVALID")
		return &PINCommandError{
			Operation: "verify_user",
			Err:       err,
		}
	}

	fmt.Fprintln(out, "User PIN: VALID")
	return nil
}
