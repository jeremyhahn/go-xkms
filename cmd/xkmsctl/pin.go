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

package main

import (
	"context"
	"os"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// pinCmd is the top-level command for PIN management.
var pinCmd = &cobra.Command{
	Use:   "pin",
	Short: "Manage SO and user PINs",
	Long: `Manage the Security Officer (SO) and user PINs.

The SO PIN authorizes privileged operations (setting the user PIN,
resetting the lockout counter). The user PIN authorizes day-to-day
operations such as password store access.

PINs are read from flags when provided; otherwise they are prompted
interactively without echo (or read from stdin when piped).

Subcommands:
  so-set         Set the SO PIN
  so-change      Change the SO PIN
  so-verify      Verify the SO PIN
  user-set       Set the user PIN (SO authorization)
  user-change    Change the user PIN
  user-verify    Verify the user PIN
  lockout        Show PIN lockout status
  lockout-reset  Reset the PIN lockout counter (SO authorization)`,
}

// pinSOSetCmd sets the SO PIN.
var pinSOSetCmd = &cobra.Command{
	Use:   "so-set",
	Short: "Set the Security Officer PIN",
	Long: `Set the Security Officer PIN. When the SO PIN is already set,
--current-pin must match the existing PIN.

Example:
  xkmsctl pin so-set`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		currentPIN := fr.String("current-pin")
		newPIN := fr.String("new-pin")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		pin, err := resolvePIN(newPIN, "New SO PIN")
		if err != nil {
			handleError(err)
			return
		}

		pinSOSet(cfg, printer, &client.SetSOPINRequest{
			CurrentSOPIN: currentPIN,
			NewSOPIN:     pin,
		})
	},
}

// pinSOChangeCmd changes the SO PIN.
var pinSOChangeCmd = &cobra.Command{
	Use:   "so-change",
	Short: "Change the Security Officer PIN",
	Long: `Change the Security Officer PIN.

Example:
  xkmsctl pin so-change`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		currentPIN := fr.String("current-pin")
		newPIN := fr.String("new-pin")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		current, err := resolvePIN(currentPIN, "Current SO PIN")
		if err != nil {
			handleError(err)
			return
		}
		next, err := resolvePIN(newPIN, "New SO PIN")
		if err != nil {
			handleError(err)
			return
		}

		pinSOChange(cfg, printer, &client.ChangeSOPINRequest{
			CurrentSOPIN: current,
			NewSOPIN:     next,
		})
	},
}

// pinSOVerifyCmd verifies the SO PIN.
var pinSOVerifyCmd = &cobra.Command{
	Use:   "so-verify",
	Short: "Verify the Security Officer PIN",
	Long: `Verify the Security Officer PIN.

Example:
  xkmsctl pin so-verify`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		flagPIN := fr.String("pin")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		pin, err := resolvePIN(flagPIN, "SO PIN")
		if err != nil {
			handleError(err)
			return
		}

		pinSOVerify(cfg, printer, &client.VerifySOPINRequest{SOPIN: pin})
	},
}

// pinUserSetCmd sets the user PIN.
var pinUserSetCmd = &cobra.Command{
	Use:   "user-set",
	Short: "Set the user PIN",
	Long: `Set the user PIN. Requires SO PIN authorization.

Example:
  xkmsctl pin user-set`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		soPIN := fr.String("so-pin")
		newPIN := fr.String("new-pin")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		so, err := resolvePIN(soPIN, "SO PIN")
		if err != nil {
			handleError(err)
			return
		}
		next, err := resolvePIN(newPIN, "New user PIN")
		if err != nil {
			handleError(err)
			return
		}

		pinUserSet(cfg, printer, &client.SetUserPINRequest{
			SOPIN:      so,
			NewUserPIN: next,
		})
	},
}

// pinUserChangeCmd changes the user PIN.
var pinUserChangeCmd = &cobra.Command{
	Use:   "user-change",
	Short: "Change the user PIN",
	Long: `Change the user PIN.

Example:
  xkmsctl pin user-change`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		currentPIN := fr.String("current-pin")
		newPIN := fr.String("new-pin")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		current, err := resolvePIN(currentPIN, "Current user PIN")
		if err != nil {
			handleError(err)
			return
		}
		next, err := resolvePIN(newPIN, "New user PIN")
		if err != nil {
			handleError(err)
			return
		}

		pinUserChange(cfg, printer, &client.ChangeUserPINRequest{
			CurrentUserPIN: current,
			NewUserPIN:     next,
		})
	},
}

// pinUserVerifyCmd verifies the user PIN.
var pinUserVerifyCmd = &cobra.Command{
	Use:   "user-verify",
	Short: "Verify the user PIN",
	Long: `Verify the user PIN.

Example:
  xkmsctl pin user-verify`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		flagPIN := fr.String("pin")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		pin, err := resolvePIN(flagPIN, "User PIN")
		if err != nil {
			handleError(err)
			return
		}

		pinUserVerify(cfg, printer, &client.VerifyUserPINRequest{UserPIN: pin})
	},
}

// pinLockoutCmd shows the PIN lockout status.
var pinLockoutCmd = &cobra.Command{
	Use:   "lockout",
	Short: "Show PIN lockout status",
	Long: `Display the current PIN lockout status.

Example:
  xkmsctl pin lockout`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		pinLockout(cfg, printer)
	},
}

// pinLockoutResetCmd resets the PIN lockout counter.
var pinLockoutResetCmd = &cobra.Command{
	Use:   "lockout-reset",
	Short: "Reset the PIN lockout counter",
	Long: `Reset the PIN lockout counter. Requires SO PIN authorization.

Example:
  xkmsctl pin lockout-reset`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		soPIN := fr.String("so-pin")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		so, err := resolvePIN(soPIN, "SO PIN")
		if err != nil {
			handleError(err)
			return
		}

		pinLockoutReset(cfg, printer, &client.ResetLockoutRequest{SOPIN: so})
	},
}

// createPINClient creates and connects a client, returning the client
// and a cleanup function. The caller must call cleanup when done.
func createPINClient(cfg *Config) (client.Client, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateClientFailed, Err: err}
	}

	if err := cl.Connect(context.Background()); err != nil {
		closeQuietly(cl)
		return nil, nil, &WrappedError{Sentinel: ErrConnectFailed, Err: err}
	}

	return cl, func() { closeQuietly(cl) }, nil
}

// pinSOSet sets the SO PIN via the SDK client.
func pinSOSet(cfg *Config, printer *Printer, req *client.SetSOPINRequest) {
	cl, cleanup, err := createPINClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Setting SO PIN")

	if err := cl.SetSOPIN(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrSetSOPINFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess("SO PIN set"); err != nil {
		handleError(err)
	}
}

// pinSOChange changes the SO PIN via the SDK client.
func pinSOChange(cfg *Config, printer *Printer, req *client.ChangeSOPINRequest) {
	cl, cleanup, err := createPINClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Changing SO PIN")

	if err := cl.ChangeSOPIN(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrChangeSOPINFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess("SO PIN changed"); err != nil {
		handleError(err)
	}
}

// pinSOVerify verifies the SO PIN via the SDK client.
func pinSOVerify(cfg *Config, printer *Printer, req *client.VerifySOPINRequest) {
	cl, cleanup, err := createPINClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Verifying SO PIN")

	if err := cl.VerifySOPIN(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrVerifySOPINFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess("SO PIN verified"); err != nil {
		handleError(err)
	}
}

// pinUserSet sets the user PIN via the SDK client.
func pinUserSet(cfg *Config, printer *Printer, req *client.SetUserPINRequest) {
	cl, cleanup, err := createPINClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Setting user PIN")

	if err := cl.SetUserPIN(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrSetUserPINFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess("User PIN set"); err != nil {
		handleError(err)
	}
}

// pinUserChange changes the user PIN via the SDK client.
func pinUserChange(cfg *Config, printer *Printer, req *client.ChangeUserPINRequest) {
	cl, cleanup, err := createPINClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Changing user PIN")

	if err := cl.ChangeUserPIN(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrChangeUserPINFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess("User PIN changed"); err != nil {
		handleError(err)
	}
}

// pinUserVerify verifies the user PIN via the SDK client.
func pinUserVerify(cfg *Config, printer *Printer, req *client.VerifyUserPINRequest) {
	cl, cleanup, err := createPINClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Verifying user PIN")

	if err := cl.VerifyUserPIN(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrVerifyUserPINFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess("User PIN verified"); err != nil {
		handleError(err)
	}
}

// pinLockout shows the PIN lockout status via the SDK client.
func pinLockout(cfg *Config, printer *Printer) {
	cl, cleanup, err := createPINClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving PIN lockout status")

	resp, err := cl.GetLockoutStatus(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetLockoutStatusFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("PIN Lockout Status:\n")
		printer.printf("  Failed Attempts: %d\n", resp.FailedAttempts)
		printer.printf("  Max Attempts:    %d\n", resp.MaxAttempts)
		printer.printf("  Locked:          %t\n", resp.IsLocked)
		if resp.LockoutUntil != "" {
			printer.printf("  Locked Until:    %s\n", resp.LockoutUntil)
		}
		if resp.RecoverySeconds > 0 {
			printer.printf("  Recovery In:     %ds\n", resp.RecoverySeconds)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// pinLockoutReset resets the PIN lockout counter via the SDK client.
func pinLockoutReset(cfg *Config, printer *Printer, req *client.ResetLockoutRequest) {
	cl, cleanup, err := createPINClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Resetting PIN lockout counter")

	if err := cl.ResetLockout(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrResetLockoutFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess("PIN lockout counter reset"); err != nil {
		handleError(err)
	}
}

func init() {
	// pin so-set flags
	pinSOSetCmd.Flags().String("current-pin", "", "current SO PIN (required when the SO PIN is already set)")
	pinSOSetCmd.Flags().String("new-pin", "", "new SO PIN ('-' reads stdin; prompted when omitted)")

	// pin so-change flags
	pinSOChangeCmd.Flags().String("current-pin", "", "current SO PIN ('-' reads stdin; prompted when omitted)")
	pinSOChangeCmd.Flags().String("new-pin", "", "new SO PIN ('-' reads stdin; prompted when omitted)")

	// pin so-verify flags
	pinSOVerifyCmd.Flags().String("pin", "", "SO PIN ('-' reads stdin; prompted when omitted)")

	// pin user-set flags
	pinUserSetCmd.Flags().String("so-pin", "", "SO PIN authorizing the operation ('-' reads stdin; prompted when omitted)")
	pinUserSetCmd.Flags().String("new-pin", "", "new user PIN ('-' reads stdin; prompted when omitted)")

	// pin user-change flags
	pinUserChangeCmd.Flags().String("current-pin", "", "current user PIN ('-' reads stdin; prompted when omitted)")
	pinUserChangeCmd.Flags().String("new-pin", "", "new user PIN ('-' reads stdin; prompted when omitted)")

	// pin user-verify flags
	pinUserVerifyCmd.Flags().String("pin", "", "user PIN ('-' reads stdin; prompted when omitted)")

	// pin lockout-reset flags
	pinLockoutResetCmd.Flags().String("so-pin", "", "SO PIN authorizing the reset ('-' reads stdin; prompted when omitted)")

	// Build subcommand tree
	pinCmd.AddCommand(pinSOSetCmd)
	pinCmd.AddCommand(pinSOChangeCmd)
	pinCmd.AddCommand(pinSOVerifyCmd)
	pinCmd.AddCommand(pinUserSetCmd)
	pinCmd.AddCommand(pinUserChangeCmd)
	pinCmd.AddCommand(pinUserVerifyCmd)
	pinCmd.AddCommand(pinLockoutCmd)
	pinCmd.AddCommand(pinLockoutResetCmd)

	// Register with root
	rootCmd.AddCommand(pinCmd)
}
