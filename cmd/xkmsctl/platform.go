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
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/spf13/cobra"
)

// platformCmd is the top-level command for the sealed platform store.
var platformCmd = &cobra.Command{
	Use:   "platform",
	Short: "Manage the sealed platform credential store",
	Long: `Manage the machine-local sealed credential store (platform store).

Secrets are sealed to the platform's hardware sealer (TPM 2.0 when
available) and can only be recovered on the same platform.

Subcommands:
  put     Store a secret
  get     Retrieve a secret
  delete  Delete a secret
  list    List stored secret names
  reseal  Reseal a secret with the current sealing key
  status  Show platform store status`,
}

// platformPutCmd stores a secret in the platform store.
var platformPutCmd = &cobra.Command{
	Use:   "put <name>",
	Short: "Store a secret in the platform store",
	Long: `Store a secret in the sealed platform store.

The secret bytes are taken from --value, from a file via --file, from
stdin when --value is "-", or from an interactive no-echo prompt when
both flags are omitted.

Examples:
  xkmsctl platform put db-password --value s3cret
  xkmsctl platform put tls-key --file ./key.pem
  echo -n "s3cret" | xkmsctl platform put db-password --value -`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		value := fr.String("value")
		file := fr.String("file")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if value != "" && file != "" {
			handleError(ErrPlatformSecretSourceConflict)
			return
		}

		var secret []byte
		if file != "" {
			data, err := os.ReadFile(filepath.Clean(file))
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrReadSecretFileFailed, Err: err})
				return
			}
			secret = data
		} else {
			resolved, err := resolveSecret(value, "Secret")
			if err != nil {
				handleError(err)
				return
			}
			secret = []byte(resolved)
		}

		if len(secret) == 0 {
			handleError(ErrPlatformSecretRequired)
			return
		}

		platformPut(cfg, printer, &client.SealStorePutRequest{
			Name:   args[0],
			Secret: secret,
		})
	},
}

// platformGetCmd retrieves a secret from the platform store.
var platformGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Retrieve a secret from the platform store",
	Long: `Retrieve and unseal a secret from the platform store.

Without --output the secret is printed base64-encoded; with --output
the raw secret bytes are written to the file (mode 0600).

Examples:
  xkmsctl platform get db-password
  xkmsctl platform get tls-key --output ./key.pem`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		outputFile := fr.String("output")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		platformGet(cfg, printer, args[0], outputFile)
	},
}

// platformDeleteCmd deletes a secret from the platform store.
var platformDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a secret from the platform store",
	Long: `Delete a secret from the platform store.

Example:
  xkmsctl platform delete db-password`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		platformDelete(cfg, printer, args[0])
	},
}

// platformListCmd lists stored secret names.
var platformListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored secret names",
	Long: `List the names of all secrets in the platform store.

Example:
  xkmsctl platform list`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		platformList(cfg, printer)
	},
}

// platformResealCmd reseals a secret with the current sealing key.
var platformResealCmd = &cobra.Command{
	Use:   "reseal <name>",
	Short: "Reseal a secret with the current sealing key",
	Long: `Reseal a secret with the current platform sealing key. Use this
after a sealer change (for example a PCR policy refresh) to rebind the
secret to the new sealing state.

Example:
  xkmsctl platform reseal db-password`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		platformReseal(cfg, printer, args[0])
	},
}

// platformStatusCmd shows the platform store status.
var platformStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show platform store status",
	Long: `Display the platform store status including the active sealer
and stored secret count.

Example:
  xkmsctl platform status`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		platformStatus(cfg, printer)
	},
}

// createPlatformClient creates and connects a client, returning the client
// and a cleanup function. The caller must call cleanup when done.
func createPlatformClient(cfg *Config) (client.Client, func(), error) {
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

// platformPut stores a secret via the SDK client.
// platformPut sends req and wipes req.Secret once it returns, on every path.
func platformPut(cfg *Config, printer *Printer, req *client.SealStorePutRequest) {
	defer secure.Wipe(req.Secret)

	cl, cleanup, err := createPlatformClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Storing platform secret %q (%d bytes)", req.Name, len(req.Secret))

	if err := cl.SealStorePut(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrPutPlatformSecretFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Secret %q stored", req.Name)); err != nil {
		handleError(err)
	}
}

// platformGet retrieves a secret via the SDK client.
func platformGet(cfg *Config, printer *Printer, name, outputFile string) {
	cl, cleanup, err := createPlatformClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving platform secret %q", name)

	resp, err := cl.SealStoreGet(context.Background(), &client.SealStoreGetRequest{Name: name})
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetPlatformSecretFailed, Err: err})
		return
	}
	// Each output path wipes the secret as soon as it has consumed it:
	// handleError exits the process, which skips a deferred wipe.
	if outputFile != "" {
		err := fsutil.WriteFileAtomic(outputFile, resp.Secret, 0600)
		secure.Wipe(resp.Secret)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteSecretFileFailed, Err: err})
			return
		}
		if err := printer.PrintSuccess(fmt.Sprintf("Secret %q written to %s", name, outputFile)); err != nil {
			handleError(err)
		}
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		err = printer.PrintJSON(resp)
	case OutputFormatTable, OutputFormatText:
		printer.printf("Platform Secret:\n")
		printer.printf("  Name:   %s\n", resp.Name)
		printer.printf("  Secret: %s\n", base64.StdEncoding.EncodeToString(resp.Secret))
	}
	secure.Wipe(resp.Secret)
	if err == nil {
		err = printer.Err()
	}
	if err != nil {
		handleError(err)
	}
}

// platformDelete deletes a secret via the SDK client.
func platformDelete(cfg *Config, printer *Printer, name string) {
	cl, cleanup, err := createPlatformClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Deleting platform secret %q", name)

	if err := cl.SealStoreDelete(context.Background(), &client.SealStoreDeleteRequest{Name: name}); err != nil {
		handleError(&WrappedError{Sentinel: ErrDeletePlatformSecretFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Secret %q deleted", name)); err != nil {
		handleError(err)
	}
}

// platformList lists stored secret names via the SDK client.
func platformList(cfg *Config, printer *Printer) {
	cl, cleanup, err := createPlatformClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Listing platform secrets")

	resp, err := cl.SealStoreList(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListPlatformSecretsFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(map[string]interface{}{
			"names": resp.Names,
			"total": len(resp.Names),
		}); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		if len(resp.Names) == 0 {
			printer.println("No secrets stored")
			return
		}
		printer.println("Platform Secrets:")
		for _, name := range resp.Names {
			printer.printf("  - %s\n", name)
		}
		printer.printf("\nTotal: %d secret(s)\n", len(resp.Names))
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// platformReseal reseals a secret via the SDK client.
func platformReseal(cfg *Config, printer *Printer, name string) {
	cl, cleanup, err := createPlatformClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Resealing platform secret %q", name)

	if err := cl.SealStoreReseal(context.Background(), &client.SealStoreResealRequest{Name: name}); err != nil {
		handleError(&WrappedError{Sentinel: ErrResealPlatformSecretFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Secret %q resealed", name)); err != nil {
		handleError(err)
	}
}

// platformStatus shows the platform store status via the SDK client.
func platformStatus(cfg *Config, printer *Printer) {
	cl, cleanup, err := createPlatformClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving platform store status")

	resp, err := cl.SealStoreStatus(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrPlatformStoreStatusFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Platform Store Status:\n")
		printer.printf("  Available: %t\n", resp.Available)
		if resp.SealerID != "" {
			printer.printf("  Sealer:    %s\n", resp.SealerID)
		}
		printer.printf("  Secrets:   %d\n", resp.SecretCount)
		for _, name := range resp.SecretNames {
			printer.printf("    - %s\n", name)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func init() {
	// platform put flags
	platformPutCmd.Flags().String("value", "", "secret value ('-' reads stdin; prompted when omitted)")
	platformPutCmd.Flags().String("file", "", "read the secret bytes from a file")

	// platform get flags
	platformGetCmd.Flags().String("output", "", "write the raw secret bytes to a file (mode 0600)")

	// Build subcommand tree
	platformCmd.AddCommand(platformPutCmd)
	platformCmd.AddCommand(platformGetCmd)
	platformCmd.AddCommand(platformDeleteCmd)
	platformCmd.AddCommand(platformListCmd)
	platformCmd.AddCommand(platformResealCmd)
	platformCmd.AddCommand(platformStatusCmd)

	// Register with root
	rootCmd.AddCommand(platformCmd)
}
