// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/fido2"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/user"
	"github.com/spf13/cobra"
)

// adminCmd represents the admin command
var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Manage administrator accounts",
	Long:  `Commands for managing administrator accounts for the keychain service.`,
}

// adminCreateCmd creates a new admin account
var adminCreateCmd = &cobra.Command{
	Use:   "create <username>",
	Short: "Create a new administrator account",
	Long: `Create a new administrator account with a FIDO2 security key.

All administrators have the admin role and full access to manage the keychain.

Example:
  keychain admin create admin@example.com --display-name "Admin User"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		displayName, _ := cmd.Flags().GetString("display-name")
		storagePath, _ := cmd.Flags().GetString("storage-path")
		devicePath, _ := cmd.Flags().GetString("device")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		rpID, _ := cmd.Flags().GetString("rp-id")
		rpName, _ := cmd.Flags().GetString("rp-name")
		requireUV, _ := cmd.Flags().GetBool("user-verification")

		if displayName == "" {
			displayName = username
		}

		storagePath = resolveStoragePath(storagePath)
		printVerbose("Using user store at: %s", storagePath)

		userStore, err := openUserStore(storagePath)
		if err != nil {
			handleError(err)
			return
		}
		defer func() { _ = userStore.Close() }()

		// Create FIDO2 handler
		fidoConfig := fido2.DefaultConfig
		fidoConfig.DevicePath = devicePath
		fidoConfig.RequireUserVerification = requireUV
		enumerator := fido2.NewDefaultEnumerator()

		handler, err := fido2.NewHandler(&fidoConfig, enumerator)
		if err != nil {
			handleError(fmt.Errorf("failed to create FIDO2 handler: %w", err))
			return
		}
		defer func() { _ = handler.Close() }()

		if err := printer.PrintMessage("Creating administrator account..."); err != nil {
			handleError(err)
			return
		}

		if err := printer.PrintMessage(fmt.Sprintf("Username: %s", username)); err != nil {
			handleError(err)
			return
		}

		if err := printer.PrintMessage(fmt.Sprintf("Display Name: %s", displayName)); err != nil {
			handleError(err)
			return
		}

		// Create enrollment config
		enrollConfig := fido2.DefaultEnrollmentConfig(username)
		enrollConfig.RelyingParty.ID = rpID
		enrollConfig.RelyingParty.Name = rpName
		enrollConfig.User.DisplayName = displayName
		enrollConfig.Timeout = timeout
		enrollConfig.RequireUserVerification = requireUV

		if err := printer.PrintMessage("\nPlease touch your security key to register..."); err != nil {
			handleError(err)
			return
		}

		// Register the credential
		result, err := handler.EnrollKey(enrollConfig)
		if err != nil {
			handleError(fmt.Errorf("failed to register credential: %w", err))
			return
		}

		printVerbose("FIDO2 credential registered successfully")

		// Create the admin user
		ctx := context.Background()
		newAdmin, err := userStore.Create(ctx, username, displayName, user.RoleAdmin)
		if err != nil {
			handleError(fmt.Errorf("failed to create admin: %w", err))
			return
		}

		// Add the credential to the user
		userCred := &user.Credential{
			ID:              result.CredentialID,
			PublicKey:       result.PublicKey,
			AttestationType: "packed",
			AAGUID:          result.AAGUID,
			SignCount:       result.SignCount,
			Name:            "Security Key",
			CreatedAt:       time.Now().UTC(),
			Salt:            result.Salt,
		}
		newAdmin.AddCredential(userCred)

		// Save the user with credential
		if err := userStore.Update(ctx, newAdmin); err != nil {
			handleError(fmt.Errorf("failed to save user credential: %w", err))
			return
		}

		if err := printer.PrintSuccess("\nAdministrator created successfully!"); err != nil {
			handleError(err)
			return
		}

		// Print summary
		if cfg.OutputFormat == "json" {
			summary := map[string]interface{}{
				"success":       true,
				"username":      username,
				"display_name":  displayName,
				"role":          "admin",
				"credential_id": base64.URLEncoding.EncodeToString(result.CredentialID),
			}
			if err := printer.PrintJSON(summary); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("\nAdmin ID: %s\n", base64.URLEncoding.EncodeToString(newAdmin.ID))
			fmt.Printf("Username: %s\n", newAdmin.Username)
			fmt.Printf("Role: %s\n", newAdmin.Role)
			fmt.Printf("Credential ID: %s\n", base64.URLEncoding.EncodeToString(result.CredentialID))
			fmt.Printf("\nYou can now use this security key to authenticate to the keychain web UI.\n")
		}
	},
}

// adminListCmd lists all admin accounts
var adminListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all administrator accounts",
	Long:  `List all administrator accounts configured in the keychain service.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		storagePath, _ := cmd.Flags().GetString("storage-path")
		storagePath = resolveStoragePath(storagePath)

		userStore, err := openUserStore(storagePath)
		if err != nil {
			handleError(err)
			return
		}
		defer func() { _ = userStore.Close() }()

		// List admins
		ctx := context.Background()
		admins, err := userStore.List(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to list admins: %w", err))
			return
		}

		if len(admins) == 0 {
			if err := printer.PrintMessage("No administrator accounts configured."); err != nil {
				handleError(err)
			}
			return
		}

		// Print admins
		if cfg.OutputFormat == "json" {
			adminList := make([]map[string]interface{}, len(admins))
			for i, a := range admins {
				adminList[i] = map[string]interface{}{
					"id":               base64.URLEncoding.EncodeToString(a.ID),
					"username":         a.Username,
					"display_name":     a.DisplayName,
					"role":             string(a.Role),
					"enabled":          a.Enabled,
					"credential_count": len(a.Credentials),
					"created_at":       a.CreatedAt.Format(time.RFC3339),
				}
				if a.LastLoginAt != nil {
					adminList[i]["last_login_at"] = a.LastLoginAt.Format(time.RFC3339)
				}
			}
			if err := printer.PrintJSON(map[string]interface{}{
				"admins": adminList,
				"total":  len(adminList),
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("%-40s %-20s %-12s %-8s %-5s\n", "ID", "USERNAME", "ROLE", "ENABLED", "CREDS")
			fmt.Println(repeatString("-", 90))
			for _, a := range admins {
				fmt.Printf("%-40s %-20s %-12s %-8t %-5d\n",
					base64.URLEncoding.EncodeToString(a.ID)[:16]+"...",
					truncateString(a.Username, 20),
					a.Role,
					a.Enabled,
					len(a.Credentials),
				)
			}
			fmt.Printf("\nTotal: %d administrator(s)\n", len(admins))
		}
	},
}

// adminGetCmd gets details for a specific admin
var adminGetCmd = &cobra.Command{
	Use:   "get <username>",
	Short: "Get administrator details",
	Long:  `Get detailed information about a specific administrator account.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		storagePath, _ := cmd.Flags().GetString("storage-path")
		storagePath = resolveStoragePath(storagePath)

		userStore, err := openUserStore(storagePath)
		if err != nil {
			handleError(err)
			return
		}
		defer func() { _ = userStore.Close() }()

		ctx := context.Background()
		a, err := userStore.GetByUsername(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to get admin: %w", err))
			return
		}

		if cfg.OutputFormat == "json" {
			adminInfo := map[string]interface{}{
				"id":               base64.URLEncoding.EncodeToString(a.ID),
				"username":         a.Username,
				"display_name":     a.DisplayName,
				"role":             string(a.Role),
				"enabled":          a.Enabled,
				"credential_count": len(a.Credentials),
				"created_at":       a.CreatedAt.Format(time.RFC3339),
			}
			if a.LastLoginAt != nil {
				adminInfo["last_login_at"] = a.LastLoginAt.Format(time.RFC3339)
			}

			// Include credential details
			creds := make([]map[string]interface{}, len(a.Credentials))
			for i, c := range a.Credentials {
				creds[i] = map[string]interface{}{
					"id":         base64.URLEncoding.EncodeToString(c.ID),
					"name":       c.Name,
					"created_at": c.CreatedAt.Format(time.RFC3339),
				}
				if c.LastUsedAt != nil {
					creds[i]["last_used_at"] = c.LastUsedAt.Format(time.RFC3339)
				}
			}
			adminInfo["credentials"] = creds

			if err := printer.PrintJSON(adminInfo); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("Administrator Details:\n")
			fmt.Printf("  ID:           %s\n", base64.URLEncoding.EncodeToString(a.ID))
			fmt.Printf("  Username:     %s\n", a.Username)
			fmt.Printf("  Display Name: %s\n", a.DisplayName)
			fmt.Printf("  Role:         %s\n", a.Role)
			fmt.Printf("  Enabled:      %t\n", a.Enabled)
			fmt.Printf("  Created:      %s\n", a.CreatedAt.Format(time.RFC3339))
			if a.LastLoginAt != nil {
				fmt.Printf("  Last Login:   %s\n", a.LastLoginAt.Format(time.RFC3339))
			}
			fmt.Printf("\n  Credentials (%d):\n", len(a.Credentials))
			for i, c := range a.Credentials {
				fmt.Printf("    %d. %s\n", i+1, c.Name)
				fmt.Printf("       ID: %s\n", base64.URLEncoding.EncodeToString(c.ID)[:16]+"...")
				fmt.Printf("       Created: %s\n", c.CreatedAt.Format(time.RFC3339))
				if c.LastUsedAt != nil {
					fmt.Printf("       Last Used: %s\n", c.LastUsedAt.Format(time.RFC3339))
				}
			}
		}
	},
}

// adminDeleteCmd deletes an admin account
var adminDeleteCmd = &cobra.Command{
	Use:   "delete <username>",
	Short: "Delete an administrator account",
	Long: `Delete an administrator account.

Note: You cannot delete the last administrator account.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		storagePath, _ := cmd.Flags().GetString("storage-path")
		storagePath = resolveStoragePath(storagePath)

		userStore, err := openUserStore(storagePath)
		if err != nil {
			handleError(err)
			return
		}
		defer func() { _ = userStore.Close() }()

		ctx := context.Background()

		// Get the user by username to get the ID
		a, err := userStore.GetByUsername(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to find admin: %w", err))
			return
		}

		// Delete the user
		if err := userStore.Delete(ctx, a.ID); err != nil {
			handleError(fmt.Errorf("failed to delete admin: %w", err))
			return
		}

		if cfg.OutputFormat == "json" {
			if err := printer.PrintJSON(map[string]interface{}{
				"success":  true,
				"message":  fmt.Sprintf("Administrator '%s' deleted successfully", username),
				"username": username,
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("Administrator '%s' deleted successfully.\n", username)
		}
	},
}

// adminDisableCmd disables an admin account
var adminDisableCmd = &cobra.Command{
	Use:   "disable <username>",
	Short: "Disable an administrator account",
	Long:  `Disable an administrator account. Disabled accounts cannot authenticate.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		storagePath, _ := cmd.Flags().GetString("storage-path")
		storagePath = resolveStoragePath(storagePath)

		userStore, err := openUserStore(storagePath)
		if err != nil {
			handleError(err)
			return
		}
		defer func() { _ = userStore.Close() }()

		ctx := context.Background()

		a, err := userStore.GetByUsername(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to find admin: %w", err))
			return
		}

		a.Enabled = false
		if err := userStore.Update(ctx, a); err != nil {
			handleError(fmt.Errorf("failed to disable admin: %w", err))
			return
		}

		if cfg.OutputFormat == "json" {
			if err := printer.PrintJSON(map[string]interface{}{
				"success":  true,
				"message":  fmt.Sprintf("Administrator '%s' disabled", username),
				"username": username,
				"enabled":  false,
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("Administrator '%s' has been disabled.\n", username)
		}
	},
}

// adminEnableCmd enables an admin account
var adminEnableCmd = &cobra.Command{
	Use:   "enable <username>",
	Short: "Enable an administrator account",
	Long:  `Enable a previously disabled administrator account.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		storagePath, _ := cmd.Flags().GetString("storage-path")
		storagePath = resolveStoragePath(storagePath)

		userStore, err := openUserStore(storagePath)
		if err != nil {
			handleError(err)
			return
		}
		defer func() { _ = userStore.Close() }()

		ctx := context.Background()

		a, err := userStore.GetByUsername(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to find admin: %w", err))
			return
		}

		a.Enabled = true
		if err := userStore.Update(ctx, a); err != nil {
			handleError(fmt.Errorf("failed to enable admin: %w", err))
			return
		}

		if cfg.OutputFormat == "json" {
			if err := printer.PrintJSON(map[string]interface{}{
				"success":  true,
				"message":  fmt.Sprintf("Administrator '%s' enabled", username),
				"username": username,
				"enabled":  true,
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("Administrator '%s' has been enabled.\n", username)
		}
	},
}

// adminStatusCmd shows the bootstrap status
var adminStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show administrator setup status",
	Long:  `Show whether the keychain service has any administrator accounts configured.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		storagePath, _ := cmd.Flags().GetString("storage-path")
		storagePath = resolveStoragePath(storagePath)

		userStore, err := openUserStore(storagePath)
		if err != nil {
			handleError(err)
			return
		}
		defer func() { _ = userStore.Close() }()

		// Check status
		ctx := context.Background()
		hasAdmins, err := userStore.HasAnyUsers(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to check admin status: %w", err))
			return
		}

		count, err := userStore.Count(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to count admins: %w", err))
			return
		}

		if cfg.OutputFormat == "json" {
			status := map[string]interface{}{
				"requires_setup": !hasAdmins,
				"admin_count":    count,
			}
			if !hasAdmins {
				status["message"] = "No administrators configured. Run 'keychain admin create' to create an administrator."
			} else {
				status["message"] = "System is configured and ready."
			}
			if err := printer.PrintJSON(status); err != nil {
				handleError(err)
			}
		} else {
			if !hasAdmins {
				fmt.Println("Status: NOT CONFIGURED")
				fmt.Println("\nNo administrators configured.")
				fmt.Println("Run 'keychain admin create <username>' to create an administrator.")
			} else {
				fmt.Println("Status: CONFIGURED")
				fmt.Printf("Administrator accounts: %d\n", count)
			}
		}
	},
}

func init() {
	// Add subcommands
	adminCmd.AddCommand(adminCreateCmd)
	adminCmd.AddCommand(adminListCmd)
	adminCmd.AddCommand(adminGetCmd)
	adminCmd.AddCommand(adminDeleteCmd)
	adminCmd.AddCommand(adminDisableCmd)
	adminCmd.AddCommand(adminEnableCmd)
	adminCmd.AddCommand(adminStatusCmd)

	// Common flags
	adminCmd.PersistentFlags().String("storage-path", "", "path to keychain storage (default: $KEYCHAIN_STORAGE_PATH or /var/lib/keychain)")

	// create flags
	adminCreateCmd.Flags().String("display-name", "", "admin display name (defaults to username)")
	adminCreateCmd.Flags().String("rp-id", "go-keychain", "relying party ID")
	adminCreateCmd.Flags().String("rp-name", "Go Keychain", "relying party name")
	adminCreateCmd.Flags().Duration("timeout", 30*time.Second, "timeout for user presence")
	adminCreateCmd.Flags().String("device", "", "specific FIDO2 device path to use")
	adminCreateCmd.Flags().Bool("user-verification", false, "require user verification (PIN)")
}

// Helper functions

func resolveStoragePath(storagePath string) string {
	if storagePath == "" {
		storagePath = os.Getenv("KEYCHAIN_STORAGE_PATH")
		if storagePath == "" {
			storagePath = "/var/lib/keychain"
		}
	}
	return storagePath
}

func openUserStore(storagePath string) (user.Store, error) {
	userStoragePath := storagePath + "/users"
	userStorage, err := file.New(userStoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create user storage: %w", err)
	}

	userStore, err := user.NewFileStore(userStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to create user store: %w", err)
	}

	return userStore, nil
}

func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
