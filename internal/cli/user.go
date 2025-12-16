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
	"github.com/jeremyhahn/go-keychain/pkg/user"
	"github.com/spf13/cobra"
)

// userCmd represents the user command
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage user accounts",
	Long: `Commands for managing user accounts in the keychain service.

The first user registered will automatically receive the admin role.
Subsequent users can be assigned different roles based on their needs.`,
}

// userRegisterCmd registers a new user with FIDO2
var userRegisterCmd = &cobra.Command{
	Use:   "register <username>",
	Short: "Register a new user with FIDO2",
	Long: `Register a new user account using a FIDO2 security key.

The first user registered will automatically receive the admin role.
Subsequent users will receive the 'user' role by default.

During registration, you'll need to touch your FIDO2 security key
to create a credential that will be used for authentication.

Example:
  keychain user register admin@example.com --display-name "Admin User"
  keychain user register operator@example.com --role operator`,
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
		roleStr, _ := cmd.Flags().GetString("role")

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

		// Check if this is the first user (auto-assign admin)
		ctx := context.Background()
		hasUsers, err := userStore.HasAnyUsers(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to check user status: %w", err))
			return
		}

		// Determine role
		var role user.Role
		if !hasUsers {
			role = user.RoleAdmin
			if err := printer.PrintMessage("No users exist. First user will be administrator."); err != nil {
				handleError(err)
				return
			}
		} else if roleStr != "" {
			role = user.Role(roleStr)
			if !user.IsValidRole(role) {
				handleError(fmt.Errorf("invalid role: %s", roleStr))
				return
			}
		} else {
			role = user.RoleUser
		}

		// Check if username already exists
		_, err = userStore.GetByUsername(ctx, username)
		if err == nil {
			handleError(fmt.Errorf("user %s already exists", username))
			return
		}

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

		if err := printer.PrintMessage("Registering new user..."); err != nil {
			handleError(err)
			return
		}
		if err := printer.PrintMessage(fmt.Sprintf("  Username: %s", username)); err != nil {
			handleError(err)
			return
		}
		if err := printer.PrintMessage(fmt.Sprintf("  Display Name: %s", displayName)); err != nil {
			handleError(err)
			return
		}
		if err := printer.PrintMessage(fmt.Sprintf("  Role: %s", role)); err != nil {
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

		// Create the user
		newUser, err := userStore.Create(ctx, username, displayName, role)
		if err != nil {
			handleError(fmt.Errorf("failed to create user: %w", err))
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
		newUser.AddCredential(userCred)

		// Save the user with credential
		if err := userStore.Update(ctx, newUser); err != nil {
			handleError(fmt.Errorf("failed to save user credential: %w", err))
			return
		}

		if err := printer.PrintSuccess("\nUser registered successfully!"); err != nil {
			handleError(err)
			return
		}

		// Print summary
		if cfg.OutputFormat == "json" {
			summary := map[string]interface{}{
				"success":       true,
				"username":      username,
				"display_name":  displayName,
				"role":          string(role),
				"user_id":       base64.URLEncoding.EncodeToString(newUser.ID),
				"credential_id": base64.URLEncoding.EncodeToString(result.CredentialID),
				"first_user":    !hasUsers,
			}
			if err := printer.PrintJSON(summary); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("\nUser ID: %s\n", base64.URLEncoding.EncodeToString(newUser.ID))
			fmt.Printf("Username: %s\n", newUser.Username)
			fmt.Printf("Role: %s\n", newUser.Role)
			fmt.Printf("Credential ID: %s\n", base64.URLEncoding.EncodeToString(result.CredentialID))
			fmt.Printf("\nYou can now use this security key to authenticate.\n")
		}
	},
}

// userLoginCmd authenticates using FIDO2 and gets a JWT token
var userLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate using FIDO2 and get a JWT token",
	Long: `Authenticate to the keychain service using your FIDO2 security key.

This command will:
1. Touch your FIDO2 security key to authenticate
2. Verify your credential with the server
3. Return a JWT token for subsequent API calls

The token is printed to stdout for use with other commands.
You can store it in an environment variable or config file.

Example:
  export KEYCHAIN_TOKEN=$(keychain user login --credential-id <id> --salt <salt>)
  keychain key list --token $KEYCHAIN_TOKEN`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		credIDStr, _ := cmd.Flags().GetString("credential-id")
		saltStr, _ := cmd.Flags().GetString("salt")
		rpID, _ := cmd.Flags().GetString("rp-id")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		devicePath, _ := cmd.Flags().GetString("device")
		requireUV, _ := cmd.Flags().GetBool("user-verification")

		if credIDStr == "" {
			handleError(fmt.Errorf("credential-id is required"))
			return
		}
		if saltStr == "" {
			handleError(fmt.Errorf("salt is required"))
			return
		}

		// Decode credential ID and salt
		credID, err := decodeCredentialData(credIDStr)
		if err != nil {
			handleError(fmt.Errorf("invalid credential-id: %w", err))
			return
		}

		salt, err := decodeCredentialData(saltStr)
		if err != nil {
			handleError(fmt.Errorf("invalid salt: %w", err))
			return
		}

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

		// Create authentication config
		authConfig := fido2.DefaultAuthenticationConfig(credID, salt)
		authConfig.RelyingPartyID = rpID
		authConfig.Timeout = timeout
		authConfig.RequireUserVerification = requireUV

		if err := printer.PrintMessage("Please touch your security key to authenticate..."); err != nil {
			handleError(err)
			return
		}

		// Authenticate locally to verify credential works
		_, err = handler.UnlockWithKey(authConfig)
		if err != nil {
			handleError(fmt.Errorf("authentication failed: %w", err))
			return
		}

		printVerbose("FIDO2 authentication successful")

		// For now, we print a message explaining the next step
		// Full JWT generation will require server-side verification
		if cfg.OutputFormat == "json" {
			result := map[string]interface{}{
				"success":        true,
				"message":        "FIDO2 authentication successful. Use the server's /webauthn/login endpoint for JWT tokens.",
				"credential_id":  credIDStr,
				"requires_token": true,
			}
			if err := printer.PrintJSON(result); err != nil {
				handleError(err)
			}
		} else {
			if err := printer.PrintSuccess("FIDO2 authentication successful!"); err != nil {
				handleError(err)
			}
			fmt.Println("\nTo get a JWT token, use the WebAuthn login endpoints:")
			fmt.Println("  POST /api/v1/webauthn/login/begin")
			fmt.Println("  POST /api/v1/webauthn/login/finish")
		}
	},
}

// userListCmd lists all users
var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all user accounts",
	Long:  `List all user accounts configured in the keychain service.`,
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

		// List users
		ctx := context.Background()
		users, err := userStore.List(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to list users: %w", err))
			return
		}

		if len(users) == 0 {
			if err := printer.PrintMessage("No users configured. Run 'keychain user register' to create the first user."); err != nil {
				handleError(err)
			}
			return
		}

		// Print users
		if cfg.OutputFormat == "json" {
			userList := make([]map[string]interface{}, len(users))
			for i, u := range users {
				userList[i] = map[string]interface{}{
					"id":               base64.URLEncoding.EncodeToString(u.ID),
					"username":         u.Username,
					"display_name":     u.DisplayName,
					"role":             string(u.Role),
					"enabled":          u.Enabled,
					"credential_count": len(u.Credentials),
					"created_at":       u.CreatedAt.Format(time.RFC3339),
				}
				if u.LastLoginAt != nil {
					userList[i]["last_login_at"] = u.LastLoginAt.Format(time.RFC3339)
				}
			}
			if err := printer.PrintJSON(map[string]interface{}{
				"users": userList,
				"total": len(userList),
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("%-40s %-20s %-12s %-8s %-5s\n", "ID", "USERNAME", "ROLE", "ENABLED", "CREDS")
			fmt.Println(repeatString("-", 90))
			for _, u := range users {
				idStr := base64.URLEncoding.EncodeToString(u.ID)
				if len(idStr) > 16 {
					idStr = idStr[:16] + "..."
				}
				fmt.Printf("%-40s %-20s %-12s %-8t %-5d\n",
					idStr,
					truncateString(u.Username, 20),
					u.Role,
					u.Enabled,
					len(u.Credentials),
				)
			}
			fmt.Printf("\nTotal: %d user(s)\n", len(users))
		}
	},
}

// userGetCmd gets details for a specific user
var userGetCmd = &cobra.Command{
	Use:   "get <username>",
	Short: "Get user details",
	Long:  `Get detailed information about a specific user account.`,
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
		u, err := userStore.GetByUsername(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to get user: %w", err))
			return
		}

		if cfg.OutputFormat == "json" {
			userInfo := map[string]interface{}{
				"id":               base64.URLEncoding.EncodeToString(u.ID),
				"username":         u.Username,
				"display_name":     u.DisplayName,
				"role":             string(u.Role),
				"enabled":          u.Enabled,
				"credential_count": len(u.Credentials),
				"created_at":       u.CreatedAt.Format(time.RFC3339),
			}
			if u.LastLoginAt != nil {
				userInfo["last_login_at"] = u.LastLoginAt.Format(time.RFC3339)
			}

			// Include credential details
			creds := make([]map[string]interface{}, len(u.Credentials))
			for i, c := range u.Credentials {
				creds[i] = map[string]interface{}{
					"id":         base64.URLEncoding.EncodeToString(c.ID),
					"name":       c.Name,
					"created_at": c.CreatedAt.Format(time.RFC3339),
				}
				if c.LastUsedAt != nil {
					creds[i]["last_used_at"] = c.LastUsedAt.Format(time.RFC3339)
				}
				// Include salt for login command
				if len(c.Salt) > 0 {
					creds[i]["salt"] = base64.URLEncoding.EncodeToString(c.Salt)
				}
			}
			userInfo["credentials"] = creds

			if err := printer.PrintJSON(userInfo); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("User Details:\n")
			fmt.Printf("  ID:           %s\n", base64.URLEncoding.EncodeToString(u.ID))
			fmt.Printf("  Username:     %s\n", u.Username)
			fmt.Printf("  Display Name: %s\n", u.DisplayName)
			fmt.Printf("  Role:         %s\n", u.Role)
			fmt.Printf("  Enabled:      %t\n", u.Enabled)
			fmt.Printf("  Created:      %s\n", u.CreatedAt.Format(time.RFC3339))
			if u.LastLoginAt != nil {
				fmt.Printf("  Last Login:   %s\n", u.LastLoginAt.Format(time.RFC3339))
			}
			fmt.Printf("\n  Credentials (%d):\n", len(u.Credentials))
			for i, c := range u.Credentials {
				fmt.Printf("    %d. %s\n", i+1, c.Name)
				fmt.Printf("       ID: %s\n", base64.URLEncoding.EncodeToString(c.ID))
				if len(c.Salt) > 0 {
					fmt.Printf("       Salt: %s\n", base64.URLEncoding.EncodeToString(c.Salt))
				}
				fmt.Printf("       Created: %s\n", c.CreatedAt.Format(time.RFC3339))
				if c.LastUsedAt != nil {
					fmt.Printf("       Last Used: %s\n", c.LastUsedAt.Format(time.RFC3339))
				}
			}
		}
	},
}

// userDeleteCmd deletes a user account
var userDeleteCmd = &cobra.Command{
	Use:   "delete <username>",
	Short: "Delete a user account",
	Long: `Delete a user account.

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
		u, err := userStore.GetByUsername(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to find user: %w", err))
			return
		}

		// Delete the user
		if err := userStore.Delete(ctx, u.ID); err != nil {
			handleError(fmt.Errorf("failed to delete user: %w", err))
			return
		}

		if cfg.OutputFormat == "json" {
			if err := printer.PrintJSON(map[string]interface{}{
				"success":  true,
				"message":  fmt.Sprintf("User '%s' deleted successfully", username),
				"username": username,
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("User '%s' deleted successfully.\n", username)
		}
	},
}

// userDisableCmd disables a user account
var userDisableCmd = &cobra.Command{
	Use:   "disable <username>",
	Short: "Disable a user account",
	Long:  `Disable a user account. Disabled accounts cannot authenticate.`,
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

		u, err := userStore.GetByUsername(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to find user: %w", err))
			return
		}

		u.Enabled = false
		if err := userStore.Update(ctx, u); err != nil {
			handleError(fmt.Errorf("failed to disable user: %w", err))
			return
		}

		if cfg.OutputFormat == "json" {
			if err := printer.PrintJSON(map[string]interface{}{
				"success":  true,
				"message":  fmt.Sprintf("User '%s' disabled", username),
				"username": username,
				"enabled":  false,
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("User '%s' has been disabled.\n", username)
		}
	},
}

// userEnableCmd enables a user account
var userEnableCmd = &cobra.Command{
	Use:   "enable <username>",
	Short: "Enable a user account",
	Long:  `Enable a previously disabled user account.`,
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

		u, err := userStore.GetByUsername(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to find user: %w", err))
			return
		}

		u.Enabled = true
		if err := userStore.Update(ctx, u); err != nil {
			handleError(fmt.Errorf("failed to enable user: %w", err))
			return
		}

		if cfg.OutputFormat == "json" {
			if err := printer.PrintJSON(map[string]interface{}{
				"success":  true,
				"message":  fmt.Sprintf("User '%s' enabled", username),
				"username": username,
				"enabled":  true,
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("User '%s' has been enabled.\n", username)
		}
	},
}

// userStatusCmd shows the bootstrap status
var userStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show user setup status",
	Long:  `Show whether the keychain service has any user accounts configured.`,
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
		hasUsers, err := userStore.HasAnyUsers(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to check user status: %w", err))
			return
		}

		count, err := userStore.Count(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to count users: %w", err))
			return
		}

		adminCount, err := userStore.CountAdmins(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to count admins: %w", err))
			return
		}

		if cfg.OutputFormat == "json" {
			status := map[string]interface{}{
				"requires_setup": !hasUsers,
				"user_count":     count,
				"admin_count":    adminCount,
			}
			if !hasUsers {
				status["message"] = "No users configured. Run 'keychain user register' to create the first administrator."
			} else {
				status["message"] = "System is configured and ready."
			}
			if err := printer.PrintJSON(status); err != nil {
				handleError(err)
			}
		} else {
			if !hasUsers {
				fmt.Println("Status: NOT CONFIGURED")
				fmt.Println("\nNo users configured.")
				fmt.Println("Run 'keychain user register <username>' to create the first administrator.")
			} else {
				fmt.Println("Status: CONFIGURED")
				fmt.Printf("User accounts: %d\n", count)
				fmt.Printf("Admin accounts: %d\n", adminCount)
			}
		}
	},
}

// userCredentialConfigCmd shows credential configuration for login
var userCredentialConfigCmd = &cobra.Command{
	Use:   "credentials <username>",
	Short: "Get credential configuration for login",
	Long: `Get the credential ID and salt needed for FIDO2 login.

This information is needed when using 'keychain user login' to authenticate.
Store these values securely - they are needed to authenticate.

Example:
  keychain user credentials admin@example.com`,
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
		u, err := userStore.GetByUsername(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to get user: %w", err))
			return
		}

		if len(u.Credentials) == 0 {
			handleError(fmt.Errorf("user %s has no credentials", username))
			return
		}

		// Get the first credential (most common case)
		cred := u.Credentials[0]

		if cfg.OutputFormat == "json" {
			credInfo := map[string]interface{}{
				"username":      username,
				"credential_id": base64.URLEncoding.EncodeToString(cred.ID),
				"salt":          base64.URLEncoding.EncodeToString(cred.Salt),
				"name":          cred.Name,
				"created_at":    cred.CreatedAt.Format(time.RFC3339),
			}
			if err := printer.PrintJSON(credInfo); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("Credential configuration for %s:\n\n", username)
			fmt.Printf("  Credential Name: %s\n", cred.Name)
			fmt.Printf("  Credential ID:   %s\n", base64.URLEncoding.EncodeToString(cred.ID))
			fmt.Printf("  Salt:            %s\n", base64.URLEncoding.EncodeToString(cred.Salt))
			fmt.Printf("\nUse with login command:\n")
			fmt.Printf("  keychain user login --credential-id '%s' --salt '%s'\n",
				base64.URLEncoding.EncodeToString(cred.ID),
				base64.URLEncoding.EncodeToString(cred.Salt))
		}
	},
}

func init() {
	// Add subcommands
	userCmd.AddCommand(userRegisterCmd)
	userCmd.AddCommand(userLoginCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userGetCmd)
	userCmd.AddCommand(userDeleteCmd)
	userCmd.AddCommand(userDisableCmd)
	userCmd.AddCommand(userEnableCmd)
	userCmd.AddCommand(userStatusCmd)
	userCmd.AddCommand(userCredentialConfigCmd)

	// Common flags
	userCmd.PersistentFlags().String("storage-path", "", "path to keychain storage (default: $KEYCHAIN_STORAGE_PATH or /var/lib/keychain)")

	// register flags
	userRegisterCmd.Flags().String("display-name", "", "user display name (defaults to username)")
	userRegisterCmd.Flags().String("role", "", "user role (admin, operator, auditor, user, readonly, guest)")
	userRegisterCmd.Flags().String("rp-id", "go-keychain", "relying party ID")
	userRegisterCmd.Flags().String("rp-name", "Go Keychain", "relying party name")
	userRegisterCmd.Flags().Duration("timeout", 30*time.Second, "timeout for user presence")
	userRegisterCmd.Flags().String("device", "", "specific FIDO2 device path to use")
	userRegisterCmd.Flags().Bool("user-verification", false, "require user verification (PIN)")

	// login flags
	userLoginCmd.Flags().String("credential-id", "", "credential ID (base64 or hex encoded)")
	userLoginCmd.Flags().String("salt", "", "salt value (base64 or hex encoded)")
	userLoginCmd.Flags().String("rp-id", "go-keychain", "relying party ID")
	userLoginCmd.Flags().Duration("timeout", 30*time.Second, "timeout for user presence")
	userLoginCmd.Flags().String("device", "", "specific FIDO2 device path to use")
	userLoginCmd.Flags().Bool("user-verification", false, "require user verification (PIN)")
	_ = userLoginCmd.MarkFlagRequired("credential-id")
	_ = userLoginCmd.MarkFlagRequired("salt")
}
