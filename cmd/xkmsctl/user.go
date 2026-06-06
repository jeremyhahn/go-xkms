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
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	"github.com/spf13/cobra"
)

// webAuthnRegistration drives the server-side WebAuthn registration ceremony for
// the given user. It creates the xkms user (in the embedded qrdb node), begins the
// ceremony on the server, runs the local FIDO2 authenticator against the returned
// options, and finishes the ceremony on the server. The returned attestation
// carries the credential ID assigned by the authenticator.
//
// The role is resolved by the caller: admin enrollment always passes RoleAdmin,
// while user registration passes RoleAdmin for the first user and the requested
// role otherwise.
func webAuthnRegistration(
	ctx context.Context,
	cl client.Client,
	handler *fido2.FIDO2Handler,
	printer *Printer,
	username, displayName, role, origin string,
	requireUV bool,
	timeout time.Duration,
) (*fido2.WebAuthnAttestation, error) {
	// Create the xkms user in the embedded qrdb node behind the server.
	if _, err := cl.CreateUser(ctx, &client.CreateUserRequest{
		Username:    username,
		DisplayName: displayName,
		Role:        role,
	}); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Begin the server-side registration ceremony.
	beginResp, err := cl.BeginRegistration(ctx, &client.BeginRegistrationRequest{
		Username:    username,
		DisplayName: displayName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to begin registration: %w", err)
	}

	// Parse the server's PublicKeyCredentialCreationOptions.
	var creation protocol.CredentialCreation
	if err := json.Unmarshal([]byte(beginResp.OptionsJSON), &creation); err != nil {
		return nil, fmt.Errorf("failed to parse registration options: %w", err)
	}

	rpID := creation.Response.RelyingParty.ID
	rpName := creation.Response.RelyingParty.Name
	userName := creation.Response.User.Name

	userID, err := decodeWebAuthnUserID(creation.Response.User.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user handle: %w", err)
	}

	if origin == "" {
		origin = "https://" + rpID
	}

	if err := printer.PrintPrompt("\nPlease touch your security key to register..."); err != nil {
		return nil, err
	}

	// Run the local FIDO2 authenticator against the server's challenge.
	att, err := handler.RegisterWebAuthn(fido2.WebAuthnRegistrationOptions{
		Challenge:               creation.Response.Challenge,
		Origin:                  origin,
		RPID:                    rpID,
		RPName:                  rpName,
		UserID:                  userID,
		UserName:                userName,
		UserDisplayName:         displayName,
		RequireUserVerification: requireUV,
		Timeout:                 timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register credential: %w", err)
	}

	// Finish the server-side ceremony with the authenticator's attestation.
	if _, err := cl.FinishRegistration(ctx, &client.FinishRegistrationRequest{
		SessionID:       beginResp.SessionID,
		AttestationJSON: string(att.PublicKeyCredentialJSON),
	}); err != nil {
		return nil, fmt.Errorf("failed to finish registration: %w", err)
	}

	return att, nil
}

// decodeWebAuthnUserID extracts the WebAuthn user handle bytes from the JSON-decoded
// User.ID field of a CredentialCreation. The go-webauthn library serializes the
// handle as a base64url string, so after json.Unmarshal it arrives as a Go string.
func decodeWebAuthnUserID(id any) ([]byte, error) {
	switch v := id.(type) {
	case string:
		return base64.RawURLEncoding.DecodeString(v)
	case []byte:
		return v, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected user handle type %T", id)
	}
}

// userCmd represents the user command
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage user accounts",
	Long: `Commands for managing user accounts in the xkms service.

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
  xkmsctl user register admin@example.com --display-name "Admin User"
  xkmsctl user register operator@example.com --role operator`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		displayName, _ := cmd.Flags().GetString("display-name")
		devicePath, _ := cmd.Flags().GetString("device")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		requireUV, _ := cmd.Flags().GetBool("user-verification")
		roleStr, _ := cmd.Flags().GetString("role")

		if displayName == "" {
			displayName = username
		}

		// Connect to the xkms service.
		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(fmt.Errorf("failed to create client: %w", err))
			return
		}
		defer func() { _ = cl.Close() }()

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(fmt.Errorf("failed to connect: %w", err))
			return
		}
		printVerbose("Connected to xkms service")

		// The first user registered becomes the administrator; otherwise use the
		// requested role (defaulting to the standard user role).
		role := string(RoleUser)
		if roleStr != "" {
			r := Role(roleStr)
			if !IsValidRole(r) {
				handleError(fmt.Errorf("invalid role: %s", roleStr))
				return
			}
			role = roleStr
		}

		listResp, err := cl.ListUsers(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to check user status: %w", err))
			return
		}
		firstUser := len(listResp.Users) == 0
		if firstUser {
			role = string(RoleAdmin)
			if err := printer.PrintMessage("No users exist. First user will be administrator."); err != nil {
				handleError(err)
				return
			}
		}

		// Create FIDO2 handler.
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

		att, err := webAuthnRegistration(ctx, cl, handler, printer, username, displayName, role, "", requireUV, timeout)
		if err != nil {
			handleError(err)
			return
		}

		printVerbose("FIDO2 credential registered successfully")

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
				"role":          role,
				"auth_method":   "fido2",
				"credential_id": base64.URLEncoding.EncodeToString(att.CredentialID),
				"first_user":    firstUser,
			}
			if err := printer.PrintJSON(summary); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("\nUsername: %s\n", username)
			fmt.Printf("Role: %s\n", role)
			fmt.Printf("Credential ID: %s\n", base64.URLEncoding.EncodeToString(att.CredentialID))
			fmt.Printf("\nYou can now use this security key to authenticate.\n")
		}
	},
}

// userLoginCmd authenticates using FIDO2 and gets a JWT token
var userLoginCmd = &cobra.Command{
	Use:   "login <username>",
	Short: "Authenticate using FIDO2 and get a JWT token",
	Long: `Authenticate to the xkms service using your FIDO2 security key.

This command drives the server-side WebAuthn authentication ceremony:
1. The server issues an authentication challenge and the allow-list of
   credentials registered for the user.
2. You touch your FIDO2 security key to produce a signed assertion.
3. The server verifies the assertion signature and returns a JWT token
   for subsequent API calls.

The token is printed to stdout for use with other commands. You can store
it in an environment variable or config file.

Example:
  export XKMS_TOKEN=$(xkmsctl user login admin@example.com)
  xkmsctl key list --token $XKMS_TOKEN`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		timeout, _ := cmd.Flags().GetDuration("timeout")
		devicePath, _ := cmd.Flags().GetString("device")
		requireUV, _ := cmd.Flags().GetBool("user-verification")

		// Connect to the xkms service.
		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(fmt.Errorf("failed to create client: %w", err))
			return
		}
		defer func() { _ = cl.Close() }()

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(fmt.Errorf("failed to connect: %w", err))
			return
		}
		printVerbose("Connected to xkms service")

		// Step 1: Begin the server-side authentication ceremony. The server
		// returns the challenge and the allow-list of registered credentials.
		beginResp, err := cl.BeginAuthentication(ctx, &client.BeginAuthenticationRequest{
			Username: username,
		})
		if err != nil {
			handleError(fmt.Errorf("failed to begin authentication: %w", err))
			return
		}

		// Step 2: Parse the server's PublicKeyCredentialRequestOptions to recover
		// the challenge, relying-party ID, and the allowed credential IDs.
		var assertionOpts protocol.CredentialAssertion
		if err := json.Unmarshal([]byte(beginResp.OptionsJSON), &assertionOpts); err != nil {
			handleError(fmt.Errorf("failed to parse authentication options: %w", err))
			return
		}

		challenge := []byte(assertionOpts.Response.Challenge)
		rpID := assertionOpts.Response.RelyingPartyID
		origin := "https://" + rpID

		allowList := make([][]byte, 0, len(assertionOpts.Response.AllowedCredentials))
		for _, cred := range assertionOpts.Response.AllowedCredentials {
			allowList = append(allowList, cred.CredentialID)
		}

		// Step 3: Build the FIDO2 handler and drive the local authenticator.
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

		if err := printer.PrintPrompt("\nPlease touch your security key to authenticate..."); err != nil {
			handleError(err)
			return
		}

		assertion, err := handler.AuthenticateWebAuthn(fido2.WebAuthnAuthenticationOptions{
			Challenge:               challenge,
			Origin:                  origin,
			RPID:                    rpID,
			AllowCredentialIDs:      allowList,
			RequireUserVerification: requireUV,
			Timeout:                 timeout,
		})
		if err != nil {
			handleError(fmt.Errorf("authentication failed: %w", err))
			return
		}

		// Step 4: Finish the ceremony. The server verifies the assertion
		// signature and issues a JWT token on success.
		finishResp, err := cl.FinishAuthentication(ctx, &client.FinishAuthenticationRequest{
			SessionID:     beginResp.SessionID,
			Username:      username,
			AssertionJSON: string(assertion.PublicKeyCredentialJSON),
		})
		if err != nil {
			handleError(fmt.Errorf("failed to finish authentication: %w", err))
			return
		}
		if !finishResp.Success {
			msg := finishResp.Message
			if msg == "" {
				msg = "authentication was rejected by the server"
			}
			handleError(fmt.Errorf("authentication failed: %s", msg))
			return
		}

		printVerbose("FIDO2 authentication successful")

		if cfg.OutputFormat == "json" {
			result := map[string]interface{}{
				"success":  true,
				"username": username,
				"token":    finishResp.Token,
			}
			if err := printer.PrintJSON(result); err != nil {
				handleError(err)
			}
		} else {
			if err := printer.PrintSuccess("FIDO2 authentication successful!"); err != nil {
				handleError(err)
			}
			fmt.Printf("\nUsername: %s\n", username)
			fmt.Printf("Token: %s\n", finishResp.Token)
		}
	},
}

// userListCmd lists all users
var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all user accounts",
	Long:  `List all user accounts configured in the xkms service.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(fmt.Errorf("failed to create client: %w", err))
			return
		}
		defer func() { _ = cl.Close() }()

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(fmt.Errorf("failed to connect: %w", err))
			return
		}
		printVerbose("Connected to xkms service")

		resp, err := cl.ListUsers(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to list users: %w", err))
			return
		}
		users := resp.Users

		if len(users) == 0 {
			if err := printer.PrintMessage("No users configured. Run 'xkmsctl user register' to create the first user."); err != nil {
				handleError(err)
			}
			return
		}

		// Print users
		if cfg.OutputFormat == "json" {
			userList := make([]map[string]interface{}, len(users))
			for i, u := range users {
				userList[i] = map[string]interface{}{
					"username":     u.Username,
					"display_name": u.DisplayName,
					"role":         u.Role,
					"enabled":      u.Enabled,
					"created_at":   u.CreatedAt.Format(time.RFC3339),
				}
				if u.LastLogin != nil {
					userList[i]["last_login"] = u.LastLogin.Format(time.RFC3339)
				}
			}
			if err := printer.PrintJSON(map[string]interface{}{
				"users": userList,
				"total": len(userList),
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("%-24s %-24s %-12s %-8s\n", "USERNAME", "DISPLAY NAME", "ROLE", "ENABLED")
			fmt.Println(repeatString("-", 70))
			for _, u := range users {
				fmt.Printf("%-24s %-24s %-12s %-8t\n",
					truncateString(u.Username, 24),
					truncateString(u.DisplayName, 24),
					u.Role,
					u.Enabled,
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

		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(fmt.Errorf("failed to create client: %w", err))
			return
		}
		defer func() { _ = cl.Close() }()

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(fmt.Errorf("failed to connect: %w", err))
			return
		}
		printVerbose("Connected to xkms service")

		resp, err := cl.GetUser(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to get user: %w", err))
			return
		}
		u := resp.User

		// Fetch the user's credentials for display.
		var creds []client.CredentialInfo
		if credResp, credErr := cl.ListUserCredentials(ctx, username); credErr == nil {
			creds = credResp.Credentials
		} else {
			printVerbose("failed to list credentials for %s: %v", username, credErr)
		}

		if cfg.OutputFormat == "json" {
			userInfo := map[string]interface{}{
				"username":     u.Username,
				"display_name": u.DisplayName,
				"role":         u.Role,
				"enabled":      u.Enabled,
				"created_at":   u.CreatedAt.Format(time.RFC3339),
			}
			if u.LastLogin != nil {
				userInfo["last_login"] = u.LastLogin.Format(time.RFC3339)
			}

			credList := make([]map[string]interface{}, len(creds))
			for i, c := range creds {
				credList[i] = map[string]interface{}{
					"id":           c.ID,
					"display_name": c.DisplayName,
				}
			}
			userInfo["credentials"] = credList

			if err := printer.PrintJSON(userInfo); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("User Details:\n")
			fmt.Printf("  Username:     %s\n", u.Username)
			fmt.Printf("  Display Name: %s\n", u.DisplayName)
			fmt.Printf("  Role:         %s\n", u.Role)
			fmt.Printf("  Enabled:      %t\n", u.Enabled)
			fmt.Printf("  Created:      %s\n", u.CreatedAt.Format(time.RFC3339))
			if u.LastLogin != nil {
				fmt.Printf("  Last Login:   %s\n", u.LastLogin.Format(time.RFC3339))
			}
			fmt.Printf("\n  Credentials (%d):\n", len(creds))
			for i, c := range creds {
				name := c.DisplayName
				if name == "" {
					name = c.ID
				}
				fmt.Printf("    %d. %s\n", i+1, name)
				fmt.Printf("       ID: %s\n", c.ID)
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

		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(fmt.Errorf("failed to create client: %w", err))
			return
		}
		defer func() { _ = cl.Close() }()

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(fmt.Errorf("failed to connect: %w", err))
			return
		}
		printVerbose("Connected to xkms service")

		if err := cl.DeleteUser(ctx, username); err != nil {
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

		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(fmt.Errorf("failed to create client: %w", err))
			return
		}
		defer func() { _ = cl.Close() }()

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(fmt.Errorf("failed to connect: %w", err))
			return
		}
		printVerbose("Connected to xkms service")

		if err := cl.DisableUser(ctx, username); err != nil {
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

		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(fmt.Errorf("failed to create client: %w", err))
			return
		}
		defer func() { _ = cl.Close() }()

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(fmt.Errorf("failed to connect: %w", err))
			return
		}
		printVerbose("Connected to xkms service")

		if err := cl.EnableUser(ctx, username); err != nil {
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
	Long:  `Show whether the xkms service has any user accounts configured.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(fmt.Errorf("failed to create client: %w", err))
			return
		}
		defer func() { _ = cl.Close() }()

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(fmt.Errorf("failed to connect: %w", err))
			return
		}
		printVerbose("Connected to xkms service")

		resp, err := cl.ListUsers(ctx)
		if err != nil {
			handleError(fmt.Errorf("failed to check user status: %w", err))
			return
		}

		count := len(resp.Users)
		adminCount := 0
		for _, u := range resp.Users {
			if u.Role == string(RoleAdmin) {
				adminCount++
			}
		}
		hasUsers := count > 0

		if cfg.OutputFormat == "json" {
			status := map[string]interface{}{
				"requires_setup": !hasUsers,
				"user_count":     count,
				"admin_count":    adminCount,
			}
			if !hasUsers {
				status["message"] = "No users configured. Run 'xkmsctl user register' to create the first administrator."
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
				fmt.Println("Run 'xkmsctl user register <username>' to create the first administrator.")
			} else {
				fmt.Println("Status: CONFIGURED")
				fmt.Printf("User accounts: %d\n", count)
				fmt.Printf("Admin accounts: %d\n", adminCount)
			}
		}
	},
}

// userCredentialConfigCmd lists the WebAuthn credentials registered for a user.
var userCredentialConfigCmd = &cobra.Command{
	Use:   "credentials <username>",
	Short: "List the FIDO2 credentials registered for a user",
	Long: `List the FIDO2 credentials registered for a user.

The server supplies the allow-list automatically during 'xkmsctl user login',
so the credential IDs shown here are informational.

Example:
  xkmsctl user credentials admin@example.com`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(fmt.Errorf("failed to create client: %w", err))
			return
		}
		defer func() { _ = cl.Close() }()

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(fmt.Errorf("failed to connect: %w", err))
			return
		}
		printVerbose("Connected to xkms service")

		resp, err := cl.ListUserCredentials(ctx, username)
		if err != nil {
			handleError(fmt.Errorf("failed to list credentials: %w", err))
			return
		}
		creds := resp.Credentials

		if len(creds) == 0 {
			handleError(fmt.Errorf("user %s has no credentials", username))
			return
		}

		if cfg.OutputFormat == "json" {
			credList := make([]map[string]interface{}, len(creds))
			for i, c := range creds {
				credList[i] = map[string]interface{}{
					"id":           c.ID,
					"display_name": c.DisplayName,
				}
			}
			if err := printer.PrintJSON(map[string]interface{}{
				"username":    username,
				"credentials": credList,
				"total":       len(credList),
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("Credentials for %s (%d):\n\n", username, len(creds))
			for i, c := range creds {
				name := c.DisplayName
				if name == "" {
					name = c.ID
				}
				fmt.Printf("  %d. %s\n", i+1, name)
				fmt.Printf("     ID: %s\n", c.ID)
			}
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
	userCmd.PersistentFlags().String("storage-path", "", "path to xkms storage (default: $XKMS_STORAGE_PATH or /var/lib/xkms)")

	// register flags
	userRegisterCmd.Flags().String("display-name", "", "user display name (defaults to username)")
	userRegisterCmd.Flags().String("role", "", "user role (admin, operator, auditor, user, readonly, guest)")
	userRegisterCmd.Flags().String("rp-id", "go-xkms", "relying party ID")
	userRegisterCmd.Flags().String("rp-name", "Go xKMS", "relying party name")
	userRegisterCmd.Flags().Duration("timeout", 30*time.Second, "timeout for user presence")
	userRegisterCmd.Flags().String("device", "", "specific FIDO2 device path to use")
	userRegisterCmd.Flags().Bool("user-verification", false, "require user verification (PIN)")

	// login flags. The server supplies the credential allow-list during the
	// authentication ceremony, so no credential-id/salt flags are needed.
	userLoginCmd.Flags().Duration("timeout", 30*time.Second, "timeout for user presence")
	userLoginCmd.Flags().String("device", "", "specific FIDO2 device path to use")
	userLoginCmd.Flags().Bool("user-verification", false, "require user verification (PIN)")
}
