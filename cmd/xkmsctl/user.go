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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	webauthnclient "github.com/jeremyhahn/go-xkms/sdk/go/webauthnclient"
	"github.com/spf13/cobra"
)

// createInvitedUser creates the xkms user (in the embedded qrdb node) and
// returns the server's response, which for an account with an email login
// key now always carries a one-time activation invitation (go-xkms#1294
// part B): CreateUser creates such an account PENDING, holding no
// credential, and mints the invitation in the same call.
//
// This is the replacement for the pre-#1294 webAuthnRegistration helper,
// which drove CreateUser, BeginRegistration and a local hardware ceremony
// back to back. BeginRegistration now refuses an account CreateUser just
// created — enrolling its first credential is authorized by the invitation,
// never by having just created the account — so that ceremony can no longer
// run inline here. Redeem the printed invitation with
// 'xkmsctl user invite redeem' (see user_invite.go) to enroll the first
// FIDO2 passkey or PIV credential and activate the account.
func createInvitedUser(
	ctx context.Context,
	cl client.Client,
	username, email, displayName, role string,
) (*client.GetUserResponse, error) {
	resp, err := cl.CreateUser(ctx, &client.CreateUserRequest{
		Username: username,
		// The canonical tenant-unique login key. WebAuthn enrollment resolves
		// through it, so an account created without one is provisioned and
		// unreachable; it is supplied explicitly rather than taken from the
		// username, which is a separate identifier that merely often looks
		// like an email.
		Email:       email,
		DisplayName: displayName,
		Role:        role,
	})
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreateUserFailed, Err: err}
	}
	if resp == nil {
		// Every real transport returns a non-nil response alongside a nil
		// error; guard anyway so a misbehaving client degrades to "no
		// invitation to show" rather than a nil dereference below.
		resp = &client.GetUserResponse{}
	}
	return resp, nil
}

// printInvite reports the one-time activation invitation CreateUser minted,
// which is the only place it is ever shown: only its digest is stored, so a
// caller that loses this output must delete and recreate the account.
func printInvite(printer *Printer, cfg *Config, invite *client.InviteInfo) error {
	if invite == nil {
		return nil
	}
	if cfg.OutputFormat == "json" {
		return printer.PrintJSON(map[string]interface{}{
			"invite_token":      invite.Token,
			"invite_url":        invite.URL,
			"invite_expires_at": invite.ExpiresAt.Format(time.RFC3339),
		})
	}
	fmt.Println("\nActivation invitation (shown once — only its digest is stored):")
	fmt.Printf("  Token:      %s\n", invite.Token)
	if invite.URL != "" {
		fmt.Printf("  Link:       %s\n", invite.URL)
	}
	fmt.Printf("  Expires:    %s\n", invite.ExpiresAt.Format(time.RFC3339))
	fmt.Println("\nSend this link to the invitee, or redeem it yourself with")
	fmt.Println("'xkmsctl user invite redeem' to enroll the first FIDO2 passkey or PIV")
	fmt.Println("credential and activate the account.")
	return nil
}

// webAuthnAttestationResponse is the subset of the WebAuthn PublicKeyCredential
// attestation document extractWebAuthnCredentialID reads.
type webAuthnAttestationResponse struct {
	RawID string `json:"rawId"`
}

// extractWebAuthnCredentialID recovers the authenticator-assigned credential
// ID bytes from an attestation document's base64url-encoded "rawId" field, for
// display after a successful registration.
func extractWebAuthnCredentialID(attestationJSON []byte) ([]byte, error) {
	var doc webAuthnAttestationResponse
	if err := json.Unmarshal(attestationJSON, &doc); err != nil {
		return nil, &WrappedError{Sentinel: ErrDecodeCredentialIDFailed, Err: err}
	}
	credentialID, err := base64.RawURLEncoding.DecodeString(doc.RawID)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrDecodeCredentialIDFailed, Err: err}
	}
	return credentialID, nil
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
	Long: `Create a new user account, pending activation.

The first user registered will automatically receive the admin role.
Subsequent users will receive the 'user' role by default.

The account is created PENDING, holding no credential: an administrator
cannot enroll a passkey on an invitee's behalf, so this command no longer
drives a local FIDO2 ceremony inline (go-xkms#1294 part B). It prints a
one-time activation invitation instead — shown exactly once, since only its
digest is stored. Send the link to the invitee, or redeem it yourself (from
the machine holding the security key) with 'xkmsctl user invite redeem'.

Example:
  xkmsctl user register admin --email admin@example.com --display-name "Admin User"
  xkmsctl user register operator --email operator@example.com --role operator`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		email := fr.String("email")
		displayName := fr.String("display-name")
		roleStr := fr.String("role")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if email == "" {
			// handleError, not print-and-return: a bare return leaves Cobra's
			// Run with nothing to report, so the process exits 0 and every
			// script calling this sees a rejected registration as a success.
			handleError(ErrEmailRequired)
			return
		}
		email, err := validateLoginKey(email)
		if err != nil {
			handleError(err)
			return
		}

		if displayName == "" {
			displayName = username
		}

		// Connect to the xkms service.
		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
			return
		}
		defer closeQuietly(cl)

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
			return
		}
		printVerbose("Connected to xkms service")

		// The first user registered becomes the administrator; otherwise use the
		// requested role (defaulting to the standard user role).
		role := string(RoleUser)
		if roleStr != "" {
			r := Role(roleStr)
			if !IsValidRole(r) {
				handleError(&WrappedDetailError{Sentinel: ErrInvalidRole, Detail: roleStr})
				return
			}
			role = roleStr
		}

		listResp, err := cl.ListUsers(ctx)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCheckUserStatusFailed, Err: err})
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

		// CreateUser creates the account PENDING and mints a one-time
		// activation invitation in the same call (go-xkms#1294 part B); it
		// no longer enrolls a passkey inline (see createInvitedUser).
		resp, err := createInvitedUser(ctx, cl, username, email, displayName, role)
		if err != nil {
			handleError(err)
			return
		}

		if err := printer.PrintSuccess("\nUser created successfully; activation is pending."); err != nil {
			handleError(err)
			return
		}
		if err := printInvite(printer, cfg, resp.Invite); err != nil {
			handleError(err)
			return
		}
		if cfg.OutputFormat == "json" {
			if err := printer.PrintJSON(map[string]interface{}{
				"success":      true,
				"username":     username,
				"display_name": displayName,
				"role":         role,
				"first_user":   firstUser,
				"pending":      true,
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("\nUsername: %s\n", username)
			fmt.Printf("Role: %s\n", role)
		}
	},
}

// loginAssertion runs the local half of the login ceremony: it drives
// adapter, the SDK re-export of the single canonical WebAuthn ceremony
// driver's hardware authenticator, against the server's BeginAuthentication
// options, carries the resolved CTAP2 PIN into the assertion request, and
// classifies PIN failures before they reach the operator (see
// ceremonyFailure).
//
// It exists as a named function rather than inline in the command closure so
// the one place the PIN enters the ceremony is reachable by tests driving a
// real authenticator (go-xkms#309).
func loginAssertion(
	ctx context.Context,
	adapter webauthnclient.AuthenticatorAdapter,
	optionsJSON []byte,
	origin string,
	pin *secure.Secret,
) ([]byte, error) {
	assertion, err := adapter.GetAssertion(ctx, &webauthnclient.CeremonyOptions{
		OptionsJSON: optionsJSON,
		Origin:      origin,
		PIN:         pin,
	})
	if err != nil {
		return nil, ceremonyFailure(ErrAuthenticationFailed, pin, err)
	}
	return assertion, nil
}

// userLoginCmd authenticates using FIDO2 and gets a JWT token
var userLoginCmd = &cobra.Command{
	// <email>, not <username>: the argument is passed straight to
	// BeginAuthentication, which resolves the account with GetUserByEmail. The
	// command's own example has always shown an email, but the signature said
	// "username" and invited `user login alice` — which now cannot resolve,
	// because the canonical login key and the username are separate values.
	Use:   "login <email>",
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

An authenticator with a CTAP2 PIN set refuses the assertion unless the
request carries the PIN. An authenticator with no PIN configured needs none.

` + pinUsage + `

Example:
  export XKMS_TOKEN=$(xkmsctl user login admin@example.com)
  xkmsctl key list --token $XKMS_TOKEN

  # Login against a PIN-protected authenticator, with no PIN in the process list
  printf '%s' "$PIN" | xkmsctl user login admin@example.com --pin-stdin`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// The login key is checked before anything reaches the network: a
		// username here would run the whole ceremony against nothing, and
		// correcting it should not first cost a round trip.
		email, err := validateLoginKey(args[0])
		if err != nil {
			handleError(err)
			return
		}
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		timeout := fr.Duration("timeout")
		devicePath := fr.String("device")
		requireUV := fr.Bool("user-verification")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		// Resolve the PIN before anything reaches the network: a --pin-stdin
		// with nothing on standard input is operator input to correct, and
		// correcting it should not first cost a server round trip or a
		// half-consumed challenge. An empty PIN is legitimate here — it is
		// what an authenticator with no PIN configured needs.
		pin, err := resolvePINInput(cmd)
		if err != nil {
			handleError(err)
			return
		}
		origin, err := resolveWebAuthnOrigin(cmd, cfg.Server)
		if err != nil {
			handleError(err)
			return
		}

		// Connect to the xkms service.
		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
			return
		}
		defer closeQuietly(cl)

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
			return
		}
		printVerbose("Connected to xkms service")

		// Step 1: Begin the server-side authentication ceremony against the
		// account's email, the login key the server resolves with
		// GetUserByEmail. The server returns the challenge and the allow-list
		// of registered credentials.
		beginResp, err := cl.BeginAuthentication(ctx, &client.BeginAuthenticationRequest{
			Email: email,
		})
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrBeginAuthenticationFailed, Err: err})
			return
		}

		// Step 2: Build the hardware CTAP2 authenticator adapter.
		fidoConfig := fido2.DefaultConfig
		fidoConfig.DevicePath = devicePath
		fidoConfig.RequireUserVerification = requireUV
		fidoConfig.UserPresenceTimeout = timeout
		enumerator := cfg.HIDDeviceEnumerator()

		adapter, err := webauthnclient.NewHardwareAdapter(&fidoConfig, enumerator)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateFIDO2HandlerFailed, Err: err})
			return
		}
		defer closeQuietly(adapter)

		if err := printer.PrintPrompt("\nPlease touch your security key to authenticate..."); err != nil {
			handleError(err)
			return
		}

		// Step 3: Drive the local authenticator against the server's
		// PublicKeyCredentialRequestOptions. The adapter parses the options
		// JSON itself and refuses an rpId the origin does not cover.
		assertion, err := loginAssertion(ctx, adapter, []byte(beginResp.OptionsJSON), origin, pin)
		if err != nil {
			handleError(err)
			return
		}

		// Step 4: Finish the ceremony. The server verifies the assertion
		// signature and issues a JWT token on success.
		finishResp, err := cl.FinishAuthentication(ctx, &client.FinishAuthenticationRequest{
			SessionID:     beginResp.SessionID,
			Email:         email,
			AssertionJSON: string(assertion),
		})
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrFinishAuthenticationFailed, Err: err})
			return
		}
		if !finishResp.Success {
			msg := finishResp.Message
			if msg == "" {
				msg = "authentication was rejected by the server"
			}
			handleError(&WrappedDetailError{Sentinel: ErrAuthenticationFailed, Detail: msg})
			return
		}

		printVerbose("FIDO2 authentication successful")

		if cfg.OutputFormat == "json" {
			result := map[string]interface{}{
				"success": true,
				"email":   email,
				"token":   finishResp.Token,
			}
			if err := printer.PrintJSON(result); err != nil {
				handleError(err)
			}
		} else {
			if err := printer.PrintSuccess("FIDO2 authentication successful!"); err != nil {
				handleError(err)
			}
			fmt.Printf("\nEmail: %s\n", email)
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
			handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
			return
		}
		defer closeQuietly(cl)

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
			return
		}
		printVerbose("Connected to xkms service")

		resp, err := cl.ListUsers(ctx)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrListUsersFailed, Err: err})
			return
		}
		users := resp.Users

		if len(users) == 0 {
			if err := printer.PrintMessage("No users configured. Run 'xkmsctl user register <username> --email <address>' to create the first user."); err != nil {
				handleError(err)
			}
			return
		}

		// Print users
		if cfg.OutputFormat == "json" {
			userList := make([]map[string]interface{}, len(users))
			for i, u := range users {
				userList[i] = map[string]interface{}{
					"username": u.Username,
					// The canonical login key. JSON is built by hand here, so it
					// does NOT inherit the struct tag — a claim I made in a
					// commit message without checking, and it was false. Machine
					// output was missing the one field WebAuthn login needs
					// while the table showed it (Codex, go-xkms #190).
					"email":        u.Email,
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
			// EMAIL is the canonical login key everything resolves by, so it
			// belongs in the operator's view of a user; JSON output already
			// carries it through the struct tag.
			fmt.Printf("%-20s %-28s %-20s %-12s %-8s\n", "USERNAME", "EMAIL", "DISPLAY NAME", "ROLE", "ENABLED")
			fmt.Println(repeatString("-", 92))
			for _, u := range users {
				fmt.Printf("%-20s %-28s %-20s %-12s %-8t\n",
					truncateString(u.Username, 20),
					truncateString(u.Email, 28),
					truncateString(u.DisplayName, 20),
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
			handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
			return
		}
		defer closeQuietly(cl)

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
			return
		}
		printVerbose("Connected to xkms service")

		resp, err := cl.GetUser(ctx, username)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrGetUserFailed, Err: err})
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
				"email":        u.Email,
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
			handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
			return
		}
		defer closeQuietly(cl)

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
			return
		}
		printVerbose("Connected to xkms service")

		if err := cl.DeleteUser(ctx, username); err != nil {
			handleError(&WrappedError{Sentinel: ErrDeleteUserFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
			return
		}
		defer closeQuietly(cl)

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
			return
		}
		printVerbose("Connected to xkms service")

		if err := cl.DisableUser(ctx, username); err != nil {
			handleError(&WrappedError{Sentinel: ErrDisableUserFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
			return
		}
		defer closeQuietly(cl)

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
			return
		}
		printVerbose("Connected to xkms service")

		if err := cl.EnableUser(ctx, username); err != nil {
			handleError(&WrappedError{Sentinel: ErrEnableUserFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
			return
		}
		defer closeQuietly(cl)

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
			return
		}
		printVerbose("Connected to xkms service")

		resp, err := cl.ListUsers(ctx)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCheckUserStatusFailed, Err: err})
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
				status["message"] = "No users configured. Run 'xkmsctl user register <username> --email <address>' to create the first administrator."
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
				fmt.Println("Run 'xkmsctl user register <username> --email <address>' to create the first administrator.")
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
			handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
			return
		}
		defer closeQuietly(cl)

		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
			return
		}
		printVerbose("Connected to xkms service")

		resp, err := cl.ListUserCredentials(ctx, username)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrListCredentialsFailed, Err: err})
			return
		}
		creds := resp.Credentials

		if len(creds) == 0 {
			handleError(&UserNoCredentialsError{Username: username})
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

// userUpdateCmd updates a user account (enable/disable state).
var userUpdateCmd = &cobra.Command{
	Use:   "update <username>",
	Short: "Update a user account",
	Long: `Update a user account's enabled state. Exactly one of --enable or
--disable must be provided; this maps onto the server's per-direction
enable/disable endpoints (POST /api/v1/users/{username}/enable or
/disable).

Examples:
  xkmsctl user update alice --enable
  xkmsctl user update alice --disable`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		enable := fr.Bool("enable")
		disable := fr.Bool("disable")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if enable == disable {
			handleError(ErrUserUpdateEnableFlagRequired)
			return
		}

		userUpdate(cfg, printer, username, enable)
	},
}

// userUpdate updates a user's enabled state via the SDK client.
func userUpdate(cfg *Config, printer *Printer, username string, enable bool) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}
	printVerbose("Connected to xkms service")

	if enable {
		if err := cl.EnableUser(ctx, username); err != nil {
			handleError(&WrappedError{Sentinel: ErrEnableUserFailed, Err: err})
			return
		}
	} else {
		if err := cl.DisableUser(ctx, username); err != nil {
			handleError(&WrappedError{Sentinel: ErrDisableUserFailed, Err: err})
			return
		}
	}

	// Read back the user so the output reflects the server's state.
	resp, err := cl.GetUser(ctx, username)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetUserFailed, Err: err})
		return
	}
	u := resp.User

	if cfg.OutputFormat == "json" {
		if err := printer.PrintJSON(map[string]interface{}{
			"success":  true,
			"username": u.Username,
			"enabled":  u.Enabled,
			"role":     u.Role,
		}); err != nil {
			handleError(err)
		}
	} else {
		fmt.Printf("User '%s' updated (enabled: %t).\n", u.Username, u.Enabled)
	}
}

// userBindCertCmd binds an mTLS certificate to a user.
var userBindCertCmd = &cobra.Command{
	Use:   "bind-cert <username>",
	Short: "Bind an mTLS certificate to a user",
	Long: `Bind an mTLS client certificate to a user account so the user can
authenticate with that certificate.

The binding identifier is the canonical qrdb SPKI SHA-256 thumbprint.
Provide either the certificate PEM file (--cert-file, from which the
thumbprint and expiry are computed) or a precomputed thumbprint
(--thumbprint, optionally with --not-after).

Examples:
  xkmsctl user bind-cert alice --cert-file alice.pem
  xkmsctl user bind-cert alice --thumbprint 9f3a... --not-after 1767225600`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		thumbprint := fr.String("thumbprint")
		certFile := fr.String("cert-file")
		notAfter := fr.Int64("not-after")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if (thumbprint == "") == (certFile == "") {
			handleError(ErrUserCertSourceRequired)
			return
		}

		if certFile != "" {
			cert, err := loadPEMCertificate(certFile)
			if err != nil {
				handleError(err)
				return
			}
			thumbprint = qrdbsdk.ComputeSPKIThumbprint(cert)
			notAfter = cert.NotAfter.Unix()
		}

		userBindCert(cfg, printer, username, thumbprint, notAfter)
	},
}

// loadPEMCertificate reads and parses the first certificate PEM block in
// the given file.
func loadPEMCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, &CertFileReadError{Path: path, Err: err}
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &PEMBlockDecodeError{Path: path}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &CertFileParseError{Path: path, Err: err}
	}
	return cert, nil
}

// userBindCert binds a certificate thumbprint to a user via the SDK client.
func userBindCert(cfg *Config, printer *Printer, username, thumbprint string, notAfterUnix int64) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer closeQuietly(cl)

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}
	printVerbose("Connected to xkms service")

	if err := cl.BindUserCert(ctx, username, thumbprint, notAfterUnix); err != nil {
		handleError(&WrappedError{Sentinel: ErrBindCertFailed, Err: err})
		return
	}

	if cfg.OutputFormat == "json" {
		if err := printer.PrintJSON(map[string]interface{}{
			"success":    true,
			"username":   username,
			"thumbprint": thumbprint,
			"not_after":  notAfterUnix,
		}); err != nil {
			handleError(err)
		}
	} else {
		fmt.Printf("Certificate bound to user '%s'.\n", username)
		fmt.Printf("  Thumbprint: %s\n", thumbprint)
		if notAfterUnix > 0 {
			fmt.Printf("  Not After:  %s\n", time.Unix(notAfterUnix, 0).UTC().Format(time.RFC3339))
		}
	}
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
	userCmd.AddCommand(userUpdateCmd)
	userCmd.AddCommand(userBindCertCmd)

	// Common flags
	userCmd.PersistentFlags().String("storage-path", "", "path to xkms storage (default: $XKMS_STORAGE_PATH or /var/lib/xkms)")

	// register flags
	userRegisterCmd.Flags().String("email", "", "canonical login key for the user (REQUIRED)")
	userRegisterCmd.Flags().String("display-name", "", "user display name (defaults to username)")
	userRegisterCmd.Flags().String("role", "", "user role (so, admin, operator, user, auditor, custodian)")

	// login flags. The server supplies the credential allow-list during the
	// authentication ceremony, so no credential-id/salt flags are needed.
	userLoginCmd.Flags().Duration("timeout", 30*time.Second, "timeout for user presence")
	userLoginCmd.Flags().String("device", "", "specific FIDO2 device path to use")
	userLoginCmd.Flags().Bool("user-verification", false, "require user verification (PIN)")
	addPINFlags(userLoginCmd)
	addOriginFlag(userLoginCmd)

	// update flags
	userUpdateCmd.Flags().Bool("enable", false, "enable the user account")
	userUpdateCmd.Flags().Bool("disable", false, "disable the user account")

	// bind-cert flags
	userBindCertCmd.Flags().String("cert-file", "", "client certificate PEM file (thumbprint and expiry are computed)")
	userBindCertCmd.Flags().String("thumbprint", "", "precomputed SPKI SHA-256 thumbprint (hex)")
	userBindCertCmd.Flags().Int64("not-after", 0, "binding expiry as Unix seconds (with --thumbprint)")
}

// validateLoginKey refuses a login key that is not an email address and
// returns it trimmed. The server stores the value verbatim as the account's
// index key, so the address must parse and must be the bare address, not a
// display-name form; full RFC 5322 conformance is not the goal, telling an
// email from a username is.
func validateLoginKey(value string) (string, error) {
	value = strings.TrimSpace(value)
	addr, err := mail.ParseAddress(value)
	if err != nil || addr.Address != value {
		return "", ErrLoginKeyNotEmail
	}
	return value, nil
}
