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
	"encoding/pem"
	"fmt"
	"os"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	"github.com/spf13/cobra"
)

// adminCreateHandler is a function that implements admin enrollment for a given
// authentication method. The map-based dispatch table below provides O(1) lookup.
type adminCreateHandler func(cmd *cobra.Command, username string, cfg *Config, printer *Printer, storagePath string) error

// adminCreateHandlers maps authentication method names to their enrollment handlers.
var adminCreateHandlers = map[string]adminCreateHandler{
	"fido2": enrollFIDO2Admin,
	"mtls":  enrollMTLSAdmin,
}

// adminCmd represents the admin command
var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Manage administrator accounts",
	Long:  `Commands for managing administrator accounts for the xkms service.`,
}

// adminCreateCmd creates a new admin account
var adminCreateCmd = &cobra.Command{
	Use:   "create <username>",
	Short: "Create a new administrator account",
	Long: `Create a new administrator account with a FIDO2 security key or mTLS certificate.

All administrators have the admin role and full access to manage the xkms.

Example (FIDO2):
  xkmsctl admin create admin@example.com --display-name "Admin User"

Example (mTLS with certificate file):
  xkmsctl admin create admin@example.com --method mtls --cert-file /path/to/client.pem

Example (mTLS with PKCS#11 token):
  xkmsctl admin create admin@example.com --method mtls --pkcs11-module /usr/lib/libxkey11.so`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		username := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		storagePath, _ := cmd.Flags().GetString("storage-path")
		storagePath = resolveStoragePath(storagePath)
		printVerbose("Using user store at: %s", storagePath)

		method, _ := cmd.Flags().GetString("method")

		handler, ok := adminCreateHandlers[method]
		if !ok {
			return fmt.Errorf("%w: %s (supported: fido2, mtls)", ErrUnsupportedAuthMethod, method)
		}

		if err := handler(cmd, username, cfg, printer, storagePath); err != nil {
			handleError(err)
			return err
		}

		return nil
	},
}

// enrollFIDO2Admin performs FIDO2-based admin enrollment by driving the
// server-side WebAuthn registration ceremony through the SDK. The admin role is
// always assigned.
func enrollFIDO2Admin(cmd *cobra.Command, username string, cfg *Config, printer *Printer, storagePath string) error {
	displayName, _ := cmd.Flags().GetString("display-name")
	devicePath, _ := cmd.Flags().GetString("device")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	requireUV, _ := cmd.Flags().GetBool("user-verification")

	if displayName == "" {
		displayName = username
	}

	// Connect to the xkms service.
	cl, err := cfg.CreateClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	printVerbose("Connected to xkms service")

	// Create FIDO2 handler
	fidoConfig := fido2.DefaultConfig
	fidoConfig.DevicePath = devicePath
	fidoConfig.RequireUserVerification = requireUV
	enumerator := fido2.NewDefaultEnumerator()

	handler, err := fido2.NewHandler(&fidoConfig, enumerator)
	if err != nil {
		return fmt.Errorf("failed to create FIDO2 handler: %w", err)
	}
	defer func() { _ = handler.Close() }()

	if err := printer.PrintMessage("Creating administrator account..."); err != nil {
		return err
	}

	if err := printer.PrintMessage(fmt.Sprintf("Username: %s", username)); err != nil {
		return err
	}

	if err := printer.PrintMessage(fmt.Sprintf("Display Name: %s", displayName)); err != nil {
		return err
	}

	att, err := webAuthnRegistration(ctx, cl, handler, printer, username, displayName, string(RoleAdmin), "", requireUV, timeout)
	if err != nil {
		return err
	}

	printVerbose("FIDO2 credential registered successfully")

	if err := printer.PrintSuccess("\nAdministrator created successfully!"); err != nil {
		return err
	}

	// Print summary
	if cfg.OutputFormat == "json" {
		summary := map[string]interface{}{
			"success":       true,
			"username":      username,
			"display_name":  displayName,
			"role":          "admin",
			"auth_method":   "fido2",
			"credential_id": base64.URLEncoding.EncodeToString(att.CredentialID),
		}
		if err := printer.PrintJSON(summary); err != nil {
			return err
		}
	} else {
		fmt.Printf("\nUsername: %s\n", username)
		fmt.Printf("Role: %s\n", string(RoleAdmin))
		fmt.Printf("Credential ID: %s\n", base64.URLEncoding.EncodeToString(att.CredentialID))
		fmt.Printf("\nYou can now use this security key to authenticate to the xkms web UI.\n")
	}

	return nil
}

// enrollMTLSAdmin performs mTLS certificate-based admin enrollment. It reads a
// client certificate from either a PEM file (--cert-file) or a PKCS#11 token
// (--pkcs11-module), computes the canonical SPKI thumbprint, and creates an admin
// user with a CertBinding.
func enrollMTLSAdmin(cmd *cobra.Command, username string, cfg *Config, printer *Printer, storagePath string) error {
	displayName, _ := cmd.Flags().GetString("display-name")
	if displayName == "" {
		displayName = username
	}

	cert, err := loadEnrollmentCert(cmd, cfg)
	if err != nil {
		return err
	}

	// Compute the canonical mTLS identity (qrdb SPKI thumbprint) for the cert
	// binding. Using the same algorithm qrdb/quicbaas use keeps cert bindings
	// consistent across the stack and makes re-issued certs for the same key
	// resolve to the same bound identifier.
	fingerprint := qrdbsdk.ComputeSPKIThumbprint(cert)

	if err := printer.PrintMessage("Creating administrator account (mTLS)..."); err != nil {
		return err
	}

	if err := printer.PrintMessage(fmt.Sprintf("Username: %s", username)); err != nil {
		return err
	}

	if err := printer.PrintMessage(fmt.Sprintf("Display Name: %s", displayName)); err != nil {
		return err
	}

	if err := printer.PrintMessage(fmt.Sprintf("Certificate Subject: %s", cert.Subject.String())); err != nil {
		return err
	}

	// Create the admin user and bind the mTLS certificate through the SDK,
	// persisting both in the embedded qrdb node behind the xkms server.
	cl, err := cfg.CreateClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	if _, err := cl.CreateUser(ctx, &client.CreateUserRequest{
		Username:    username,
		DisplayName: displayName,
		Role:        string(RoleAdmin),
	}); err != nil {
		return fmt.Errorf("failed to create admin: %w", err)
	}

	var notAfterUnix int64
	if !cert.NotAfter.IsZero() {
		notAfterUnix = cert.NotAfter.Unix()
	}
	if err := cl.BindUserCert(ctx, username, fingerprint, notAfterUnix); err != nil {
		return fmt.Errorf("failed to bind cert: %w", err)
	}

	if err := printer.PrintSuccess("\nAdministrator created successfully!"); err != nil {
		return err
	}

	// Print summary
	if cfg.OutputFormat == "json" {
		summary := map[string]interface{}{
			"success":      true,
			"username":     username,
			"display_name": displayName,
			"role":         "admin",
			"auth_method":  "mtls",
			"fingerprint":  fingerprint,
			"subject":      cert.Subject.String(),
			"issuer":       cert.Issuer.String(),
			"not_after":    cert.NotAfter.Format(time.RFC3339),
		}
		if err := printer.PrintJSON(summary); err != nil {
			return err
		}
	} else {
		fmt.Printf("\nUsername: %s\n", username)
		fmt.Printf("Role: %s\n", string(RoleAdmin))
		fmt.Printf("Auth Method: mTLS\n")
		fmt.Printf("Fingerprint: %s\n", fingerprint)
		fmt.Printf("Subject: %s\n", cert.Subject.String())
		fmt.Printf("Issuer: %s\n", cert.Issuer.String())
		fmt.Printf("Expires: %s\n", cert.NotAfter.Format(time.RFC3339))
		fmt.Printf("\nThis certificate can now be used for mTLS authentication to the xkms.\n")
	}

	return nil
}

// loadEnrollmentCert loads an X.509 certificate from either --cert-file or --pkcs11-module.
// Returns the parsed certificate or a typed error.
func loadEnrollmentCert(cmd *cobra.Command, cfg *Config) (*x509.Certificate, error) {
	certFile, _ := cmd.Flags().GetString("cert-file")

	if certFile != "" {
		return loadCertFromFile(certFile)
	}

	if cfg.PKCS11Module != "" {
		tlsCfg, cleanup, err := client.NewPKCS11TLSConfig(&client.PKCS11TLSConfig{
			ModulePath: cfg.PKCS11Module,
			SlotID:     cfg.PKCS11Slot,
			PIN:        cfg.PKCS11PIN,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to load PKCS#11 certificate: %w", err)
		}
		defer cleanup()

		if len(tlsCfg.Certificates) == 0 || tlsCfg.Certificates[0].Leaf == nil {
			return nil, ErrNoCertificateSource
		}

		return tlsCfg.Certificates[0].Leaf, nil
	}

	return nil, ErrNoCertificateSource
}

// loadCertFromFile reads and parses a PEM-encoded X.509 certificate from the given path.
func loadCertFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCertFileRead, path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: %s: no PEM block found", ErrCertFileParse, path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCertFileParse, path, err)
	}

	return cert, nil
}

// adminListCmd lists all admin accounts
var adminListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all administrator accounts",
	Long:  `List all administrator accounts configured in the xkms service.`,
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
			handleError(fmt.Errorf("failed to list admins: %w", err))
			return
		}

		// Filter to administrator accounts only.
		admins := make([]client.UserInfo, 0, len(resp.Users))
		for _, u := range resp.Users {
			if u.Role == string(RoleAdmin) {
				admins = append(admins, u)
			}
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
					"username":     a.Username,
					"display_name": a.DisplayName,
					"role":         a.Role,
					"enabled":      a.Enabled,
					"created_at":   a.CreatedAt.Format(time.RFC3339),
				}
				if a.LastLogin != nil {
					adminList[i]["last_login"] = a.LastLogin.Format(time.RFC3339)
				}
			}
			if err := printer.PrintJSON(map[string]interface{}{
				"admins": adminList,
				"total":  len(adminList),
			}); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("%-24s %-24s %-12s %-8s\n", "USERNAME", "DISPLAY NAME", "ROLE", "ENABLED")
			fmt.Println(repeatString("-", 70))
			for _, a := range admins {
				fmt.Printf("%-24s %-24s %-12s %-8t\n",
					truncateString(a.Username, 24),
					truncateString(a.DisplayName, 24),
					a.Role,
					a.Enabled,
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
			handleError(fmt.Errorf("failed to get admin: %w", err))
			return
		}
		a := resp.User

		// Fetch the admin's credentials for display.
		var creds []client.CredentialInfo
		if credResp, credErr := cl.ListUserCredentials(ctx, username); credErr == nil {
			creds = credResp.Credentials
		} else {
			printVerbose("failed to list credentials for %s: %v", username, credErr)
		}

		if cfg.OutputFormat == "json" {
			adminInfo := map[string]interface{}{
				"username":     a.Username,
				"display_name": a.DisplayName,
				"role":         a.Role,
				"enabled":      a.Enabled,
				"created_at":   a.CreatedAt.Format(time.RFC3339),
			}
			if a.LastLogin != nil {
				adminInfo["last_login"] = a.LastLogin.Format(time.RFC3339)
			}

			credList := make([]map[string]interface{}, len(creds))
			for i, c := range creds {
				credList[i] = map[string]interface{}{
					"id":           c.ID,
					"display_name": c.DisplayName,
				}
			}
			adminInfo["credentials"] = credList

			if err := printer.PrintJSON(adminInfo); err != nil {
				handleError(err)
			}
		} else {
			fmt.Printf("Administrator Details:\n")
			fmt.Printf("  Username:     %s\n", a.Username)
			fmt.Printf("  Display Name: %s\n", a.DisplayName)
			fmt.Printf("  Role:         %s\n", a.Role)
			fmt.Printf("  Enabled:      %t\n", a.Enabled)
			fmt.Printf("  Created:      %s\n", a.CreatedAt.Format(time.RFC3339))
			if a.LastLogin != nil {
				fmt.Printf("  Last Login:   %s\n", a.LastLogin.Format(time.RFC3339))
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
	Long:  `Show whether the xkms service has any administrator accounts configured.`,
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
			handleError(fmt.Errorf("failed to check admin status: %w", err))
			return
		}

		adminCount := 0
		for _, u := range resp.Users {
			if u.Role == string(RoleAdmin) {
				adminCount++
			}
		}
		hasAdmins := adminCount > 0

		if cfg.OutputFormat == "json" {
			status := map[string]interface{}{
				"requires_setup": !hasAdmins,
				"admin_count":    adminCount,
				"user_count":     len(resp.Users),
			}
			if !hasAdmins {
				status["message"] = "No administrators configured. Run 'xkmsctl admin create' to create an administrator."
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
				fmt.Println("Run 'xkmsctl admin create <username>' to create an administrator.")
			} else {
				fmt.Println("Status: CONFIGURED")
				fmt.Printf("Administrator accounts: %d\n", adminCount)
				fmt.Printf("Total user accounts: %d\n", len(resp.Users))
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
	adminCmd.PersistentFlags().String("storage-path", "", "path to xkms storage (default: $XKMS_STORAGE_PATH or /var/lib/xkms)")

	// create flags
	adminCreateCmd.Flags().String("display-name", "", "admin display name (defaults to username)")
	adminCreateCmd.Flags().String("rp-id", "go-xkms", "relying party ID")
	adminCreateCmd.Flags().String("rp-name", "Go xKMS", "relying party name")
	adminCreateCmd.Flags().Duration("timeout", 30*time.Second, "timeout for user presence")
	adminCreateCmd.Flags().String("device", "", "specific FIDO2 device path to use")
	adminCreateCmd.Flags().Bool("user-verification", false, "require user verification (PIN)")

	// Authentication method flag (read at runtime via cmd.Flags().GetString("method"))
	adminCreateCmd.Flags().String("method", "fido2",
		"authentication method for admin enrollment (fido2, mtls)")

	// mTLS-specific flags
	adminCreateCmd.Flags().String("cert-file", "",
		"path to PEM certificate file for mTLS enrollment (alternative to --pkcs11-module)")
}

// Helper functions

func resolveStoragePath(storagePath string) string {
	if storagePath == "" {
		storagePath = os.Getenv("XKMS_STORAGE_PATH")
		if storagePath == "" {
			storagePath = "/var/lib/xkms"
		}
	}
	return storagePath
}

func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
