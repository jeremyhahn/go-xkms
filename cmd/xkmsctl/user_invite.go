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
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	webauthnclient "github.com/jeremyhahn/go-xkms/sdk/go/webauthnclient"
	"github.com/spf13/cobra"
)

// parseInviteReference resolves the tenant ID and token "user invite redeem"
// needs from its positional argument and --tenant-id flag. The argument may
// be the full invitation link printInvite prints (which carries both,
// buildInviteURL-shaped: ".../invite/<tenant>/<token>") or a bare token,
// in which case --tenant-id is required.
func parseInviteReference(arg, tenantFlag string) (tenantID, token string, err error) {
	arg = strings.TrimSpace(arg)
	const marker = "/invite/"
	if idx := strings.LastIndex(arg, marker); idx != -1 {
		rest := arg[idx+len(marker):]
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", ErrInviteReferenceInvalid
		}
		tenantID, errTenant := url.PathUnescape(parts[0])
		if errTenant != nil {
			return "", "", ErrInviteReferenceInvalid
		}
		token, errToken := url.PathUnescape(parts[1])
		if errToken != nil {
			return "", "", ErrInviteReferenceInvalid
		}
		return tenantID, token, nil
	}
	if arg == "" || tenantFlag == "" {
		return "", "", ErrInviteReferenceInvalid
	}
	return tenantFlag, arg, nil
}

// redeemInviteFIDO2 drives the invite-authorized WebAuthn registration
// ceremony: BeginInviteRegistration opens it, a local CTAP2 authenticator
// produces the attestation, and FinishInviteRegistration binds the
// credential, activates the account, and redeems the invitation, in that
// safe order (go-xkms#1294 part B).
func redeemInviteFIDO2(
	ctx context.Context,
	cl client.Client,
	printer *Printer,
	tenantID, token string,
	adapter webauthnclient.AuthenticatorAdapter,
	origin string,
	pin *secure.Secret,
) (*client.FinishInviteRegistrationResponse, error) {
	beginResp, err := cl.BeginInviteRegistration(ctx, &client.BeginInviteRegistrationRequest{
		TenantID: tenantID,
		Token:    token,
	})
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrBeginInviteRegistrationFailed, Err: err}
	}

	if err := printer.PrintPrompt("\nPlease touch your security key to activate the account..."); err != nil {
		return nil, err
	}

	attestation, err := adapter.MakeCredential(ctx, &webauthnclient.CeremonyOptions{
		OptionsJSON: []byte(beginResp.OptionsJSON),
		Origin:      origin,
		PIN:         pin,
	})
	if err != nil {
		return nil, ceremonyFailure(ErrFinishInviteRegistrationFailed, pin, err)
	}

	finishResp, err := cl.FinishInviteRegistration(ctx, &client.FinishInviteRegistrationRequest{
		TenantID:        tenantID,
		Token:           token,
		SessionID:       beginResp.SessionID,
		AttestationJSON: string(attestation),
	})
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrFinishInviteRegistrationFailed, Err: err}
	}
	return finishResp, nil
}

// userInviteCmd groups the invitation-redemption subcommands.
var userInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Redeem account-activation invitations",
	Long: `Commands for redeeming the one-time activation invitations
'xkmsctl user register' and 'xkmsctl admin create' mint.`,
}

// userInviteRedeemCmd redeems an activation invitation from the CLI, over
// the default transport, enrolling the invitee's first credential and
// activating the account (go-xkms#1294 part B). This replaces the
// REST-curl workaround: invite redemption is now a capability on every
// transport, xkmsctl's default transport included.
var userInviteRedeemCmd = &cobra.Command{
	Use:   "redeem <invite-link-or-token>",
	Short: "Redeem an account-activation invitation",
	Long: `Redeem a one-time activation invitation, enrolling the invitee's
first credential and activating the account.

Accepts either the full invitation link 'xkmsctl user register' /
'xkmsctl admin create' printed (which carries the tenant and token), or a
bare token with --tenant-id.

FIDO2 (the default, --method fido2) drives the local CTAP2 security key
through the registration ceremony, the same way 'xkmsctl user login' drives
it through authentication.

PIV (--method piv) activates the account with a PIV certificate instead:
provide --piv-cert-file with the certificate PEM to present.

` + pinUsage + `

Examples:
  xkmsctl user invite redeem "https://kms.example.com/ui/#/invite/acme/b64url-secret"
  xkmsctl user invite redeem b64url-secret --tenant-id acme
  xkmsctl user invite redeem b64url-secret --tenant-id acme --method piv --piv-cert-file piv-cert.pem`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		tenantFlag := fr.String("tenant-id")
		method := fr.String("method")
		devicePath := fr.String("device")
		requireUV := fr.Bool("user-verification")
		timeout := fr.Duration("timeout")
		pivCertFile := fr.String("piv-cert-file")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if method == "" {
			method = "fido2"
		}
		if method != "fido2" && method != "piv" {
			handleError(ErrInviteMethodInvalid)
			return
		}

		tenantID, token, err := parseInviteReference(args[0], tenantFlag)
		if err != nil {
			handleError(err)
			return
		}

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

		inviteResp, err := cl.GetInvite(ctx, &client.GetInviteRequest{TenantID: tenantID, Token: token})
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrGetInviteFailed, Err: err})
			return
		}
		if err := printer.PrintMessage(fmt.Sprintf("Invitation for %s (expires %s)", inviteResp.Email, inviteResp.ExpiresAt.Format(time.RFC3339))); err != nil {
			handleError(err)
			return
		}

		var userID uint64
		switch method {
		case "piv":
			if pivCertFile == "" {
				handleError(ErrPIVCertFileRequired)
				return
			}
			certPEM, err := os.ReadFile(filepath.Clean(pivCertFile))
			if err != nil {
				handleError(&CertFileReadError{Path: pivCertFile, Err: err})
				return
			}
			activateResp, err := cl.ActivateInvitePIV(ctx, &client.ActivateInvitePIVRequest{
				TenantID: tenantID,
				Token:    token,
				CertPEM:  string(certPEM),
			})
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrActivateInvitePIVFailed, Err: err})
				return
			}
			userID = activateResp.UserID

		default: // "fido2"
			origin, err := resolveWebAuthnOrigin(cmd, cfg.Server)
			if err != nil {
				handleError(err)
				return
			}
			pin, err := resolvePINInput(cmd.Context(), cmd)
			if err != nil {
				handleError(err)
				return
			}

			fidoConfig := fido2.DefaultConfig
			fidoConfig.DevicePath = devicePath
			fidoConfig.RequireUserVerification = requireUV
			fidoConfig.UserPresenceTimeout = timeout
			enumerator := fido2.NewDefaultEnumerator()

			adapter, err := webauthnclient.NewHardwareAdapter(&fidoConfig, enumerator)
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrCreateFIDO2HandlerFailed, Err: err})
				return
			}
			defer closeQuietly(adapter)

			finishResp, err := redeemInviteFIDO2(ctx, cl, printer, tenantID, token, adapter, origin, pin)
			if err != nil {
				handleError(err)
				return
			}
			userID = finishResp.UserID
		}

		if cfg.OutputFormat == "json" {
			if err := printer.PrintJSON(map[string]interface{}{
				"success": true,
				"user_id": fmt.Sprintf("%d", userID),
				"method":  method,
			}); err != nil {
				handleError(err)
			}
			return
		}
		if err := printer.PrintSuccess("Account activated."); err != nil {
			handleError(err)
			return
		}
		fmt.Printf("User ID: %d\n", userID)
	},
}

func init() {
	userCmd.AddCommand(userInviteCmd)
	userInviteCmd.AddCommand(userInviteRedeemCmd)

	userInviteRedeemCmd.Flags().String("tenant-id", "", "tenant ID (required with a bare token; not needed with the full invitation link)")
	userInviteRedeemCmd.Flags().String("method", "fido2", "activation method: fido2 or piv")
	userInviteRedeemCmd.Flags().String("device", "", "specific FIDO2 device path to use (--method fido2)")
	userInviteRedeemCmd.Flags().Bool("user-verification", false, "require user verification / PIN (--method fido2)")
	userInviteRedeemCmd.Flags().Duration("timeout", 30*time.Second, "timeout for user presence (--method fido2)")
	userInviteRedeemCmd.Flags().String("piv-cert-file", "", "PIV certificate PEM file to present (--method piv)")
	addPINFlags(userInviteRedeemCmd)
	addOriginFlag(userInviteRedeemCmd)
}
