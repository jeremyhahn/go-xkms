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

// init_officer.go implements the Security Officer enrolment verbs — step 1 of
// go-qrdb's SO distribution model, without which an M-of-N ceremony cannot run
// at all.
//
// go-qrdb owns the officer registry, the CSR signing, and the thumbprint
// binding; go-xkms exposes them through pkg/init so xkmsd and every project
// composed on it offer the SAME flow. That is the point: a capability present
// in one project and absent from another is a gap, not a design choice.
//
// Nothing here returns share bytes. Registration assigns a share INDEX; the
// shares are sealed into memguard enclaves at initialization and released to
// each officer exactly once through the live claim handshake in init.go.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// =============================================================================
// Wire types (mirroring pkg/api/rest/handlers_init.go)
// =============================================================================

// officerRegisterRequest registers one officer from their CSR.
type officerRegisterRequest struct {
	Username          string `json:"username"`
	CSRPEM            string `json:"csr_pem"`
	AuthenticatorType string `json:"authenticator_type,omitempty"`
	AuthenticatorRef  string `json:"authenticator_ref,omitempty"`
}

// officerRegisterResponse carries the issued certificate and share index.
type officerRegisterResponse struct {
	CertPEM    string `json:"cert_pem"`
	ShareIndex int    `json:"share_index"`
}

// officerStatusEntry is the public view of one enrolled officer.
type officerStatusEntry struct {
	Username       string `json:"username"`
	CertThumbprint string `json:"cert_thumbprint,omitempty"`
	ShareIndex     int    `json:"share_index"`
	AuthFactor     string `json:"auth_factor,omitempty"`
}

// officerStatusResponse lists the enrolled officers.
type officerStatusResponse struct {
	Officers []officerStatusEntry `json:"officers"`
}

// enrollExternalOfficerRequest enrols an officer holding external key material.
type enrollExternalOfficerRequest struct {
	Username          string `json:"username"`
	CertPEM           string `json:"cert_pem,omitempty"`
	PubKeyPEM         string `json:"pubkey_pem,omitempty"`
	AuthenticatorType string `json:"authenticator_type,omitempty"`
	AuthenticatorRef  string `json:"authenticator_ref,omitempty"`
}

// =============================================================================
// Flags
// =============================================================================

var (
	officerUsername   string
	officerCSRFile    string
	officerOutput     string
	officerAuthType   string
	officerAuthRef    string
	officerCertFile   string
	officerPubKeyFile string
)

// =============================================================================
// Commands
// =============================================================================

// initOfficerCmd is the 'xkmsctl init officer' group.
var initOfficerCmd = &cobra.Command{
	Use:   "officer",
	Short: "Manage Security Officer enrolment",
	Long: `Manage Security Officer enrolment.

The admin submits each officer's CSR, the ceremony CA signs it, and the
officer is bound to the SHA-256 thumbprint of the issued certificate. The
response carries that certificate and the officer's share index — never
share bytes.

Officers generate their keypair on a security key or PIV smartcard, so the
private key never exists as a file.`,
}

// initOfficerRegisterCmd is 'xkmsctl init officer register'.
var initOfficerRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a Security Officer from their CSR",
	Long: `Register a Security Officer.

Example:
  xkmsctl init officer register \
      --username alice --csr alice.csr --output alice.crt`,
	RunE: runInitOfficerRegister,
}

// initOfficerStatusCmd is 'xkmsctl init officer status'.
var initOfficerStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show per-officer enrolment and claim status",
	Long: `Show per-officer enrolment and claim status.

Reports public metadata only. Share bytes are never returned.`,
	RunE: runInitOfficerStatus,
}

// initEnrollExternalOfficerCmd is 'xkmsctl init enroll-external-officer'.
var initEnrollExternalOfficerCmd = &cobra.Command{
	Use:   "enroll-external-officer",
	Short: "Enrol an officer whose key material is held externally",
	Long: `Enrol an officer holding externally-issued key material.

Use this when an officer already has a certificate from a corporate CA, or
a bare public key, rather than submitting a CSR for the ceremony CA to sign.

Example:
  xkmsctl init enroll-external-officer --username dan --cert dan.pem`,
	RunE: runInitEnrollExternalOfficer,
}

// runInitOfficerRegister executes 'init officer register'.
func runInitOfficerRegister(cmd *cobra.Command, args []string) error {
	if officerUsername == "" {
		return ErrUsernameRequired
	}
	if officerCSRFile == "" {
		return ErrCSRFileRequired
	}

	csrPEM, err := os.ReadFile(officerCSRFile)
	if err != nil {
		return &WrappedError{Sentinel: ErrCertFileRead, Err: err}
	}

	client, err := createInitHTTPClient(globalConfig, false)
	if err != nil {
		return err
	}

	resp, err := doInitRequest(client, http.MethodPost,
		fmt.Sprintf("%s/api/v1/init/officer/register", globalConfig.Server),
		officerRegisterRequest{
			Username:          officerUsername,
			CSRPEM:            string(csrPEM),
			AuthenticatorType: officerAuthType,
			AuthenticatorRef:  officerAuthRef,
		})
	if err != nil {
		return err
	}
	body, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var registered officerRegisterResponse
	if err := json.Unmarshal(body, &registered); err != nil {
		return &WrappedError{Sentinel: ErrJSONParseFailed, Err: err}
	}

	if officerOutput != "" {
		if err := os.WriteFile(officerOutput, []byte(registered.CertPEM), 0600); err != nil {
			return &WrappedError{Sentinel: ErrCertFileWrite, Err: err}
		}
		fmt.Printf("Officer %s registered (share index %d); certificate written to %s\n",
			officerUsername, registered.ShareIndex, officerOutput)
		return nil
	}
	if globalConfig.OutputFormat == "json" {
		return outputJSON(registered)
	}
	fmt.Printf("Officer:     %s\nShare Index: %d\n\n", officerUsername, registered.ShareIndex)
	fmt.Print(registered.CertPEM)
	return nil
}

// runInitOfficerStatus executes 'init officer status'.
func runInitOfficerStatus(cmd *cobra.Command, args []string) error {
	client, err := createInitHTTPClient(globalConfig, false)
	if err != nil {
		return err
	}

	resp, err := doInitRequest(client, http.MethodGet,
		fmt.Sprintf("%s/api/v1/init/officer/status", globalConfig.Server), nil)
	if err != nil {
		return err
	}
	body, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var status officerStatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		return &WrappedError{Sentinel: ErrJSONParseFailed, Err: err}
	}

	if globalConfig.OutputFormat == "json" {
		return outputJSON(status)
	}
	if len(status.Officers) == 0 {
		fmt.Println("No Security Officers enrolled.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tINDEX\tFACTOR\tTHUMBPRINT")
	for _, o := range status.Officers {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", o.Username, o.ShareIndex, o.AuthFactor, o.CertThumbprint)
	}
	return tw.Flush()
}

// runInitEnrollExternalOfficer executes 'init enroll-external-officer'.
func runInitEnrollExternalOfficer(cmd *cobra.Command, args []string) error {
	if officerUsername == "" {
		return ErrUsernameRequired
	}
	if (officerCertFile == "") == (officerPubKeyFile == "") {
		return ErrExternalOfficerMaterial
	}

	var certPEM, pubKeyPEM []byte
	var err error
	if officerCertFile != "" {
		if certPEM, err = os.ReadFile(officerCertFile); err != nil {
			return &WrappedError{Sentinel: ErrCertFileRead, Err: err}
		}
	} else {
		if pubKeyPEM, err = os.ReadFile(officerPubKeyFile); err != nil {
			return &WrappedError{Sentinel: ErrCertFileRead, Err: err}
		}
	}

	client, err := createInitHTTPClient(globalConfig, false)
	if err != nil {
		return err
	}

	resp, err := doInitRequest(client, http.MethodPost,
		fmt.Sprintf("%s/api/v1/init/enroll-external-officer", globalConfig.Server),
		enrollExternalOfficerRequest{
			Username:          officerUsername,
			CertPEM:           string(certPEM),
			PubKeyPEM:         string(pubKeyPEM),
			AuthenticatorType: officerAuthType,
			AuthenticatorRef:  officerAuthRef,
		})
	if err != nil {
		return err
	}
	body, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	if globalConfig.OutputFormat == "json" {
		fmt.Println(string(body))
		return nil
	}
	fmt.Printf("External officer %s enrolled.\n", officerUsername)
	return nil
}

func init() {
	initCmd.AddCommand(initOfficerCmd, initEnrollExternalOfficerCmd)
	initOfficerCmd.AddCommand(initOfficerRegisterCmd, initOfficerStatusCmd)

	initOfficerRegisterCmd.Flags().StringVar(&officerUsername, "username", "", "Officer username (required)")
	initOfficerRegisterCmd.Flags().StringVar(&officerCSRFile, "csr", "", "Path to the officer's PEM-encoded CSR (required)")
	initOfficerRegisterCmd.Flags().StringVar(&officerOutput, "output", "", "Output file for the issued certificate (default: stdout)")
	initOfficerRegisterCmd.Flags().StringVar(&officerAuthType, "auth-factor", "", "Authenticator backing the officer credential (mtls | webauthn | piv)")
	initOfficerRegisterCmd.Flags().StringVar(&officerAuthRef, "auth-ref", "", "Authenticator reference (security key or PIV slot identifier)")

	initEnrollExternalOfficerCmd.Flags().StringVar(&officerUsername, "username", "", "Officer username (required)")
	initEnrollExternalOfficerCmd.Flags().StringVar(&officerCertFile, "cert", "", "PEM-encoded certificate issued by an external CA")
	initEnrollExternalOfficerCmd.Flags().StringVar(&officerPubKeyFile, "pubkey", "", "PEM-encoded public key (admin-asserted trust)")
	initEnrollExternalOfficerCmd.Flags().StringVar(&officerAuthType, "auth-factor", "", "Authenticator backing the officer credential (mtls | webauthn | piv)")
	initEnrollExternalOfficerCmd.Flags().StringVar(&officerAuthRef, "auth-ref", "", "Authenticator reference")
}
