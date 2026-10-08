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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

// credentialSubmitRequest is the JSON request body for submitting a credential.
type credentialSubmitRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"` // base64-encoded
}

// credentialSubmitResponse is the JSON response for a successful credential submission.
type credentialSubmitResponse struct {
	Status string `json:"status"`
}

// credentialStrategyResponse is the JSON response for the credential strategy endpoint.
type credentialStrategyResponse struct {
	Strategy   string `json:"strategy"`
	AutoUnseal bool   `json:"auto_unseal"`
}

// credentialListResponse is the server's reply to a credential listing. It
// carries names only; values never cross the seal boundary.
type credentialListResponse struct {
	Names []string `json:"names"`
}

// credentialCmd is the top-level command for managing backend credentials.
var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage backend credentials",
	Long: `Manage backend credentials for the xkmsd server.

Backend credentials (such as PKCS#11 User PINs or cloud KMS credentials)
can be submitted to the server during the init ceremony or during
operational mode.

Subcommands:
  submit    Submit a backend credential
  list      List the names of the credentials the server holds
  strategy  Check the configured credential strategy

There is no separate "rotate" verb: rotation is submitting a new value for an
existing name, which "submit" already does. A credential value has no read
path out of the server, so nothing is lost by replacing one in place.`,
}

// credentialSubmitCmd submits a backend credential.
var credentialSubmitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Submit a backend credential",
	Long: `Submit a backend credential to the server.

The credential value is base64-encoded before being sent to the server.
mTLS authentication is required.

Example:
  xkmsctl credential submit --server https://xkmsd:8443 \
    --tls-cert so.pem --tls-key so-key.pem --tls-ca ca.pem \
    --name "pkcs11-user-pin" --value "user123"`,
	RunE: runCredentialSubmit,
}

// credentialListCmd lists the credentials the server already holds.
var credentialListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List the credentials the server holds",
	Long: `List the names of the backend credentials the server has been given.

Names only — a credential value has no read path out of the server. Use this
to see which credentials are still outstanding before a backend can unseal.
mTLS authentication is required.

Example:
  xkmsctl credential list --server https://xkmsd:8443 \
    --tls-cert so.pem --tls-key so-key.pem --tls-ca ca.pem`,
	RunE: runCredentialList,
}

// credentialStrategyCmd checks the credential strategy.
var credentialStrategyCmd = &cobra.Command{
	Use:   "strategy",
	Short: "Check the configured credential strategy",
	Long: `Query the server for the configured credential strategy.

mTLS authentication is required.

Example:
  xkmsctl credential strategy --server https://xkmsd:8443 \
    --tls-cert so.pem --tls-key so-key.pem --tls-ca ca.pem`,
	RunE: runCredentialStrategy,
}

// runCredentialSubmit submits a backend credential to the server.
func runCredentialSubmit(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	if cfg.Server == "" {
		return ErrServerRequired
	}

	fr := newFlagReader(cmd)
	name := fr.String("name")
	value := fr.String("value")
	if err := fr.Err(); err != nil {
		return err
	}
	if name == "" {
		return ErrCredentialNameRequired
	}
	if value == "" {
		return ErrCredentialValueRequired
	}

	httpClient, err := createServerHTTPClient(cfg, false)
	if err != nil {
		return err
	}

	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	printVerbose("Submitting credential: %s", name)

	url := cfg.Server + "/api/v1/credentials/submit"
	reqBody := credentialSubmitRequest{
		Name:  name,
		Value: base64.StdEncoding.EncodeToString([]byte(value)),
	}

	resp, err := doServerRequest(httpClient, http.MethodPost, url, reqBody)
	if err != nil {
		return err
	}

	body, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var result credentialSubmitResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return &WrappedDetailError{Sentinel: ErrHTTPRequestFailed, Detail: "failed to parse submit response", Err: err}
	}

	switch printer.format {
	case OutputFormatJSON:
		return printer.PrintJSON(map[string]interface{}{
			"status": result.Status,
			"name":   name,
		})
	default:
		return printer.PrintSuccess(fmt.Sprintf("Credential %q submitted successfully (status: %s)", name, result.Status))
	}
}

// runCredentialStrategy queries the server for the credential strategy.
func runCredentialStrategy(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	if cfg.Server == "" {
		return ErrServerRequired
	}

	httpClient, err := createServerHTTPClient(cfg, false)
	if err != nil {
		return err
	}

	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	printVerbose("Querying credential strategy")

	url := cfg.Server + "/api/v1/credentials/strategy"
	resp, err := doServerRequest(httpClient, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	body, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var result credentialStrategyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return &WrappedDetailError{Sentinel: ErrHTTPRequestFailed, Detail: "failed to parse strategy response", Err: err}
	}

	switch printer.format {
	case OutputFormatJSON:
		return printer.PrintJSON(map[string]interface{}{
			"strategy":    result.Strategy,
			"auto_unseal": result.AutoUnseal,
		})
	default:
		printer.printf("Credential Strategy:\n")
		printer.printf("  Strategy:    %s\n", result.Strategy)
		printer.printf("  Auto-unseal: %t\n", result.AutoUnseal)
		return printer.Err()
	}
}

// runCredentialList lists the names of the credentials the server holds.
func runCredentialList(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	if cfg.Server == "" {
		return ErrServerRequired
	}

	httpClient, err := createServerHTTPClient(cfg, false)
	if err != nil {
		return err
	}

	printer := NewPrinter(cfg.OutputFormat, os.Stdout)

	printVerbose("Listing submitted credentials")

	url := cfg.Server + "/api/v1/credentials"
	resp, err := doServerRequest(httpClient, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	body, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var result credentialListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return &WrappedDetailError{Sentinel: ErrHTTPRequestFailed, Detail: "failed to parse list response", Err: err}
	}

	switch printer.format {
	case OutputFormatJSON:
		return printer.PrintJSON(map[string]interface{}{"names": result.Names})
	default:
		if len(result.Names) == 0 {
			printer.printf("No credentials submitted.\n")
			return printer.Err()
		}
		printer.printf("Submitted credentials:\n")
		for _, name := range result.Names {
			printer.printf("  %s\n", name)
		}
		return printer.Err()
	}
}

func init() {
	// credential submit flags
	credentialSubmitCmd.Flags().String("name", "", "credential name (e.g., pkcs11-user-pin)")
	credentialSubmitCmd.Flags().String("value", "", "credential value")

	// Build subcommand tree
	credentialCmd.AddCommand(credentialSubmitCmd)
	credentialCmd.AddCommand(credentialStrategyCmd)
	credentialCmd.AddCommand(credentialListCmd)
}
