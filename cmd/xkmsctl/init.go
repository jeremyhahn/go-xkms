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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// initHTTPClientFactory is a test injection point for creating HTTP clients.
// When non-nil, createInitHTTPClient uses this factory instead of building
// a real TLS client, enabling tests to supply httptest.Server clients.
var initHTTPClientFactory func(cfg *Config) (*http.Client, error)

// initStatusResponse is the JSON response for the init ceremony status endpoint.
type initStatusResponse struct {
	State string `json:"state"`
}

// claimCertBeginRequest is the JSON request body for beginning a certificate claim.
type claimCertBeginRequest struct {
	Username string `json:"username"`
}

// claimCertBeginResponse is the JSON response for a successful claim-cert begin.
type claimCertBeginResponse struct {
	Nonce string `json:"nonce"`
}

// claimCertCompleteRequest is the JSON request body for completing a certificate
// claim. The server verifies Signature against the public key in the officer's
// pre-submitted CSR, so no public key travels on the wire.
type claimCertCompleteRequest struct {
	Username  string `json:"username"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// claimCertCompleteResponse is the JSON response for a successful claim-cert
// complete. Both fields carry PEM text, matching the server's
// ClaimCertCompleteResponse.
type claimCertCompleteResponse struct {
	CertPEM   string `json:"cert_pem"`
	CACertPEM string `json:"ca_cert_pem"`
}

// claimShareBeginRequest is the JSON request body for beginning a Shamir share
// claim. Share claim is a two round-trip challenge-response, mirroring
// claim-cert: the server binds the challenge to the caller's mTLS certificate
// thumbprint, which it derives from the TLS handshake -- no thumbprint is ever
// sent on the wire.
type claimShareBeginRequest struct {
	Username string `json:"username"`
}

// claimShareBeginResponse is the JSON response for a successful claim-share
// begin. Nonce is the hex-encoded challenge the officer must sign.
type claimShareBeginResponse struct {
	Nonce string `json:"nonce"`
}

// claimShareCompleteRequest is the JSON request body for completing a Shamir
// share claim. The server verifies Signature against the public key recorded
// for the officer at enrollment, so no public key travels on the wire.
type claimShareCompleteRequest struct {
	Username  string `json:"username"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// claimShareCompleteResponse is the JSON response for a successful share
// claim. Share is the raw JSON share document produced by the ceremony service.
type claimShareCompleteResponse struct {
	ShareIndex int             `json:"share_index"`
	Share      json.RawMessage `json:"share"`
}

// signCSRInitRequest is the JSON request body for signing a CSR during init.
type signCSRInitRequest struct {
	Username string `json:"username"`
	SOPin    string `json:"so_pin"`
	CSRPEM   string `json:"csr_pem"`
	Role     string `json:"role"`
}

// signCSRInitResponse is the JSON response for a successful init CSR signing.
type signCSRInitResponse struct {
	CertPEM string `json:"cert_pem"`
}

// serverErrorResponse is the structure of error responses from the server.
type serverErrorResponse struct {
	Error string `json:"error"`
}

var (
	// initCmd is the root command for the init ceremony.
	initCmd = &cobra.Command{
		Use:   "init",
		Short: "Manage the initialization ceremony",
	}

	// initStatusCmd queries the current ceremony state.
	initStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "Show the current ceremony state",
		RunE:  runInitStatus,
	}

	// claimCertCmd manages certificate claims.
	claimCertCmd = &cobra.Command{
		Use:   "claim-cert",
		Short: "Claim a server certificate",
		RunE:  runClaimCert,
	}

	// claimShareCmd manages share claims.
	claimShareCmd = &cobra.Command{
		Use:   "claim-share",
		Short: "Claim a threshold share",
		Long: `Claim the Shamir share assigned to an officer.

Share claim is a two round-trip challenge-response, exactly like claim-cert.
The officer presents the certificate claim-cert issued them as an mTLS client
certificate; the server matches its thumbprint against the officer's enrolment
record, issues a single-use nonce, and releases the share only after verifying
a signature over that nonce. Knowing an officer's username is not enough.`,
		RunE: runClaimShare,
	}

	// initSignCSRCmd signs a CSR during initialization with SO authorization.
	initSignCSRCmd = &cobra.Command{
		Use:   "sign-csr",
		Short: "Sign a CSR during initialization with SO authorization",
		Long: `Sign a Certificate Signing Request (CSR) during the initialization ceremony.

Requires SO PIN authorization and a valid role. The CSR is signed by the CA
and the resulting certificate is returned. The system must be in the enrolling
or operational state.

Supported roles: so, admin, operator, user, auditor, custodian`,
		RunE: runInitSignCSR,
	}
)

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.AddCommand(initStatusCmd, claimCertCmd, claimShareCmd, initSignCSRCmd)

	claimCertCmd.Flags().StringVar(&claimCertUsername, "username", "", "Username (required)")
	claimCertCmd.Flags().StringVar(&claimCertKeyFile, "key", "", "PEM-encoded private key matching the submitted CSR (required)")
	claimCertCmd.Flags().StringVar(&claimCertSpkiPin, "spki-pin", "", "SPKI SHA-256 pin for server (required)")
	claimCertCmd.Flags().StringVar(&claimCertOutput, "output", "", "Output file for the issued certificate (default: stdout)")
	claimCertCmd.Flags().StringVar(&claimCertCAOutput, "ca-output", "", "Output file for the CA bundle returned with the certificate")

	claimShareCmd.Flags().StringVar(&claimShareUsername, "username", "", "Username (required)")
	claimShareCmd.Flags().StringVar(&claimShareCertFile, "cert", "", "PEM-encoded officer certificate issued by claim-cert (required)")
	claimShareCmd.Flags().StringVar(&claimShareKeyFile, "key", "", "PEM-encoded private key matching the officer certificate (required)")
	claimShareCmd.Flags().StringVar(&claimShareCAFile, "ca-cert", "", "PEM-encoded CA bundle used to verify the server (defaults to the SPKI pin)")
	claimShareCmd.Flags().StringVar(&claimShareSpkiPin, "spki-pin", "", "SPKI SHA-256 pin for server (required)")
	claimShareCmd.Flags().StringVar(&claimShareOutput, "output", "", "Output file for share")

	initSignCSRCmd.Flags().StringVar(&signCSRUsername, "username", "", "Username of the requesting officer (required)")
	initSignCSRCmd.Flags().StringVar(&signCSRFile, "csr", "", "Path to PEM-encoded CSR file (required)")
	initSignCSRCmd.Flags().StringVar(&signCSRRole, "role", "", "Role for the certificate: so, admin, operator, user, auditor, custodian (required)")
	initSignCSRCmd.Flags().StringVar(&signCSROutput, "output", "", "Output file for signed certificate (default: stdout)")
}

var (
	claimCertUsername  string
	claimCertKeyFile   string
	claimCertSpkiPin   string
	claimCertOutput    string
	claimCertCAOutput  string
	claimShareUsername string
	claimShareCertFile string
	claimShareKeyFile  string
	claimShareCAFile   string
	claimShareSpkiPin  string
	claimShareOutput   string
	signCSRUsername    string
	signCSRFile        string
	signCSRRole        string
	signCSROutput      string
)

// signNonce signs a nonce with the provided private key.
func signNonce(nonce []byte, key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		hash := sha256.Sum256(nonce)
		sig, err := ecdsa.SignASN1(rand.Reader, k, hash[:])
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrNonceSignFailed, Err: err}
		}
		return sig, nil

	case *rsa.PrivateKey:
		hash := sha256.Sum256(nonce)
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, hash[:])
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrNonceSignFailed, Err: err}
		}
		return sig, nil

	case ed25519.PrivateKey:
		sig := ed25519.Sign(k, nonce)
		return sig, nil

	default:
		return nil, &WrappedDetailError{Sentinel: ErrUnsupportedKeyType, Detail: fmt.Sprintf("%T", key)}
	}
}

// checkServerResponse reads the response body and checks for non-2xx status codes.
// On success, it returns the response body bytes. On failure, it returns a typed error.
func checkServerResponse(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &WrappedDetailError{Sentinel: ErrHTTPRequestFailed, Detail: "failed to read response body", Err: err}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return respBody, nil
	}

	// Try to extract a server error message
	var serverErr serverErrorResponse
	if json.Unmarshal(respBody, &serverErr) == nil && serverErr.Error != "" {
		return nil, &WrappedDetailError{Sentinel: ErrServerResponseError, Detail: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, serverErr.Error)}
	}

	return nil, &WrappedDetailError{Sentinel: ErrServerResponseError, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// createInitHTTPClient creates the appropriate HTTP client based on flags.
// For claim-cert, it uses SPKI-pinned TLS. For other init commands, it uses mTLS.
func createInitHTTPClient(cfg *Config, requireSPKI bool) (*http.Client, error) {
	// Allow test injection
	if initHTTPClientFactory != nil {
		return initHTTPClientFactory(cfg)
	}

	if requireSPKI {
		if cfg.SPKIPin == "" {
			return nil, ErrSPKIPinRequired
		}
		return newSPKIHTTPClient(cfg.SPKIPin), nil
	}

	// mTLS client
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return nil, &WrappedDetailError{Sentinel: ErrCertFileRead, Detail: "--tls-cert and --tls-key are required for mTLS"}
	}
	return newMTLSHTTPClient(cfg.TLSCert, cfg.TLSKey, cfg.TLSCACert)
}

// runInitStatus queries the server for the current init ceremony state.
func runInitStatus(cmd *cobra.Command, args []string) error {
	client, err := createInitHTTPClient(globalConfig, false)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/api/v1/init/status", globalConfig.Server)
	resp, err := client.Get(endpoint)
	if err != nil {
		return &WrappedError{Sentinel: ErrHTTPRequestFailed, Err: err}
	}

	respBody, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var status initStatusResponse
	if err := json.Unmarshal(respBody, &status); err != nil {
		return &WrappedError{Sentinel: ErrJSONParseFailed, Err: err}
	}

	if globalConfig.OutputFormat == "json" {
		return outputJSON(status)
	}
	fmt.Printf("State: %s\n", status.State)
	return nil
}

// loadCSRPrivateKey reads a PEM-encoded private key from path. The key must be
// the one whose public half was submitted in the officer's CSR: the server
// verifies the challenge signature against the CSR public key, so any other key
// fails verification. PKCS#8, SEC 1 ("EC PRIVATE KEY") and PKCS#1
// ("RSA PRIVATE KEY") encodings are accepted.
func loadCSRPrivateKey(path string) (crypto.PrivateKey, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrPrivateKeyRead, Err: err}
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, &WrappedDetailError{Sentinel: ErrPrivateKeyParse, Detail: "no PEM block found in " + path}
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, &WrappedDetailError{Sentinel: ErrPrivateKeyParse, Detail: path, Err: err}
	}
	return key, nil
}

// writePEMOutput writes PEM text to path when path is non-empty and reports
// the destination, otherwise prints the text to stdout.
func writePEMOutput(path, label, pemText string, sentinel error) error {
	if path == "" {
		fmt.Print(pemText)
		return nil
	}
	if err := os.WriteFile(path, []byte(pemText), 0600); err != nil {
		return &WrappedError{Sentinel: sentinel, Err: err}
	}
	fmt.Printf("%s written to %s\n", label, path)
	return nil
}

// runClaimCert claims an officer's enrollment certificate using the ceremony's
// two-step challenge-response protocol. The nonce returned by
// /api/v1/init/claim-cert/begin is signed with the private key matching the
// officer's pre-submitted CSR; the server verifies that signature against the
// CSR public key before releasing the certificate.
func runClaimCert(cmd *cobra.Command, args []string) error {
	// Validate required arguments
	if claimCertUsername == "" {
		return ErrUsernameRequired
	}
	if claimCertKeyFile == "" {
		return ErrKeyFileRequired
	}
	if claimCertSpkiPin == "" {
		return ErrSPKIPinRequired
	}

	// The challenge must be signed with the CSR key, so load it before any
	// network round trip: a bad key path should not consume a server nonce.
	privKey, err := loadCSRPrivateKey(claimCertKeyFile)
	if err != nil {
		return err
	}

	// Create a temporary config with SPKI pin for claim-cert
	certConfig := &Config{
		Server:       globalConfig.Server,
		OutputFormat: globalConfig.OutputFormat,
		SPKIPin:      claimCertSpkiPin,
	}

	client, err := createInitHTTPClient(certConfig, true)
	if err != nil {
		return err
	}

	// Step 1: Begin the challenge
	beginReq := claimCertBeginRequest{Username: claimCertUsername}
	beginBody, err := json.Marshal(beginReq)
	if err != nil {
		return &WrappedError{Sentinel: ErrJSONMarshalFailed, Err: err}
	}

	endpoint := fmt.Sprintf("%s/api/v1/init/claim-cert/begin", globalConfig.Server)
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(beginBody))
	if err != nil {
		return &WrappedError{Sentinel: ErrHTTPRequestFailed, Err: err}
	}

	respBody, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var beginResp claimCertBeginResponse
	if err := json.Unmarshal(respBody, &beginResp); err != nil {
		return &WrappedError{Sentinel: ErrJSONParseFailed, Err: err}
	}

	// Step 2: Sign the nonce with the CSR private key.
	nonce, err := hex.DecodeString(beginResp.Nonce)
	if err != nil {
		return &WrappedError{Sentinel: ErrNonceDecode, Err: err}
	}

	sig, err := signNonce(nonce, privKey)
	if err != nil {
		return err
	}

	// Step 3: Complete the challenge
	completeReq := claimCertCompleteRequest{
		Username:  claimCertUsername,
		Nonce:     beginResp.Nonce,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	completeBody, err := json.Marshal(completeReq)
	if err != nil {
		return &WrappedError{Sentinel: ErrJSONMarshalFailed, Err: err}
	}

	completeEndpoint := fmt.Sprintf("%s/api/v1/init/claim-cert/complete", globalConfig.Server)
	completeResp, err := client.Post(completeEndpoint, "application/json", bytes.NewReader(completeBody))
	if err != nil {
		return &WrappedError{Sentinel: ErrHTTPRequestFailed, Err: err}
	}

	completeRespBody, err := checkServerResponse(completeResp)
	if err != nil {
		return err
	}

	var claimed claimCertCompleteResponse
	if err := json.Unmarshal(completeRespBody, &claimed); err != nil {
		return &WrappedError{Sentinel: ErrJSONParseFailed, Err: err}
	}

	if err := writePEMOutput(claimCertOutput, "Certificate", claimed.CertPEM, ErrCertFileWrite); err != nil {
		return err
	}

	// The CA bundle is only persisted when the operator asks for it; printing
	// it alongside the certificate would corrupt a redirected certificate file.
	if claimCertCAOutput != "" {
		if err := writePEMOutput(claimCertCAOutput, "CA bundle", claimed.CACertPEM, ErrCertFileWrite); err != nil {
			return err
		}
	}

	return nil
}

// runClaimShare claims an officer's Shamir share over the ceremony's two-step
// challenge-response protocol, mirroring runClaimCert. The officer's
// certificate is presented as an mTLS client certificate: the server derives
// its thumbprint from the TLS handshake and matches it against the officer's
// enrolment record before issuing the nonce at
// /api/v1/init/claim-share/begin and again before releasing the share at
// /api/v1/init/claim-share/complete. The nonce is signed with the private key
// matching that certificate. The share is released exactly once per officer.
func runClaimShare(cmd *cobra.Command, args []string) error {
	// Validate required arguments.
	if claimShareUsername == "" {
		return ErrUsernameRequired
	}
	if claimShareCertFile == "" {
		return ErrCertFileRequired
	}
	if claimShareKeyFile == "" {
		return ErrKeyFileRequired
	}
	if claimShareSpkiPin == "" {
		return ErrSPKIPinRequired
	}

	// The challenge must be signed with the key matching the officer
	// certificate, so load it before any network round trip: a bad key path
	// should not consume a server nonce.
	privKey, err := loadCSRPrivateKey(claimShareKeyFile)
	if err != nil {
		return err
	}

	// The share endpoints require a client certificate, so the transport is
	// mTLS with the server still pinned by SPKI: the officer has the CA
	// bundle only after claim-cert, and pinning is what the ceremony
	// published.
	shareConfig := &Config{
		Server:       globalConfig.Server,
		OutputFormat: globalConfig.OutputFormat,
		SPKIPin:      claimShareSpkiPin,
		TLSCert:      claimShareCertFile,
		TLSKey:       claimShareKeyFile,
		TLSCACert:    claimShareCAFile,
	}

	client, err := createClaimShareHTTPClient(shareConfig)
	if err != nil {
		return err
	}

	// Step 1: Begin the challenge.
	beginBody, err := json.Marshal(claimShareBeginRequest{Username: claimShareUsername})
	if err != nil {
		return &WrappedError{Sentinel: ErrJSONMarshalFailed, Err: err}
	}

	endpoint := fmt.Sprintf("%s/api/v1/init/claim-share/begin", globalConfig.Server)
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(beginBody))
	if err != nil {
		return &WrappedError{Sentinel: ErrHTTPRequestFailed, Err: err}
	}

	respBody, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var beginResp claimShareBeginResponse
	if err := json.Unmarshal(respBody, &beginResp); err != nil {
		return &WrappedError{Sentinel: ErrJSONParseFailed, Err: err}
	}

	// Step 2: Sign the nonce with the officer's private key.
	nonce, err := hex.DecodeString(beginResp.Nonce)
	if err != nil {
		return &WrappedError{Sentinel: ErrNonceDecode, Err: err}
	}

	sig, err := signNonce(nonce, privKey)
	if err != nil {
		return err
	}

	// Step 3: Complete the challenge and receive the share.
	completeBody, err := json.Marshal(claimShareCompleteRequest{
		Username:  claimShareUsername,
		Nonce:     beginResp.Nonce,
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return &WrappedError{Sentinel: ErrJSONMarshalFailed, Err: err}
	}

	completeEndpoint := fmt.Sprintf("%s/api/v1/init/claim-share/complete", globalConfig.Server)
	completeResp, err := client.Post(completeEndpoint, "application/json", bytes.NewReader(completeBody))
	if err != nil {
		return &WrappedError{Sentinel: ErrHTTPRequestFailed, Err: err}
	}

	completeRespBody, err := checkServerResponse(completeResp)
	if err != nil {
		return err
	}

	var claimed claimShareCompleteResponse
	if err := json.Unmarshal(completeRespBody, &claimed); err != nil {
		return &WrappedError{Sentinel: ErrJSONParseFailed, Err: err}
	}
	if len(claimed.Share) == 0 {
		return ErrShareMissingInResponse
	}

	if claimShareOutput != "" {
		if err := os.WriteFile(claimShareOutput, claimed.Share, 0600); err != nil {
			return &WrappedError{Sentinel: ErrShareFileWrite, Err: err}
		}
		fmt.Printf("Share written to %s\n", claimShareOutput)
		return nil
	}

	fmt.Println(string(claimed.Share))
	return nil
}

// createClaimShareHTTPClient builds the client the share-claim handshake
// needs: the officer certificate is presented for mTLS while the server is
// still verified by SPKI pin (or by an explicit CA bundle when the officer
// saved one from claim-cert). Test injection goes through the same factory
// hook every other init command uses.
func createClaimShareHTTPClient(cfg *Config) (*http.Client, error) {
	if initHTTPClientFactory != nil {
		return initHTTPClientFactory(cfg)
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCertFileRead, Err: err}
	}

	tlsConfig := xkmssdk.NewSPKIPinnedTLSConfig(cfg.SPKIPin)
	tlsConfig.Certificates = []tls.Certificate{cert}

	if cfg.TLSCACert != "" {
		caPEM, readErr := os.ReadFile(cfg.TLSCACert)
		if readErr != nil {
			return nil, &WrappedError{Sentinel: ErrCertFileRead, Err: readErr}
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, ErrInvalidCA
		}
		tlsConfig.RootCAs = caPool
	}

	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}, nil
}

// runInitSignCSR handles CSR signing during initialization with SO authorization.
// It reads the CSR file, sends it to the server with the SO PIN and role, and
// writes the signed certificate to the output file or stdout.
func runInitSignCSR(cmd *cobra.Command, args []string) error {
	// Validate required flags.
	if signCSRUsername == "" {
		return ErrUsernameRequired
	}
	if signCSRFile == "" {
		return ErrCSRFileRequired
	}
	if signCSRRole == "" {
		return ErrRoleRequired
	}
	if globalConfig.SOPin == "" {
		return ErrSOPinRequired
	}

	// Read the CSR file.
	csrPEM, err := os.ReadFile(signCSRFile)
	if err != nil {
		return &WrappedError{Sentinel: ErrCertFileRead, Err: err}
	}

	// Create the HTTP client (mTLS for authenticated operations).
	client, err := createInitHTTPClient(globalConfig, false)
	if err != nil {
		return err
	}

	// Build the request.
	reqBody := signCSRInitRequest{
		Username: signCSRUsername,
		SOPin:    globalConfig.SOPin,
		CSRPEM:   string(csrPEM),
		Role:     signCSRRole,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return &WrappedError{Sentinel: ErrJSONMarshalFailed, Err: err}
	}

	endpoint := fmt.Sprintf("%s/api/v1/init/sign-csr", globalConfig.Server)
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return &WrappedError{Sentinel: ErrHTTPRequestFailed, Err: err}
	}

	respBody, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var signResp signCSRInitResponse
	if err := json.Unmarshal(respBody, &signResp); err != nil {
		return &WrappedError{Sentinel: ErrJSONParseFailed, Err: err}
	}

	// Write the signed certificate.
	if signCSROutput != "" {
		if err := os.WriteFile(signCSROutput, []byte(signResp.CertPEM), 0600); err != nil {
			return &WrappedError{Sentinel: ErrCertFileWrite, Err: err}
		}
		fmt.Printf("Signed certificate written to %s\n", signCSROutput)
	} else {
		if globalConfig.OutputFormat == "json" {
			return outputJSON(signResp)
		}
		fmt.Print(signResp.CertPEM)
	}

	return nil
}

// newSPKIHTTPClient creates an HTTP client that pins the server's SPKI.
func newSPKIHTTPClient(pin string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: xkmssdk.NewSPKIPinnedTLSConfig(pin),
		},
	}
}

// newMTLSHTTPClient creates an HTTP client that uses mTLS.
func newMTLSHTTPClient(certFile, keyFile, caFile string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCertFileRead, Err: err}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// Load CA certificate if provided
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrCertFileRead, Err: err}
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, ErrInvalidCA
		}

		tlsConfig.RootCAs = caPool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{Transport: transport}, nil
}

// doInitRequest is a helper for making init ceremony requests.
func doInitRequest(client *http.Client, method, url string, body interface{}) (*http.Response, error) {
	return doInitRequestContext(context.Background(), client, method, url, body)
}

// doInitRequestContext is doInitRequest with a caller-supplied context, so a
// cancelled command stops its in-flight request instead of waiting out the
// transport timeout.
func doInitRequestContext(ctx context.Context, client *http.Client, method, url string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrJSONMarshalFailed, Err: err}
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrHTTPRequestFailed, Err: err}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return client.Do(req)
}

// outputJSON marshals v as indented JSON and writes it to stdout.
func outputJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return &WrappedError{Sentinel: ErrJSONMarshalFailed, Err: err}
	}
	fmt.Println(string(data))
	return nil
}
