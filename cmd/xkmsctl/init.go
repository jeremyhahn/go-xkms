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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"
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

// claimCertCompleteRequest is the JSON request body for completing a certificate claim.
type claimCertCompleteRequest struct {
	Username  string `json:"username"`
	Nonce     string `json:"nonce"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// claimCertCompleteResponse is the JSON response for a successful claim-cert complete.
type claimCertCompleteResponse struct {
	Certificate string `json:"certificate"`
}

// claimShareBeginRequest is the JSON request body for beginning a share claim.
type claimShareBeginRequest struct {
	Username string `json:"username"`
}

// claimShareBeginResponse is the JSON response for a successful claim-share begin.
type claimShareBeginResponse struct {
	Nonce string `json:"nonce"`
}

// claimShareCompleteRequest is the JSON request body for completing a share claim.
type claimShareCompleteRequest struct {
	Username  string `json:"username"`
	Nonce     string `json:"nonce"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// claimShareCompleteResponse is the JSON response for a successful claim-share complete.
type claimShareCompleteResponse struct {
	Share      string `json:"share"`
	ShareIndex int    `json:"share_index"`
	Threshold  int    `json:"threshold"`
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
		RunE:  runClaimShare,
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
	claimCertCmd.Flags().StringVar(&claimCertSpkiPin, "spki-pin", "", "SPKI SHA-256 pin for server (required)")
	claimCertCmd.Flags().StringVar(&claimCertOutput, "output", "", "Output file for certificate")

	claimShareCmd.Flags().StringVar(&claimShareUsername, "username", "", "Username (required)")
	claimShareCmd.Flags().StringVar(&claimShareSpkiPin, "spki-pin", "", "SPKI SHA-256 pin for server (required)")
	claimShareCmd.Flags().StringVar(&claimShareOutput, "output", "", "Output file for share")

	initSignCSRCmd.Flags().StringVar(&signCSRUsername, "username", "", "Username of the requesting officer (required)")
	initSignCSRCmd.Flags().StringVar(&signCSRFile, "csr", "", "Path to PEM-encoded CSR file (required)")
	initSignCSRCmd.Flags().StringVar(&signCSRRole, "role", "", "Role for the certificate: so, admin, operator, user, auditor, custodian (required)")
	initSignCSRCmd.Flags().StringVar(&signCSROutput, "output", "", "Output file for signed certificate (default: stdout)")
}

var (
	claimCertUsername  string
	claimCertSpkiPin   string
	claimCertOutput    string
	claimShareUsername string
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
			return nil, fmt.Errorf("%w: %w", ErrNonceSignFailed, err)
		}
		return sig, nil

	case *rsa.PrivateKey:
		hash := sha256.Sum256(nonce)
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, hash[:])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNonceSignFailed, err)
		}
		return sig, nil

	case ed25519.PrivateKey:
		sig := ed25519.Sign(k, nonce)
		return sig, nil

	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, key)
	}
}

// checkServerResponse reads the response body and checks for non-2xx status codes.
// On success, it returns the response body bytes. On failure, it returns a typed error.
func checkServerResponse(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response body: %w", ErrHTTPRequestFailed, err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return respBody, nil
	}

	// Try to extract a server error message
	var serverErr serverErrorResponse
	if json.Unmarshal(respBody, &serverErr) == nil && serverErr.Error != "" {
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrServerResponseError, resp.StatusCode, serverErr.Error)
	}

	return nil, fmt.Errorf("%w: HTTP %d", ErrServerResponseError, resp.StatusCode)
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
		return nil, fmt.Errorf("%w: --tls-cert and --tls-key are required for mTLS", ErrCertFileRead)
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
		return fmt.Errorf("%w: %w", ErrHTTPRequestFailed, err)
	}

	respBody, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var status initStatusResponse
	if err := json.Unmarshal(respBody, &status); err != nil {
		return fmt.Errorf("%w: %w", ErrJSONParseFailed, err)
	}

	if globalConfig.OutputFormat == "json" {
		return outputJSON(status)
	}
	fmt.Printf("State: %s\n", status.State)
	return nil
}

// runClaimCert handles certificate claims with full challenge-response protocol.
func runClaimCert(cmd *cobra.Command, args []string) error {
	// Validate required arguments
	if claimCertUsername == "" {
		return ErrUsernameRequired
	}
	if claimCertSpkiPin == "" {
		return ErrSPKIPinRequired
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
		return fmt.Errorf("%w: %w", ErrJSONMarshalFailed, err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/init/claim-cert/begin", globalConfig.Server)
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(beginBody))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHTTPRequestFailed, err)
	}

	respBody, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var beginResp claimCertBeginResponse
	if err := json.Unmarshal(respBody, &beginResp); err != nil {
		return fmt.Errorf("%w: %w", ErrJSONParseFailed, err)
	}

	// Step 2: Generate keypair and sign nonce
	nonce, err := hex.DecodeString(beginResp.Nonce)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNonceDecode, err)
	}

	pubKey, privKey, err := generateNoiseKeyPair()
	if err != nil {
		return err
	}

	sig, err := signNonce(nonce, privKey)
	if err != nil {
		return err
	}

	// Step 3: Complete the challenge
	completeReq := claimCertCompleteRequest{
		Username:  claimCertUsername,
		Nonce:     beginResp.Nonce,
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	completeBody, err := json.Marshal(completeReq)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJSONMarshalFailed, err)
	}

	completeEndpoint := fmt.Sprintf("%s/api/v1/init/claim-cert/complete", globalConfig.Server)
	completeResp, err := client.Post(completeEndpoint, "application/json", bytes.NewReader(completeBody))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHTTPRequestFailed, err)
	}

	completeRespBody, err := checkServerResponse(completeResp)
	if err != nil {
		return err
	}

	var completeResp2 claimCertCompleteResponse
	if err := json.Unmarshal(completeRespBody, &completeResp2); err != nil {
		return fmt.Errorf("%w: %w", ErrJSONParseFailed, err)
	}

	// Write certificate to output file if specified, otherwise print to stdout
	certPEM, err := base64.StdEncoding.DecodeString(completeResp2.Certificate)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBase64Decode, err)
	}

	if claimCertOutput != "" {
		if err := os.WriteFile(claimCertOutput, certPEM, 0600); err != nil {
			return fmt.Errorf("%w: %w", ErrCertFileWrite, err)
		}
		fmt.Printf("Certificate written to %s\n", claimCertOutput)
	} else {
		fmt.Print(string(certPEM))
	}

	return nil
}

// runClaimShare handles share claims with full challenge-response protocol.
func runClaimShare(cmd *cobra.Command, args []string) error {
	// Validate required arguments
	if claimShareUsername == "" {
		return ErrUsernameRequired
	}
	if claimShareSpkiPin == "" {
		return ErrSPKIPinRequired
	}

	// Create a temporary config with SPKI pin for claim-share
	shareConfig := &Config{
		Server:       globalConfig.Server,
		OutputFormat: globalConfig.OutputFormat,
		SPKIPin:      claimShareSpkiPin,
	}

	client, err := createInitHTTPClient(shareConfig, true)
	if err != nil {
		return err
	}

	// Step 1: Begin the challenge
	beginReq := claimShareBeginRequest{Username: claimShareUsername}
	beginBody, err := json.Marshal(beginReq)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJSONMarshalFailed, err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/init/claim-share/begin", globalConfig.Server)
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(beginBody))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHTTPRequestFailed, err)
	}

	respBody, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var beginResp claimShareBeginResponse
	if err := json.Unmarshal(respBody, &beginResp); err != nil {
		return fmt.Errorf("%w: %w", ErrJSONParseFailed, err)
	}

	// Step 2: Generate keypair and sign nonce
	nonce, err := hex.DecodeString(beginResp.Nonce)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNonceDecode, err)
	}

	pubKey, privKey, err := generateNoiseKeyPair()
	if err != nil {
		return err
	}

	sig, err := signNonce(nonce, privKey)
	if err != nil {
		return err
	}

	// Step 3: Complete the challenge
	completeReq := claimShareCompleteRequest{
		Username:  claimShareUsername,
		Nonce:     beginResp.Nonce,
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	completeBody, err := json.Marshal(completeReq)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJSONMarshalFailed, err)
	}

	completeEndpoint := fmt.Sprintf("%s/api/v1/init/claim-share/complete", globalConfig.Server)
	completeResp, err := client.Post(completeEndpoint, "application/json", bytes.NewReader(completeBody))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHTTPRequestFailed, err)
	}

	completeRespBody, err := checkServerResponse(completeResp)
	if err != nil {
		return err
	}

	var completeResp2 claimShareCompleteResponse
	if err := json.Unmarshal(completeRespBody, &completeResp2); err != nil {
		return fmt.Errorf("%w: %w", ErrJSONParseFailed, err)
	}

	// Write share to output file if specified, otherwise print to stdout
	sharePEM, err := base64.StdEncoding.DecodeString(completeResp2.Share)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBase64Decode, err)
	}

	if claimShareOutput != "" {
		if err := os.WriteFile(claimShareOutput, sharePEM, 0600); err != nil {
			return fmt.Errorf("%w: %w", ErrShareFileWrite, err)
		}
		fmt.Printf("Share %d/%d written to %s\n", completeResp2.ShareIndex, completeResp2.Threshold, claimShareOutput)
	} else {
		fmt.Printf("Share %d/%d:\n", completeResp2.ShareIndex, completeResp2.Threshold)
		fmt.Print(string(sharePEM))
	}

	return nil
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
		return fmt.Errorf("%w: %w", ErrCertFileRead, err)
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
		return fmt.Errorf("%w: %w", ErrJSONMarshalFailed, err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/init/sign-csr", globalConfig.Server)
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHTTPRequestFailed, err)
	}

	respBody, err := checkServerResponse(resp)
	if err != nil {
		return err
	}

	var signResp signCSRInitResponse
	if err := json.Unmarshal(respBody, &signResp); err != nil {
		return fmt.Errorf("%w: %w", ErrJSONParseFailed, err)
	}

	// Write the signed certificate.
	if signCSROutput != "" {
		if err := os.WriteFile(signCSROutput, []byte(signResp.CertPEM), 0600); err != nil {
			return fmt.Errorf("%w: %w", ErrCertFileWrite, err)
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

// generateKeyPair generates an ECDSA P-256 keypair and returns the public key bytes and private key.
func generateNoiseKeyPair() ([]byte, crypto.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrKeyGenFailed, err)
	}

	pubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrPubKeyMarshalFailed, err)
	}

	return pubKey, privKey, nil
}

// newSPKIHTTPClient creates an HTTP client that pins the server's SPKI.
func newSPKIHTTPClient(pin string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: spki.NewPinnedTLSConfig(pin),
		},
	}
}

// newMTLSHTTPClient creates an HTTP client that uses mTLS.
func newMTLSHTTPClient(certFile, keyFile, caFile string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertFileRead, err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Load CA certificate if provided
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCertFileRead, err)
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
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrJSONMarshalFailed, err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTTPRequestFailed, err)
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
		return fmt.Errorf("%w: %w", ErrJSONMarshalFailed, err)
	}
	fmt.Println(string(data))
	return nil
}
