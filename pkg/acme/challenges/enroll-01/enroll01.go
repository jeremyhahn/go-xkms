// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package enroll01

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// enroll-01 Challenge Implementation
//
// The enroll-01 challenge is a custom ACME extension that facilitates OEM enrollment
// of new TPM-equipped devices during manufacturer provisioning. It implements the
// procedures outlined in Section 6 - Identity Provisioning - of the TCG TPM 2.0 Keys
// for Device Identity and Attestation specification.
//
// Reference: https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf
//
// This challenge specifically supports the procedures in:
// - Section 6.2: OEM Installation of IAK and IDevID in a Single Pass
// - Section 6.1.4: Included Attestation Variation
//
// TPM Requirements:
// - TPM 2.0 compliant hardware or software TPM
// - Endorsement Key (EK) certificate provisioned by manufacturer
// - Ability to create Attestation Keys (AK/IAK) in the TPM
// - Support for TPM2_MakeCredential and TPM2_ActivateCredential operations
//
// Challenge Flow:
// 1. ACME server initiates challenge and provides challenge token
// 2. Client creates TCG-CSR-IDEVID with key authorization as qualifying data
// 3. Client starts HTTP server to serve CSR and handle credential activation
// 4. Server performs HTTP GET to /.well-known/acme-challenge/{token} to retrieve TCG-CSR-IDEVID
// 5. Server verifies CSR and generates credential using TPM2_MakeCredential
// 6. Server sends credential blob and encrypted secret to /.well-known/acme-activation/{token}
// 7. Client activates credential using TPM2_ActivateCredential and returns decrypted secret
// 8. Server verifies decrypted secret matches original, confirming:
//    - Client possesses private keys in the CSR
//    - Keys reside in an authentic TPM
//    - Device has valid EK certificate chain
//
// Security Properties:
// - Proves possession of TPM-bound private keys
// - Validates EK certificate chain to manufacturer root
// - Verifies AK/IAK certification by EK
// - Ensures keys are non-exportable and TPM-resident
// - Binds device identity to specific TPM

const (
	secretPath    = "/.well-known/acme-activation/" // #nosec G101 - URL path, not a credential
	challengePath = "/.well-known/acme-challenge/"
)

var (
	serverShutdownTimeout = 5 * time.Second
)

// activateCredentialRequest represents the JSON payload sent to the client
// for TPM credential activation
type activateCredentialRequest struct {
	CredentialBlob  string `json:"credentialBlob"`
	EncryptedSecret string `json:"encryptedSecret"`
}

// CertificateAuthority defines the CA interface needed for enroll-01 verification
type CertificateAuthority interface {
	// VerifyTCG_CSR_IDevIDBytes verifies a TCG-CSR-IDEVID and returns credential components
	// Returns: credentialBlob, encryptedSecret, plainSecret, error
	VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg interface{}) ([]byte, []byte, []byte, error)

	// DefaultSignatureAlgorithm returns the CA's default signature algorithm
	DefaultSignatureAlgorithm() x509.SignatureAlgorithm
}

// TrustedPlatformModule defines the TPM interface needed for enroll-01 setup
type TrustedPlatformModule interface {
	// EKCertificate returns the TPM Endorsement Key certificate
	EKCertificate() ([]byte, error)

	// IAKAttributes returns the attestation key attributes
	IAKAttributes() (interface{}, error)

	// CreateIDevID creates an IDevID key and generates TCG-CSR-IDEVID
	// Parameters: akAttrs, ekCert, qualifyingData
	// Returns: IDevID handle, TCG-CSR-IDEVID, error
	CreateIDevID(akAttrs interface{}, ekCert []byte, qualifyingData []byte) (interface{}, interface{}, error)

	// ActivateCredential performs TPM2_ActivateCredential operation
	// Parameters: credentialBlob, encryptedSecret
	// Returns: decrypted secret, error
	ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error)
}

// Verify performs enroll-01 challenge verification.
//
// This function implements the server-side verification flow:
// 1. Retrieves TCG-CSR-IDEVID from client's challenge endpoint
// 2. Verifies CSR signature and certificate chain
// 3. Generates credential using TPM2_MakeCredential
// 4. Sends credential to client for activation
// 5. Verifies activated secret matches original
//
// Parameters:
//   - resolver: DNS resolver for domain name resolution
//   - ca: Certificate Authority for CSR verification and credential generation
//   - domain: Domain name to verify
//   - port: HTTP port for challenge communication
//   - token: Challenge token
//   - keyAuth: Key authorization (used as qualifying data)
//
// Returns:
//   - nil if credential activation succeeds and secret matches
//   - error if verification fails at any step
func Verify(
	resolver *net.Resolver,
	ca CertificateAuthority,
	domain, port, token, keyAuth string) error {

	// Retrieve the TCG-CSR-IDevID from the challenge endpoint
	endpoint := fmt.Sprintf("http://%s:%s%s%s", domain, port, challengePath, token)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
				Resolver:  resolver,
			}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// Enroll-01 uses plain HTTP - no TLS config needed
			// since we don't follow redirects
		},
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return caerrors.ConnectionFailureError("enroll-01: unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Decode the packed TCG-CSR-IDevID
	packedCSR, err := base64.RawURLEncoding.DecodeString(string(body))
	if err != nil {
		return err
	}

	// Verify the TCG-CSR-IDevID and get back the credential blob, encrypted secret,
	// and raw plain-text secret for comparison with the decrypted secret returned
	// from the client.
	credentialBlob, encryptedSecret, secret, err := ca.VerifyTCG_CSR_IDevIDBytes(
		packedCSR, ca.DefaultSignatureAlgorithm())
	if err != nil {
		return err
	}

	// Send the encrypted credential to the client for activation
	secretEndpoint := fmt.Sprintf("http://%s:%s%s%s", domain, port, secretPath, token)

	activationRequest := &activateCredentialRequest{
		CredentialBlob:  base64.RawURLEncoding.EncodeToString(credentialBlob),
		EncryptedSecret: base64.RawURLEncoding.EncodeToString(encryptedSecret),
	}

	jsonData, err := json.Marshal(activationRequest)
	if err != nil {
		return err
	}

	resp, err = client.Post(secretEndpoint, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return caerrors.ConnectionFailureError("enroll-01: activation failed with status code: %d", resp.StatusCode)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if !bytes.Equal(body, secret) {
		return caerrors.VerificationFailureError("enroll-01: invalid credential activation")
	}

	return nil
}

// Setup initializes the enroll-01 challenge on the client side.
//
// This function:
// 1. Creates TCG-CSR-IDEVID with key authorization as qualifying data
// 2. Starts HTTP server to handle challenge and activation requests
// 3. Returns packed CSR for transmission to ACME server
//
// Parameters:
//   - port: HTTP port to listen on
//   - keyAuth: Key authorization (used as qualifying data in CSR)
//   - ca: Certificate Authority (not used in client setup)
//   - tpm: Trusted Platform Module for key creation and activation
//
// Returns:
//   - Packed TCG-CSR-IDEVID as byte array
//   - error if setup fails
//
// The HTTP server will handle two endpoints:
// - GET /.well-known/acme-challenge/{token}: Returns packed CSR
// - POST /.well-known/acme-activation/{token}: Activates credential and returns secret
func Setup(
	port, keyAuth string,
	ca CertificateAuthority,
	tpm TrustedPlatformModule) ([]byte, error) {

	ekCert, err := tpm.EKCertificate()
	if err != nil {
		return nil, err
	}

	akAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return nil, err
	}

	_, tcgCSRInterface, err := tpm.CreateIDevID(akAttrs, ekCert, []byte(keyAuth))
	if err != nil {
		return nil, err
	}

	// The CreateIDevID interface expects to return interface{}, but it should return *xkmssdk.TCG_CSR_IDEVID
	// For now, we'll handle this with type assertion
	tcgCSR, ok := tcgCSRInterface.(*xkmssdk.TCG_CSR_IDEVID)
	if !ok {
		return nil, caerrors.InternalServerError("enroll-01: CreateIDevID returned unexpected type")
	}

	packedCSR, err := xkmssdk.PackIDevIDCSR(tcgCSR)
	if err != nil {
		return nil, err
	}

	startServer(port, tpm, packedCSR)

	return packedCSR, nil
}

// startServer initializes the HTTP server and starts listening for incoming requests.
func startServer(port string, tpm TrustedPlatformModule, packedCSR []byte) {
	// Create local server and shutdown state to avoid race conditions
	var shutdownOnce sync.Once

	addr := fmt.Sprintf(":%s", port)

	// Create server first so handlers can reference it
	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Set up HTTP server to handle challenges with closures capturing local state
	mux := http.NewServeMux()
	mux.HandleFunc(challengePath, challengeHandlerHTTPx(packedCSR))
	mux.HandleFunc(secretPath, activateCredentialHandlerWithShutdown(tpm, server, &shutdownOnce))
	server.Handler = mux

	// Start the HTTP server in a separate goroutine
	go func() {
		log.Printf("Starting HTTP server on %s for enroll-01 challenge", addr)
		// Listen on all interfaces
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("ERROR: Failed to listen on %s: %v", addr, err)
			return
		}
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("ERROR: HTTP server error: %v", err)
		}
	}()

	// Handle graceful shutdown on interrupt signals
	go handleShutdownWithServer(server, &shutdownOnce)
}

// activateCredentialHandlerWithShutdown returns the HTTP handler for credential activation
// with proper server shutdown support.
//
// This handler:
// 1. Receives credential blob and encrypted secret from ACME server
// 2. Calls TPM2_ActivateCredential to decrypt the secret
// 3. Returns the decrypted secret to prove TPM possession
// 4. Initiates server shutdown after successful activation
func activateCredentialHandlerWithShutdown(
	tpm TrustedPlatformModule,
	server *http.Server,
	shutdownOnce *sync.Once) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Extract the token from the URL path
		token := r.URL.Path[len(secretPath):]
		if token == "" {
			http.Error(w, "Token not provided", http.StatusBadRequest)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed. Use POST.", http.StatusMethodNotAllowed)
			return
		}

		// Ensure the Content-Type is application/json
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			log.Printf("Error reading request body: %v", err)
			return
		}
		defer func() { _ = r.Body.Close() }()

		// Limit the size of the request body to prevent abuse
		const maxBodySize = 1048576 // 1MB
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		// Unmarshal the JSON into the request struct
		var activationRequest activateCredentialRequest
		if err := json.Unmarshal(body, &activationRequest); err != nil {
			http.Error(w, "Invalid activation request", http.StatusBadRequest)
			log.Printf("JSON unmarshal error: %v", err)
			return
		}

		credentialBlob, err := base64.RawURLEncoding.DecodeString(activationRequest.CredentialBlob)
		if err != nil {
			http.Error(w, "Invalid credential blob", http.StatusBadRequest)
			log.Printf("Failed to decode credential blob: %v", err)
			return
		}

		encryptedSecret, err := base64.RawURLEncoding.DecodeString(activationRequest.EncryptedSecret)
		if err != nil {
			http.Error(w, "Invalid encrypted secret", http.StatusBadRequest)
			log.Printf("Failed to decode encrypted secret: %v", err)
			return
		}

		secret, err := tpm.ActivateCredential(credentialBlob, encryptedSecret)
		if err != nil {
			http.Error(w, "Failed to activate credential", http.StatusInternalServerError)
			log.Printf("Failed to activate credential: %v", err)
			return
		}

		// Serve the decrypted secret
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(secret)
		if err != nil {
			log.Printf("Failed to write response for token %s: %v", token, err)
			return
		}

		// Initiate server shutdown after successful activation (if server provided)
		if server != nil && shutdownOnce != nil {
			go shutdownOnce.Do(func() {
				ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
				defer cancel()
				if err := server.Shutdown(ctx); err != nil {
					log.Printf("WARNING: Server shutdown failed: %v", err)
				}
			})
		}
	}
}

// challengeHandlerHTTPx returns an HTTP handler that serves the TCG-CSR-IDEVID.
//
// The handler responds to GET requests with the base64url-encoded packed CSR.
func challengeHandlerHTTPx(packedCSR []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the token from the URL path
		token := r.URL.Path[len(challengePath):]
		if token == "" {
			http.Error(w, "Token not provided", http.StatusBadRequest)
			return
		}

		encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)

		// Serve the encoded CSR
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(encodedCSR))
		if err != nil {
			log.Printf("Failed to write response for token %s: %v", token, err)
			return
		}
	}
}

// handleShutdownWithServer listens for OS interrupt signals and gracefully shuts down the server.
func handleShutdownWithServer(server *http.Server, shutdownOnce *sync.Once) {
	if server == nil || shutdownOnce == nil {
		return
	}

	// Create a channel to receive OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received
	sig := <-sigChan
	log.Printf("Received signal: %v. Initiating shutdown...", sig)

	// Initiate server shutdown
	shutdownOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("WARNING: Server shutdown failed: %v", err)
		}
	})
}
