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

package enroll01

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
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

// ErrActivationUnreadable is returned when a credential activated, but the
// endorsement key and activation key it was made for cannot be read back out of
// the TCG-CSR-IDEVID. The challenge is refused rather than validated without
// the evidence finalization binds to.
var ErrActivationUnreadable = errors.New("enroll-01: the activated endorsement key cannot be read from the TCG-CSR-IDEVID")

// activateCredentialRequest represents the JSON payload sent to the client
// for TPM credential activation
type activateCredentialRequest struct {
	CredentialBlob  string `json:"credentialBlob"`
	EncryptedSecret string `json:"encryptedSecret"`
}

// TCGCSRVerifier verifies a TCG-CSR-IDEVID and produces the
// TPM2_MakeCredential challenge components used by the enroll-01 challenge.
type TCGCSRVerifier interface {
	// VerifyTCG_CSR_IDevIDBytes verifies a TCG-CSR-IDEVID and returns credential components
	// Returns: credentialBlob, encryptedSecret, plainSecret, error
	//
	// sigAlg is x509.SignatureAlgorithm, matching pkg/ca.TCGCA exactly. It was
	// declared interface{} here, and because Go requires an exact method
	// signature match, *ca.CA -- the only production implementation -- did not
	// satisfy this interface. The capability assertion in
	// sdk/go/acme/attestation.go therefore always failed and every enroll-01
	// challenge returned ErrACMEEnrollCAUnsupported, so TPM IDevID enrollment
	// could never succeed. The tests passed because the mock was written
	// against interface{} and matched the declaration the real CA could not.
	VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg x509.SignatureAlgorithm) ([]byte, []byte, []byte, error)

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

// maxCSRResponseBytes caps the challenge endpoint's response: a
// base64url-encoded packed TCG-CSR-IDEVID of at most
// xkmssdk.MaxIDevIDCSRSize bytes.
var maxCSRResponseBytes = int64(base64.RawURLEncoding.EncodedLen(xkmssdk.MaxIDevIDCSRSize))

// Activation is what a completed enroll-01 credential activation established
// about the TPM that answered (go-xkms#1391).
//
// The credential was made for the endorsement key in EKCertificate and bound
// to the activation key whose TPMT_PUBLIC is AttestPub, and only the TPM
// holding both could activate it. An order's finalize request must therefore
// be built around THIS endorsement key and THIS activation key: any other is
// a TCG-CSR the activation never covered. Activation is the evidence that
// comparison is made against, kept on the challenge between the two requests.
type Activation struct {
	// EKCertificate is the endorsement key certificate whose key the
	// credential was made for. Its chain was verified against the CA's
	// configured TPM-manufacturer roots before the credential was generated.
	EKCertificate *x509.Certificate

	// AttestPub is the TPMT_PUBLIC of the key the credential was bound to: the
	// IAK the TCG-CSR-IDEVID carries.
	AttestPub []byte
}

// Verify performs enroll-01 challenge verification. It is VerifyActivation for
// a caller that has no use for what the activation established.
func Verify(
	client *validation.Client,
	ca TCGCSRVerifier,
	domain, port, token, keyAuth string) error {

	_, err := VerifyActivation(client, ca, domain, port, token, keyAuth)
	return err
}

// VerifyActivation performs enroll-01 challenge verification and returns the
// endorsement key and activation key it activated.
//
// This function implements the server-side verification flow:
// 1. Retrieves TCG-CSR-IDEVID from client's challenge endpoint
// 2. Verifies CSR signature and certificate chain
// 3. Generates credential using TPM2_MakeCredential
// 4. Sends credential to client for activation
// 5. Verifies activated secret matches original
//
// Both requests go through client, the shared challenge-validation client:
// domain must be a bare hostname or IP literal, a reserved target address
// is refused after DNS resolution, redirects are refused, and each response
// is capped (the CSR at maxCSRResponseBytes, the activation secret at
// validation.DefaultMaxResponseBytes).
//
// Parameters:
//   - client: the shared challenge-validation client
//   - ca: TCG-CSR-IDEVID verifier for CSR verification and credential generation
//   - domain: the permanent-identifier host to contact
//   - port: HTTP port for challenge communication
//   - token: Challenge token
//   - keyAuth: Key authorization (used as qualifying data)
//
// Returns:
//   - the Activation if credential activation succeeds and the secret matches
//   - error if verification fails at any step
func VerifyActivation(
	client *validation.Client,
	ca TCGCSRVerifier,
	domain, port, token, keyAuth string) (*Activation, error) {

	ctx := context.Background()

	// Retrieve the TCG-CSR-IDevID from the challenge endpoint
	body, err := client.Get(ctx, validation.Target{
		Host:             domain,
		Port:             port,
		Path:             challengePath + token,
		MaxResponseBytes: maxCSRResponseBytes,
	})
	if err != nil {
		return nil, err
	}

	// Decode the packed TCG-CSR-IDevID
	packedCSR, err := base64.RawURLEncoding.DecodeString(string(body))
	if err != nil {
		return nil, err
	}

	// Verify the TCG-CSR-IDevID and get back the credential blob, encrypted secret,
	// and raw plain-text secret for comparison with the decrypted secret returned
	// from the client.
	credentialBlob, encryptedSecret, secret, err := ca.VerifyTCG_CSR_IDevIDBytes(
		packedCSR, ca.DefaultSignatureAlgorithm())
	if err != nil {
		return nil, err
	}

	activationRequest := &activateCredentialRequest{
		CredentialBlob:  base64.RawURLEncoding.EncodeToString(credentialBlob),
		EncryptedSecret: base64.RawURLEncoding.EncodeToString(encryptedSecret),
	}

	jsonData, err := json.Marshal(activationRequest)
	if err != nil {
		return nil, err
	}

	// Send the encrypted credential to the client for activation
	activated, err := client.Post(ctx, validation.Target{
		Host: domain,
		Port: port,
		Path: secretPath + token,
	}, "application/json", jsonData)
	if err != nil {
		return nil, err
	}

	// subtle.ConstantTimeCompare rather than bytes.Equal: this is the
	// verifier's proof-of-possession check, so the comparison must not leak
	// through timing how many leading bytes of a forged secret matched.
	// ConstantTimeCompare returns 0 immediately when the lengths differ,
	// which is acceptable here because the secret's length is not itself
	// secret.
	if subtle.ConstantTimeCompare(activated, secret) != 1 {
		return nil, caerrors.VerificationFailureError("enroll-01: invalid credential activation")
	}

	// The credential was made from this very CSR, so what it activated is
	// what this CSR names. Read it only now, once activation has succeeded.
	return activationOf(packedCSR)
}

// activationOf reads the endorsement key certificate and activation key out of
// the packed TCG-CSR-IDEVID a credential was just activated for.
func activationOf(packedCSR []byte) (*Activation, error) {
	tcgCSR, err := xkmssdk.UnmarshalIDevIDCSR(packedCSR)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrActivationUnreadable, Detail: "the TCG-CSR-IDEVID does not unpack", Cause: err}
	}
	ekCertificate, _, err := evidence.ParseEKCertificateChain(tcgCSR.CsrContents.EkCert)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrActivationUnreadable, Detail: "the endorsement key certificate does not parse", Cause: err}
	}
	if len(tcgCSR.CsrContents.AttestPub) == 0 {
		return nil, &errs.Detail{Err: ErrActivationUnreadable, Detail: "the TCG-CSR-IDEVID carries no activation key"}
	}
	return &Activation{EKCertificate: ekCertificate, AttestPub: tcgCSR.CsrContents.AttestPub}, nil
}

// Format is the entities.DeviceAttestation format of an enroll-01 activation
// record.
const Format = "enroll-01"

// Record converts the activation into the form the ACME server persists on the
// challenge that validated it: the evidence finalization compares a
// TCG-CSR-IDEVID against.
//
// identifierType is the authorization's identifier type. DeviceIdentityValue is
// the TCG permanentIdentifier of the activated endorsement key certificate --
// the identity of the TPM, and not the order's identifier, which for enroll-01
// is the address the server dialed. LeafDER is the activated endorsement key
// certificate and PubArea the activation key's TPMT_PUBLIC.
func (a *Activation) Record(identifierType, keyAuthorization string) (*entities.DeviceAttestation, error) {
	permanentIdentifier, err := pkgca.EKCertificatePermanentIdentifier(a.EKCertificate)
	if err != nil {
		return nil, err
	}
	return &entities.DeviceAttestation{
		Format:              Format,
		DeviceIdentityType:  identifierType,
		DeviceIdentityValue: permanentIdentifier,
		KeyAuthorization:    keyAuthorization,
		LeafDER:             a.EKCertificate.Raw,
		PubArea:             a.AttestPub,
	}, nil
}

// Setup initializes the enroll-01 challenge on the client side.
//
// This function:
// 1. Creates TCG-CSR-IDEVID with key authorization as qualifying data
// 2. Starts HTTP server to handle challenge and activation requests
// 3. Returns packed CSR for transmission to ACME server
//
// Parameters:
//   - listenAddr: the address the challenge server binds, passed to
//     net.Listen verbatim ("127.0.0.1:8080", ":8080"); a bare port ("8080")
//     is accepted and binds every interface, as earlier callers expect
//   - keyAuth: Key authorization (used as qualifying data in CSR)
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
	listenAddr, keyAuth string,
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

	startServer(listenAddress(listenAddr), tpm, packedCSR)

	return packedCSR, nil
}

// listenAddress normalises what Setup was given: a host:port (or ":port")
// is passed to net.Listen verbatim; a bare port keeps the historical
// meaning of every interface. Which host to bind is the caller's
// configuration, never a literal here (go-xkms#140).
func listenAddress(listenAddr string) string {
	if strings.Contains(listenAddr, ":") {
		return listenAddr
	}
	return ":" + listenAddr
}

// startServer initializes the HTTP server and starts listening for incoming requests.
func startServer(addr string, tpm TrustedPlatformModule, packedCSR []byte) {
	// Create local server and shutdown state to avoid race conditions
	var shutdownOnce sync.Once

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

		// Limit the size of the request body to prevent abuse. This must run
		// before any read of r.Body: reading first and wrapping afterward
		// never applies the limit, since the unbounded read has already
		// buffered the whole body in memory.
		const maxBodySize = 1048576 // 1MB
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		// The body is read in full below, and net/http closes the server
		// request body itself once the handler returns, so a close error
		// here is neither actionable nor meaningful (go-xkms#866).
		defer func() { _ = r.Body.Close() }()

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				log.Printf("Request body exceeded %d bytes", maxBodySize)
				return
			}
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			log.Printf("Error reading request body: %v", err)
			return
		}

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
