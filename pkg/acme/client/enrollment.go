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

package client

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// TPM enrollment errors
var (
	ErrEnrollmentFailed  = errors.New("acme-client: device enrollment failed")
	ErrEndorsementFailed = errors.New("acme-client: EK certificate request failed")
	ErrAttestationFailed = errors.New("acme-client: device attestation failed")
	ErrMissingTPMModule  = errors.New("acme-client: TPM module required for enrollment")
	ErrInvalidIPAddress  = errors.New("acme-client: invalid IP address format")
	ErrEnvVarNotFound    = errors.New("acme-client: environment variable not found")
	ErrInvalidChallenge  = errors.New("acme-client: invalid challenge type")
	ErrOrderNotReady     = errors.New("acme-client: order not ready for finalization")
	ErrActivationFailed  = errors.New("acme-client: credential activation failed")
)

// ekRequest represents the endorsement key request for endorse-01 challenge
//
//nolint:unused // Used in tests and future endorse-01 challenge integration
type ekRequest struct {
	EKPublicKey  string `json:"ekPublicKey"`
	EKAttributes string `json:"ekAttributes"`
	CSR          string `json:"csr"`
}

// activateCredentialRequest represents the credential activation request
type activateCredentialRequest struct {
	CredentialBlob  string `json:"credentialBlob"`
	EncryptedSecret string `json:"encryptedSecret"`
}

// EnrollmentConfig defines the configuration for TPM device enrollment.
//
// YAML/mapstructure tags match the reference implementation's existing
// enrollment YAML (go-trusted-platform). The TPMModule field is runtime-only
// and tagged `yaml:"-"` so YAML decoders do not try to populate it.
type EnrollmentConfig struct {
	// Challenge specifies the challenge type (enroll-01, endorse-01, device-attest-01)
	Challenge string `yaml:"challenge" json:"challenge" mapstructure:"challenge"`

	// IPAddress specifies the target IP address (supports ${ENV_VAR} expansion)
	IPAddress string `yaml:"ip" json:"ip" mapstructure:"ip"`

	// TPMModule provides TPM operations interface
	TPMModule TPMModule `yaml:"-" json:"-" mapstructure:"-"`

	// Port specifies the HTTP port for challenge communication (default: 8080)
	Port string `yaml:"port,omitempty" json:"port,omitempty" mapstructure:"port"`

	// ListenHost is the host every challenge listener this enrollment opens
	// (enroll-01, endorse-01, device-attest-01) binds, joined with Port
	// through net.JoinHostPort. Empty, the defaults-layer value, binds every
	// interface. xkmsd passes its server.host here so the exchange binds
	// exactly what every other daemon listener binds (go-xkms#140).
	ListenHost string `yaml:"listen-host,omitempty" json:"listen_host,omitempty" mapstructure:"listen-host"`

	// CommonName specifies the certificate common name
	CommonName string `yaml:"common-name,omitempty" json:"common_name,omitempty" mapstructure:"common-name"`

	// PCRSelection specifies PCR indices for device-attest-01 challenge
	PCRSelection []int `yaml:"pcr-selection,omitempty" json:"pcr_selection,omitempty" mapstructure:"pcr-selection"`

	// Timeout specifies the HTTP client timeout (default: 30 seconds)
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty" mapstructure:"timeout"`
}

// Validate validates the enrollment configuration
// listenAddr is the address a challenge listener binds: ListenHost and Port
// through net.JoinHostPort, so an IPv6 host is bracketed and the empty
// default host binds every interface.
func (ec *EnrollmentConfig) listenAddr() string {
	return net.JoinHostPort(ec.ListenHost, ec.Port)
}

func (ec *EnrollmentConfig) Validate() error {
	if ec.Challenge == "" {
		return ErrInvalidChallenge
	}

	validChallenges := map[string]bool{
		string(ChallengeTypeEnroll01):       true,
		string(ChallengeTypeEndorse01):      true,
		string(ChallengeTypeDeviceAttest01): true,
	}

	if !validChallenges[ec.Challenge] {
		return caerrors.MalformedError("invalid challenge type: %s", ec.Challenge)
	}

	if ec.TPMModule == nil {
		return ErrMissingTPMModule
	}

	if ec.IPAddress == "" {
		return ErrInvalidIPAddress
	}

	// Set defaults
	if ec.Port == "" {
		ec.Port = "8080"
	}

	if ec.Timeout == 0 {
		ec.Timeout = 30 * time.Second
	}

	return nil
}

// expandEnvVars expands environment variables in the format ${VAR_NAME}
func expandEnvVars(input string) (string, error) {
	re := regexp.MustCompile(`\$\{([A-Z_][A-Z0-9_]*)\}`)

	result := input
	matches := re.FindAllStringSubmatch(input, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		varName := match[1]
		varValue := os.Getenv(varName)

		if varValue == "" {
			return "", caerrors.MalformedError("environment variable not found: %s", varName)
		}

		result = strings.ReplaceAll(result, match[0], varValue)
	}

	return result, nil
}

// EnrollDevice performs TPM device enrollment using the enroll-01 challenge.
// Returns an EnrollmentResult containing both the IAK and IDevID certificates.
func (c *Client) EnrollDevice(ctx context.Context, config *EnrollmentConfig) (*EnrollmentResult, error) {
	if err := config.Validate(); err != nil {
		return nil, caerrors.MalformedError("invalid enrollment config: %v", err)
	}

	// Expand environment variables in IP address
	ipAddress, err := expandEnvVars(config.IPAddress)
	if err != nil {
		return nil, caerrors.MalformedError("failed to expand IP address: %v", err)
	}

	c.logger.Info("starting device enrollment",
		"challenge", config.Challenge,
		"ip_address", ipAddress,
		"port", config.Port,
		"directory_url", c.config.DirectoryURL)

	// Create order for device enrollment
	deadline, hasDeadline := ctx.Deadline()
	c.logger.Info("creating ACME order - calling AuthorizeOrder",
		"authz_type", string(AuthzTypePermanentIdentifier),
		"authz_value", ipAddress,
		"directory_url", c.config.DirectoryURL,
		"context_has_deadline", hasDeadline,
		"context_deadline", deadline)

	// authorizeOrder registers the account on first use (RFC 8555 requires
	// the server-issued KID, not a bare JWK, on every authenticated request
	// after registration) before creating the order.
	order, err := c.authorizeOrder(ctx, []acme.AuthzID{
		{
			Type:  string(AuthzTypePermanentIdentifier),
			Value: ipAddress,
		},
	})
	if err != nil {
		return nil, caerrors.InternalServerError("enrollment failed: failed to create order: %v", err)
	}

	c.logger.Debug("order created",
		"order_uri", order.URI,
		"status", order.Status)

	// Store the TCG-CSR-IDEVID for finalization - the server expects
	// the TCG-CSR-IDEVID to be sent during finalization, not a standard x509 CSR
	var tcgCSRDER []byte

	// Process authorizations
	for _, authzURL := range order.AuthzURLs {
		authz, err := c.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, caerrors.InternalServerError("enrollment failed: failed to get authorization: %v", err)
		}

		// Find the enroll-01 challenge
		var enrollChallenge *acme.Challenge
		for i := range authz.Challenges {
			if authz.Challenges[i].Type == config.Challenge {
				enrollChallenge = authz.Challenges[i]
				break
			}
		}

		if enrollChallenge == nil {
			return nil, caerrors.InternalServerError("enrollment failed: %s challenge not offered by server", config.Challenge)
		}

		c.logger.Debug("found challenge",
			"type", enrollChallenge.Type,
			"token", enrollChallenge.Token,
			"uri", enrollChallenge.URI)

		// Generate key authorization
		keyAuth, err := c.client.HTTP01ChallengeResponse(enrollChallenge.Token)
		if err != nil {
			return nil, caerrors.InternalServerError("enrollment failed: failed to generate key authorization: %v", err)
		}

		// Setup the enroll-01 challenge by creating TCG-CSR-IDEVID
		idevidCSR, err := config.TPMModule.CreateIDevID([]byte(keyAuth))
		if err != nil {
			return nil, caerrors.InternalServerError("enrollment failed: challenge setup failed: %v", err)
		}

		// Store the TCG-CSR-IDEVID for finalization
		tcgCSRDER = idevidCSR.CSR

		// Start HTTP server to handle challenge
		go c.startEnrollServer(config, idevidCSR, enrollChallenge.Token)

		// Give server time to start
		time.Sleep(100 * time.Millisecond)

		c.logger.Debug("challenge setup complete",
			"csr_length", len(idevidCSR.CSR),
			"listening_port", config.Port)

		// Accept the challenge
		_, err = c.client.Accept(ctx, enrollChallenge)
		if err != nil {
			return nil, caerrors.InternalServerError("enrollment failed: failed to accept challenge: %v", err)
		}

		c.logger.Debug("challenge accepted, waiting for authorization")

		// Wait for authorization to complete
		authz, err = c.client.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return nil, caerrors.InternalServerError("enrollment failed: authorization failed: %v", err)
		}

		if authz.Status != acme.StatusValid {
			return nil, caerrors.InternalServerError("enrollment failed: authorization status is not valid: %s", authz.Status)
		}

		c.logger.Debug("authorization completed successfully")
	}

	// Wait for order to be ready
	order, err = c.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, caerrors.InternalServerError("enrollment failed: order wait failed: %v", err)
	}

	if order.Status != acme.StatusReady {
		return nil, caerrors.InternalServerError("order not ready: order status is %s, expected ready", order.Status)
	}

	// For enroll-01, send the TCG-CSR-IDEVID for finalization
	// The server expects the packed TCG-CSR-IDEVID, not a standard x509 CSR
	if tcgCSRDER == nil {
		return nil, caerrors.InternalServerError("enrollment failed: TCG-CSR-IDEVID not available for finalization")
	}

	c.logger.Debug("sending TCG-CSR-IDEVID for finalization",
		"csr_length", len(tcgCSRDER))

	// Finalize the order with TCG-CSR-IDEVID
	certChain, certURL, err := c.client.CreateOrderCert(ctx, order.FinalizeURL, tcgCSRDER, true)
	if err != nil {
		return nil, caerrors.InternalServerError("enrollment failed: order finalization failed: %v", err)
	}

	// The server returns both IAK and IDevID certificates, followed by the
	// issuing chain (RFC 8555 §7.4.2):
	// certChain[0]  = IAK certificate
	// certChain[1]  = IDevID certificate
	// certChain[2:] = the issuing chain, leaf-ward first
	if len(certChain) < 2 {
		return nil, caerrors.InternalServerError("enrollment failed: expected 2 certificates (IAK and IDevID), got %d", len(certChain))
	}

	// Parse the IAK certificate
	iakCert, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return nil, caerrors.MalformedError("enrollment failed: failed to parse IAK certificate: %v", err)
	}

	// Parse the IDevID certificate
	idevidCert, err := x509.ParseCertificate(certChain[1])
	if err != nil {
		return nil, caerrors.MalformedError("enrollment failed: failed to parse IDevID certificate: %v", err)
	}

	chain, err := parseIssuingChain(certChain[2:])
	if err != nil {
		return nil, err
	}

	c.logger.Info("device enrollment completed successfully",
		"cert_url", certURL,
		"iak_subject", iakCert.Subject.CommonName,
		"iak_serial", iakCert.SerialNumber,
		"idevid_subject", idevidCert.Subject.CommonName,
		"idevid_serial", idevidCert.SerialNumber,
		"not_before", idevidCert.NotBefore,
		"not_after", idevidCert.NotAfter)

	return &EnrollmentResult{
		IAKCertificate:    iakCert,
		IDevIDCertificate: idevidCert,
		Chain:             chain,
	}, nil
}

// startEnrollServer starts an HTTP server for enroll-01 challenge handling
func (c *Client) startEnrollServer(config *EnrollmentConfig, idevidCSR *IDevIDCSR, token string) {
	mux := http.NewServeMux()

	// Challenge endpoint - serves the packed TCG-CSR-IDEVID
	challengePath := "/.well-known/acme-challenge/"
	mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, token) {
			http.NotFound(w, r)
			return
		}

		// Return base64url-encoded CSR
		encodedCSR := base64.RawURLEncoding.EncodeToString(idevidCSR.CSR)
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(encodedCSR)); err != nil {
			c.logger.Error("failed to write enroll-01 challenge response", "error", err)
		}
	})

	// Activation endpoint - handles credential activation
	activatePath := "/.well-known/acme-activation/"
	mux.HandleFunc(activatePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !strings.HasSuffix(r.URL.Path, token) {
			http.NotFound(w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		var activateReq activateCredentialRequest
		if err := json.Unmarshal(body, &activateReq); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// Decode credential blob and encrypted secret
		credBlob, err := base64.RawURLEncoding.DecodeString(activateReq.CredentialBlob)
		if err != nil {
			http.Error(w, "invalid credential blob", http.StatusBadRequest)
			return
		}

		encSecret, err := base64.RawURLEncoding.DecodeString(activateReq.EncryptedSecret)
		if err != nil {
			http.Error(w, "invalid encrypted secret", http.StatusBadRequest)
			return
		}

		// Activate credential using TPM
		secret, err := config.TPMModule.ActivateCredential(credBlob, encSecret)
		if err != nil {
			c.logger.Error("credential activation failed", "error", err)
			http.Error(w, "activation failed", http.StatusInternalServerError)
			return
		}

		// Return the decrypted secret
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := w.Write(secret); err != nil {
			c.logger.Error("failed to write enroll-01 activation response", "error", err)
		}
	})

	addr := config.listenAddr()
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	c.logger.Debug("starting enroll-01 HTTP server", "addr", addr)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		c.logger.Error("HTTP server error", "error", err)
	}
}

// RequestEndorsementKeyCertificate requests an EK certificate via endorse-01 challenge.
// This is used for TPMs without manufacturer-issued EK certificates (e.g., swtpm, virtual TPMs).
// The flow uses the serialized EK public key as the permanent identifier, and the server
// validates the request via EAB or server policy (the endorse-01 verifier returns nil).
func (c *Client) RequestEndorsementKeyCertificate(ctx context.Context, config *EnrollmentConfig) (*x509.Certificate, error) {
	if err := config.Validate(); err != nil {
		return nil, caerrors.MalformedError("invalid enrollment config: %v", err)
	}

	// Get EK public key directly from TPM
	ekPubKey := config.TPMModule.EK()
	if ekPubKey == nil {
		return nil, caerrors.BadPublicKeyError("endorsement failed: EK public key not available")
	}

	// Serialize the EK public key to use as permanent identifier
	ekPubKeyBytes, err := x509.MarshalPKIXPublicKey(ekPubKey)
	if err != nil {
		return nil, caerrors.BadPublicKeyError("endorsement failed: failed to marshal EK public key: %v", err)
	}

	// Use base64 encoded EK public key as permanent identifier
	ekIdentifier := base64.RawURLEncoding.EncodeToString(ekPubKeyBytes)

	// Format CommonName as "{hostname}-ek" for clarity (e.g., "client0-ek", "server-ek")
	commonName := "ek"
	if config.CommonName != "" {
		commonName = fmt.Sprintf("%s-ek", config.CommonName)
	}

	subject := pkix.Name{CommonName: commonName}

	// Ask for the TPM's manufacturer code to be recorded in the EK
	// certificate. A later enroll-01 names the TPM by it (TCG DevID v1 r12
	// §8.1), and a TPM that needs endorse-01 has no manufacturer EK
	// certificate to supply it from.
	manufacturer, err := config.TPMModule.TPMManufacturer()
	if err != nil {
		return nil, caerrors.BadCSRError("endorsement failed: %v", err)
	}
	manufacturerSAN, err := ca.TCGTPMManufacturerSubjectAltName(subject, manufacturer)
	if err != nil {
		return nil, caerrors.BadCSRError("endorsement failed: %v", err)
	}

	c.logger.Info("requesting EK certificate via endorse-01",
		"challenge", config.Challenge)

	// Create order with serialized EK public key as permanent identifier
	order, err := c.authorizeOrder(ctx, []acme.AuthzID{
		{
			Type:  string(AuthzTypePermanentIdentifier),
			Value: ekIdentifier,
		},
	})
	if err != nil {
		return nil, caerrors.InternalServerError("endorsement failed: failed to create order: %v", err)
	}

	c.logger.Debug("order created",
		"order_uri", order.URI,
		"status", order.Status)

	// Process authorizations
	for _, authzURL := range order.AuthzURLs {
		authz, err := c.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, caerrors.InternalServerError("endorsement failed: failed to get authorization: %v", err)
		}

		// Find the endorse-01 challenge
		var endorseChallenge *acme.Challenge
		for i := range authz.Challenges {
			if authz.Challenges[i].Type == config.Challenge {
				endorseChallenge = authz.Challenges[i]
				break
			}
		}

		if endorseChallenge == nil {
			return nil, caerrors.InternalServerError("endorsement failed: %s challenge not offered by server", config.Challenge)
		}

		c.logger.Debug("found endorse-01 challenge",
			"type", endorseChallenge.Type,
			"token", endorseChallenge.Token,
			"uri", endorseChallenge.URI)

		// Accept the challenge - endorse-01 verification is handled by EAB/server policy
		// (the verifier returns nil), so no HTTP server setup is needed
		_, err = c.client.Accept(ctx, endorseChallenge)
		if err != nil {
			return nil, caerrors.InternalServerError("endorsement failed: failed to accept challenge: %v", err)
		}

		c.logger.Debug("endorse-01 challenge accepted, waiting for authorization")

		// Wait for authorization to complete
		authz, err = c.client.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return nil, caerrors.InternalServerError("endorsement failed: authorization failed: %v", err)
		}

		if authz.Status != acme.StatusValid {
			return nil, caerrors.InternalServerError("endorsement failed: authorization status is not valid: %s", authz.Status)
		}

		c.logger.Debug("endorse-01 authorization completed successfully")
	}

	// Wait for order to be ready
	order, err = c.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, caerrors.InternalServerError("endorsement failed: order wait failed: %v", err)
	}

	if order.Status != acme.StatusReady {
		return nil, caerrors.InternalServerError("order not ready: order status is %s, expected ready", order.Status)
	}

	// Create CSR for EK certificate. The CA issues the certificate for the
	// EK public key named by the order's permanent identifier.
	template := &x509.CertificateRequest{
		Subject:         subject,
		ExtraExtensions: []pkix.Extension{manufacturerSAN},
	}

	// Create CSR with the account signer (the CA will issue a certificate
	// for the EK public key based on the order's permanent identifier)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, c.accountSigner)
	if err != nil {
		return nil, caerrors.BadCSRError("endorsement failed: failed to create CSR: %v", err)
	}

	// Finalize the order
	certChain, certURL, err := c.client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, caerrors.InternalServerError("endorsement failed: order finalization failed: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return nil, caerrors.MalformedError("endorsement failed: failed to parse certificate: %v", err)
	}

	c.logger.Info("EK certificate provisioned successfully via endorse-01",
		"cert_url", certURL,
		"subject", cert.Subject.CommonName,
		"serial", cert.SerialNumber,
		"not_before", cert.NotBefore,
		"not_after", cert.NotAfter)

	return cert, nil
}

// setupEndorseChallenge sets up the HTTP server for endorse-01 challenge
//
//nolint:unused // Used in tests and future endorse-01 challenge integration
func (c *Client) setupEndorseChallenge(config *EnrollmentConfig, keyAuth, token string) error {
	// Get EK certificate from TPM
	ekCert, err := config.TPMModule.EKCertificate()
	if err != nil {
		return caerrors.BadPublicKeyError("failed to get EK certificate: %v", err)
	}

	// Get EK attributes
	ekAttrs, err := config.TPMModule.EKAttributes()
	if err != nil {
		return caerrors.InternalServerError("failed to get EK attributes: %v", err)
	}

	// Serialize EK public key
	ekPubKeyBytes, err := x509.MarshalPKIXPublicKey(ekCert.PublicKey)
	if err != nil {
		return caerrors.BadPublicKeyError("failed to marshal EK public key: %v", err)
	}

	// Create EK request
	req := ekRequest{
		EKPublicKey:  base64.RawURLEncoding.EncodeToString(ekPubKeyBytes),
		EKAttributes: fmt.Sprintf("%v", ekAttrs),
		CSR:          "",
	}

	// Start HTTP server to serve EK request and handle activation
	go c.startEndorseServer(config, req, token)

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	return nil
}

// startEndorseServer starts an HTTP server for endorse-01 challenge handling
//
//nolint:unused // Used in tests and future endorse-01 challenge integration
func (c *Client) startEndorseServer(config *EnrollmentConfig, req ekRequest, token string) {
	mux := http.NewServeMux()

	// Challenge endpoint - serves EK request
	challengePath := "/.well-known/acme-challenge/"
	mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, token) {
			http.NotFound(w, r)
			return
		}

		jsonData, err := json.Marshal(req)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(jsonData); err != nil {
			c.logger.Error("failed to write endorse-01 challenge response", "error", err)
		}
	})

	// Activation endpoint - handles credential activation
	activatePath := "/.well-known/acme-activation/"
	mux.HandleFunc(activatePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !strings.HasSuffix(r.URL.Path, token) {
			http.NotFound(w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		var activateReq activateCredentialRequest
		if err := json.Unmarshal(body, &activateReq); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// Decode credential blob and encrypted secret
		credBlob, err := base64.RawURLEncoding.DecodeString(activateReq.CredentialBlob)
		if err != nil {
			http.Error(w, "invalid credential blob", http.StatusBadRequest)
			return
		}

		encSecret, err := base64.RawURLEncoding.DecodeString(activateReq.EncryptedSecret)
		if err != nil {
			http.Error(w, "invalid encrypted secret", http.StatusBadRequest)
			return
		}

		// Activate credential using TPM
		secret, err := config.TPMModule.ActivateCredential(credBlob, encSecret)
		if err != nil {
			c.logger.Error("credential activation failed", "error", err)
			http.Error(w, "activation failed", http.StatusInternalServerError)
			return
		}

		// Return the decrypted secret
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := w.Write(secret); err != nil {
			c.logger.Error("failed to write endorse-01 activation response", "error", err)
		}
	})

	addr := config.listenAddr()
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	c.logger.Debug("starting endorse-01 HTTP server", "addr", addr)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		c.logger.Error("HTTP server error", "error", err)
	}
}

// DeviceAttest performs device attestation using the device-attest-01 challenge
func (c *Client) DeviceAttest(ctx context.Context, config *EnrollmentConfig, pcrSelection []int) (*x509.Certificate, error) {
	if err := config.Validate(); err != nil {
		return nil, caerrors.MalformedError("invalid enrollment config: %v", err)
	}

	// Expand environment variables in IP address
	ipAddress, err := expandEnvVars(config.IPAddress)
	if err != nil {
		return nil, caerrors.MalformedError("failed to expand IP address: %v", err)
	}

	c.logger.Info("starting device attestation",
		"challenge", config.Challenge,
		"ip_address", ipAddress,
		"port", config.Port,
		"pcr_count", len(pcrSelection))

	// Create order for attestation
	order, err := c.authorizeOrder(ctx, []acme.AuthzID{
		{
			Type:  string(AuthzTypePermanentIdentifier),
			Value: ipAddress,
		},
	})
	if err != nil {
		return nil, caerrors.InternalServerError("attestation failed: failed to create order: %v", err)
	}

	c.logger.Debug("order created",
		"order_uri", order.URI,
		"status", order.Status)

	// Process authorizations
	for _, authzURL := range order.AuthzURLs {
		authz, err := c.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, caerrors.InternalServerError("attestation failed: failed to get authorization: %v", err)
		}

		// Find the device-attest-01 challenge
		var attestChallenge *acme.Challenge
		for i := range authz.Challenges {
			if authz.Challenges[i].Type == config.Challenge {
				attestChallenge = authz.Challenges[i]
				break
			}
		}

		if attestChallenge == nil {
			return nil, caerrors.InternalServerError("attestation failed: %s challenge not offered by server", config.Challenge)
		}

		c.logger.Debug("found challenge",
			"type", attestChallenge.Type,
			"token", attestChallenge.Token,
			"uri", attestChallenge.URI)

		// Generate key authorization
		keyAuth, err := c.client.HTTP01ChallengeResponse(attestChallenge.Token)
		if err != nil {
			return nil, caerrors.InternalServerError("attestation failed: failed to generate key authorization: %v", err)
		}

		// Setup the device-attest-01 challenge
		attestStmt, err := c.setupAttestChallenge(config, keyAuth, pcrSelection)
		if err != nil {
			return nil, caerrors.InternalServerError("attestation failed: challenge setup failed: %v", err)
		}

		// Start HTTP server to serve attestation
		go c.startAttestServer(config, attestStmt, attestChallenge.Token)

		// Give server time to start
		time.Sleep(100 * time.Millisecond)

		c.logger.Debug("challenge setup complete", "port", config.Port)

		// Accept the challenge
		_, err = c.client.Accept(ctx, attestChallenge)
		if err != nil {
			return nil, caerrors.InternalServerError("attestation failed: failed to accept challenge: %v", err)
		}

		c.logger.Debug("challenge accepted, waiting for authorization")

		// Wait for authorization to complete
		authz, err = c.client.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return nil, caerrors.InternalServerError("attestation failed: authorization failed: %v", err)
		}

		if authz.Status != acme.StatusValid {
			return nil, caerrors.InternalServerError("attestation failed: authorization status is not valid: %s", authz.Status)
		}

		c.logger.Debug("authorization completed successfully")
	}

	// Wait for order to be ready
	order, err = c.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, caerrors.InternalServerError("attestation failed: order wait failed: %v", err)
	}

	if order.Status != acme.StatusReady {
		return nil, caerrors.InternalServerError("order not ready: order status is %s, expected ready", order.Status)
	}

	// Create CSR for attestation certificate
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: config.CommonName,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, c.accountSigner)
	if err != nil {
		return nil, caerrors.BadCSRError("attestation failed: failed to create CSR: %v", err)
	}

	// Finalize the order
	certChain, certURL, err := c.client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, caerrors.InternalServerError("attestation failed: order finalization failed: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return nil, caerrors.MalformedError("attestation failed: failed to parse certificate: %v", err)
	}

	c.logger.Info("device attestation completed successfully",
		"cert_url", certURL,
		"subject", cert.Subject.CommonName,
		"serial", cert.SerialNumber,
		"not_before", cert.NotBefore,
		"not_after", cert.NotAfter)

	return cert, nil
}

// setupAttestChallenge generates the attestation statement for device-attest-01
func (c *Client) setupAttestChallenge(config *EnrollmentConfig, keyAuth string, pcrSelection []int) ([]byte, error) {
	// Generate TPM quote using key authorization as qualifying data
	quote, err := config.TPMModule.Quote([]byte(keyAuth), pcrSelection)
	if err != nil {
		return nil, caerrors.BadAttestationStatementError("failed to generate TPM quote: %v", err)
	}

	// Get IAK attributes for AK certificate
	iakAttrs, err := config.TPMModule.IAKAttributes()
	if err != nil {
		return nil, caerrors.BadAttestationStatementError("failed to get IAK attributes: %v", err)
	}

	// Get EK certificate for the certificate chain
	ekCert, err := config.TPMModule.EKCertificate()
	if err != nil {
		return nil, caerrors.BadAttestationStatementError("failed to get EK certificate: %v", err)
	}

	// Determine the COSE algorithm from the quote's signature algorithm
	// If not available, fall back to the IAK attributes
	coseAlg := COSEAlgorithmUnknown
	if quote.SignatureAlgorithm != 0 {
		coseAlg = COSEAlgorithmFromSignatureAlgorithm(quote.SignatureAlgorithm)
	} else if iakAttrs.SignatureAlgorithm != 0 {
		coseAlg = COSEAlgorithmFromSignatureAlgorithm(iakAttrs.SignatureAlgorithm)
	}

	// Default to RS256 if algorithm couldn't be determined
	if coseAlg == COSEAlgorithmUnknown {
		coseAlg = COSEAlgorithmRS256
		c.logger.Warn("could not determine signature algorithm, defaulting to RS256")
	}

	// Create attestation object with configurable algorithm
	attestObj := map[string]interface{}{
		"fmt": "tpm",
		"attStmt": map[string]interface{}{
			"ver":      "2.0",
			"alg":      int(coseAlg),
			"x5c":      []interface{}{ekCert.Raw},
			"sig":      quote.Signature,
			"certInfo": quote.Quote,
			"pubArea":  iakAttrs.TPMPublicBytes,
		},
	}

	// Encode attestation object as JSON
	return json.Marshal(attestObj)
}

// startAttestServer starts an HTTP server for device-attest-01 challenge handling
func (c *Client) startAttestServer(config *EnrollmentConfig, attestStmt []byte, token string) {
	mux := http.NewServeMux()

	// Challenge endpoint - serves attestation statement
	challengePath := "/.well-known/acme-challenge/"
	mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, token) {
			http.NotFound(w, r)
			return
		}

		// Wrap attestation in the expected request format
		attestReq := map[string]interface{}{
			"attStmt": attestStmt,
		}

		jsonData, err := json.Marshal(attestReq)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(jsonData); err != nil {
			c.logger.Error("failed to write device-attest-01 challenge response", "error", err)
		}
	})

	addr := config.listenAddr()
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	c.logger.Debug("starting device-attest-01 HTTP server", "addr", addr)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		c.logger.Error("HTTP server error", "error", err)
	}
}

// parseIssuingChain parses the certificates a server appended after the
// end-entity certificate(s), per RFC 8555 §7.4.2. Order is preserved:
// leaf-ward first, root last.
//
// An unparseable entry is an error rather than a silent skip. The chain is
// what lets a caller resolve the issuer of its own certificate, and a
// partial chain would fail later and further from the cause. A server that
// sends no chain yields an empty result, which is tolerated so an older
// enrollment server still works.
func parseIssuingChain(ders [][]byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for i, der := range ders {
		issuer, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, caerrors.MalformedError(
				"enrollment failed: failed to parse issuing chain certificate %d: %v", i, err)
		}
		chain = append(chain, issuer)
	}
	return chain, nil
}
