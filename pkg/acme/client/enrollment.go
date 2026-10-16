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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	acmeserver "github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
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

	// IPAddress specifies the target IP address (supports ${ENV_VAR} expansion).
	// Required for enroll-01 and endorse-01, whose server contacts the device
	// there. Ignored by device-attest-01: the client POSTs its attestation and
	// the server never contacts the device.
	IPAddress string `yaml:"ip" json:"ip" mapstructure:"ip"`

	// TPMModule provides TPM operations interface
	TPMModule TPMModule `yaml:"-" json:"-" mapstructure:"-"`

	// Port specifies the HTTP port for challenge communication (default: 8080).
	// Not used by device-attest-01, which opens no listener.
	Port string `yaml:"port,omitempty" json:"port,omitempty" mapstructure:"port"`

	// ListenHost is the host every challenge listener this enrollment opens
	// (enroll-01, endorse-01) binds, joined with Port
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
		return caerrors.Wrap(caerrors.Malformed, ErrInvalidChallenge, "invalid challenge type: %s", ec.Challenge)
	}

	if ec.TPMModule == nil {
		return ErrMissingTPMModule
	}

	if ec.IPAddress == "" && ec.Challenge != string(ChallengeTypeDeviceAttest01) {
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
			return "", caerrors.Wrap(caerrors.Malformed, ErrEnvVarNotFound, "environment variable not found: %s", varName)
		}

		result = strings.ReplaceAll(result, match[0], varValue)
	}

	return result, nil
}

// EnrollDevice performs TPM device enrollment using the enroll-01 challenge.
// Returns an EnrollmentResult containing both the IAK and IDevID certificates.
func (c *Client) EnrollDevice(ctx context.Context, config *EnrollmentConfig) (*EnrollmentResult, error) {
	if err := config.Validate(); err != nil {
		return nil, caerrors.Wrap(caerrors.Malformed, err, "invalid enrollment config")
	}

	// Expand environment variables in IP address
	ipAddress, err := expandEnvVars(config.IPAddress)
	if err != nil {
		return nil, caerrors.Wrap(caerrors.Malformed, err, "failed to expand IP address")
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

	// enrollSrv holds the challenge server for the authorization currently
	// being processed. The deferred shutdown below runs on every return
	// path -- success or error -- so the configured port is always free
	// again by the time EnrollDevice returns.
	var enrollSrv *challengeServer
	defer func() { enrollSrv.shutdown() }()

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

		// Start HTTP server to handle challenge. The listener binds
		// synchronously inside startEnrollServer, so a port conflict fails
		// fast here instead of surfacing later as an opaque
		// WaitAuthorization timeout, and no artificial delay is needed
		// before the ACME server can reach it. A prior iteration's server
		// (a second authzURL on the same order) is shut down first: both
		// bind the same configured address.
		enrollSrv.shutdown()
		enrollSrv, err = c.startEnrollServer(config, idevidCSR, enrollChallenge.Token)
		if err != nil {
			return nil, caerrors.Wrap(caerrors.InternalServer, err, "enrollment failed: failed to start challenge server")
		}

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

	// Install the issued IAK certificate so a later device-attest-01
	// challenge (deviceattest01.Setup) can read it back via IAKCertificate
	// for the statement's x5c[0] -- without this, a device that enrolls and
	// attests in separate processes (the normal case on real hardware) has
	// no certificate to answer with, even though enrollment succeeded
	// (go-xkms#1100).
	if err := config.TPMModule.ProvisionIAKCert(iakCert); err != nil {
		return nil, caerrors.Wrap(caerrors.InternalServer, err, "enrollment failed: failed to install IAK certificate")
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

// challengeServer is a challenge-response HTTP server for the enroll-01 and
// device-attest-01 TPM enrollment challenges.
//
// newChallengeServer binds the listener synchronously, so a port conflict
// is reported to the caller immediately as a typed error instead of being
// discarded in a background goroutine's log line. shutdown blocks until the
// listener is closed and the serve goroutine has exited, so the port is
// free again the instant shutdown returns -- a long-running agent that
// enrolls twice never finds its own first attempt still holding the port.
type challengeServer struct {
	server       *http.Server
	done         chan struct{}
	shutdownOnce sync.Once
	logger       *slog.Logger
	label        string
}

// newChallengeServer binds addr synchronously via net.Listen and starts
// serving mux on a background goroutine. The returned *challengeServer must
// be released with shutdown to free addr; shutdown is nil-safe so it can be
// deferred unconditionally even when newChallengeServer returned an error.
func newChallengeServer(addr string, mux *http.ServeMux, logger *slog.Logger, label string) (*challengeServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to bind %s challenge listener on %s: %v", label, addr, err)
	}

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	cs := &challengeServer{
		server: server,
		done:   make(chan struct{}),
		logger: logger,
		label:  label,
	}

	go func() {
		defer close(cs.done)
		logger.Debug("starting challenge HTTP server", "server", label, "addr", addr)
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "server", label, "error", err)
		}
	}()

	return cs, nil
}

// shutdown gracefully stops the server and waits for its serve goroutine to
// exit before returning, guaranteeing the listener's port is free by the
// time shutdown returns. Idempotent and nil-receiver safe.
func (cs *challengeServer) shutdown() {
	if cs == nil {
		return
	}
	cs.shutdownOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := cs.server.Shutdown(ctx); err != nil {
			cs.logger.Error("challenge server shutdown error", "server", cs.label, "error", err)
		}
		<-cs.done
	})
}

// startEnrollServer builds the enroll-01 challenge mux and binds it to
// config.listenAddr() synchronously, returning a *challengeServer the
// caller must shut down (see challengeServer.shutdown) to release the port.
func (c *Client) startEnrollServer(config *EnrollmentConfig, idevidCSR *IDevIDCSR, token string) (*challengeServer, error) {
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

		// Limit the size of the request body to prevent abuse. This must run
		// before any read of r.Body: reading first and wrapping afterward
		// never applies the limit, since the unbounded read has already
		// buffered the whole body in memory (mirrors enroll01.activateCredentialHandlerWithShutdown).
		r.Body = http.MaxBytesReader(w, r.Body, acmeserver.MaxRequestBodySize)
		defer func() { _ = r.Body.Close() }()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
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

	return newChallengeServer(config.listenAddr(), mux, c.logger, "enroll-01")
}

// RequestEndorsementKeyCertificate requests an EK certificate via endorse-01 challenge.
// This is used for TPMs without manufacturer-issued EK certificates (e.g., swtpm, virtual TPMs).
// The flow uses the serialized EK public key as the permanent identifier, and the server
// validates the request via EAB or server policy (the endorse-01 verifier returns nil).
func (c *Client) RequestEndorsementKeyCertificate(ctx context.Context, config *EnrollmentConfig) (*x509.Certificate, error) {
	if err := config.Validate(); err != nil {
		return nil, caerrors.Wrap(caerrors.Malformed, err, "invalid enrollment config")
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

		// Limit the size of the request body to prevent abuse. This must run
		// before any read of r.Body: reading first and wrapping afterward
		// never applies the limit, since the unbounded read has already
		// buffered the whole body in memory (mirrors enroll01.activateCredentialHandlerWithShutdown).
		r.Body = http.MaxBytesReader(w, r.Body, acmeserver.MaxRequestBodySize)
		defer func() { _ = r.Body.Close() }()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
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
// (draft-ietf-acme-device-attest-10).
//
// The certificate is issued for the TPM key config.TPMModule attests under
// config.CommonName (TPMModule.CreateAttestedKey): the challenge response is
// the IAK's TPM2_Certify of that key, and the CSR is signed by it, which is
// what lets the server bind the one to the other.
//
// The client answers each challenge by POSTing it the attestation as
// {"attObj": base64url(CBOR)}; the server verifies it from that payload and
// NEVER CONTACTS THE DEVICE. DeviceAttest therefore opens no listener, needs no
// address for the device (config.IPAddress, Port and ListenHost are unused),
// and works for a device the server could not reach: one behind NAT, or on a
// serial port with this process as its gateway.
//
// The order's permanent-identifier is the device's own identity
// (TPMModule.DeviceIdentity): the server refuses a challenge whose attested
// identity is not the order's identifier, and an IP address is never an
// attested identity.
func (c *Client) DeviceAttest(ctx context.Context, config *EnrollmentConfig) (*x509.Certificate, error) {
	if err := config.Validate(); err != nil {
		return nil, caerrors.Wrap(caerrors.Malformed, err, "invalid enrollment config")
	}

	deviceIdentity, err := config.TPMModule.DeviceIdentity()
	if err != nil {
		return nil, caerrors.Wrap(caerrors.InternalServer, err, "attestation failed: the device identity is unavailable")
	}

	c.logger.Info("starting device attestation",
		"challenge", config.Challenge,
		"device_identity", deviceIdentity)

	// Create order for attestation
	order, err := c.authorizeOrder(ctx, []acme.AuthzID{
		{
			Type:  string(AuthzTypePermanentIdentifier),
			Value: deviceIdentity,
		},
	})
	if err != nil {
		return nil, caerrors.InternalServerError("attestation failed: failed to create order: %v", err)
	}

	c.logger.Debug("order created",
		"order_uri", order.URI,
		"status", order.Status)

	// Process authorizations. Every one is answered for the same key, the
	// one the CSR is signed with below.
	var attested *AttestedKey
	var attestedKeyAuth string

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

		// Attest the certificate key over this challenge. The statement is
		// the payload the server verifies; nothing is served.
		attested, err = c.setupAttestChallenge(config, keyAuth)
		if err != nil {
			return nil, caerrors.InternalServerError("attestation failed: challenge setup failed: %v", err)
		}
		attestedKeyAuth = keyAuth

		// Respond to the challenge with the attestation as its payload
		// (golang.org/x/crypto/acme sends Challenge.Payload in place of "{}").
		attestChallenge.Payload = attested.Statement
		_, err = c.client.Accept(ctx, attestChallenge)
		if err != nil {
			return nil, caerrors.InternalServerError("attestation failed: failed to accept challenge: %v", err)
		}

		c.logger.Debug("challenge answered, waiting for authorization")

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

	if attested == nil {
		return nil, caerrors.InternalServerError("attestation failed: the order carried no authorization to attest")
	}

	csrDER, err := attestedKeyCSR(config.CommonName, deviceIdentity, attestedKeyAuth, attested)
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

// deviceAttestCSR is the device-attest-01 finalize request. It is signed by
// the attested key, because the server certifies the key the device's TPM
// certified and no other, and it names the order's permanent identifier in the
// RFC 4043 permanentIdentifier otherName the server matches the order against
// -- never the Common Name, which is display text.
// attestedKeyCSR is the finalize request for the attested key. A DICE device
// mints it from the possession template over the challenge it answered
// (go-xkms#1441), carrying the claims set of the alias certificate it
// attested with; every other format sends an ordinary request naming the
// device.
func attestedKeyCSR(commonName, deviceIdentity, keyAuth string, attested *AttestedKey) ([]byte, error) {
	if attested.Format != deviceattest01.FormatDICE {
		return deviceAttestCSR(commonName, deviceIdentity, attested.Signer)
	}
	claims, err := aliasClaims(attested.Statement)
	if err != nil {
		return nil, err
	}
	return deviceattest01.SignPossessionCSR(attested.Signer, claims, deviceattest01.DICENonce(keyAuth))
}

// aliasClaims reads the claims set of the alias certificate a "dice"
// attestation statement carries: the leaf of its x5c.
func aliasClaims(statement []byte) (*dice.ClaimsSet, error) {
	object, err := deviceattest01.ParseAttestationRequest(statement)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAttestationFailed, Detail: "the DICE statement does not parse", Cause: err}
	}
	if len(object.AttStatement.X5c) == 0 {
		return nil, &errs.Detail{Err: ErrAttestationFailed, Detail: "the DICE statement carries no alias certificate"}
	}
	leafDER, ok := object.AttStatement.X5c[0].([]byte)
	if !ok {
		return nil, &errs.Detail{Err: ErrAttestationFailed, Detail: "the DICE alias certificate is not a byte string"}
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAttestationFailed, Detail: "the DICE alias certificate does not parse", Cause: err}
	}
	claims, err := dice.UccsFromCertificate(leaf)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAttestationFailed, Detail: "the DICE alias certificate carries no readable claims set", Cause: err}
	}
	return claims, nil
}

func deviceAttestCSR(commonName, permanentIdentifier string, signer crypto.Signer) ([]byte, error) {
	identifier, err := ca.MarshalPermanentIdentifier(permanentIdentifier, nil)
	if err != nil {
		return nil, err
	}
	subject := pkix.Name{CommonName: commonName}
	san, err := ca.BuildSubjectAltName(subject, nil, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: identifier}}, nil)
	if err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{
		Subject:         subject,
		ExtraExtensions: []pkix.Extension{san},
	}
	return x509.CreateCertificateRequest(rand.Reader, template, signer)
}

// setupAttestChallenge answers a device-attest-01 challenge: the TPM
// certifies the certificate key named config.CommonName over keyAuth, and the
// returned key signs the CSR at finalization.
func (c *Client) setupAttestChallenge(config *EnrollmentConfig, keyAuth string) (*AttestedKey, error) {
	attested, err := config.TPMModule.CreateAttestedKey(config.CommonName, keyAuth)
	if err != nil {
		return nil, caerrors.BadAttestationStatementError("failed to attest the certificate key: %v", err)
	}
	return attested, nil
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
