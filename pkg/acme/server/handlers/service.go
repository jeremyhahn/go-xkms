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

package handlers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

var (
	// ErrKIDAndJWKNotAllowed is returned when both KID and JWK are present in JWS header
	ErrKIDAndJWKNotAllowed = errors.New("handlers: both kid and jwk not allowed in JWS header")

	// ErrInvalidAccountID is returned when the account ID cannot be parsed
	ErrInvalidAccountID = errors.New("handlers: invalid account ID")

	// ErrAccountNotFound is returned when an account cannot be found
	ErrAccountNotFound = errors.New("handlers: account not found")

	// ErrAccountDeactivated is returned when a deactivated account tries to make requests
	// RFC 8555 Section 7.3.6: "Once an account is deactivated, the server MUST NOT
	// accept further requests authorized by that account's key."
	ErrAccountDeactivated = errors.New("handlers: account deactivated")

	// ErrInvalidJWSSignature is returned when JWS signature verification fails
	ErrInvalidJWSSignature = errors.New("handlers: invalid JWS signature")

	// ErrFailedToGenerateID is returned when ID generation fails
	ErrFailedToGenerateID = errors.New("handlers: failed to generate ID")

	// ErrFailedToGenerateToken is returned when token generation fails
	ErrFailedToGenerateToken = errors.New("handlers: failed to generate token")

	// ErrUnsupportedKeyType is returned for unsupported public key types
	ErrUnsupportedKeyType = errors.New("handlers: unsupported key type")

	// ErrJWSURLMismatch is returned when the JWS "url" header field does not match
	// the request URL per RFC 8555 Section 6.3
	ErrJWSURLMismatch = errors.New("handlers: JWS url header does not match request URL")

	// randReader is the random reader used for ID and token generation.
	// This is a package-level variable to allow testing with mock readers.
	randReader io.Reader = rand.Reader
)

// NonceGeneratorFunc is a function type for generating nonces.
// This allows dependency injection for testing error paths.
type NonceGeneratorFunc func(length int) (string, error)

// RestServicer defines the interface for ACME REST service handlers.
// Each handler corresponds to an ACME protocol endpoint per RFC 8555.
type RestServicer interface {
	// AccountHandler retrieves account information
	AccountHandler(w http.ResponseWriter, r *http.Request)

	// AuthorizationHandler retrieves authorization status
	AuthorizationHandler(w http.ResponseWriter, r *http.Request)

	// CertificateHandler downloads a certificate
	CertificateHandler(w http.ResponseWriter, r *http.Request)

	// ChallengeHandler initiates or retrieves challenge status
	ChallengeHandler(w http.ResponseWriter, r *http.Request)

	// DirectoryHandler provides ACME directory endpoints
	DirectoryHandler(w http.ResponseWriter, r *http.Request)

	// NewAccountHandler creates a new ACME account
	NewAccountHandler(w http.ResponseWriter, r *http.Request)

	// NewNonceHandler generates a new nonce
	NewNonceHandler(w http.ResponseWriter, r *http.Request)

	// NewOrderHandler creates a new certificate order
	NewOrderHandler(w http.ResponseWriter, r *http.Request)

	// OrderHandler retrieves order status
	OrderHandler(w http.ResponseWriter, r *http.Request)

	// OrdersListHandler lists orders for an account
	OrdersListHandler(w http.ResponseWriter, r *http.Request)

	// OrderFinalizeHandler finalizes an order with a CSR
	OrderFinalizeHandler(w http.ResponseWriter, r *http.Request)

	// RevokeCertHandler revokes a certificate
	RevokeCertHandler(w http.ResponseWriter, r *http.Request)

	// KeyChangeHandler performs account key rollover
	KeyChangeHandler(w http.ResponseWriter, r *http.Request)

	// CABundleHandler returns the CA bundle (non-RFC 8555 compliant)
	CABundleHandler(w http.ResponseWriter, r *http.Request)
}

const (
	nonceSize = 16
)

// Params contains the configuration parameters for the ACME REST service.
type Params struct {
	// BaseRESTURI is the base URL for ACME endpoints (e.g., "https://acme.example.com")
	BaseRESTURI string

	// CA is the certificate authority for issuing certificates
	CA ca.TCGCA

	// CAAIdentities are the CAA identities for this server
	CAAIdentities []string

	// CAAValidator performs CAA validation before certificate issuance
	// If nil, CAA validation will be disabled
	CAAValidator CAAValidatorInterface

	// ChallengeMap maps challenge types to their verifier functions
	ChallengeMap map[string]common.ChallengeVerifierFunc

	// EndorseEABRequired indicates whether EAB is required for endorse-01 challenges.
	// When true, accounts attempting endorse-01 challenges must have been created
	// with External Account Binding that authorizes EK certificate issuance.
	EndorseEABRequired bool

	// EndorseDeviceIDMetaKey is the metadata key used to validate device identity
	// in EAB for endorse-01 challenges. If empty, device ID validation is skipped.
	// Common values: "device_id", "ek_pubkey_hash", "serial_number"
	EndorseDeviceIDMetaKey string

	// ExternalAccountRequired indicates whether external account binding is required
	// per RFC 8555 Section 7.3.4. When true, newAccount requests MUST include an
	// externalAccountBinding field associating the new account with an external account.
	ExternalAccountRequired bool

	// Logger is the structured logger
	Logger *slog.Logger

	// NonceGenerator is the function used to generate nonces.
	// If nil, uses common.GenerateNonce.
	// This allows tests to inject a failing generator for error path testing.
	NonceGenerator NonceGeneratorFunc

	// StorageFactory creates DAO instances for persistence
	StorageFactory storage.Factory

	// TermsOfService is the URL to the terms of service
	TermsOfService string

	// OrderFinalizeHooks is the registry of hooks to execute upon successful order finalization
	// Applications can register custom hooks to perform actions like DNS registration,
	// device inventory updates, notifications, etc.
	OrderFinalizeHooks *OrderFinalizeHookRegistry

	// PreIssuanceHooks is the registry of hooks to execute BEFORE certificate signing.
	// These hooks can validate compliance, attestation, or any other criteria and
	// return an error to block certificate issuance.
	PreIssuanceHooks *PreIssuanceHookRegistry

	// GlobalComplianceConfig is the server-wide default compliance configuration.
	// This is used as a fallback when tenants don't have their own compliance config.
	GlobalComplianceConfig *GlobalComplianceConfig

	// KMSService provides key management for tenant CA signing.
	// When configured, the service can sign certificates using tenant-specific CA keys
	// managed by QRDB KMS instead of the global CA.
	// If nil, all certificates are signed by the global CA.
	KMSService kms.KMSService
}

// CAAValidatorInterface defines the interface for CAA validation.
// This allows for dependency injection and testing with mock validators.
type CAAValidatorInterface interface {
	Validate(ctx context.Context, domain string, isWildcard bool) error
}

// RestService implements the ACME REST service handlers.
type RestService struct {
	baseRESTURI             string
	ca                      ca.TCGCA
	caaIdentities           []string
	caaValidator            CAAValidatorInterface
	challengeMap            map[string]common.ChallengeVerifierFunc
	endorseEABRequired      bool
	endorseDeviceIDMetaKey  string
	externalAccountRequired bool
	globalComplianceConfig  *GlobalComplianceConfig
	kmsService              kms.KMSService
	logger                  *slog.Logger
	nonceGenerator          NonceGeneratorFunc
	nonceStore              *common.NonceStore
	orderFinalizeHooks      *OrderFinalizeHookRegistry
	params                  *Params
	preIssuanceHooks        *PreIssuanceHookRegistry
	storageFactory          storage.Factory
	termsOfService          string
	RestServicer
}

// NewRestService creates a new ACME REST service with the provided parameters.
func NewRestService(params *Params) (RestServicer, error) {
	if params == nil {
		return nil, caerrors.MalformedError("handlers: params cannot be nil")
	}

	if params.BaseRESTURI == "" {
		return nil, caerrors.MalformedError("handlers: BaseRESTURI is required")
	}

	if params.CA == nil {
		return nil, caerrors.MalformedError("handlers: CA is required")
	}

	if params.Logger == nil {
		return nil, caerrors.MalformedError("handlers: Logger is required")
	}

	if params.StorageFactory == nil {
		return nil, caerrors.MalformedError("handlers: StorageFactory is required")
	}

	// Default challenge map if not provided
	if params.ChallengeMap == nil {
		params.ChallengeMap = make(map[string]common.ChallengeVerifierFunc)
	}

	// Default nonce generator if not provided
	nonceGen := params.NonceGenerator
	if nonceGen == nil {
		nonceGen = common.GenerateNonce
	}

	return &RestService{
		baseRESTURI:             params.BaseRESTURI,
		ca:                      params.CA,
		caaIdentities:           params.CAAIdentities,
		caaValidator:            params.CAAValidator,
		challengeMap:            params.ChallengeMap,
		endorseEABRequired:      params.EndorseEABRequired,
		endorseDeviceIDMetaKey:  params.EndorseDeviceIDMetaKey,
		externalAccountRequired: params.ExternalAccountRequired,
		globalComplianceConfig:  params.GlobalComplianceConfig,
		kmsService:              params.KMSService,
		logger:                  params.Logger,
		nonceGenerator:          nonceGen,
		nonceStore:              common.NewNonceStore(time.Minute * 10),
		orderFinalizeHooks:      params.OrderFinalizeHooks,
		params:                  params,
		preIssuanceHooks:        params.PreIssuanceHooks,
		storageFactory:          params.StorageFactory,
		termsOfService:          params.TermsOfService,
	}, nil
}

// GetStorageFactory returns the storage factory for creating DAOs.
// This is useful for tests that need to verify storage state.
func (s *RestService) GetStorageFactory() storage.Factory {
	return s.storageFactory
}

// GetNonceStore returns the nonce store for managing replay protection.
// This is useful for tests that need to add valid nonces.
func (s *RestService) GetNonceStore() *common.NonceStore {
	return s.nonceStore
}

// SetOrderFinalizeHooks sets the order finalize hook registry.
// This allows tests to register custom hooks for order finalization.
func (s *RestService) SetOrderFinalizeHooks(registry *OrderFinalizeHookRegistry) {
	s.orderFinalizeHooks = registry
	// Also update params for handler code that checks s.params.OrderFinalizeHooks
	if s.params != nil {
		s.params.OrderFinalizeHooks = registry
	}
}

// GetOrderFinalizeHooks returns the order finalize hook registry.
func (s *RestService) GetOrderFinalizeHooks() *OrderFinalizeHookRegistry {
	return s.orderFinalizeHooks
}

// SetPreIssuanceHooks sets the pre-issuance hook registry.
// This allows applications to register hooks that execute BEFORE certificate signing.
func (s *RestService) SetPreIssuanceHooks(registry *PreIssuanceHookRegistry) {
	s.preIssuanceHooks = registry
	// Also update params for handler code that checks s.params.PreIssuanceHooks
	if s.params != nil {
		s.params.PreIssuanceHooks = registry
	}
}

// GetPreIssuanceHooks returns the pre-issuance hook registry.
func (s *RestService) GetPreIssuanceHooks() *PreIssuanceHookRegistry {
	return s.preIssuanceHooks
}

// SetGlobalComplianceConfig sets the global compliance configuration.
// This allows applications to configure server-wide compliance settings.
func (s *RestService) SetGlobalComplianceConfig(config *GlobalComplianceConfig) {
	s.globalComplianceConfig = config
	// Also update params for handler code that checks s.params.GlobalComplianceConfig
	if s.params != nil {
		s.params.GlobalComplianceConfig = config
	}
}

// GetGlobalComplianceConfig returns the global compliance configuration.
func (s *RestService) GetGlobalComplianceConfig() *GlobalComplianceConfig {
	return s.globalComplianceConfig
}

// SetCAAValidator sets the CAA validator.
// This allows tests to inject mock validators.
func (s *RestService) SetCAAValidator(validator CAAValidatorInterface) {
	s.caaValidator = validator
}

// GetCAAValidator returns the CAA validator.
func (s *RestService) GetCAAValidator() CAAValidatorInterface {
	return s.caaValidator
}

// SetNonceGenerator sets the nonce generator function.
// This allows tests to inject a failing generator for error path testing.
func (s *RestService) SetNonceGenerator(gen NonceGeneratorFunc) {
	s.nonceGenerator = gen
}

// GetNonceGenerator returns the nonce generator function.
func (s *RestService) GetNonceGenerator() NonceGeneratorFunc {
	return s.nonceGenerator
}

// generateNonce generates a nonce using the configured generator.
// This internal method allows all nonce generation to be controlled via dependency injection.
func (s *RestService) generateNonce(length int) (string, error) {
	return s.nonceGenerator(length)
}

// respondWithAccount writes an ACME account response to the HTTP response writer.
func (s *RestService) respondWithAccount(
	w http.ResponseWriter, account *entities.ACMEAccount, statusCode int) {

	nonce, err := s.generateNonce(nonceSize)
	if err != nil {
		writeError(w, common.ServerInternal("Unable to generate nonce"))
		return
	}
	s.nonceStore.Add(nonce)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", fmt.Sprintf("%s/acme/directory>;rel=\"index\"", s.baseRESTURI))
	w.Header().Set("Location", s.accountURL(account))
	w.WriteHeader(statusCode)

	// Per RFC 8555 Section 7.1.2, account response includes externalAccountBinding
	// when the account was created with one
	clientAccount := struct {
		Status                 string      `json:"status"`
		Contact                []string    `json:"contact,omitempty"`
		Orders                 string      `json:"orders"`
		ExternalAccountBinding interface{} `json:"externalAccountBinding,omitempty"`
	}{
		Status:                 account.Status,
		Contact:                account.Contact,
		Orders:                 account.Orders,
		ExternalAccountBinding: account.ExternalAccountBinding,
	}

	s.encodeJSON(w, clientAccount)
}

// accountURL returns the URL for an account resource.
func (s *RestService) accountURL(account *entities.ACMEAccount) string {
	return fmt.Sprintf("%s/acme/account/%d", s.baseRESTURI, account.ID)
}

// ValidateContactURLs validates ACME contact URLs per RFC 8555.
// Only mailto URLs are currently supported.
func ValidateContactURLs(contacts []string) *entities.Error {
	for _, contact := range contacts {
		if strings.HasPrefix(contact, "mailto:") {
			emailAddress := strings.TrimPrefix(contact, "mailto:")
			// Check for 'hfields' and multiple 'addr-spec'
			if strings.Contains(emailAddress, "?") {
				return common.InvalidContact("Invalid mailto URL: contains hfields")
			}
			if strings.Contains(emailAddress, ",") {
				return common.InvalidContact("Invalid mailto URL: contains multiple addr-spec")
			}
			if _, err := mail.ParseAddress(emailAddress); err != nil {
				return common.InvalidContact("Invalid mailto URL: invalid email address")
			}
		} else {
			return common.UnsupportedContact("Unsupported contact URL scheme")
		}
	}
	return nil
}

// orderResponse writes an ACME order response to the HTTP response writer.
func (s *RestService) orderResponse(w http.ResponseWriter, order *entities.ACMEOrder) {
	nonce, err := s.generateNonce(nonceSize)
	if err != nil {
		writeError(w, common.ServerInternal("Unable to generate nonce"))
		return
	}
	s.nonceStore.Add(nonce)

	clientOrder := struct {
		Status         string                    `json:"status"`
		Expires        string                    `json:"expires,omitempty"`
		Identifiers    []entities.ACMEIdentifier `json:"identifiers"`
		NotBefore      string                    `json:"notBefore,omitempty"`
		NotAfter       string                    `json:"notAfter,omitempty"`
		Error          *entities.Error           `json:"error,omitempty"`
		Authorizations []string                  `json:"authorizations"`
		Finalize       string                    `json:"finalize"`
		Certificate    string                    `json:"certificate,omitempty"`
	}{
		Status:         order.Status,
		Expires:        order.Expires,
		Identifiers:    order.Identifiers,
		NotBefore:      order.NotBefore,
		NotAfter:       order.NotAfter,
		Error:          order.Error,
		Authorizations: order.Authorizations,
		Finalize:       order.Finalize,
		Certificate:    order.Certificate,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", s.baseRESTURI))
	s.encodeJSON(w, clientOrder)
}

// encodeJSON encodes the value as JSON to the response writer and logs any errors.
// This helper ensures JSON encoding errors are never silently ignored.
func (s *RestService) encodeJSON(w http.ResponseWriter, v any) {
	encodeJSONWithLogger(w, v, s.logger)
}

// encodeJSONWithLogger encodes JSON and logs errors using the provided logger.
// If logger is nil, uses slog.Default().
func encodeJSONWithLogger(w http.ResponseWriter, v any, logger *slog.Logger) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("failed to encode JSON response",
			slog.String("error", err.Error()))
	}
}

// challengeResponse writes an ACME challenge response to the HTTP response writer.
func challengeResponse(w http.ResponseWriter, challenge *entities.ACMEChallenge) {
	clientChallenge := struct {
		Type      string          `json:"type"`
		URL       string          `json:"url"`
		Status    string          `json:"status"`
		Token     string          `json:"token"`
		Validated string          `json:"validated,omitempty"`
		Error     *entities.Error `json:"error,omitempty"`
	}{
		Type:      challenge.Type,
		URL:       challenge.URL,
		Status:    challenge.Status,
		Token:     challenge.Token,
		Validated: challenge.Validated,
		Error:     challenge.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	encodeJSONWithLogger(w, clientChallenge, nil)
}

// writeError writes an ACME error response to the HTTP response writer.
func writeError(w http.ResponseWriter, err *entities.Error) {
	w.Header().Set("Content-Type", "application/problem+json")
	if err.Status == 0 {
		err.Status = http.StatusInternalServerError
	}
	w.WriteHeader(err.Status)
	encodeJSONWithLogger(w, err, nil)
}

// requestURL reconstructs the full request URL from the base REST URI and
// the request path. When ACME routes are mounted under a path prefix
// (e.g., /api/v1), r.URL.Path includes the full prefix while baseRESTURI
// already contains it. This method strips the overlapping prefix to avoid
// doubling (e.g., https://host/api/v1/api/v1/acme/new-account).
func (s *RestService) requestURL(r *http.Request) (string, error) {
	parsedBase, err := url.Parse(s.baseRESTURI)
	if err != nil {
		return "", caerrors.InternalServerError("failed to parse base URI: %v", err)
	}
	relPath := strings.TrimPrefix(r.URL.Path, parsedBase.Path)
	return s.baseRESTURI + relPath, nil
}

// parseKID parses a JWS request with a KID (Key ID) in the protected header.
// It validates the JWS signature, nonce, and retrieves the associated account.
func (s *RestService) parseKID(ctx context.Context, r *http.Request) (*entities.ACMEAccount, []byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, caerrors.InternalServerError("failed to read request body: %v", err)
	}
	defer func() { _ = r.Body.Close() }()

	jwsString := strings.TrimSpace(string(body))
	jws, err := jose.ParseSigned(jwsString, server.AllowedJOSEAlgorithms)
	if err != nil {
		return nil, nil, caerrors.MalformedError("failed to parse JWS: %v", err)
	}

	if len(jws.Signatures) == 0 {
		return nil, nil, caerrors.MalformedError("no signatures found in JWS")
	}

	protectedHeader := jws.Signatures[0].Header

	if protectedHeader.JSONWebKey != nil && protectedHeader.KeyID != "" {
		return nil, nil, ErrKIDAndJWKNotAllowed
	}

	if protectedHeader.KeyID == "" {
		return nil, nil, caerrors.MalformedError("KID not found in JWS header")
	}

	if !s.nonceStore.Exists(protectedHeader.Nonce) {
		return nil, nil, common.BadNonce("Invalid or missing Replay-Nonce")
	}

	// RFC 8555 Section 6.3: Validate that the JWS "url" header field matches
	// the request URL. This prevents replay attacks where a signed JWS intended
	// for one endpoint is submitted to a different endpoint.
	expectedURL, urlErr := s.requestURL(r)
	if urlErr != nil {
		return nil, nil, urlErr
	}
	jwsURL, ok := protectedHeader.ExtraHeaders["url"].(string)
	if !ok || jwsURL != expectedURL {
		return nil, nil, caerrors.MalformedError("JWS url header does not match request URL")
	}

	accountID, err := ParseAccountID(protectedHeader.KeyID)
	if err != nil {
		return nil, nil, ErrInvalidAccountID
	}

	accountDAO, err := s.storageFactory.AccountDAO()
	if err != nil {
		return nil, nil, caerrors.StorageFailureError("failed to create account DAO")
	}

	account, err := accountDAO.Get(ctx, accountID)
	if err != nil {
		// Distinguish between "not found" and storage errors
		if qrdbsdk.IsDAONotFound(err) {
			return nil, nil, ErrAccountNotFound
		}
		// For storage failures, return a more specific error
		return nil, nil, caerrors.StorageFailureError("storage error retrieving account: %v", err)
	}

	// RFC 8555 Section 7.3.6: Reject requests from deactivated accounts
	// "Once an account is deactivated, the server MUST NOT accept further
	// requests authorized by that account's key."
	if account.Status == common.StatusDeactivated {
		return nil, nil, ErrAccountDeactivated
	}

	publicKey, err := xkmssdk.DecodePublicKeyPEM([]byte(account.Key))
	if err != nil {
		return nil, nil, caerrors.MalformedError("failed to decode account public key")
	}

	payload, err := jws.Verify(publicKey)
	if err != nil {
		return nil, nil, ErrInvalidJWSSignature
	}

	return account, payload, nil
}

// parseJWS parses a JWS request with a JWK (JSON Web Key) in the protected header.
// This is used for new account creation where no KID exists yet.
func (s *RestService) parseJWS(r *http.Request) (*jose.JSONWebKey, []byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, caerrors.InternalServerError("failed to read request body: %v", err)
	}
	defer func() { _ = r.Body.Close() }()

	jwsString := strings.TrimSpace(string(body))
	jws, err := jose.ParseSigned(jwsString, server.AllowedJOSEAlgorithms)
	if err != nil {
		return nil, nil, caerrors.MalformedError("failed to parse JWS: %v", err)
	}

	if len(jws.Signatures) == 0 {
		return nil, nil, caerrors.MalformedError("no signatures found in JWS")
	}

	protectedHeader := jws.Signatures[0].Header

	if protectedHeader.JSONWebKey == nil {
		return nil, nil, caerrors.MalformedError("JWK not found in JWS header")
	}

	if !s.nonceStore.Exists(protectedHeader.Nonce) {
		return nil, nil, common.BadNonce("Invalid or missing Replay-Nonce")
	}

	// RFC 8555 Section 6.3: Validate that the JWS "url" header field matches
	// the request URL. This prevents replay attacks where a signed JWS intended
	// for one endpoint is submitted to a different endpoint.
	expectedURL, urlErr := s.requestURL(r)
	if urlErr != nil {
		return nil, nil, urlErr
	}
	jwsURL, ok := protectedHeader.ExtraHeaders["url"].(string)
	if !ok || jwsURL != expectedURL {
		return nil, nil, caerrors.MalformedError("JWS url header does not match request URL")
	}

	jwk := protectedHeader.JSONWebKey
	payload, err := jws.Verify(jwk)
	if err != nil {
		return nil, nil, ErrInvalidJWSSignature
	}

	return jwk, payload, nil
}

// KeyAuthorization computes the key authorization for a challenge token.
// Format: token.thumbprint where thumbprint is the JWK thumbprint.
func KeyAuthorization(token string, accountKey crypto.PublicKey) (string, error) {
	jwkThumbprint, err := JWKThumbprint(accountKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, jwkThumbprint), nil
}

// JWKThumbprint computes the JWK thumbprint of a public key per RFC 7638.
// The thumbprint is base64url(SHA-256(UTF8(JWK canonical JSON))).
func JWKThumbprint(pubKey crypto.PublicKey) (string, error) {
	var jwk map[string]interface{}

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		nBytes := key.N.Bytes()
		eBytes := big.NewInt(int64(key.E)).Bytes()
		jwk = map[string]interface{}{
			"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		}
	case *ecdsa.PublicKey:
		// Use ECDH conversion to avoid deprecated ecdsa.PublicKey.X/Y fields.
		// ECDH().Bytes() returns the uncompressed point encoding (0x04 || X || Y)
		// with fixed-length, zero-padded coordinates.
		ecdhKey, err := key.ECDH()
		if err != nil {
			return "", caerrors.InternalServerError("failed to convert ECDSA key to ECDH: %v", err)
		}
		raw := ecdhKey.Bytes()
		// Uncompressed point format: 0x04 || X || Y
		coordLen := (len(raw) - 1) / 2
		xBytes := raw[1 : 1+coordLen]
		yBytes := raw[1+coordLen:]
		jwk = map[string]interface{}{
			"crv": key.Curve.Params().Name,
			"kty": "EC",
			"x":   base64.RawURLEncoding.EncodeToString(xBytes),
			"y":   base64.RawURLEncoding.EncodeToString(yBytes),
		}
	case ed25519.PublicKey:
		jwk = map[string]interface{}{
			"crv": "Ed25519",
			"kty": "OKP",
			"x":   base64.RawURLEncoding.EncodeToString(key),
		}
	default:
		return "", ErrUnsupportedKeyType
	}

	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return "", caerrors.SerializationFailureError("failed to marshal JWK: %v", err)
	}

	hasher := sha256.New()
	hasher.Write(jwkJSON)
	digest := hasher.Sum(nil)

	thumbprint := base64.RawURLEncoding.EncodeToString(digest)
	return thumbprint, nil
}

// ParseAccountID extracts the account ID from an account URL.
func ParseAccountID(accountURL string) (uint64, error) {
	pieces := strings.Split(accountURL, "/")
	accountID, err := strconv.ParseUint(pieces[len(pieces)-1], 10, 64)
	if err != nil {
		return 0, ErrInvalidAccountID
	}
	return accountID, nil
}

// AccountIDFromPublicKey generates a deterministic account ID from a public key.
// It uses the SHA-256 hash of the JWK thumbprint to create a uint64 ID.
func AccountIDFromPublicKey(pubKey crypto.PublicKey) (uint64, error) {
	thumbprint, err := JWKThumbprint(pubKey)
	if err != nil {
		return 0, err
	}
	// Use SHA-256 of thumbprint to generate deterministic uint64
	hash := sha256.Sum256([]byte(thumbprint))
	return binary.BigEndian.Uint64(hash[:8]), nil
}

// isValidDomainName validates a domain name per RFC 1035.
// Domain names must:
// - Be between 1 and 253 characters total
// - Consist of labels separated by dots
// - Each label must be 1-63 characters
// - Labels can contain lowercase letters, digits, and hyphens
// - Labels cannot start or end with a hyphen
// - Labels cannot be all numeric (except for the TLD)
func isValidDomainName(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 1 {
		return false
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}

		// Check for invalid characters and positioning
		for i, ch := range label {
			if !((ch >= 'a' && ch <= 'z') ||
				(ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') ||
				ch == '-') {
				return false
			}

			// Hyphens cannot be at the start or end
			if ch == '-' && (i == 0 || i == len(label)-1) {
				return false
			}
		}
	}

	return true
}

// GenerateID generates a cryptographically secure random ID.
func GenerateID() (uint64, error) {
	return generateIDWithReader(randReader)
}

// generateIDWithReader generates a cryptographically secure random ID using the provided reader.
// This internal function allows for testing with mock readers.
func generateIDWithReader(reader io.Reader) (uint64, error) {
	id := make([]byte, nonceSize)
	n, err := reader.Read(id)
	if err != nil {
		return 0, err
	}
	if n != nonceSize {
		return 0, ErrFailedToGenerateID
	}
	// Convert first 8 bytes to uint64
	return binary.BigEndian.Uint64(id[:8]), nil
}

// GenerateToken generates a cryptographically secure random token.
func GenerateToken() (string, error) {
	return generateTokenWithReader(randReader)
}

// generateTokenWithReader generates a cryptographically secure random token using the provided reader.
// This internal function allows for testing with mock readers.
func generateTokenWithReader(reader io.Reader) (string, error) {
	id := make([]byte, nonceSize)
	n, err := reader.Read(id)
	if err != nil {
		return "", err
	}
	if n != nonceSize {
		return "", ErrFailedToGenerateToken
	}
	return base64.RawURLEncoding.EncodeToString(id), nil
}
