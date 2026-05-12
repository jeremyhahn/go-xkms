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

// Package embedded provides an embedded in-process transport implementation
// for the Trusted CA SDK.
//
// The embedded transport enables direct in-process communication with the CA
// server without network overhead. This is useful for testing, embedded
// deployments, and scenarios where the CA runs in the same process as the client.
// It supports both ACME and Admin API operations.
//
// Example usage:
//
//	restService, _ := handlers.NewRestService(&handlers.Params{...})
//	cfg := &transport.Config{}
//	t, err := embedded.NewTransport(cfg, embedded.WithService(restService))
//	if err != nil {
//	    return err
//	}
//	defer t.Close()
//
//	// Make requests directly to the embedded service
//	resp, err := t.Request(ctx, "directory", "get", nil)
package embedded

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

// RestServicer defines the interface for ACME REST service handlers.
// This interface matches the handlers.RestServicer interface from pkg/acme/server/handlers
// but is defined here to avoid circular dependencies in the SDK.
type RestServicer interface {
	AccountHandler(w http.ResponseWriter, r *http.Request)
	AuthorizationHandler(w http.ResponseWriter, r *http.Request)
	CertificateHandler(w http.ResponseWriter, r *http.Request)
	ChallengeHandler(w http.ResponseWriter, r *http.Request)
	DirectoryHandler(w http.ResponseWriter, r *http.Request)
	NewAccountHandler(w http.ResponseWriter, r *http.Request)
	NewNonceHandler(w http.ResponseWriter, r *http.Request)
	NewOrderHandler(w http.ResponseWriter, r *http.Request)
	OrderHandler(w http.ResponseWriter, r *http.Request)
	OrdersListHandler(w http.ResponseWriter, r *http.Request)
	OrderFinalizeHandler(w http.ResponseWriter, r *http.Request)
	RevokeCertHandler(w http.ResponseWriter, r *http.Request)
	KeyChangeHandler(w http.ResponseWriter, r *http.Request)
}

// HandlerFunc is the function signature for ACME handlers.
type HandlerFunc func(w http.ResponseWriter, r *http.Request)

// routeKey combines service and method for map-based dispatch.
type routeKey struct {
	service string
	method  string
}

// Transport implements transport.Transport using direct in-process calls.
type Transport struct {
	cfg          *transport.Config
	service      RestServicer
	adminService AdminServicer
	handlers     map[routeKey]HandlerFunc
	healthy      atomic.Bool
}

// Option configures the embedded transport.
type Option func(*Transport) error

// WithService sets the REST service for the embedded transport.
func WithService(svc RestServicer) Option {
	return func(t *Transport) error {
		if svc == nil {
			return errors.NewInvalidInput("embedded.WithService", "service cannot be nil")
		}
		t.service = svc
		return nil
	}
}

// NewTransport creates a new embedded transport with the given configuration.
func NewTransport(cfg *transport.Config, opts ...Option) (transport.Transport, error) {
	if cfg == nil {
		return nil, errors.NewInvalidInput("embedded.NewTransport", "config cannot be nil")
	}

	t := &Transport{
		cfg:      cfg,
		handlers: make(map[routeKey]HandlerFunc),
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(t); err != nil {
			return nil, err
		}
	}

	// Validate that at least one service is provided
	if t.service == nil && t.adminService == nil {
		return nil, errors.NewConfiguration("embedded.NewTransport", "at least one service is required - use WithService and/or WithAdminService options")
	}

	// Initialize handler dispatch maps for O(1) routing
	if t.service != nil {
		t.initHandlers()
	}
	t.initAdminHandlers()

	t.healthy.Store(true)
	return t, nil
}

// initHandlers initializes the ACME handler dispatch map.
func (t *Transport) initHandlers() {
	t.handlers = map[routeKey]HandlerFunc{
		// Directory
		{service: "directory", method: "get"}: t.service.DirectoryHandler,

		// Nonce
		{service: "nonce", method: "new"}: t.service.NewNonceHandler,

		// Account
		{service: "account", method: "create"}:    t.service.NewAccountHandler,
		{service: "account", method: "get"}:       t.service.AccountHandler,
		{service: "account", method: "update"}:    t.service.AccountHandler,
		{service: "account", method: "keychange"}: t.service.KeyChangeHandler,

		// Order
		{service: "order", method: "create"}:   t.service.NewOrderHandler,
		{service: "order", method: "get"}:      t.service.OrderHandler,
		{service: "order", method: "list"}:     t.service.OrdersListHandler,
		{service: "order", method: "finalize"}: t.service.OrderFinalizeHandler,

		// Authorization
		{service: "authorization", method: "get"}: t.service.AuthorizationHandler,

		// Challenge
		{service: "challenge", method: "get"}:     t.service.ChallengeHandler,
		{service: "challenge", method: "respond"}: t.service.ChallengeHandler,

		// Certificate
		{service: "certificate", method: "get"}:    t.service.CertificateHandler,
		{service: "certificate", method: "revoke"}: t.service.RevokeCertHandler,
	}
}

// Request sends a unary request directly to the in-process CA.
func (t *Transport) Request(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
	const op = "embedded.Transport.Request"

	if !t.healthy.Load() {
		return nil, errors.NewUnavailable(op, "transport is not healthy")
	}

	// Look up handler using map-based dispatch
	key := routeKey{service: service, method: method}
	handler, ok := t.handlers[key]
	if !ok {
		return nil, errors.NewNotFound(op, "unknown service/method: "+service+"/"+method)
	}

	// Create mock HTTP request
	httpReq, err := t.createHTTPRequest(ctx, service, method, req)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidInput, op, "failed to create HTTP request")
	}

	// Create response recorder
	recorder := httptest.NewRecorder()

	// Call handler directly
	handler(recorder, httpReq)

	// Parse response
	return t.parseResponse(recorder, service, method)
}

// createHTTPRequest creates an HTTP request for the handler.
func (t *Transport) createHTTPRequest(ctx context.Context, service, method string, req interface{}) (*http.Request, error) {
	var body io.Reader
	httpMethod := http.MethodPost

	// Set HTTP method based on service/method
	switch {
	case service == "directory" && method == "get":
		httpMethod = http.MethodGet
	case service == "nonce" && method == "new":
		httpMethod = http.MethodHead
	case isAdminService(service):
		httpMethod = t.adminHTTPMethod(service, method)
	}

	// Serialize request body if present
	if req != nil {
		jsonBody, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(jsonBody)
	}

	// Build request URL (embedded uses placeholder URLs)
	url := "http://embedded/" + service + "/" + method
	httpReq, err := http.NewRequestWithContext(ctx, httpMethod, url, body)
	if err != nil {
		return nil, err
	}

	// Set content type for POST/PUT requests
	if (httpMethod == http.MethodPost || httpMethod == http.MethodPut) && body != nil {
		httpReq.Header.Set("Content-Type", "application/jose+json")
	}

	return httpReq, nil
}

// adminHTTPMethod returns the appropriate HTTP method for admin operations.
func (t *Transport) adminHTTPMethod(service, method string) string {
	switch method {
	case "create", "revoke", "createRootCA", "createIntermediateCA":
		return http.MethodPost
	case "update", "updateStatus", "updateIntermediateCAStatus":
		return http.MethodPut
	case "delete", "disable":
		return http.MethodDelete
	case "list", "get", "status", "stats", "listIntermediateCAs", "getIntermediateCA":
		return http.MethodGet
	default:
		return http.MethodPost
	}
}

// parseResponse parses the HTTP response and returns the appropriate type.
func (t *Transport) parseResponse(recorder *httptest.ResponseRecorder, service, method string) (interface{}, error) {
	const op = "embedded.Transport.parseResponse"

	// Check for error responses
	if recorder.Code >= 400 {
		return nil, t.parseErrorResponse(recorder)
	}

	// Get response body
	body := recorder.Body.Bytes()

	// Get nonce from headers
	nonce := recorder.Header().Get("Replay-Nonce")

	// Get location from headers
	location := recorder.Header().Get("Location")

	// For admin services, return a generic JSON response
	if isAdminService(service) {
		return t.parseAdminResponse(body, nonce, location)
	}

	// Parse based on ACME service/method
	return t.parseTypedResponse(body, nonce, location, service, method)
}

// parseAdminResponse parses admin responses as generic JSON.
func (t *Transport) parseAdminResponse(body []byte, nonce, location string) (interface{}, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "embedded.Transport.parseAdminResponse", "failed to parse admin response")
	}
	return result, nil
}

// parseTypedResponse parses the response into the appropriate SDK type.
func (t *Transport) parseTypedResponse(body []byte, nonce, location, service, method string) (interface{}, error) {
	const op = "embedded.Transport.parseTypedResponse"

	switch service {
	case "directory":
		return t.parseDirectoryResponse(body, nonce)
	case "nonce":
		return t.parseNonceResponse(nonce)
	case "account":
		return t.parseAccountResponse(body, nonce, location, method)
	case "order":
		return t.parseOrderResponse(body, nonce, location, method)
	case "authorization":
		return t.parseAuthorizationResponse(body, nonce)
	case "challenge":
		return t.parseChallengeResponse(body, nonce)
	case "certificate":
		return t.parseCertificateResponse(body, nonce, method)
	default:
		return nil, errors.NewNotFound(op, "unknown service: "+service)
	}
}

// parseDirectoryResponse parses a directory response.
func (t *Transport) parseDirectoryResponse(body []byte, nonce string) (interface{}, error) {
	const op = "embedded.Transport.parseDirectoryResponse"

	var dir directoryResponse
	if err := json.Unmarshal(body, &dir); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, op, "failed to parse directory response")
	}

	return &GetDirectoryResponse{
		NewNonce:   dir.NewNonce,
		NewAccount: dir.NewAccount,
		NewOrder:   dir.NewOrder,
		NewAuthz:   dir.NewAuthz,
		RevokeCert: dir.RevokeCert,
		KeyChange:  dir.KeyChange,
		Meta:       dir.Meta,
		Nonce:      nonce,
	}, nil
}

// parseNonceResponse parses a nonce response.
func (t *Transport) parseNonceResponse(nonce string) (interface{}, error) {
	const op = "embedded.Transport.parseNonceResponse"

	if nonce == "" {
		return nil, errors.NewInternal(op, "no nonce in response")
	}

	return &GetNonceResponse{
		Nonce: nonce,
	}, nil
}

// parseAccountResponse parses an account response.
func (t *Transport) parseAccountResponse(body []byte, nonce, location, method string) (interface{}, error) {
	const op = "embedded.Transport.parseAccountResponse"

	var acct accountResponse
	if err := json.Unmarshal(body, &acct); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, op, "failed to parse account response")
	}

	account := &AccountResponse{
		Status:                 acct.Status,
		Contact:                acct.Contact,
		Orders:                 acct.Orders,
		ExternalAccountBinding: acct.ExternalAccountBinding,
		Location:               location,
		Nonce:                  nonce,
	}

	switch method {
	case "create":
		return &CreateAccountResponse{Account: account, Location: location, Nonce: nonce}, nil
	case "get", "update":
		return &GetAccountResponse{Account: account, Nonce: nonce}, nil
	case "keychange":
		return &KeyChangeResponse{Account: account, Nonce: nonce}, nil
	default:
		return account, nil
	}
}

// parseOrderResponse parses an order response.
func (t *Transport) parseOrderResponse(body []byte, nonce, location, method string) (interface{}, error) {
	const op = "embedded.Transport.parseOrderResponse"

	// Handle list response separately
	if method == "list" {
		var list ordersListResponse
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, op, "failed to parse orders list response")
		}
		return &ListOrdersResponse{
			Orders: list.Orders,
			Nonce:  nonce,
		}, nil
	}

	var order orderResponse
	if err := json.Unmarshal(body, &order); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, op, "failed to parse order response")
	}

	orderResp := &OrderResponse{
		Status:         order.Status,
		Expires:        order.Expires,
		Identifiers:    order.Identifiers,
		NotBefore:      order.NotBefore,
		NotAfter:       order.NotAfter,
		Error:          order.Error,
		Authorizations: order.Authorizations,
		Finalize:       order.Finalize,
		Certificate:    order.Certificate,
		Location:       location,
		Nonce:          nonce,
	}

	switch method {
	case "create":
		return &CreateOrderResponse{Order: orderResp, Location: location, Nonce: nonce}, nil
	case "get":
		return &GetOrderResponse{Order: orderResp, Nonce: nonce}, nil
	case "finalize":
		return &FinalizeOrderResponse{Order: orderResp, Location: location, Nonce: nonce}, nil
	default:
		return orderResp, nil
	}
}

// parseAuthorizationResponse parses an authorization response.
func (t *Transport) parseAuthorizationResponse(body []byte, nonce string) (interface{}, error) {
	const op = "embedded.Transport.parseAuthorizationResponse"

	var authz authorizationResponse
	if err := json.Unmarshal(body, &authz); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, op, "failed to parse authorization response")
	}

	return &GetAuthorizationResponse{
		Authorization: &AuthorizationResponse{
			Identifier: authz.Identifier,
			Status:     authz.Status,
			Expires:    authz.Expires,
			Challenges: authz.Challenges,
			Wildcard:   authz.Wildcard,
		},
		Nonce: nonce,
	}, nil
}

// parseChallengeResponse parses a challenge response.
func (t *Transport) parseChallengeResponse(body []byte, nonce string) (interface{}, error) {
	const op = "embedded.Transport.parseChallengeResponse"

	var chal challengeResponse
	if err := json.Unmarshal(body, &chal); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, op, "failed to parse challenge response")
	}

	return &GetChallengeResponse{
		Challenge: &ChallengeResponse{
			Type:      chal.Type,
			URL:       chal.URL,
			Status:    chal.Status,
			Token:     chal.Token,
			Validated: chal.Validated,
			Error:     chal.Error,
		},
		Nonce: nonce,
	}, nil
}

// parseCertificateResponse parses a certificate response.
func (t *Transport) parseCertificateResponse(body []byte, nonce, method string) (interface{}, error) {
	const op = "embedded.Transport.parseCertificateResponse"

	if method == "revoke" {
		return &RevokeCertificateResponse{Nonce: nonce}, nil
	}

	// Certificate response is typically PEM data
	return &GetCertificateResponse{
		Certificate: string(body),
		Nonce:       nonce,
	}, nil
}

// parseErrorResponse parses an ACME error response.
func (t *Transport) parseErrorResponse(recorder *httptest.ResponseRecorder) error {
	const op = "embedded.Transport.parseErrorResponse"

	body := recorder.Body.Bytes()

	var acmeErr acmeErrorResponse
	if err := json.Unmarshal(body, &acmeErr); err != nil {
		// Return generic error if cannot parse
		return errors.NewInternal(op, "request failed with status "+recorder.Result().Status)
	}

	// Map ACME error type to SDK error code
	code := errors.ParseACMEErrorType(acmeErr.Type)

	return errors.New(code, op, acmeErr.Detail)
}

// RequestStream initiates a streaming request.
// Note: Streaming is not supported for embedded transport as ACME is request/response.
func (t *Transport) RequestStream(ctx context.Context, service, method string, req interface{}) (transport.Stream, error) {
	return nil, errors.NewUnimplemented("embedded.Transport.RequestStream", "streaming not supported for embedded transport")
}

// Conn returns the underlying embedded server reference.
func (t *Transport) Conn() interface{} {
	return t.service
}

// Close closes the transport connection.
func (t *Transport) Close() error {
	t.healthy.Store(false)
	return nil
}

// Healthy returns true if the transport is healthy.
func (t *Transport) Healthy() bool {
	return t.healthy.Load()
}

// Factory creates embedded transports.
type Factory struct {
	service      RestServicer
	adminService AdminServicer
}

// NewFactory creates a new embedded transport factory.
func NewFactory(svc RestServicer) transport.Factory {
	return &Factory{service: svc}
}

// NewAdminFactory creates a new embedded transport factory with admin service support.
func NewAdminFactory(svc RestServicer, adminSvc AdminServicer) transport.Factory {
	return &Factory{service: svc, adminService: adminSvc}
}

// Create creates a new embedded transport with the given configuration.
func (f *Factory) Create(cfg *transport.Config) (transport.Transport, error) {
	opts := []Option{WithService(f.service)}
	if f.adminService != nil {
		opts = append(opts, WithAdminService(f.adminService))
	}
	return NewTransport(cfg, opts...)
}

// Response types for internal parsing

type directoryResponse struct {
	NewNonce   string        `json:"newNonce"`
	NewAccount string        `json:"newAccount"`
	NewOrder   string        `json:"newOrder"`
	NewAuthz   string        `json:"newAuthz,omitempty"`
	RevokeCert string        `json:"revokeCert"`
	KeyChange  string        `json:"keyChange"`
	Meta       *MetaResponse `json:"meta,omitempty"`
}

type accountResponse struct {
	Status                 string      `json:"status"`
	Contact                []string    `json:"contact,omitempty"`
	Orders                 string      `json:"orders,omitempty"`
	ExternalAccountBinding interface{} `json:"externalAccountBinding,omitempty"`
}

type orderResponse struct {
	Status         string               `json:"status"`
	Expires        string               `json:"expires,omitempty"`
	Identifiers    []IdentifierResponse `json:"identifiers"`
	NotBefore      string               `json:"notBefore,omitempty"`
	NotAfter       string               `json:"notAfter,omitempty"`
	Error          *ACMEErrorResponse   `json:"error,omitempty"`
	Authorizations []string             `json:"authorizations"`
	Finalize       string               `json:"finalize"`
	Certificate    string               `json:"certificate,omitempty"`
}

type ordersListResponse struct {
	Orders []string `json:"orders"`
}

type authorizationResponse struct {
	Identifier IdentifierResponse  `json:"identifier"`
	Status     string              `json:"status"`
	Expires    string              `json:"expires,omitempty"`
	Challenges []ChallengeResponse `json:"challenges"`
	Wildcard   bool                `json:"wildcard,omitempty"`
}

type challengeResponse struct {
	Type      string             `json:"type"`
	URL       string             `json:"url"`
	Status    string             `json:"status"`
	Token     string             `json:"token"`
	Validated string             `json:"validated,omitempty"`
	Error     *ACMEErrorResponse `json:"error,omitempty"`
}

type acmeErrorResponse struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status,omitempty"`
}

// Public response types for SDK consumers

// MetaResponse contains ACME server metadata.
type MetaResponse struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CAAIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

// GetDirectoryResponse contains the directory response.
type GetDirectoryResponse struct {
	NewNonce   string        `json:"newNonce"`
	NewAccount string        `json:"newAccount"`
	NewOrder   string        `json:"newOrder"`
	NewAuthz   string        `json:"newAuthz,omitempty"`
	RevokeCert string        `json:"revokeCert"`
	KeyChange  string        `json:"keyChange"`
	Meta       *MetaResponse `json:"meta,omitempty"`
	Nonce      string        `json:"nonce,omitempty"`
}

// GetNonceResponse contains the nonce response.
type GetNonceResponse struct {
	Nonce string `json:"nonce"`
}

// AccountResponse contains account details.
type AccountResponse struct {
	Status                 string      `json:"status"`
	Contact                []string    `json:"contact,omitempty"`
	Orders                 string      `json:"orders,omitempty"`
	ExternalAccountBinding interface{} `json:"externalAccountBinding,omitempty"`
	Location               string      `json:"location,omitempty"`
	Nonce                  string      `json:"nonce,omitempty"`
}

// CreateAccountResponse contains the create account response.
type CreateAccountResponse struct {
	Account  *AccountResponse `json:"account"`
	Location string           `json:"location"`
	Nonce    string           `json:"nonce,omitempty"`
}

// GetAccountResponse contains the get account response.
type GetAccountResponse struct {
	Account *AccountResponse `json:"account"`
	Nonce   string           `json:"nonce,omitempty"`
}

// KeyChangeResponse contains the key change response.
type KeyChangeResponse struct {
	Account *AccountResponse `json:"account"`
	Nonce   string           `json:"nonce,omitempty"`
}

// IdentifierResponse represents an ACME identifier.
type IdentifierResponse struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ACMEErrorResponse represents an ACME error.
type ACMEErrorResponse struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status,omitempty"`
}

// OrderResponse contains order details.
type OrderResponse struct {
	Status         string               `json:"status"`
	Expires        string               `json:"expires,omitempty"`
	Identifiers    []IdentifierResponse `json:"identifiers"`
	NotBefore      string               `json:"notBefore,omitempty"`
	NotAfter       string               `json:"notAfter,omitempty"`
	Error          *ACMEErrorResponse   `json:"error,omitempty"`
	Authorizations []string             `json:"authorizations"`
	Finalize       string               `json:"finalize"`
	Certificate    string               `json:"certificate,omitempty"`
	Location       string               `json:"location,omitempty"`
	Nonce          string               `json:"nonce,omitempty"`
}

// CreateOrderResponse contains the create order response.
type CreateOrderResponse struct {
	Order    *OrderResponse `json:"order"`
	Location string         `json:"location"`
	Nonce    string         `json:"nonce,omitempty"`
}

// GetOrderResponse contains the get order response.
type GetOrderResponse struct {
	Order *OrderResponse `json:"order"`
	Nonce string         `json:"nonce,omitempty"`
}

// FinalizeOrderResponse contains the finalize order response.
type FinalizeOrderResponse struct {
	Order    *OrderResponse `json:"order"`
	Location string         `json:"location"`
	Nonce    string         `json:"nonce,omitempty"`
}

// ListOrdersResponse contains the list orders response.
type ListOrdersResponse struct {
	Orders []string `json:"orders"`
	Nonce  string   `json:"nonce,omitempty"`
}

// ChallengeResponse contains challenge details.
type ChallengeResponse struct {
	Type      string             `json:"type"`
	URL       string             `json:"url"`
	Status    string             `json:"status"`
	Token     string             `json:"token"`
	Validated string             `json:"validated,omitempty"`
	Error     *ACMEErrorResponse `json:"error,omitempty"`
}

// GetChallengeResponse contains the get challenge response.
type GetChallengeResponse struct {
	Challenge *ChallengeResponse `json:"challenge"`
	Nonce     string             `json:"nonce,omitempty"`
}

// AuthorizationResponse contains authorization details.
type AuthorizationResponse struct {
	Identifier IdentifierResponse  `json:"identifier"`
	Status     string              `json:"status"`
	Expires    string              `json:"expires,omitempty"`
	Challenges []ChallengeResponse `json:"challenges"`
	Wildcard   bool                `json:"wildcard,omitempty"`
}

// GetAuthorizationResponse contains the get authorization response.
type GetAuthorizationResponse struct {
	Authorization *AuthorizationResponse `json:"authorization"`
	Nonce         string                 `json:"nonce,omitempty"`
}

// GetCertificateResponse contains the get certificate response.
type GetCertificateResponse struct {
	Certificate string `json:"certificate"`
	Nonce       string `json:"nonce,omitempty"`
}

// RevokeCertificateResponse contains the revoke certificate response.
type RevokeCertificateResponse struct {
	Nonce string `json:"nonce,omitempty"`
}
