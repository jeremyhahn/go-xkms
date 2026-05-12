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

package client

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"golang.org/x/crypto/acme"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

var (
	ErrAccountNotFound           = errors.New("acme-client: account not found")
	ErrAccountDeactivated        = errors.New("acme-client: account has been permanently deactivated")
	ErrAccountUpdateFailed       = errors.New("acme-client: failed to update account")
	ErrRegistrationFailed        = errors.New("acme-client: registration failed")
	ErrOrderCreationFailed       = errors.New("acme-client: order creation failed")
	ErrOrderNotFound             = errors.New("acme-client: order not found")
	ErrOrderListFailed           = errors.New("acme-client: failed to list orders")
	ErrChallengeResolution       = errors.New("acme-client: challenge resolution failed")
	ErrChallengeFinalization     = errors.New("acme-client: challenge finalization failed")
	ErrAuthorizationFailed       = errors.New("acme-client: authorization failed")
	ErrAuthorizationDeactivated  = errors.New("acme-client: authorization deactivation failed")
	ErrCABundleDownloadFailed    = errors.New("acme-client: CA bundle download failed")
	ErrInvalidCACertificate      = errors.New("acme-client: invalid CA certificate")
	ErrInvalidCrossSignerAuthzID = errors.New("acme-client: invalid cross-signer authorization type, only 'dns' supported")
	ErrCertificateNotFound       = errors.New("acme-client: certificate not found")
	ErrInvalidConfiguration      = errors.New("acme-client: invalid configuration")
	ErrNilSigner                 = errors.New("acme-client: nil signer provided")
	ErrNilStorage                = errors.New("acme-client: nil storage provided")
	ErrInvalidAccountURI         = errors.New("acme-client: invalid account URI format")
	ErrInvalidOrderURL           = errors.New("acme-client: invalid order URL")
	ErrInvalidAuthorizationURL   = errors.New("acme-client: invalid authorization URL")
	ErrNoOrdersURL               = errors.New("acme-client: account has no orders URL")

	mailTo = "mailto:"
)

// Client represents an ACME client for certificate management
type Client struct {
	accountEmail       string
	accountSigner      crypto.Signer
	client             *acme.Client
	config             *Config
	httpClient         *http.Client
	logger             *slog.Logger
	mutex              sync.RWMutex
	storage            qrdbsdk.GenericDAO[*entities.ACMEAccount]
	certificateStorage qrdbsdk.GenericDAO[*entities.ACMECertificate]
	orderStorage       qrdbsdk.GenericDAO[*entities.ACMEOrder]
}

// Params defines the parameters for creating a new ACME client
type Params struct {
	AccountEmail       string
	AccountSigner      crypto.Signer
	Config             *Config
	Logger             *slog.Logger
	Storage            qrdbsdk.GenericDAO[*entities.ACMEAccount]
	CertificateStorage qrdbsdk.GenericDAO[*entities.ACMECertificate]
	OrderStorage       qrdbsdk.GenericDAO[*entities.ACMEOrder]
}

// NewClient creates a new ACME client with the provided parameters
func NewClient(params *Params) (*Client, error) {
	if params == nil {
		return nil, ErrInvalidConfiguration
	}
	if params.AccountSigner == nil {
		return nil, ErrNilSigner
	}
	if params.Storage == nil {
		return nil, ErrNilStorage
	}
	if params.Config == nil {
		params.Config = DefaultConfig()
	}
	if params.Logger == nil {
		params.Logger = slog.Default()
	}

	client := &Client{
		accountEmail:       params.AccountEmail,
		accountSigner:      params.AccountSigner,
		config:             params.Config,
		logger:             params.Logger,
		storage:            params.Storage,
		certificateStorage: params.CertificateStorage,
		orderStorage:       params.OrderStorage,
		mutex:              sync.RWMutex{},
	}

	// Create HTTP client with custom transport
	httpClient, err := client.createHTTPClient(params.Config.DirectoryURL)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to create HTTP client: %v", err)
	}
	client.httpClient = httpClient

	// Create ACME client
	acmeClient := &acme.Client{
		DirectoryURL: params.Config.DirectoryURL,
		Key:          params.AccountSigner,
		HTTPClient:   httpClient,
	}
	client.client = acmeClient

	return client, nil
}

// createHTTPClient creates an HTTP client with custom TLS configuration
func (c *Client) createHTTPClient(directoryURL string) (*http.Client, error) {
	defer c.mutex.Unlock()
	c.mutex.Lock()

	// Create x509 root CA certificate pool using the OS trusted root CA store
	rootCAs, err := c.createCACertPool(directoryURL)
	if err != nil {
		return nil, err
	}

	// Create a secure transport using the ACME server CA bundle
	// Note: ForceAttemptHTTP2=false and TLSNextProto={} disable HTTP/2
	// This is needed due to compatibility issues with some ACME servers
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS13,
		},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}

	return &http.Client{
		Transport: transport,
		Timeout:   c.config.Timeout,
	}, nil
}

// createCACertPool creates a certificate pool for TLS verification
func (c *Client) createCACertPool(directoryURL string) (*x509.CertPool, error) {
	c.logger.Info("createCACertPool called",
		slog.String("directory", directoryURL),
		slog.Bool("systemCertPool", c.config.SystemCertPool),
		slog.Bool("requestServerBundle", c.config.RequestServerBundle))

	// Create x509 root CA certificate pool
	var rootCAs *x509.CertPool
	var err error

	if c.config.SystemCertPool {
		// Use OS system certificate pool as base
		rootCAs, err = x509.SystemCertPool()
		if err != nil {
			return nil, caerrors.TLSErrorCreate("failed to load system root CAs: %v", err)
		}
		c.logger.Info("using OS system certificate pool as base")
	} else {
		// Use empty certificate pool for isolated/private CA environments
		rootCAs = x509.NewCertPool()
		c.logger.Info("using empty certificate pool (isolated mode)")
	}

	// If custom CA certificates are provided, add them to the pool
	if len(c.config.TrustedRoots) > 0 {
		for _, certPEM := range c.config.TrustedRoots {
			if ok := rootCAs.AppendCertsFromPEM([]byte(certPEM)); !ok {
				return nil, ErrInvalidCACertificate
			}
		}
	}

	// If the ACME client config does not have the request-server-bundle
	// flag set, return the system root CA certificate pool
	if !c.config.RequestServerBundle {
		c.logger.Info("requestServerBundle is false, skipping CA bundle fetch")
		return rootCAs, nil
	}

	c.logger.Info("requestServerBundle is true, fetching CA bundle from server")

	// Add the ACME server CA bundle to the x509 root CA certificate pool
	certs, err := c.fetchCABundle(directoryURL)
	if err != nil {
		c.logger.Error("failed to fetch CA bundle", slog.String("error", err.Error()))
		return nil, caerrors.ConnectionFailureError("failed to get ACME server CA bundle: %v", err)
	}

	c.logger.Info("fetched CA bundle from server", slog.Int("certCount", len(certs)))

	// Add the downloaded ACME server CA bundle to the ACME client trusted
	// root certificate pool
	for _, cert := range certs {
		c.logger.Info("adding CA cert to pool", slog.String("subject", cert.Subject.CommonName))
		rootCAs.AddCert(cert)
	}

	return rootCAs, nil
}

// fetchCABundle retrieves the CA bundle from a custom ACME server endpoint.
// TrustedRoots must be pre-configured in the client config to verify the TLS
// connection to the ACME server. If no TrustedRoots are configured and
// SystemCertPool is false, this will fail because there are no trusted
// certificates to verify the server's TLS certificate.
func (c *Client) fetchCABundle(directoryURL string) ([]*x509.Certificate, error) {
	// Build the TLS root CA pool for the CA bundle fetch request.
	// This uses the already-configured TrustedRoots and/or SystemCertPool
	// to establish trust for the initial connection.
	var fetchRootCAs *x509.CertPool
	var err error

	if c.config.SystemCertPool {
		fetchRootCAs, err = x509.SystemCertPool()
		if err != nil {
			return nil, caerrors.TLSErrorCreate("failed to load system root CAs for CA bundle fetch: %v", err)
		}
	} else {
		fetchRootCAs = x509.NewCertPool()
	}

	// Add any pre-configured TrustedRoots
	if len(c.config.TrustedRoots) > 0 {
		for _, certPEM := range c.config.TrustedRoots {
			fetchRootCAs.AppendCertsFromPEM([]byte(certPEM))
		}
	}

	// Create the ca-bundle ACME server endpoint
	parsedURL, err := url.Parse(directoryURL)
	if err != nil {
		return nil, caerrors.MalformedError("failed to parse directory URL: %v", err)
	}
	dir := path.Dir(parsedURL.Path)
	newPath := path.Join(dir, "ca-bundle")
	parsedURL.Path = newPath

	c.logger.Info("fetching CA bundle", slog.String("url", parsedURL.String()))

	// Retrieve the CA bundle from the ACME server using TLS with
	// pre-configured trust anchors
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    fetchRootCAs,
			MinVersion: tls.VersionTLS13,
		},
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	resp, err := httpClient.Get(parsedURL.String())
	if err != nil {
		c.logger.Error("failed to fetch CA bundle", slog.String("url", parsedURL.String()), slog.String("error", err.Error()))
		return nil, caerrors.ConnectionFailureError("failed to fetch CA bundle: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		c.logger.Error("CA bundle download failed", slog.Int("status", resp.StatusCode))
		return nil, ErrCABundleDownloadFailed
	}

	// Read the response body
	certBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to read CA bundle: %v", err)
	}

	// Parse the certificates
	certs := []*x509.Certificate{}
	for len(certBytes) > 0 {
		cert, rest := pem.Decode(certBytes)
		if cert == nil {
			break
		}
		x509Cert, err := x509.ParseCertificate(cert.Bytes)
		if err != nil {
			return nil, caerrors.MalformedError("failed to parse certificate in CA bundle: %v", err)
		}
		certs = append(certs, x509Cert)
		certBytes = rest
	}

	return certs, nil
}

// AccountSigner returns the ACME account signer
func (c *Client) AccountSigner() crypto.Signer {
	return c.accountSigner
}

// Account returns the ACME account associated with the account email
func (c *Client) Account() (*acme.Account, error) {
	defer c.mutex.RUnlock()
	c.mutex.RLock()

	if c.accountEmail == "" {
		return nil, ErrAccountNotFound
	}

	acmeAccount, err := c.client.GetReg(context.Background(), "")
	if err != nil {
		return nil, caerrors.AccountDoesNotExistError("failed to get account: %v", err)
	}

	return acmeAccount, nil
}

// extractAccountIDFromURI extracts the account ID from an ACME account URI.
// ACME account URIs typically follow the pattern: https://server/acme/account/{id}
func extractAccountIDFromURI(uri string) (uint64, error) {
	if uri == "" {
		return 0, ErrInvalidAccountURI
	}

	// Parse the URI to get the path
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return 0, caerrors.MalformedError("invalid account URI: failed to parse URI: %v", err)
	}

	// Extract the last path segment (the account ID)
	parts := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	if len(parts) == 0 {
		return 0, caerrors.MalformedError("invalid account URI: no path segments in URI")
	}

	idStr := parts[len(parts)-1]
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return 0, caerrors.MalformedError("invalid account URI: invalid account ID format: %v", err)
	}

	if id == 0 {
		return 0, caerrors.MalformedError("invalid account URI: account ID cannot be zero")
	}

	return id, nil
}

// RegisterAccount registers a new account with the ACME server
func (c *Client) RegisterAccount() (*acme.Account, error) {
	defer c.mutex.RUnlock()
	c.mutex.RLock()

	c.logger.Info("registering ACME account",
		slog.String("email", c.accountEmail),
		slog.String("directory_url", c.config.DirectoryURL))

	account := &acme.Account{
		Contact: []string{fmt.Sprintf("%s%s", mailTo, c.accountEmail)},
	}

	newAccount, err := c.client.Register(context.Background(), account, acme.AcceptTOS)
	if err != nil {
		// When the account key is already registered, x/crypto/acme
		// returns ErrAccountAlreadyExists AFTER caching the account URL
		// as the client's KID. The KID is what subsequent POST-as-GET /
		// AuthorizeOrder / certificate requests need, so this path is a
		// success — the client state is ready. Fetch the account via
		// GetReg so callers get a populated *acme.Account.
		if errors.Is(err, acme.ErrAccountAlreadyExists) {
			c.logger.Info("ACME account already registered; reusing cached KID",
				slog.String("directory_url", c.config.DirectoryURL))
			existing, regErr := c.client.GetReg(context.Background(), "")
			if regErr != nil {
				c.logger.Warn("failed to fetch existing ACME account (continuing with cached KID)",
					slog.String("error", regErr.Error()))
				return account, nil
			}
			newAccount = existing
		} else {
			c.logger.Error("ACME account registration failed",
				slog.String("error", err.Error()),
				slog.String("directory_url", c.config.DirectoryURL))
			return nil, caerrors.InternalServerError("failed to register account: %v", err)
		}
	}

	c.logger.Info("ACME account registered successfully",
		slog.String("uri", newAccount.URI),
		slog.String("status", newAccount.Status))

	// Save the account to storage
	if c.storage != nil {
		// Extract account ID from the URI
		accountID, err := extractAccountIDFromURI(newAccount.URI)
		if err != nil {
			c.logger.Warn("failed to extract account ID from URI",
				slog.String("uri", newAccount.URI),
				slog.String("error", err.Error()))
		} else {
			accountEntity := &entities.ACMEAccount{
				ID:      accountID,
				Contact: newAccount.Contact,
				Status:  newAccount.Status,
				URL:     newAccount.URI,
			}
			if err := c.storage.Save(context.Background(), accountEntity); err != nil {
				c.logger.Warn("failed to save account to storage",
					slog.Uint64("id", accountID),
					slog.String("error", err.Error()))
			} else {
				c.logger.Info("account saved to storage successfully",
					slog.Uint64("id", accountID))
			}
		}
	}

	c.logger.Info("registered new ACME account", slog.String("email", c.accountEmail))
	return newAccount, nil
}

// UpdateAccount updates the account contact information on the ACME server.
// Per RFC 8555 Section 7.3.2, this performs a POST to the account URL with
// the updated contact information.
//
// The contacts parameter should be a list of email addresses without the
// "mailto:" prefix - this method will add the prefix automatically.
//
// Example:
//
//	account, err := client.UpdateAccount(ctx, []string{"new@example.com", "backup@example.com"})
func (c *Client) UpdateAccount(ctx context.Context, contacts []string) (*acme.Account, error) {
	c.logger.Info("updating ACME account contacts",
		slog.Any("contacts", contacts))

	// Format contacts with mailto: prefix
	formattedContacts := make([]string, len(contacts))
	for i, contact := range contacts {
		if strings.HasPrefix(contact, mailTo) {
			formattedContacts[i] = contact
		} else {
			formattedContacts[i] = mailTo + contact
		}
	}

	// Create account object with updated contacts
	accountUpdate := &acme.Account{
		Contact: formattedContacts,
	}

	// Call the underlying ACME client's UpdateReg method
	updatedAccount, err := c.client.UpdateReg(ctx, accountUpdate)
	if err != nil {
		c.logger.Error("failed to update account",
			slog.String("error", err.Error()))
		return nil, caerrors.InternalServerError("account update failed: %v", err)
	}

	c.logger.Info("ACME account updated successfully",
		slog.String("uri", updatedAccount.URI),
		slog.String("status", updatedAccount.Status),
		slog.Any("contacts", updatedAccount.Contact))

	// Update local storage if available
	if c.storage != nil {
		accountID, err := extractAccountIDFromURI(updatedAccount.URI)
		if err != nil {
			c.logger.Warn("failed to extract account ID from URI for storage update",
				slog.String("uri", updatedAccount.URI),
				slog.String("error", err.Error()))
		} else {
			accountEntity := &entities.ACMEAccount{
				ID:      accountID,
				Contact: updatedAccount.Contact,
				Status:  updatedAccount.Status,
				URL:     updatedAccount.URI,
			}
			if err := c.storage.Save(ctx, accountEntity); err != nil {
				c.logger.Warn("failed to update account in storage",
					slog.Uint64("id", accountID),
					slog.String("error", err.Error()))
			} else {
				c.logger.Info("account updated in storage successfully",
					slog.Uint64("id", accountID))
			}
		}
	}

	// Update local email if this is the primary contact
	if len(contacts) > 0 {
		c.mutex.Lock()
		c.accountEmail = contacts[0]
		c.mutex.Unlock()
	}

	return updatedAccount, nil
}

// DeactivateAccount permanently deactivates the ACME account on the server.
// Per RFC 8555 Section 7.3.6, this sets the account status to "deactivated".
//
// WARNING: This operation is IRREVERSIBLE. Once an account is deactivated:
//   - The account can no longer be used to issue certificates
//   - The account can no longer be used to manage existing certificates
//   - The account cannot be reactivated
//   - A new account must be created to continue operations
//
// The account key pair should be preserved if there are any existing
// certificates that may need to be revoked in the future, as some CAs
// may still honor revocation requests from deactivated accounts.
func (c *Client) DeactivateAccount(ctx context.Context) error {
	c.logger.Warn("deactivating ACME account - THIS IS IRREVERSIBLE",
		slog.String("email", c.accountEmail))

	// Call the underlying ACME client's DeactivateReg method
	err := c.client.DeactivateReg(ctx)
	if err != nil {
		c.logger.Error("failed to deactivate account",
			slog.String("error", err.Error()))
		return caerrors.InternalServerError("account deactivation failed: %v", err)
	}

	c.logger.Warn("ACME account has been permanently deactivated",
		slog.String("email", c.accountEmail))

	// Update local storage if available to reflect deactivated status
	if c.storage != nil {
		// First get the current account to obtain its URI
		currentAccount, err := c.client.GetReg(ctx, "")
		if err == nil && currentAccount != nil {
			accountID, err := extractAccountIDFromURI(currentAccount.URI)
			if err == nil {
				accountEntity := &entities.ACMEAccount{
					ID:      accountID,
					Contact: currentAccount.Contact,
					Status:  acme.StatusDeactivated,
					URL:     currentAccount.URI,
				}
				if err := c.storage.Save(ctx, accountEntity); err != nil {
					c.logger.Warn("failed to update deactivated account in storage",
						slog.Uint64("id", accountID),
						slog.String("error", err.Error()))
				} else {
					c.logger.Info("account marked as deactivated in storage",
						slog.Uint64("id", accountID))
				}
			}
		}
	}

	return nil
}

// ListOrders retrieves all order URLs for the current account.
// Per RFC 8555 Section 7.1.2.1, this fetches the orders from the account's
// orders URL field.
//
// Returns a slice of order URLs that can be used with GetOrder to retrieve
// the full order details.
func (c *Client) ListOrders(ctx context.Context) ([]string, error) {
	c.logger.Info("listing orders for account")

	// First get the current account to obtain the orders URL
	account, err := c.client.GetReg(ctx, "")
	if err != nil {
		c.logger.Error("failed to get account for orders list",
			slog.String("error", err.Error()))
		return nil, caerrors.InternalServerError("failed to list orders: failed to get account: %v", err)
	}

	if account.OrdersURL == "" {
		c.logger.Warn("account has no orders URL")
		return nil, ErrNoOrdersURL
	}

	c.logger.Info("fetching orders from account",
		slog.String("ordersURL", account.OrdersURL))

	// Fetch the orders list from the orders URL
	// The ACME server returns a JSON object with an "orders" field containing
	// an array of order URLs
	orderURLs, err := c.fetchOrdersList(ctx, account.OrdersURL)
	if err != nil {
		return nil, err
	}

	c.logger.Info("retrieved orders list",
		slog.Int("count", len(orderURLs)))

	return orderURLs, nil
}

// ordersListResponse represents the JSON response from the orders list endpoint
type ordersListResponse struct {
	Orders []string `json:"orders"`
}

// fetchOrdersList fetches the list of order URLs from the given orders URL.
// This makes an authenticated POST-as-GET request to retrieve the orders.
func (c *Client) fetchOrdersList(ctx context.Context, ordersURL string) ([]string, error) {
	// The golang.org/x/crypto/acme package doesn't expose a method to fetch
	// the orders list directly, so we need to make an authenticated request
	// using the underlying HTTP client. However, ACME requires JWS-signed
	// POST-as-GET requests, which the acme.Client handles internally.
	//
	// We use a workaround by making a direct HTTP GET request. Note that
	// per RFC 8555, the orders endpoint may require authentication via
	// POST-as-GET. Some ACME servers may accept unauthenticated GET requests
	// for this endpoint, but this is not guaranteed.
	//
	// For a more robust implementation, we would need to use the acme.Client's
	// internal post method, but it's not exported. The golang.org/x/crypto/acme
	// package doesn't provide a public method for fetching the orders list.

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ordersURL, nil)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to create orders list request: %v", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to fetch orders list: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.logger.Error("orders list request failed",
			slog.Int("status", resp.StatusCode),
			slog.String("body", string(body)))
		return nil, caerrors.ConnectionFailureError("orders list server returned status %d", resp.StatusCode)
	}

	var ordersList ordersListResponse
	if err := json.NewDecoder(resp.Body).Decode(&ordersList); err != nil {
		return nil, caerrors.SerializationFailureError("failed to decode orders list response: %v", err)
	}

	return ordersList.Orders, nil
}

// GetOrder retrieves a specific order by its URL.
// Per RFC 8555 Section 7.4, this fetches the order object from the ACME server.
//
// The orderURL should be a full URL to the order resource, typically obtained
// from ListOrders or from the Location header when creating an order.
func (c *Client) GetOrder(ctx context.Context, orderURL string) (*acme.Order, error) {
	if orderURL == "" {
		return nil, ErrInvalidOrderURL
	}

	c.logger.Info("fetching order",
		slog.String("orderURL", orderURL))

	order, err := c.client.GetOrder(ctx, orderURL)
	if err != nil {
		c.logger.Error("failed to get order",
			slog.String("orderURL", orderURL),
			slog.String("error", err.Error()))

		// Check if this is a not found error
		var acmeErr *acme.Error
		if errors.As(err, &acmeErr) && acmeErr.StatusCode == http.StatusNotFound {
			return nil, caerrors.NotFoundError("order not found: %v", err)
		}

		return nil, caerrors.InternalServerError("failed to get order: %v", err)
	}

	c.logger.Info("retrieved order",
		slog.String("orderURL", orderURL),
		slog.String("status", order.Status))

	return order, nil
}

// DeactivateAuthorization deactivates an authorization by setting its status
// to "deactivated".
// Per RFC 8555 Section 7.5.2, this is useful when abandoning an order or when
// the client no longer intends to complete the authorization.
//
// Once deactivated, the authorization cannot be used to obtain certificates,
// and a new authorization must be obtained if needed.
//
// The authzURL should be a full URL to the authorization resource, typically
// obtained from the order's AuthzURLs field.
func (c *Client) DeactivateAuthorization(ctx context.Context, authzURL string) error {
	if authzURL == "" {
		return ErrInvalidAuthorizationURL
	}

	c.logger.Info("deactivating authorization",
		slog.String("authzURL", authzURL))

	// The golang.org/x/crypto/acme package calls this RevokeAuthorization,
	// but per RFC 8555 Section 7.5.2, the operation is actually "deactivation"
	err := c.client.RevokeAuthorization(ctx, authzURL)
	if err != nil {
		c.logger.Error("failed to deactivate authorization",
			slog.String("authzURL", authzURL),
			slog.String("error", err.Error()))
		return caerrors.InternalServerError("authorization deactivation failed: %v", err)
	}

	c.logger.Info("authorization deactivated successfully",
		slog.String("authzURL", authzURL))

	return nil
}

// GetAuthorization retrieves an authorization by its URL.
// This is a convenience wrapper around the underlying ACME client's
// GetAuthorization method.
func (c *Client) GetAuthorization(ctx context.Context, authzURL string) (*acme.Authorization, error) {
	if authzURL == "" {
		return nil, ErrInvalidAuthorizationURL
	}

	c.logger.Info("fetching authorization",
		slog.String("authzURL", authzURL))

	authz, err := c.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		c.logger.Error("failed to get authorization",
			slog.String("authzURL", authzURL),
			slog.String("error", err.Error()))
		return nil, caerrors.InternalServerError("authorization failed: %v", err)
	}

	c.logger.Info("retrieved authorization",
		slog.String("authzURL", authzURL),
		slog.String("status", authz.Status))

	return authz, nil
}

// RequestCertificate requests a new certificate from the ACME server
func (c *Client) RequestCertificate(ctx context.Context, req *CertificateRequest) (*x509.Certificate, error) {
	if err := req.Validate(); err != nil {
		return nil, caerrors.MalformedError("invalid certificate request: %v", err)
	}

	// Create an order for the certificate
	order, err := c.client.AuthorizeOrder(ctx, []acme.AuthzID{
		{
			Type:  req.AuthzType,
			Value: req.AuthzValue,
		},
	})
	if err != nil {
		return nil, caerrors.InternalServerError("failed to authorize order: %v", err)
	}

	// Process each authorization
	for _, authzURL := range order.AuthzURLs {
		authz, err := c.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, caerrors.InternalServerError("failed to get authorization: %v", err)
		}

		// Find and accept the requested challenge type
		var acceptedChallenge *acme.Challenge
		for _, challenge := range authz.Challenges {
			if challenge.Type == req.ChallengeType {
				// Generate key authorization
				keyAuth, err := c.client.HTTP01ChallengeResponse(challenge.Token)
				if err != nil {
					return nil, caerrors.InternalServerError("failed to generate key authorization: %v", err)
				}

				// Setup challenge (implementation-specific)
				if req.ChallengeSetup != nil {
					if err := req.ChallengeSetup(challenge.Type, challenge.Token, keyAuth); err != nil {
						return nil, caerrors.InternalServerError("challenge setup failed: %v", err)
					}
				}

				acceptedChallenge = challenge
				break
			}
		}

		if acceptedChallenge == nil {
			return nil, caerrors.MalformedError("challenge type %s not offered by server", req.ChallengeType)
		}

		// Notify the ACME server that the challenge is ready
		_, err = c.client.Accept(ctx, acceptedChallenge)
		if err != nil {
			return nil, caerrors.InternalServerError("failed to accept challenge: %v", err)
		}

		// Wait for authorization to complete
		authz, err = c.client.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return nil, caerrors.InternalServerError("failed to wait for authorization: %v", err)
		}

		if authz.Status != acme.StatusValid {
			return nil, caerrors.InternalServerError("authorization status is not valid: %s", authz.Status)
		}

		// Cleanup challenge if needed
		if req.ChallengeCleanup != nil {
			req.ChallengeCleanup(acceptedChallenge.Type)
		}
	}

	// Finalize the order with the CSR
	if req.CSR == nil {
		return nil, caerrors.MalformedError("CSR is required to finalize order")
	}

	orderCertChain, certURL, err := c.client.CreateOrderCert(ctx, order.FinalizeURL, req.CSR, true)
	if err != nil {
		return nil, caerrors.InternalServerError("failed to finalize order: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(orderCertChain[0])
	if err != nil {
		return nil, caerrors.MalformedError("failed to parse certificate: %v", err)
	}

	// Store the certificate
	if c.certificateStorage != nil {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: orderCertChain[0],
		})
		certEntity := &entities.ACMECertificate{
			CertURL:   certURL,
			PEM:       string(certPEM),
			IssuedAt:  time.Now(),
			Status:    "valid",
			ExpiresAt: cert.NotAfter,
		}
		if err := c.certificateStorage.Save(context.Background(), certEntity); err != nil {
			c.logger.Warn("failed to save certificate to storage", slog.String("error", err.Error()))
		}
	}

	// Store the order
	if c.orderStorage != nil {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: orderCertChain[0],
		})
		orderEntity := &entities.ACMEOrder{
			Status:         order.Status,
			Expires:        order.Expires.Format(time.RFC3339),
			Finalize:       order.FinalizeURL,
			Certificate:    string(certPEM),
			CertificateURL: certURL,
		}
		if err := c.orderStorage.Save(context.Background(), orderEntity); err != nil {
			c.logger.Warn("failed to save order to storage", slog.String("error", err.Error()))
		}
	}

	c.logger.Info("successfully obtained certificate",
		slog.String("subject", cert.Subject.CommonName),
		slog.Time("not_before", cert.NotBefore),
		slog.Time("not_after", cert.NotAfter))

	return cert, nil
}

// RenewCertificate renews an existing certificate
func (c *Client) RenewCertificate(ctx context.Context, oldCert *x509.Certificate, req *CertificateRequest) (*x509.Certificate, error) {
	c.logger.Info("renewing certificate", slog.String("subject", oldCert.Subject.CommonName))

	// Request a new certificate with the same parameters
	newCert, err := c.RequestCertificate(ctx, req)
	if err != nil {
		return nil, caerrors.InternalServerError("failed to renew certificate: %v", err)
	}

	return newCert, nil
}

// RevokeCertificate revokes a certificate
func (c *Client) RevokeCertificate(ctx context.Context, cert *x509.Certificate, reason acme.CRLReasonCode) error {
	c.logger.Info("revoking certificate", slog.String("subject", cert.Subject.CommonName))

	err := c.client.RevokeCert(ctx, nil, cert.Raw, reason)
	if err != nil {
		return caerrors.InternalServerError("failed to revoke certificate: %v", err)
	}

	c.logger.Info("successfully revoked certificate", slog.String("subject", cert.Subject.CommonName))
	return nil
}

// FetchCertificate retrieves a certificate from the ACME server
func (c *Client) FetchCertificate(ctx context.Context, certURL string, bundle bool) ([]*x509.Certificate, error) {
	certChain, err := c.client.FetchCert(ctx, certURL, bundle)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to fetch certificate: %v", err)
	}

	certs := make([]*x509.Certificate, 0, len(certChain))
	for _, certDER := range certChain {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, caerrors.MalformedError("failed to parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// AccountKeyRollover performs an ACME account key rollover operation
func (c *Client) AccountKeyRollover(ctx context.Context, newKey crypto.Signer) error {
	c.logger.Info("performing account key rollover")

	err := c.client.AccountKeyRollover(ctx, newKey)
	if err != nil {
		return caerrors.InternalServerError("failed to perform account key rollover: %v", err)
	}

	// Update the account signer
	c.mutex.Lock()
	c.accountSigner = newKey
	c.client.Key = newKey
	c.mutex.Unlock()

	c.logger.Info("successfully completed account key rollover")
	return nil
}

// Close closes the ACME client and releases resources
func (c *Client) Close() error {
	c.logger.Info("closing ACME client")

	// Close HTTP client if it has an idle connection closer
	if c.httpClient != nil {
		if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}

	return nil
}
