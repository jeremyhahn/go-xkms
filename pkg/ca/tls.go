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

// Package ca provides TLS helper functions for configuring secure TLS connections
// using certificates and keys managed by the XKMSCA certificate authority.
//
// # TLS Configuration
//
// The TLS helpers provide secure defaults following current best practices:
//   - Minimum TLS version: 1.2
//   - Maximum TLS version: 1.3
//   - Secure cipher suites preferring AES-GCM and ChaCha20-Poly1305
//   - ECDHE key exchange for forward secrecy
//
// # Usage Examples
//
// Server configuration with mutual TLS:
//
//	tlsConfig, err := ca.MutualTLSConfig(serverKeyAttrs)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	server := &http.Server{
//	    Addr:      ":8443",
//	    TLSConfig: tlsConfig,
//	}
//
// Client configuration:
//
//	tlsConfig, err := ca.ClientTLSConfig(clientKeyAttrs, "server.example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	client := &http.Client{
//	    Transport: &http.Transport{
//	        TLSClientConfig: tlsConfig,
//	    },
//	}
//
// Custom configuration with options:
//
//	opts := &ca.TLSConfigOptions{
//	    IsServer:          true,
//	    RequireClientCert: true,
//	    MinVersion:        tls.VersionTLS13,
//	}
//	tlsConfig, err := ca.TLSConfigWithOptions(keyAttrs, opts)
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// =============================================================================
// TLS Configuration Options
// =============================================================================

// TLSConfigOptions provides configuration options for creating TLS configurations.
//
// TLSConfigOptions allows fine-grained control over TLS settings including
// version constraints, client authentication, and cipher suite preferences.
// For most use cases, the convenience methods ServerTLSConfig, ClientTLSConfig,
// and MutualTLSConfig provide appropriate defaults.
type TLSConfigOptions struct {
	// IsServer indicates this configuration is for a TLS server.
	// When true, the configuration will be set up for accepting connections.
	// When false, the configuration is for initiating connections as a client.
	IsServer bool

	// RequireClientCert specifies whether the server requires client certificates.
	// Only applicable when IsServer is true. When true, clients must present
	// a valid certificate signed by a trusted CA.
	RequireClientCert bool

	// MinVersion is the minimum TLS version to accept.
	// Defaults to tls.VersionTLS12 if not specified.
	// Valid values: tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13
	MinVersion uint16

	// MaxVersion is the maximum TLS version to accept.
	// Defaults to tls.VersionTLS13 if not specified.
	// Set to 0 to accept the highest version supported.
	MaxVersion uint16
	// ServerName specifies the server name for SNI and certificate verification.
	// Required for client connections to verify the server's certificate.
	ServerName string

	// RootCAs is an optional custom root CA pool for verifying server certificates.
	// If nil when acting as a client, the system root CAs are used.
	// If nil when acting as a server with client auth, the CA's own pool is used.
	RootCAs *x509.CertPool

	// ClientCAs is an optional custom CA pool for verifying client certificates.
	// Only used when IsServer is true and RequireClientCert is true.
	// If nil, the CA's own certificate pool is used.
	ClientCAs *x509.CertPool

	// PreferServerCipherSuites specifies that the server's cipher suite
	// preferences should be used instead of the client's.
	// Only applicable when IsServer is true.
	// Note: In TLS 1.3, cipher suite order is not configurable.
	PreferServerCipherSuites bool

	// CipherSuites specifies the cipher suites to use.
	// If empty, SecureCipherSuites() is used to provide secure defaults.
	// Only applies to TLS 1.2 and earlier; TLS 1.3 cipher suites are not configurable.
	CipherSuites []uint16

	// SessionTicketsDisabled disables session ticket resumption.
	// When set to true, new sessions will not issue tickets and existing
	// tickets will not be used for resumption.
	SessionTicketsDisabled bool

	// NextProtos specifies the list of supported application level protocols
	// for ALPN negotiation, in order of preference.
	// Common values: "h2" for HTTP/2, "http/1.1" for HTTP/1.1
	NextProtos []string
}

// Validate checks that the TLSConfigOptions are valid.
//
// Returns ErrInvalidTLSOptions if any options are invalid or conflicting.
func (o *TLSConfigOptions) Validate() error {
	if o == nil {
		return nil
	}

	// Check for invalid version combinations
	if o.MinVersion != 0 && o.MaxVersion != 0 && o.MinVersion > o.MaxVersion {
		return fmt.Errorf("%w: min version cannot be greater than max version", ErrInvalidTLSOptions)
	}
	// Client connections should specify ServerName for certificate verification
	if !o.IsServer && o.ServerName == "" {
		slog.Warn("TLS: ServerName not specified for client connection - SNI may fail")
	}

	return nil
}

// applyDefaults fills in default values for unset options.
func (o *TLSConfigOptions) applyDefaults() {
	if o.MinVersion == 0 {
		o.MinVersion = tls.VersionTLS12
	}
	if o.MaxVersion == 0 {
		o.MaxVersion = tls.VersionTLS13
	}
}

// =============================================================================
// CA TLS Methods
// =============================================================================

// TLSCertificate returns a TLS certificate for the given key attributes.
//
// This retrieves the private key and certificate for the specified key
// and combines them into a tls.Certificate suitable for use with Go's
// TLS implementation. The certificate chain is included if available.
//
// The method delegates to the underlying xkms's GetTLSCertificate method.
//
// Parameters:
//   - attrs: Key attributes identifying the certificate and key to load
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrCertificateNotFound if no certificate exists for the key
//   - ErrKeyNotFound if the private key cannot be retrieved
//
// Thread-safe: Yes
//
// Example:
//
//	attrs := &types.KeyAttributes{
//	    CN:           "server.example.com",
//	    StoreType:    types.StoreSoftware,
//	    KeyType:      types.KeyTypeTLS,
//	    KeyAlgorithm: x509.ECDSA,
//	}
//	tlsCert, err := ca.TLSCertificate(attrs)
//	if err != nil {
//	    log.Fatal(err)
//	}
func (ca *CA) TLSCertificate(attrs *types.KeyAttributes) (tls.Certificate, error) {
	if !ca.initialized.Load() {
		return tls.Certificate{}, ErrNotInitialized
	}

	if attrs == nil {
		return tls.Certificate{}, fmt.Errorf("%w: key attributes required", ErrInvalidTLSOptions)
	}

	tlsCert, err := ca.keyStore.GetTLSCertificate(attrs.CN, attrs)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: %v", ErrTLSConfigFailed, err)
	}

	return tlsCert, nil
}

// TLSConfig returns a TLS configuration for the given key attributes.
//
// This creates a complete tls.Config with secure defaults:
//   - The certificate and private key loaded from xkms
//   - The CA certificate pool configured for verification
//   - Minimum TLS version 1.2
//   - Secure cipher suites
//
// For more control over the configuration, use TLSConfigWithOptions.
//
// Parameters:
//   - attrs: Key attributes identifying the certificate and key to use
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrTLSConfigFailed if the configuration cannot be created
//   - ErrCertificateNotFound if the certificate does not exist
//
// Thread-safe: Yes
//
// Example:
//
//	tlsConfig, err := ca.TLSConfig(serverKeyAttrs)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	listener, err := tls.Listen("tcp", ":443", tlsConfig)
func (ca *CA) TLSConfig(attrs *types.KeyAttributes) (*tls.Config, error) {
	return ca.TLSConfigWithOptions(attrs, nil)
}

// TLSConfigWithOptions returns a TLS configuration with custom options.
//
// This method provides fine-grained control over TLS configuration,
// allowing customization of version constraints, client authentication,
// cipher suites, and other TLS parameters.
//
// If opts is nil, secure defaults are applied.
//
// Parameters:
//   - attrs: Key attributes identifying the certificate and key to use
//   - opts: Configuration options (nil for defaults)
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrInvalidTLSOptions if options are invalid
//   - ErrTLSConfigFailed if the configuration cannot be created
//
// Thread-safe: Yes
//
// Example:
//
//	opts := &ca.TLSConfigOptions{
//	    IsServer:          true,
//	    RequireClientCert: true,
//	    MinVersion:        tls.VersionTLS13,
//	}
//	tlsConfig, err := ca.TLSConfigWithOptions(serverKeyAttrs, opts)
func (ca *CA) TLSConfigWithOptions(attrs *types.KeyAttributes, opts *TLSConfigOptions) (*tls.Config, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	// Use empty options if nil
	if opts == nil {
		opts = &TLSConfigOptions{}
	}

	// Validate and apply defaults
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	opts.applyDefaults()

	// Get TLS certificate
	tlsCert, err := ca.TLSCertificate(attrs)
	if err != nil {
		return nil, err
	}

	// Build CA pools for verification
	caPool := ca.buildCAPool()

	// Determine root CAs
	rootCAs := opts.RootCAs
	if rootCAs == nil {
		rootCAs = caPool
	}

	// Determine client CAs
	clientCAs := opts.ClientCAs
	if clientCAs == nil {
		clientCAs = caPool
	}

	// Determine cipher suites
	cipherSuites := opts.CipherSuites
	if len(cipherSuites) == 0 {
		cipherSuites = SecureCipherSuites()
	}

	// Build the TLS config
	config := &tls.Config{
		Certificates:             []tls.Certificate{tlsCert},
		MinVersion:               opts.MinVersion,
		MaxVersion:               opts.MaxVersion,
		CipherSuites:             cipherSuites,
		PreferServerCipherSuites: opts.PreferServerCipherSuites,
		SessionTicketsDisabled:   opts.SessionTicketsDisabled,
		NextProtos:               opts.NextProtos,
	}

	if opts.IsServer {
		// Server configuration
		config.ClientCAs = clientCAs
		if opts.RequireClientCert {
			config.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			config.ClientAuth = tls.NoClientCert
		}
	} else {
		// Client configuration
		config.RootCAs = rootCAs
		config.ServerName = opts.ServerName
	}

	return config, nil
}

// ServerTLSConfig returns a TLS configuration suitable for servers.
//
// This is a convenience method that creates a server TLS configuration
// with optional client certificate verification.
//
// Parameters:
//   - attrs: Key attributes identifying the server certificate and key
//   - requireClientCert: Whether to require client certificates (mutual TLS)
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrTLSConfigFailed if the configuration cannot be created
//
// Thread-safe: Yes
//
// Example:
//
//	// Server without client auth
//	tlsConfig, err := ca.ServerTLSConfig(serverKeyAttrs, false)
//
//	// Server with mutual TLS
//	tlsConfig, err := ca.ServerTLSConfig(serverKeyAttrs, true)
func (ca *CA) ServerTLSConfig(attrs *types.KeyAttributes, requireClientCert bool) (*tls.Config, error) {
	opts := &TLSConfigOptions{
		IsServer:                 true,
		RequireClientCert:        requireClientCert,
		PreferServerCipherSuites: true,
	}
	return ca.TLSConfigWithOptions(attrs, opts)
}

// ClientTLSConfig returns a TLS configuration suitable for clients.
//
// This is a convenience method that creates a client TLS configuration
// with proper server name indication (SNI) for certificate verification.
//
// Parameters:
//   - attrs: Key attributes identifying the client certificate and key
//   - serverName: The expected server hostname for certificate verification
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrTLSConfigFailed if the configuration cannot be created
//
// Thread-safe: Yes
//
// Example:
//
//	tlsConfig, err := ca.ClientTLSConfig(clientKeyAttrs, "api.example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	conn, err := tls.Dial("tcp", "api.example.com:443", tlsConfig)
func (ca *CA) ClientTLSConfig(attrs *types.KeyAttributes, serverName string) (*tls.Config, error) {
	opts := &TLSConfigOptions{
		IsServer:   false,
		ServerName: serverName,
	}
	return ca.TLSConfigWithOptions(attrs, opts)
}

// QuantumSafeTLSConfig creates a TLS configuration optimized for post-quantum
// cryptographic algorithms.
//
// This method starts from the standard TLSConfig and clears CurvePreferences
// so the TLS runtime can negotiate the best available option, including hybrid
// post-quantum key exchange when available. When Go's crypto/tls natively
// supports X25519Kyber768, this method will enable it automatically.
//
// Parameters:
//   - attrs: Key attributes identifying the certificate and key to use
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrTLSConfigFailed if the TLS configuration cannot be created
//
// Thread-safe: Yes
func (ca *CA) QuantumSafeTLSConfig(attrs *types.KeyAttributes) (*tls.Config, error) {
	tlsConfig, err := ca.TLSConfig(attrs)
	if err != nil {
		return nil, err
	}
	// TODO: When Go's crypto/tls supports hybrid key exchange (X25519Kyber768),
	// enable it here. For now, clear CurvePreferences to allow the TLS runtime
	// to negotiate the best available option.
	tlsConfig.CurvePreferences = nil
	return tlsConfig, nil
}

// MutualTLSConfig returns a TLS configuration for mutual TLS.
//
// This is a convenience method that creates a TLS configuration
// suitable for mutual TLS (mTLS) where both client and server
// authenticate each other with certificates.
//
// The configuration works for both server and client contexts:
//   - For servers: Requires and verifies client certificates
//   - For clients: Uses the certificate for authentication
//
// Parameters:
//   - attrs: Key attributes identifying the certificate and key
//
// Returns:
//   - ErrNotInitialized if the CA has not been initialized
//   - ErrTLSConfigFailed if the configuration cannot be created
//
// Thread-safe: Yes
//
// Example (Server):
//
//	tlsConfig, err := ca.MutualTLSConfig(serverKeyAttrs)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	server := &http.Server{
//	    Addr:      ":8443",
//	    TLSConfig: tlsConfig,
//	}
//
// Example (Client):
//
//	tlsConfig, err := ca.MutualTLSConfig(clientKeyAttrs)
//	tlsConfig.ServerName = "server.example.com"
func (ca *CA) MutualTLSConfig(attrs *types.KeyAttributes) (*tls.Config, error) {
	opts := &TLSConfigOptions{
		IsServer:                 true,
		RequireClientCert:        true,
		PreferServerCipherSuites: true,
	}
	return ca.TLSConfigWithOptions(attrs, opts)
}

// VerifyPeerCertificate creates a verification callback for TLS connections.
//
// This method returns a callback function suitable for use with
// tls.Config.VerifyPeerCertificate. The callback performs additional
// verification including:
//   - Certificate revocation checking via the CA's revocation list
//   - Logging of certificate details for debugging and auditing
//
// The callback should be used in conjunction with normal certificate
// verification, not as a replacement.
//
// Parameters:
//   - rawCerts: The raw certificate chain presented by the peer
//   - verifiedChains: The chains that were verified by the standard verification
//
// Returns:
//   - ErrCertificateRevoked if any certificate in the chain is revoked
//   - ErrCertificateNotYetValid if the certificate's NotBefore is in the future
//   - ErrCertificateExpired if the certificate has expired
//   - ErrPeerVerificationFailed for other verification errors
//
// Thread-safe: Yes
//
// Example:
//
//	tlsConfig.VerifyPeerCertificate = ca.VerifyPeerCertificate
func (ca *CA) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("%w: no certificates presented", ErrPeerVerificationFailed)
	}

	// Parse the peer certificate
	peerCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("%w: failed to parse peer certificate: %v", ErrPeerVerificationFailed, err)
	}

	// Log certificate details for auditing
	slog.Debug("TLS peer certificate verification",
		"subject", peerCert.Subject.String(),
		"issuer", peerCert.Issuer.String(),
		"serial", peerCert.SerialNumber.String(),
		"not_before", peerCert.NotBefore,
		"not_after", peerCert.NotAfter,
	)

	// Check revocation status
	revoked, err := ca.IsRevoked(peerCert.SerialNumber)
	if err != nil {
		slog.Warn("TLS: failed to check revocation status",
			"serial", peerCert.SerialNumber.String(),
			"error", err,
		)
		// Continue with verification if revocation check fails
	} else if revoked {
		slog.Warn("TLS: peer certificate is revoked",
			"subject", peerCert.Subject.String(),
			"serial", peerCert.SerialNumber.String(),
		)
		return fmt.Errorf("%w: serial %s", ErrCertificateRevoked, peerCert.SerialNumber.String())
	}

	// Check certificate validity period
	now := time.Now()
	if now.Before(peerCert.NotBefore) {
		return fmt.Errorf("%w: %v", ErrCertificateNotYetValid, peerCert.Subject.String())
	}
	if now.After(peerCert.NotAfter) {
		return fmt.Errorf("%w: %v", ErrCertificateExpired, peerCert.Subject.String())
	}

	// Check intermediate certificates in the chain
	for i := 1; i < len(rawCerts); i++ {
		intermediateCert, err := x509.ParseCertificate(rawCerts[i])
		if err != nil {
			slog.Warn("TLS: failed to parse intermediate certificate",
				"index", i,
				"error", err,
			)
			continue
		}

		revoked, err := ca.IsRevoked(intermediateCert.SerialNumber)
		if err != nil {
			slog.Warn("TLS: failed to check intermediate revocation",
				"serial", intermediateCert.SerialNumber.String(),
				"error", err,
			)
		} else if revoked {
			slog.Warn("TLS: intermediate certificate is revoked",
				"subject", intermediateCert.Subject.String(),
				"serial", intermediateCert.SerialNumber.String(),
			)
			return fmt.Errorf("%w: intermediate certificate revoked: serial %s",
				ErrCertificateRevoked, intermediateCert.SerialNumber.String())
		}
	}

	slog.Debug("TLS peer certificate verification successful",
		"subject", peerCert.Subject.String(),
	)

	return nil
}

// buildCAPool creates a certificate pool from the CA's certificates.
func (ca *CA) buildCAPool() *x509.CertPool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	pool := x509.NewCertPool()
	if ca.rootCert != nil {
		pool.AddCert(ca.rootCert)
	}
	if ca.intermediateCert != nil {
		pool.AddCert(ca.intermediateCert)
	}
	return pool
}

// =============================================================================
// Standalone TLS Helper Functions
// =============================================================================

// SecureCipherSuites returns a list of recommended cipher suites for TLS 1.2.
//
// The returned cipher suites are ordered by preference and include only
// secure algorithms with forward secrecy (ECDHE key exchange). The list
// prefers:
//  1. ChaCha20-Poly1305 (efficient on systems without AES hardware)
//  2. AES-GCM (efficient on systems with AES-NI)
//
// Note: TLS 1.3 cipher suites are not configurable in Go and are handled
// automatically by the runtime.
//
// Returns:
//   - A slice of cipher suite IDs suitable for tls.Config.CipherSuites
//
// Example:
//
//	tlsConfig.CipherSuites = ca.SecureCipherSuites()
func SecureCipherSuites() []uint16 {
	return []uint16{
		// TLS 1.2 cipher suites with ECDHE and authenticated encryption
		// ChaCha20-Poly1305 suites (efficient without hardware AES)
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

		// AES-GCM suites (efficient with hardware AES-NI)
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
}

// DefaultTLSConfig returns a secure default TLS configuration.
//
// The returned configuration has secure defaults but no certificates loaded.
// This is useful as a base configuration to be customized further.
//
// Default settings:
//   - Minimum TLS version: 1.2
//   - Maximum TLS version: 1.3
//   - Secure cipher suites for TLS 1.2
//   - Server cipher suite preference enabled
//
// Returns:
//   - A tls.Config with secure defaults
//
// Example:
//
//	config := ca.DefaultTLSConfig()
//	config.Certificates = []tls.Certificate{myCert}
func DefaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		CipherSuites:             SecureCipherSuites(),
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   false,
	}
}

// LoadTLSCertificate loads a TLS certificate from PEM-encoded data.
//
// This function parses PEM-encoded certificate and private key data
// and combines them into a tls.Certificate. The certificate chain
// can contain multiple certificates (leaf first, then intermediates).
//
// Parameters:
//   - certPEM: PEM-encoded certificate(s)
//   - keyPEM: PEM-encoded private key
//
// Returns:
//   - ErrInvalidPEM if the PEM data is malformed
//   - ErrKeyCertMismatch if the key doesn't match the certificate
//
// Example:
//
//	certPEM := []byte("-----BEGIN CERTIFICATE-----\n...")
//	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\n...")
//	tlsCert, err := ca.LoadTLSCertificate(certPEM, keyPEM)
func LoadTLSCertificate(certPEM, keyPEM []byte) (tls.Certificate, error) {
	// Parse the certificate chain
	certs, err := ParsePEMCertificateChain(certPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(certs) == 0 {
		return tls.Certificate{}, fmt.Errorf("%w: no certificates found", ErrInvalidPEM)
	}

	// Parse the private key
	privateKey, err := parsePEMPrivateKey(keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Verify key matches certificate
	if err := verifyKeyMatchesCertificate(privateKey, certs[0]); err != nil {
		return tls.Certificate{}, err
	}

	// Build the tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: make([][]byte, len(certs)),
		PrivateKey:  privateKey,
		Leaf:        certs[0],
	}
	for i, cert := range certs {
		tlsCert.Certificate[i] = cert.Raw
	}

	return tlsCert, nil
}

// LoadTLSCertificateFiles loads a TLS certificate from file paths.
//
// This function reads PEM-encoded certificate and private key files
// and combines them into a tls.Certificate.
//
// Note: For production use with go-xkms, prefer using the CA's
// TLSCertificate method which leverages secure key storage backends.
//
// Parameters:
//   - certPath: Path to PEM-encoded certificate file
//   - keyPath: Path to PEM-encoded private key file
//
// Returns:
//   - ErrInvalidPEM if the files are malformed
//   - ErrKeyCertMismatch if the key doesn't match the certificate
//   - os.PathError if files cannot be read
//
// Example:
//
//	tlsCert, err := ca.LoadTLSCertificateFiles("/path/to/cert.pem", "/path/to/key.pem")
func LoadTLSCertificateFiles(certPath, keyPath string) (tls.Certificate, error) {
	// Use the standard library's X509KeyPair which handles file reading
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: %v", ErrTLSConfigFailed, err)
	}

	// Parse the leaf certificate for the Leaf field
	if len(tlsCert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err == nil {
			tlsCert.Leaf = leaf
		}
	}

	return tlsCert, nil
}

// ParsePEMCertificateChain parses a PEM bundle into certificates.
//
// This function parses all CERTIFICATE blocks from PEM data and returns
// them as parsed x509.Certificate objects. The certificates are returned
// in the order they appear in the PEM data.
//
// Parameters:
//   - pemData: PEM-encoded certificate data (may contain multiple certs)
//
// Returns:
//   - ErrInvalidPEM if no valid certificates are found
//
// Example:
//
//	certs, err := ca.ParsePEMCertificateChain(pemBundle)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d certificates\n", len(certs))
func ParsePEMCertificateChain(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse certificate: %v", ErrInvalidPEM, err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificates found", ErrInvalidPEM)
	}

	return certs, nil
}

// =============================================================================
// Internal Helper Functions
// =============================================================================

// parsePEMPrivateKey parses a PEM-encoded private key.
func parsePEMPrivateKey(pemData []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrInvalidPEM)
	}

	// Try different private key formats
	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse PKCS#8 key: %v", ErrInvalidPEM, err)
		}
		return key, nil

	case "RSA PRIVATE KEY":
		// PKCS#1 RSA format
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse PKCS#1 RSA key: %v", ErrInvalidPEM, err)
		}
		return key, nil

	case "EC PRIVATE KEY":
		// SEC 1 EC format
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse EC key: %v", ErrInvalidPEM, err)
		}
		return key, nil

	default:
		return nil, fmt.Errorf("%w: unsupported key type: %s", ErrInvalidPEM, block.Type)
	}
}

// verifyKeyMatchesCertificate verifies that a private key matches a certificate.
func verifyKeyMatchesCertificate(key crypto.PrivateKey, cert *x509.Certificate) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: certificate has non-RSA public key", ErrKeyCertMismatch)
		}
		if k.N.Cmp(pub.N) != 0 {
			return fmt.Errorf("%w: RSA key modulus mismatch", ErrKeyCertMismatch)
		}

	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: certificate has non-ECDSA public key", ErrKeyCertMismatch)
		}
		if !k.PublicKey.Equal(pub) {
			return fmt.Errorf("%w: ECDSA key point mismatch", ErrKeyCertMismatch)
		}

	case ed25519.PrivateKey:
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: certificate has non-Ed25519 public key", ErrKeyCertMismatch)
		}
		derivedPub := k.Public().(ed25519.PublicKey)
		if !pub.Equal(derivedPub) {
			return fmt.Errorf("%w: Ed25519 key mismatch", ErrKeyCertMismatch)
		}

	default:
		return fmt.Errorf("%w: unsupported key type: %T", ErrKeyCertMismatch, key)
	}

	return nil
}

// =============================================================================
// TLS Certificate Utilities
// =============================================================================

// TLSCertificateInfo provides information about a TLS certificate.
type TLSCertificateInfo struct {
	// Subject is the certificate subject distinguished name.
	Subject string

	// Issuer is the certificate issuer distinguished name.
	Issuer string

	// SerialNumber is the certificate serial number.
	SerialNumber *big.Int

	// NotBefore is when the certificate becomes valid.
	NotBefore time.Time

	// NotAfter is when the certificate expires.
	NotAfter time.Time

	// DNSNames contains the DNS names in the SAN extension.
	DNSNames []string

	// IPAddresses contains the IP addresses in the SAN extension.
	IPAddresses []string

	// IsCA indicates whether this is a CA certificate.
	IsCA bool

	// KeyAlgorithm is the public key algorithm.
	KeyAlgorithm string
}

// GetTLSCertificateInfo extracts information from a tls.Certificate.
//
// This is a utility function for debugging and logging TLS certificate details.
//
// Parameters:
//   - tlsCert: The TLS certificate to examine
//
// Returns:
//   - nil if the certificate has no leaf certificate set
//
// Example:
//
//	info := ca.GetTLSCertificateInfo(&tlsCert)
//	if info != nil {
//	    fmt.Printf("Certificate for: %s\n", info.Subject)
//	}
func GetTLSCertificateInfo(tlsCert *tls.Certificate) *TLSCertificateInfo {
	if tlsCert == nil || tlsCert.Leaf == nil {
		return nil
	}

	cert := tlsCert.Leaf
	info := &TLSCertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DNSNames:     cert.DNSNames,
		IsCA:         cert.IsCA,
		KeyAlgorithm: cert.PublicKeyAlgorithm.String(),
	}

	// Convert IP addresses to strings
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	return info
}
