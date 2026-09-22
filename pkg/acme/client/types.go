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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	ErrInvalidRequest        = errors.New("acme-client: invalid certificate request")
	ErrMissingAuthzType      = errors.New("acme-client: missing authorization type")
	ErrMissingAuthzValue     = errors.New("acme-client: missing authorization value")
	ErrMissingChallengeType  = errors.New("acme-client: missing challenge type")
	ErrMissingCSR            = errors.New("acme-client: missing CSR")
	ErrInvalidChallengeSetup = errors.New("acme-client: invalid challenge setup function")

	ErrUnsupportedKeyType = errors.New("acme-client: unsupported private key type")
)

// ChallengeSetupFunc is a function that sets up a challenge response
// It receives the challenge type, token, and key authorization
type ChallengeSetupFunc func(challengeType, token, keyAuth string) error

// ChallengeCleanupFunc is a function that cleans up after a challenge
type ChallengeCleanupFunc func(challengeType string)

// CertificateRequest represents a request for a new certificate.
//
// YAML/mapstructure tags are present on fields that are populated from
// configuration files (AuthzType, AuthzValue, ChallengeType,
// AdditionalOptions). Runtime-only fields (CSR, PrivateKey, and the two
// function-typed challenge callbacks) carry `yaml:"-"` so YAML decoders
// never try to populate them.
type CertificateRequest struct {
	// AuthzType is the ACME authorization type (dns, ip, permanent-identifier)
	AuthzType string `yaml:"authz-type" json:"authz_type" mapstructure:"authz-type"`

	// AuthzValue is the value for the authorization (e.g., domain name, IP address)
	AuthzValue string `yaml:"authz-value" json:"authz_value" mapstructure:"authz-value"`

	// ChallengeType is the ACME challenge type (http-01, dns-01, etc.)
	ChallengeType string `yaml:"challenge-type" json:"challenge_type" mapstructure:"challenge-type"`

	// CSR is the Certificate Signing Request in DER format
	CSR []byte `yaml:"-" json:"-" mapstructure:"-"`

	// PrivateKey is the private key for the certificate (optional)
	PrivateKey crypto.PrivateKey `yaml:"-" json:"-" mapstructure:"-"`

	// ChallengeSetup is called to set up the challenge response
	ChallengeSetup ChallengeSetupFunc `yaml:"-" json:"-" mapstructure:"-"`

	// ChallengeCleanup is called to clean up after the challenge
	ChallengeCleanup ChallengeCleanupFunc `yaml:"-" json:"-" mapstructure:"-"`

	// AdditionalOptions for implementation-specific parameters
	AdditionalOptions map[string]interface{} `yaml:"additional-options,omitempty" json:"additional_options,omitempty" mapstructure:"additional-options"`
}

// Validate validates the certificate request
func (req *CertificateRequest) Validate() error {
	if req.AuthzType == "" {
		return ErrMissingAuthzType
	}

	if req.AuthzValue == "" {
		return ErrMissingAuthzValue
	}

	if req.ChallengeType == "" {
		return ErrMissingChallengeType
	}

	if len(req.CSR) == 0 {
		return ErrMissingCSR
	}

	return nil
}

// encodePrivateKeyPEM encodes a private key to PEM format.
// Used by tests to verify key serialization.
var _ = encodePrivateKeyPEM

func encodePrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	var pemBlock *pem.Block

	switch k := key.(type) {
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *ecdsa.PrivateKey:
		derBytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derBytes,
		}
	case ed25519.PrivateKey:
		derBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		}
	default:
		return nil, ErrUnsupportedKeyType
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// RenewalStatus represents the status of a certificate renewal
type RenewalStatus struct {
	// CertificateSubject is the subject DN of the certificate
	CertificateSubject string

	// NotBefore is the certificate's validity start time
	NotBefore string

	// NotAfter is the certificate's validity end time
	NotAfter string

	// DaysRemaining is the number of days until expiration
	DaysRemaining int

	// ShouldRenew indicates whether the certificate should be renewed
	ShouldRenew bool

	// RenewalAttempted indicates whether renewal was attempted
	RenewalAttempted bool

	// RenewalSuccessful indicates whether renewal was successful
	RenewalSuccessful bool

	// Error contains any error that occurred during renewal
	Error error
}

// CertificateInfo contains information about a certificate and its renewal request
type CertificateInfo struct {
	// Certificate is the x509 certificate
	Certificate *x509.Certificate

	// Request is the original certificate request used to obtain the certificate
	Request *CertificateRequest

	// Identifier is a unique identifier for the certificate
	Identifier string
}

// AuthorizationType represents an ACME authorization type
type AuthorizationType string

const (
	// AuthzTypeDNS represents DNS-based authorization
	AuthzTypeDNS AuthorizationType = "dns"

	// AuthzTypeIP represents IP-based authorization
	AuthzTypeIP AuthorizationType = "ip"

	// AuthzTypePermanentIdentifier represents permanent identifier authorization
	AuthzTypePermanentIdentifier AuthorizationType = "permanent-identifier"
)

// String returns the string representation of the authorization type
func (at AuthorizationType) String() string {
	return string(at)
}

// ChallengeType represents an ACME challenge type
type ChallengeType string

const (
	// ChallengeTypeHTTP01 represents the http-01 challenge
	ChallengeTypeHTTP01 ChallengeType = "http-01"

	// ChallengeTypeDNS01 represents the dns-01 challenge
	ChallengeTypeDNS01 ChallengeType = "dns-01"

	// ChallengeTypeTLSALPN01 represents the tls-alpn-01 challenge
	ChallengeTypeTLSALPN01 ChallengeType = "tls-alpn-01"

	// Custom challenge types for TPM-based operations

	// ChallengeTypeEndorse01 represents TPM EK certificate provisioning
	ChallengeTypeEndorse01 ChallengeType = "endorse-01"

	// ChallengeTypeEnroll01 represents TPM device enrollment
	ChallengeTypeEnroll01 ChallengeType = "enroll-01"

	// ChallengeTypeDeviceAttest01 represents TPM device attestation
	ChallengeTypeDeviceAttest01 ChallengeType = "device-attest-01"
)

// String returns the string representation of the challenge type
func (ct ChallengeType) String() string {
	return string(ct)
}

// EnrollmentResult contains the certificates returned from TPM device enrollment.
// The enroll-01 challenge returns both an IAK (Initial Attestation Key) certificate
// and an IDevID (Initial Device IDentifier) certificate.
type EnrollmentResult struct {
	// IAKCertificate is the Initial Attestation Key certificate
	IAKCertificate *x509.Certificate

	// IDevIDCertificate is the Initial Device IDentifier certificate
	IDevIDCertificate *x509.Certificate

	// Chain is the issuing chain the server returned after the end-entity
	// certificates, ordered leaf-ward first (intermediate, then root) per
	// RFC 8555 §7.4.2. It is what lets an enrolled device resolve the issuer
	// of its own certificate: the issuer is the ENROLLMENT SERVER's CA, which
	// a device's local certificate store does not otherwise hold.
	//
	// Empty when the server sent only end-entity certificates, so a caller
	// must treat it as best-effort and not assume a path can be built.
	Chain []*x509.Certificate
}

// AccountStatus represents the status of an ACME account
type AccountStatus string

const (
	// AccountStatusValid indicates the account is valid and active
	AccountStatusValid AccountStatus = "valid"

	// AccountStatusDeactivated indicates the account has been deactivated
	AccountStatusDeactivated AccountStatus = "deactivated"

	// AccountStatusRevoked indicates the account has been revoked
	AccountStatusRevoked AccountStatus = "revoked"
)

// String returns the string representation of the account status
func (as AccountStatus) String() string {
	return string(as)
}

// OrderStatus represents the status of an ACME order
type OrderStatus string

const (
	// OrderStatusPending indicates the order is pending authorization
	OrderStatusPending OrderStatus = "pending"

	// OrderStatusReady indicates the order is ready to be finalized
	OrderStatusReady OrderStatus = "ready"

	// OrderStatusProcessing indicates the order is being processed
	OrderStatusProcessing OrderStatus = "processing"

	// OrderStatusValid indicates the order is valid and certificate issued
	OrderStatusValid OrderStatus = "valid"

	// OrderStatusInvalid indicates the order is invalid
	OrderStatusInvalid OrderStatus = "invalid"
)

// String returns the string representation of the order status
func (os OrderStatus) String() string {
	return string(os)
}
