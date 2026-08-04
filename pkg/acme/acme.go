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

// Package acme provides a unified API by re-exporting types from subpackages.
//
// The ACME implementation is organized into focused subpackages:
//   - client: ACME client implementation
//   - common: Shared types and constants
//   - entities: ACME protocol entities (Account, Order, Authorization, Challenge, etc.)
//   - server: ACME server implementation
//   - storage: Storage interfaces and implementations
//   - challenges: Challenge type implementations
//
// This package provides convenient access to commonly used types at the root level.
package acme

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
)

// Client types
type (
	// Client represents an ACME client
	Client = client.Client

	// Config defines the configuration for an ACME client
	Config = client.Config

	// ClientParams contains the parameters for creating an ACME client
	ClientParams = client.Params

	// RenewalConfig defines the configuration for the auto-renewal service
	RenewalConfig = client.RenewalConfig

	// EnrollmentConfig defines the configuration for TPM device enrollment
	EnrollmentConfig = client.EnrollmentConfig

	// CrossSignConfig defines the configuration for cross-signing
	CrossSignConfig = client.CrossSignConfig

	// ChallengeSetupFunc is a function that sets up a challenge response
	ChallengeSetupFunc = client.ChallengeSetupFunc

	// ChallengeCleanupFunc is a function that cleans up after a challenge
	ChallengeCleanupFunc = client.ChallengeCleanupFunc

	// RenewalStatus represents the status of a certificate renewal
	RenewalStatus = client.RenewalStatus

	// CertificateInfo contains information about a certificate and its renewal request
	CertificateInfo = client.CertificateInfo

	// CertificateRequest represents a request for a new certificate
	CertificateRequest = client.CertificateRequest
)

// Common types
type (
	// Directory provides the ACME server's directory endpoints as per RFC 8555 Section 7.1.1
	Directory = common.Directory

	// Meta provides additional information about the ACME server
	Meta = common.Meta

	// CertificateAuthority defines the minimal interface required by challenge verifiers
	CertificateAuthority = common.CertificateAuthority

	// ChallengeVerifierFunc defines the function signature for challenge verification functions
	ChallengeVerifierFunc = common.ChallengeVerifierFunc
)

// Entity types
type (
	// ACMEAccount represents an ACME account
	ACMEAccount = entities.ACMEAccount

	// ACMEOrder represents an ACME order
	ACMEOrder = entities.ACMEOrder

	// ACMEAuthorization represents an ACME authorization
	ACMEAuthorization = entities.ACMEAuthorization

	// ACMEChallenge represents an ACME challenge
	ACMEChallenge = entities.ACMEChallenge

	// ACMECertificate represents an ACME certificate
	ACMECertificate = entities.ACMECertificate

	// ACMENonce represents an ACME nonce
	ACMENonce = entities.ACMENonce

	// ACMEIdentifier represents an ACME identifier
	ACMEIdentifier = entities.ACMEIdentifier

	// ExternalAccountBinding represents external account binding data
	ExternalAccountBinding = entities.ExternalAccountBinding

	// Error represents an ACME error
	Error = entities.Error

	// SubProblem represents a sub-problem in an ACME error
	SubProblem = entities.SubProblem
)

// Storage types
type (
	// Factory defines the interface for creating DAO instances
	Factory = storage.Factory
)

// Authorization type constants
const (
	AuthzTypeDNS                 = common.AuthzTypeDNS
	AuthzTypeIP                  = common.AuthzTypeIP
	AuthzTypePermanentIdentifier = common.AuthzTypePermanentIdentifier
)

// Challenge type constants
const (
	ChallengeTypeEnroll01       = common.ChallengeTypeEnroll01
	ChallengeTypeDNS01          = common.ChallengeTypeDNS01
	ChallengeTypeHTTP01         = common.ChallengeTypeHTTP01
	ChallengeTypeEndorse01      = common.ChallengeTypeEndorse01
	ChallengeTypeDeviceAttest01 = common.ChallengeTypeDeviceAttest01
)

// Status constants
const (
	StatusValid       = common.StatusValid
	StatusPending     = common.StatusPending
	StatusProcessing  = common.StatusProcessing
	StatusInvalid     = common.StatusInvalid
	StatusDeactivated = common.StatusDeactivated
	StatusExpired     = common.StatusExpired
	StatusRevoked     = common.StatusRevoked
	StatusReady       = common.StatusReady
)

// Typed constants from client package
type (
	// AuthorizationType represents an ACME authorization type
	AuthorizationType = client.AuthorizationType

	// ChallengeType represents an ACME challenge type
	ChallengeType = client.ChallengeType

	// AccountStatus represents the status of an ACME account
	AccountStatus = client.AccountStatus

	// OrderStatus represents the status of an ACME order
	OrderStatus = client.OrderStatus
)

// Typed constant values
const (
	// Authorization types
	AuthzTypeDNSTyped                 AuthorizationType = client.AuthzTypeDNS
	AuthzTypeIPTyped                  AuthorizationType = client.AuthzTypeIP
	AuthzTypePermanentIdentifierTyped AuthorizationType = client.AuthzTypePermanentIdentifier

	// Challenge types
	ChallengeTypeHTTP01Typed        ChallengeType = client.ChallengeTypeHTTP01
	ChallengeTypeDNS01Typed         ChallengeType = client.ChallengeTypeDNS01
	ChallengeTypeTLSALPN01Typed     ChallengeType = client.ChallengeTypeTLSALPN01
	ChallengeTypeEndorse01Typed     ChallengeType = client.ChallengeTypeEndorse01
	ChallengeTypeEnroll01Typed      ChallengeType = client.ChallengeTypeEnroll01
	ChallengeTypeDeviceAttest01Type ChallengeType = client.ChallengeTypeDeviceAttest01

	// Account status
	AccountStatusValid       AccountStatus = client.AccountStatusValid
	AccountStatusDeactivated AccountStatus = client.AccountStatusDeactivated
	AccountStatusRevoked     AccountStatus = client.AccountStatusRevoked

	// Order status
	OrderStatusPending    OrderStatus = client.OrderStatusPending
	OrderStatusReady      OrderStatus = client.OrderStatusReady
	OrderStatusProcessing OrderStatus = client.OrderStatusProcessing
	OrderStatusValidOrder OrderStatus = client.OrderStatusValid
	OrderStatusInvalid    OrderStatus = client.OrderStatusInvalid
)

// Client errors
var (
	ErrAccountNotFound           = client.ErrAccountNotFound
	ErrRegistrationFailed        = client.ErrRegistrationFailed
	ErrOrderCreationFailed       = client.ErrOrderCreationFailed
	ErrChallengeResolution       = client.ErrChallengeResolution
	ErrChallengeFinalization     = client.ErrChallengeFinalization
	ErrAuthorizationFailed       = client.ErrAuthorizationFailed
	ErrCABundleDownloadFailed    = client.ErrCABundleDownloadFailed
	ErrInvalidCACertificate      = client.ErrInvalidCACertificate
	ErrInvalidCrossSignerAuthzID = client.ErrInvalidCrossSignerAuthzID
	ErrCertificateNotFound       = client.ErrCertificateNotFound
	ErrInvalidConfiguration      = client.ErrInvalidConfiguration
	ErrNilSigner                 = client.ErrNilSigner
	ErrNilStorage                = client.ErrNilStorage
	ErrInvalidRequest            = client.ErrInvalidRequest
	ErrMissingAuthzType          = client.ErrMissingAuthzType
	ErrMissingAuthzValue         = client.ErrMissingAuthzValue
	ErrMissingChallengeType      = client.ErrMissingChallengeType
	ErrMissingCSR                = client.ErrMissingCSR
	ErrInvalidChallengeSetup     = client.ErrInvalidChallengeSetup
	ErrInvalidDirectoryURL       = client.ErrInvalidDirectoryURL
	ErrInvalidTimeout            = client.ErrInvalidTimeout
	ErrInvalidRetryAttempts      = client.ErrInvalidRetryAttempts
	ErrInvalidRenewalThreshold   = client.ErrInvalidRenewalThreshold
)

// Common errors
var (
	ErrInvalidChallengeType = common.ErrInvalidChallengeType
	ErrAccountAlreadyExists = common.ErrAccountAlreadyExists
)

// Additional errors
var (
	// ErrCrossSignerSameDirectoryURL is returned when cross-signer uses same directory as primary
	ErrCrossSignerSameDirectoryURL = errors.New("acme: cross-signer cannot use the same directory URL as the primary ACME client")
)

// Client constructor functions
var (
	// DefaultConfig returns the default ACME client configuration
	DefaultConfig = client.DefaultConfig

	// DefaultRenewalConfig returns the default renewal service configuration
	DefaultRenewalConfig = client.DefaultRenewalConfig
)
