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

package errors

import (
	"encoding/json"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// grpcMetadataKey is the metadata key used to serialize TrustedCAError data.
const grpcMetadataKey = "trustedca-error-bin"

// errorTypeToGRPCCodeMap maps ErrorType to gRPC status codes.
var errorTypeToGRPCCodeMap = map[ErrorType]codes.Code{
	InternalServer:          codes.Internal,
	Malformed:               codes.InvalidArgument,
	Unauthorized:            codes.PermissionDenied,
	NotFound:                codes.NotFound,
	RateLimit:               codes.ResourceExhausted,
	RejectedIdentifier:      codes.InvalidArgument,
	InvalidEmail:            codes.InvalidArgument,
	ConnectionFailure:       codes.Unavailable,
	CAA:                     codes.FailedPrecondition,
	MissingSCTs:             codes.Internal,
	Duplicate:               codes.AlreadyExists,
	OrderNotReady:           codes.FailedPrecondition,
	DNS:                     codes.Unavailable,
	BadPublicKey:            codes.InvalidArgument,
	BadCSR:                  codes.InvalidArgument,
	AlreadyRevoked:          codes.AlreadyExists,
	BadRevocationReason:     codes.InvalidArgument,
	UnsupportedContact:      codes.InvalidArgument,
	UnknownSerial:           codes.NotFound,
	Conflict:                codes.AlreadyExists,
	InvalidProfile:          codes.InvalidArgument,
	AlreadyReplaced:         codes.AlreadyExists,
	BadSignatureAlgorithm:   codes.InvalidArgument,
	AccountDoesNotExist:     codes.NotFound,
	BadNonce:                codes.InvalidArgument,
	ExternalAccountRequired: codes.FailedPrecondition,
	IncorrectResponse:       codes.InvalidArgument,
	InvalidContact:          codes.InvalidArgument,
	TLSError:                codes.Unavailable,
	UnsupportedIdentifier:   codes.InvalidArgument,
	UserActionRequired:      codes.FailedPrecondition,
	AccountExists:           codes.AlreadyExists,
	CompoundError:           codes.InvalidArgument,
	BadAttestationStatement: codes.InvalidArgument,
	StorageFailure:          codes.Internal,
	SerializationFailure:    codes.Internal,
	TenantNotFound:          codes.NotFound,
	TenantSuspended:         codes.PermissionDenied,
	TenantQuotaExceeded:     codes.ResourceExhausted,
	CertificateExpired:      codes.FailedPrecondition,
	CertificateNotYetValid:  codes.FailedPrecondition,
	SigningFailure:          codes.Internal,
	VerificationFailure:     codes.InvalidArgument,
	KeyGenerationFailure:    codes.Internal,
	TPMError:                codes.Internal,
	OCSPFailure:             codes.Internal,
	CRLFailure:              codes.Internal,
	PolicyViolation:         codes.PermissionDenied,
	AuthorizationExpired:    codes.FailedPrecondition,
	ChallengeTimeout:        codes.DeadlineExceeded,
	InvalidToken:            codes.Unauthenticated,
}

// grpcCodeToErrorTypeMap maps gRPC codes back to error types.
// This is a best-effort reverse mapping for when metadata is not available.
var grpcCodeToErrorTypeMap = map[codes.Code]ErrorType{
	codes.InvalidArgument:    Malformed,
	codes.PermissionDenied:   Unauthorized,
	codes.NotFound:           NotFound,
	codes.ResourceExhausted:  RateLimit,
	codes.Unavailable:        ConnectionFailure,
	codes.FailedPrecondition: OrderNotReady,
	codes.AlreadyExists:      Duplicate,
	codes.Unauthenticated:    InvalidToken,
	codes.DeadlineExceeded:   ChallengeTimeout,
	codes.Internal:           InternalServer,
}

// GRPCStatus implements the interface implicitly defined by gRPC's
// status.FromError, which uses this function to detect if the error
// produced by the gRPC server implementation is a gRPC status.Status.
//
// Implementing this means that TrustedCAErrors serialized in gRPC
// response metadata can be accompanied by a gRPC status other than
// "UNKNOWN".
func (e *TrustedCAError) GRPCStatus() *status.Status {
	return status.New(e.grpcCode(), e.Error())
}

// grpcCode maps ErrorType to gRPC status codes.
func (e *TrustedCAError) grpcCode() codes.Code {
	if c, ok := errorTypeToGRPCCodeMap[e.Type]; ok {
		return c
	}
	return codes.Unknown
}

// grpcErrorData is the serialized form of TrustedCAError for gRPC transport.
type grpcErrorData struct {
	Type       ErrorType          `json:"type"`
	Detail     string             `json:"detail"`
	SubErrors  []grpcSubErrorData `json:"sub_errors,omitempty"`
	RetryAfter int64              `json:"retry_after,omitempty"` // nanoseconds
	Instance   string             `json:"instance,omitempty"`
}

// grpcSubErrorData is the serialized form of SubError for gRPC transport.
type grpcSubErrorData struct {
	Type       ErrorType      `json:"type"`
	Detail     string         `json:"detail"`
	Identifier ACMEIdentifier `json:"identifier"`
}

// ToGRPCMetadata serializes the TrustedCAError for gRPC metadata transport.
// This enables full error type preservation across gRPC boundaries.
func (e *TrustedCAError) ToGRPCMetadata() ([]byte, error) {
	data := grpcErrorData{
		Type:       e.Type,
		Detail:     e.Detail,
		RetryAfter: int64(e.RetryAfter),
		Instance:   e.Instance,
	}
	for _, se := range e.SubErrors {
		if se.TrustedCAError != nil {
			data.SubErrors = append(data.SubErrors, grpcSubErrorData{
				Type:       se.TrustedCAError.Type,
				Detail:     se.TrustedCAError.Detail,
				Identifier: se.Identifier,
			})
		}
	}
	return json.Marshal(data)
}

// FromGRPCMetadata deserializes a TrustedCAError from gRPC metadata.
func FromGRPCMetadata(data []byte) (*TrustedCAError, error) {
	var ged grpcErrorData
	if err := json.Unmarshal(data, &ged); err != nil {
		return nil, err
	}

	tce := &TrustedCAError{
		Type:       ged.Type,
		Detail:     ged.Detail,
		RetryAfter: time.Duration(ged.RetryAfter),
		Instance:   ged.Instance,
	}

	for _, sed := range ged.SubErrors {
		tce.SubErrors = append(tce.SubErrors, SubError{
			TrustedCAError: &TrustedCAError{
				Type:   sed.Type,
				Detail: sed.Detail,
			},
			Identifier: sed.Identifier,
		})
	}

	return tce, nil
}

// GRPCMetadataKey returns the metadata key for TrustedCAError data.
func GRPCMetadataKey() string {
	return grpcMetadataKey
}

// FromGRPCStatus attempts to extract a TrustedCAError from a gRPC status.
// Returns nil if the status does not contain a TrustedCAError.
func FromGRPCStatus(s *status.Status) *TrustedCAError {
	if s == nil {
		return nil
	}

	// Map gRPC code back to ErrorType as a fallback
	errType := grpcCodeToErrorType(s.Code())

	return &TrustedCAError{
		Type:   errType,
		Detail: s.Message(),
	}
}

// grpcCodeToErrorType maps gRPC codes back to error types.
// This is a best-effort reverse mapping for when metadata is not available.
func grpcCodeToErrorType(c codes.Code) ErrorType {
	if et, ok := grpcCodeToErrorTypeMap[c]; ok {
		return et
	}
	return InternalServer
}
