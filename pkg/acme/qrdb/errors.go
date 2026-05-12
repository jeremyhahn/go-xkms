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

// Package qrdb provides integration with QRDB for distributed storage,
// key-value operations, and cluster management.
package qrdb

import (
	"errors"
	"strconv"
	"strings"
)

// ErrorCode identifies the category of a qrdb error.
type ErrorCode uint8

const (
	// ErrorCodeInvalidConfig indicates invalid configuration.
	ErrorCodeInvalidConfig ErrorCode = iota + 1
	// ErrorCodeConnection indicates a connection failure.
	ErrorCodeConnection
	// ErrorCodeNotFound indicates the requested resource was not found.
	ErrorCodeNotFound
	// ErrorCodeAlreadyExists indicates the resource already exists.
	ErrorCodeAlreadyExists
	// ErrorCodeInvalidInput indicates invalid input parameters.
	ErrorCodeInvalidInput
	// ErrorCodeInternal indicates an internal error.
	ErrorCodeInternal
	// ErrorCodeSealed indicates the service is sealed.
	ErrorCodeSealed
	// ErrorCodeNotInitialized indicates the service is not initialized.
	ErrorCodeNotInitialized
	// ErrorCodePermissionDenied indicates insufficient permissions.
	ErrorCodePermissionDenied
	// ErrorCodeSerialization indicates a serialization failure.
	ErrorCodeSerialization
	// ErrorCodeShutdown indicates the service has shut down.
	ErrorCodeShutdown
	// ErrorCodeShutdownInProgress indicates a shutdown is in progress.
	ErrorCodeShutdownInProgress
	// ErrorCodeNoLeader indicates no Raft leader is available.
	ErrorCodeNoLeader
	// ErrorCodeNotLeader indicates the node is not the Raft leader.
	ErrorCodeNotLeader
	// ErrorCodeServiceInit indicates a service initialization failure.
	ErrorCodeServiceInit
)

// errorCodeNames maps error codes to human-readable names using O(1) lookup.
var errorCodeNames = map[ErrorCode]string{
	ErrorCodeInvalidConfig:      "InvalidConfig",
	ErrorCodeConnection:         "Connection",
	ErrorCodeNotFound:           "NotFound",
	ErrorCodeAlreadyExists:      "AlreadyExists",
	ErrorCodeInvalidInput:       "InvalidInput",
	ErrorCodeInternal:           "Internal",
	ErrorCodeSealed:             "Sealed",
	ErrorCodeNotInitialized:     "NotInitialized",
	ErrorCodePermissionDenied:   "PermissionDenied",
	ErrorCodeSerialization:      "Serialization",
	ErrorCodeShutdown:           "Shutdown",
	ErrorCodeShutdownInProgress: "ShutdownInProgress",
	ErrorCodeNoLeader:           "NoLeader",
	ErrorCodeNotLeader:          "NotLeader",
	ErrorCodeServiceInit:        "ServiceInit",
}

// String returns the human-readable name of the error code.
func (c ErrorCode) String() string {
	if name, ok := errorCodeNames[c]; ok {
		return name
	}
	return "Unknown(" + strconv.Itoa(int(c)) + ")"
}

// Error is a typed error for qrdb operations. It carries an error code,
// a human-readable message, an optional underlying cause, and optional
// key-value context for debugging.
type Error struct {
	Code    ErrorCode
	Message string
	Cause   error
	Context map[string]interface{}
}

// NewError creates a new Error with the given code and message.
func NewError(code ErrorCode, msg string) *Error {
	return &Error{
		Code:    code,
		Message: msg,
	}
}

// WithCause returns a copy of the error with the given cause attached.
func (e *Error) WithCause(cause error) *Error {
	return &Error{
		Code:    e.Code,
		Message: e.Message,
		Cause:   cause,
		Context: e.Context,
	}
}

// WithContext returns a copy of the error with the given key-value pair
// added to the context map.
func (e *Error) WithContext(key string, value interface{}) *Error {
	ctx := make(map[string]interface{}, len(e.Context)+1)
	for k, v := range e.Context {
		ctx[k] = v
	}
	ctx[key] = value
	return &Error{
		Code:    e.Code,
		Message: e.Message,
		Cause:   e.Cause,
		Context: ctx,
	}
}

// Error returns a human-readable description of the error.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("qrdb: ")
	b.WriteString(e.Code.String())
	b.WriteString(": ")
	b.WriteString(e.Message)
	if e.Cause != nil {
		b.WriteString(": ")
		b.WriteString(e.Cause.Error())
	}
	return b.String()
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error {
	return e.Cause
}

// Is reports whether the target error has the same error code.
func (e *Error) Is(target error) bool {
	var t *Error
	if errors.As(target, &t) {
		return e.Code == t.Code
	}
	return false
}

// IsNotFound reports whether err is a NotFound error.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeNotFound
}

// IsAlreadyExists reports whether err is an AlreadyExists error.
func IsAlreadyExists(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeAlreadyExists
}

// IsInvalidConfig reports whether err is an InvalidConfig error.
func IsInvalidConfig(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeInvalidConfig
}

// IsConnection reports whether err is a Connection error.
func IsConnection(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeConnection
}

// IsInvalidInput reports whether err is an InvalidInput error.
func IsInvalidInput(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeInvalidInput
}

// IsInternal reports whether err is an Internal error.
func IsInternal(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeInternal
}

// IsSealed reports whether err is a Sealed error.
func IsSealed(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeSealed
}

// IsNotInitialized reports whether err is a NotInitialized error.
func IsNotInitialized(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeNotInitialized
}

// IsPermissionDenied reports whether err is a PermissionDenied error.
func IsPermissionDenied(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodePermissionDenied
}

// IsSerialization reports whether err is a Serialization error.
func IsSerialization(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeSerialization
}

// IsShutdown reports whether err is a Shutdown error.
func IsShutdown(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeShutdown
}

// IsShutdownInProgress reports whether err is a ShutdownInProgress error.
func IsShutdownInProgress(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeShutdownInProgress
}

// IsNoLeader reports whether err is a NoLeader error.
func IsNoLeader(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeNoLeader
}

// IsNotLeader reports whether err is a NotLeader error.
func IsNotLeader(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeNotLeader
}

// IsServiceInit reports whether err is a ServiceInit error.
func IsServiceInit(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrorCodeServiceInit
}
