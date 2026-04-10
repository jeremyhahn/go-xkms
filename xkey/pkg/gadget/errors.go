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

package gadget

import (
	"errors"
	"fmt"
)

// Sentinel errors for gadget transport operations.
var (
	// ErrTransportClosed indicates the transport has been closed.
	ErrTransportClosed = errors.New("gadget: transport closed")

	// ErrTransportNotReady indicates the transport is not initialized or ready.
	ErrTransportNotReady = errors.New("gadget: transport not ready")

	// ErrNilTransport indicates a nil transport was provided.
	ErrNilTransport = errors.New("gadget: nil transport")

	// ErrConfigFSNotAvailable indicates the ConfigFS filesystem is not
	// mounted or accessible.
	ErrConfigFSNotAvailable = errors.New("gadget: configfs not available")

	// ErrUDCNotFound indicates no USB Device Controller was found on
	// the system.
	ErrUDCNotFound = errors.New("gadget: UDC not found")

	// ErrGadgetAlreadyExists indicates a gadget with this name already
	// exists in ConfigFS.
	ErrGadgetAlreadyExists = errors.New("gadget: gadget already exists")

	// ErrGadgetNotBound indicates the gadget is not bound to a UDC.
	ErrGadgetNotBound = errors.New("gadget: gadget not bound")

	// ErrFunctionFSMountFailed indicates the FunctionFS instance could
	// not be mounted.
	ErrFunctionFSMountFailed = errors.New("gadget: functionfs mount failed")

	// ErrDescriptorWriteFailed indicates USB descriptors could not be
	// written to ep0.
	ErrDescriptorWriteFailed = errors.New("gadget: descriptor write failed")

	// ErrEndpointOpenFailed indicates a data endpoint could not be opened.
	ErrEndpointOpenFailed = errors.New("gadget: endpoint open failed")

	// ErrEndpointIOFailed indicates a read or write on an endpoint failed.
	ErrEndpointIOFailed = errors.New("gadget: endpoint I/O failed")

	// ErrNilDevice indicates a nil device was provided.
	ErrNilDevice = errors.New("gadget: nil device")

	// ErrNilLogger indicates a nil logger was provided.
	ErrNilLogger = errors.New("gadget: nil logger")
)

// GadgetError provides structured error information for gadget operations.
// It wraps an underlying error with the operation name for context.
type GadgetError struct {
	// Operation is the name of the operation that failed.
	Operation string

	// Err is the underlying error.
	Err error
}

// Error returns the formatted error message.
func (e *GadgetError) Error() string {
	return fmt.Sprintf("gadget: %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *GadgetError) Unwrap() error {
	return e.Err
}

// NewGadgetError creates a new GadgetError with the given operation and cause.
func NewGadgetError(operation string, err error) *GadgetError {
	return &GadgetError{
		Operation: operation,
		Err:       err,
	}
}
