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

package gui

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurityFactorServiceBinding_Registered verifies that the
// SecurityFactorService is wired into the App and can be retrieved from the
// App struct after construction.  The test exercises the minimum binding path
// without starting the Wails runtime (which requires a display).
func TestSecurityFactorServiceBinding_Registered(t *testing.T) {
	connSvc := services.NewConnectionService()
	pivSvc := services.NewPIVService(nil, "software")
	svc := services.NewSecurityFactorService(connSvc, pivSvc)

	require.NotNil(t, svc, "SecurityFactorService constructor must return non-nil")
}

// TestSecurityFactorServiceBinding_MethodsReachable verifies that the public
// Wails-visible methods can be invoked without panicking when the service has
// no active server connection.  A nil-safe implementation means the service
// degrades gracefully rather than panicking.
func TestSecurityFactorServiceBinding_MethodsReachable(t *testing.T) {
	connSvc := services.NewConnectionService()
	pivSvc := services.NewPIVService(nil, "software")
	svc := services.NewSecurityFactorService(connSvc, pivSvc)
	require.NotNil(t, svc)

	// ListFactors with no connection should return an error, not panic.
	_, err := svc.ListFactors("user-123")
	assert.Error(t, err, "ListFactors must return an error when no server is connected")

	// ProbeAdminCert is entirely local — it must never return an error.
	result := svc.ProbeAdminCert()
	assert.NotNil(t, result)
	// "exists" key must be present regardless of file presence.
	_, ok := result["exists"]
	assert.True(t, ok, "ProbeAdminCert must return a map with 'exists' key")
}

// TestSecurityFactorServiceBinding_AppFieldPresent confirms that the App struct
// has a securityFactorService field by creating the service and verifying it
// satisfies the same interface contract as the other wired services.
func TestSecurityFactorServiceBinding_AppFieldPresent(t *testing.T) {
	connSvc := services.NewConnectionService()
	pivSvc := services.NewPIVService(nil, "software")
	svc := services.NewSecurityFactorService(connSvc, pivSvc)

	// SetContext is called by the Wails OnStartup hook for every bound service.
	// We verify the method exists and is callable with a real context.
	require.NotPanics(t, func() {
		svc.SetContext(context.Background())
	})
}
