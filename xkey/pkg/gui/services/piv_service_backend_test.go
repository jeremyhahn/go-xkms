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

package services

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPIVService_GetBackend_ReturnsConstructorValue verifies that GetBackend
// returns the backend name provided to NewPIVService.
func TestPIVService_GetBackend_ReturnsConstructorValue(t *testing.T) {
	svc := NewPIVService(nil, "tpm2")
	assert.Equal(t, "tpm2", svc.GetBackend())
}

// TestPIVService_GetBackend_DefaultsToEmpty verifies that an empty backend
// string is returned correctly when no backend was specified at construction.
func TestPIVService_GetBackend_DefaultsToEmpty(t *testing.T) {
	svc := NewPIVService(nil, "")
	assert.Equal(t, "", svc.GetBackend())
}

// TestPIVService_SetBackend_UpdatesBackend verifies that SetBackend replaces
// the previously configured backend and GetBackend reflects the new value.
func TestPIVService_SetBackend_UpdatesBackend(t *testing.T) {
	svc := NewPIVService(nil, "software")
	assert.Equal(t, "software", svc.GetBackend())

	svc.SetBackend("tpm2")
	assert.Equal(t, "tpm2", svc.GetBackend())
}

// TestPIVService_SetBackend_AllowsEmptyString verifies that SetBackend accepts
// an empty string, effectively clearing the backend selection.
func TestPIVService_SetBackend_AllowsEmptyString(t *testing.T) {
	svc := NewPIVService(nil, "pkcs11")
	svc.SetBackend("")
	assert.Equal(t, "", svc.GetBackend())
}

// TestPIVService_SetBackend_PropagatedToRemoteOperation verifies that after
// calling SetBackend the new backend name is forwarded to remote calls. A
// custom capturingPIVClient records the backend field from the slot list request.
func TestPIVService_SetBackend_PropagatedToRemoteOperation(t *testing.T) {
	client := &capturingPIVClient{}

	svc := NewPIVService(client, "software")
	svc.SetContext(context.Background())
	svc.SetBackend("tpm2")

	// GetSlots routes to getRemoteSlots which calls ListPIVSlots with s.backend.
	_, err := svc.GetSlots()
	require.NoError(t, err)
	assert.Equal(t, "tpm2", client.lastListSlotsBackend)
}

// capturingPIVClient embeds mockPIVClient and overrides ListPIVSlots to
// record the backend name forwarded by PIVService.
type capturingPIVClient struct {
	mockPIVClient
	lastListSlotsBackend string
}

func (c *capturingPIVClient) ListPIVSlots(_ context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	c.lastListSlotsBackend = req.Backend
	return &transport.ListPIVSlotsResponse{}, nil
}
