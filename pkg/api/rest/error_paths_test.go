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

package rest

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/stretchr/testify/assert"
)

// --- handleTenantError ---

func TestHandleTenantError_AllCases(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"TenantNotFound", seal.ErrTenantNotFound, http.StatusNotFound},
		{"TenantAlreadyExists", seal.ErrTenantAlreadyExists, http.StatusConflict},
		{"EmptyTenantID", seal.ErrEmptyTenantID, http.StatusBadRequest},
		{"Sealed", seal.ErrSealed, http.StatusServiceUnavailable},
		{"TenantSealed", seal.ErrTenantSealed, http.StatusServiceUnavailable},
		{"NotInitialized", seal.ErrNotInitialized, http.StatusPreconditionFailed},
		{"TenantNotInitialized", seal.ErrTenantNotInitialized, http.StatusPreconditionFailed},
		{"AlreadyInitialized", seal.ErrAlreadyInitialized, http.StatusConflict},
		{"TenantAlreadyInitialized", seal.ErrTenantAlreadyInitialized, http.StatusConflict},
		{"AlreadyUnsealed", seal.ErrAlreadyUnsealed, http.StatusConflict},
		{"TenantAlreadyUnsealed", seal.ErrTenantAlreadyUnsealed, http.StatusConflict},
		{"InvalidCredentials", seal.ErrInvalidCredentials, http.StatusUnauthorized},
		{"NilSystemBarrier", seal.ErrNilSystemBarrier, http.StatusServiceUnavailable},
		{"Unknown", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handleTenantError(w, tt.err)
			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

// --- passwordHandleStoreError ---

func TestPasswordHandleStoreError_AllCases(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"StoreLocked", staticpw.ErrStoreLocked, http.StatusLocked},
		{"TenantSealed", seal.ErrTenantSealed, http.StatusServiceUnavailable},
		{"TenantNotFound", seal.ErrTenantNotFound, http.StatusNotFound},
		{"NotConfigured", staticpw.ErrNotConfigured, http.StatusServiceUnavailable},
		{"InvalidUserID", staticpw.ErrInvalidUserID, http.StatusBadRequest},
		{"NotOwner", staticpw.ErrNotOwner, http.StatusForbidden},
		{"InvalidScope", staticpw.ErrInvalidScope, http.StatusBadRequest},
		{"Unknown", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			passwordHandleStoreError(w, tt.err)
			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}
