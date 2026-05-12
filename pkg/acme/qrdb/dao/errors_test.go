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

package dao

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNilEntityError_Error(t *testing.T) {
	err := NilEntityError{EntityType: "account"}
	assert.Equal(t, "qrdb dao: account entity cannot be nil", err.Error())
}

func TestNilKVStoreError_Error(t *testing.T) {
	err := NilKVStoreError{}
	assert.Equal(t, "qrdb dao: kvstore cannot be nil", err.Error())
}

func TestInvalidIDError_Error(t *testing.T) {
	err := InvalidIDError{EntityType: "tenant", Reason: "cannot be empty"}
	assert.Equal(t, "qrdb dao: invalid tenant ID: cannot be empty", err.Error())
}

func TestNilEntityError_DifferentTypes(t *testing.T) {
	tests := []struct {
		name       string
		entityType string
		want       string
	}{
		{"order", "order", "qrdb dao: order entity cannot be nil"},
		{"certificate", "certificate", "qrdb dao: certificate entity cannot be nil"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NilEntityError{EntityType: tt.entityType}
			assert.Equal(t, tt.want, err.Error())
		})
	}
}

func TestInvalidIDError_DifferentReasons(t *testing.T) {
	tests := []struct {
		name       string
		entityType string
		reason     string
		want       string
	}{
		{"empty_eab", "external_account_binding", "kid cannot be empty",
			"qrdb dao: invalid external_account_binding ID: kid cannot be empty"},
		{"zero_account", "account", "must be non-zero",
			"qrdb dao: invalid account ID: must be non-zero"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := InvalidIDError{EntityType: tt.entityType, Reason: tt.reason}
			assert.Equal(t, tt.want, err.Error())
		})
	}
}
