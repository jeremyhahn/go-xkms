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
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// The session plane has no access token typ setting: access tokens keep the
// default "JWT" header.
func TestSessionOptions_NoAccessTokenTypeSetting(t *testing.T) {
	tests := []struct {
		name string
		typ  reflect.Type
	}{
		{"token.Config", reflect.TypeOf(token.Config{})},
		{"TokenIssuerParams", reflect.TypeOf(TokenIssuerParams{})},
		{"SessionOptions", reflect.TypeOf(SessionOptions{})},
		{"config.SessionConfig", reflect.TypeOf(config.SessionConfig{})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := tc.typ.FieldByName("AccessTokenType")
			assert.False(t, ok, "%s has no AccessTokenType field", tc.name)
		})
	}
}
