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

package grpc

import (
	"testing"

	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/stretchr/testify/assert"
)

func TestSetCeremonyService_GetCeremonyService(t *testing.T) {
	old := GetCeremonyService()
	defer SetCeremonyService(old)

	t.Run("sets and gets ceremony service", func(t *testing.T) {
		mock := "mock-ceremony-service"
		SetCeremonyService(mock)
		assert.Equal(t, mock, GetCeremonyService())
	})

	t.Run("returns nil when not set", func(t *testing.T) {
		SetCeremonyService(nil)
		assert.Nil(t, GetCeremonyService())
	})
}

func TestSetCredentialService_GetCredentialService(t *testing.T) {
	old := GetCredentialService()
	defer SetCredentialService(old)

	t.Run("sets and gets credential service", func(t *testing.T) {
		svc := &credentialspkg.Service{}
		SetCredentialService(svc)
		assert.Equal(t, svc, GetCredentialService())
	})

	t.Run("returns nil when not set", func(t *testing.T) {
		SetCredentialService(nil)
		assert.Nil(t, GetCredentialService())
	})
}
