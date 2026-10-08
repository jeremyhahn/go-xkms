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

package xkms

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/stretchr/testify/require"
)

// TestAuthorizeCaller_Unauthenticated proves an enabled authorizer refuses a
// request with no identity, and a service with RBAC disabled allows it, as
// the transport gate does.
func TestAuthorizeCaller_Unauthenticated(t *testing.T) {
	svc := serviceWithRBAC(t, &recordingRBAC{grant: "ssh:service"})
	require.ErrorIs(t, svc.AuthorizeCaller(context.Background(), auth.ResourceSSH, auth.ActionService), auth.ErrUnauthenticated)

	disabled := &XKMSService{}
	require.NoError(t, disabled.AuthorizeCaller(context.Background(), auth.ResourceSSH, auth.ActionService))
}
