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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSSHErrorMessagesNameTheCause checks that the SSH errors shown to the
// user name the backend or the underlying failure.
func TestSSHErrorMessagesNameTheCause(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"server unavailable", &SSHServerUnavailableError{Err: errors.New("dial refused")}, "dial refused"},
		{"local backend while connected", &SSHLocalBackendConnectedError{Backend: "software"}, `"software"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, tt.err.Error(), "ssh_service: ")
			assert.Contains(t, tt.err.Error(), tt.want)
		})
	}
}
