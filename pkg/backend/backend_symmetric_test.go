// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package backend

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestCapabilitiesSupportsSymmetricEncryption(t *testing.T) {
	tests := []struct {
		name string
		caps types.Capabilities
		want bool
	}{
		{
			name: "Supports symmetric encryption",
			caps: types.Capabilities{
				SymmetricEncryption: true,
			},
			want: true,
		},
		{
			name: "Does not support symmetric encryption",
			caps: types.Capabilities{
				SymmetricEncryption: false,
			},
			want: false,
		},
		{
			name: "Full capabilities with symmetric",
			caps: types.Capabilities{
				Keys:                true,
				HardwareBacked:      true,
				Signing:             true,
				Decryption:          true,
				KeyRotation:         true,
				SymmetricEncryption: true,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.caps.SupportsSymmetricEncryption(); got != tt.want {
				t.Errorf("Capabilities.SupportsSymmetricEncryption() = %v, want %v", got, tt.want)
			}
		})
	}
}
