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

package clusterca

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestClusterCAErrorMessages exercises every typed error's Error() (and Unwrap()
// where present): each must produce a non-empty message and, for wrapping
// errors, expose the wrapped cause.
func TestClusterCAErrorMessages(t *testing.T) {
	cause := errors.New("root cause")

	cases := []struct {
		name string
		err  error
		wrap error
	}{
		{"ErrMissingOption", &ErrMissingOption{Field: "RaftAddress"}, nil},
		{"ErrFileRead", &ErrFileRead{Field: "ca_cert_file", Path: "/x", Err: cause}, cause},
		{"ErrLeafDecode", &ErrLeafDecode{}, nil},
		{"ErrExistingCAWithoutStagedCerts", &ErrExistingCAWithoutStagedCerts{Identity: "Cluster CA"}, nil},
		{"ErrAnchorMismatch", &ErrAnchorMismatch{}, nil},
		{"ErrSPIFFEMismatch", &ErrSPIFFEMismatch{Expected: "a", Got: []string{"b"}}, nil},
		{"ErrACMEBackendUnsupported", &ErrACMEBackendUnsupported{KeyBackend: "vault"}, nil},
		{"ErrLocalCAJoin", &ErrLocalCAJoin{KeyBackend: "tpm2"}, nil},
		{"ErrKeyBackendUnavailable", &ErrKeyBackendUnavailable{KeyBackend: "software", Err: cause}, cause},
		{"ErrClusterCAUnbound", &ErrClusterCAUnbound{}, nil},
		{"ErrClusterCAKeyMismatch", &ErrClusterCAKeyMismatch{Subject: "Cluster CA"}, nil},
		{"ErrNoTPM", &ErrNoTPM{}, nil},
		{"ErrNoSecureCAKeyProtection", &ErrNoSecureCAKeyProtection{}, nil},
		{"ErrSealerUnavailable", &ErrSealerUnavailable{Mode: "tpm2"}, nil},
		{"ErrSealBlobCorrupt", &ErrSealBlobCorrupt{Err: cause}, cause},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotEmpty(t, tc.err.Error(), "Error() must be non-empty")
			if tc.wrap != nil {
				require.ErrorIs(t, tc.err, tc.wrap, "Unwrap() must expose the cause")
			}
		})
	}
}
