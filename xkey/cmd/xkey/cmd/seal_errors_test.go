// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// DataVerificationError (seal.go) is constructed throughout verifyDirCopy
// but nothing in this package renders or unwraps it directly, so its Error
// and Unwrap methods have never run. This is the CLI text a user sees when
// a seal's post-copy integrity check fails, and the Unwrap link is what
// lets a caller use errors.Is/errors.As against the underlying stat/walk
// failure.
package cmd

import (
	"errors"
	"io/fs"
	"testing"
)

func TestDataVerificationError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *DataVerificationError
		want string
	}{
		{
			name: "with cause",
			err:  &DataVerificationError{Path: "foo/bar", Message: "missing file in destination", Err: fs.ErrNotExist},
			want: "verify: foo/bar: missing file in destination: file does not exist",
		},
		{
			name: "without cause",
			err:  &DataVerificationError{Path: "foo/bar", Message: "size mismatch: source 1 bytes, destination 2 bytes"},
			want: "verify: foo/bar: size mismatch: source 1 bytes, destination 2 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDataVerificationError_Unwrap(t *testing.T) {
	err := &DataVerificationError{Path: "foo/bar", Message: "failed to stat source entry", Err: fs.ErrNotExist}

	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("errors.Is(err, fs.ErrNotExist) = false, want true")
	}

	noCause := &DataVerificationError{Path: "foo/bar", Message: "expected a directory in destination"}
	if noCause.Unwrap() != nil {
		t.Errorf("Unwrap() = %v, want nil when Err is unset", noCause.Unwrap())
	}
}
