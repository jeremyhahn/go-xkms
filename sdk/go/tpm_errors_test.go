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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// errVerifyPIN stands in for a caller's own error wrapping a TPM failure.
var errVerifyPIN = errors.New("verify user PIN")

func TestErrTPMAuthFailed_MatchesLibraryError(t *testing.T) {
	wrapped := errors.Join(errVerifyPIN, tpm2.ErrAuthFailed)

	if !errors.Is(wrapped, ErrTPMAuthFailed) {
		t.Fatalf("errors.Is(%v, ErrTPMAuthFailed) = false, want true", wrapped)
	}
}

func TestErrTPMAuthFailed_DoesNotMatchOtherTPMErrors(t *testing.T) {
	wrapped := errors.Join(errVerifyPIN, tpm2.ErrTransportNotInitialized)

	if errors.Is(wrapped, ErrTPMAuthFailed) {
		t.Fatalf("errors.Is(%v, ErrTPMAuthFailed) = true, want false", wrapped)
	}
}
