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

package webui

import (
	"testing"
)

func TestErrAssetLoad_Error(t *testing.T) {
	err := &ErrAssetLoad{Detail: "missing dist directory"}
	expected := "webui: failed to load assets: missing dist directory"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrAssetLoad_ErrorEmpty(t *testing.T) {
	err := &ErrAssetLoad{}
	expected := "webui: failed to load assets: "
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrIndexNotFound_Error(t *testing.T) {
	err := &ErrIndexNotFound{Detail: "file does not exist"}
	expected := "webui: index.html not found: file does not exist"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrIndexNotFound_ErrorEmpty(t *testing.T) {
	err := &ErrIndexNotFound{}
	expected := "webui: index.html not found: "
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}
