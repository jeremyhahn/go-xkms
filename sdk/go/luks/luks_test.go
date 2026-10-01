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

package luks

import (
	"context"
	"errors"
	"testing"
)

// TestNewManager_UsesProductionExecutor proves the sdk re-export wires a
// real Manager to the production, go-luks2 backed Executor: an Unlock
// against a container that does not exist on disk returns ErrVolumeNotFound
// (from the production Executor), not a generic failure.
func TestNewManager_UsesProductionExecutor(t *testing.T) {
	cfg := &VolumeConfig{
		LUKSPath:   "/nonexistent/vault.luks",
		MountPoint: "/nonexistent/mnt",
		MapperName: "xkms-sdk-test",
	}
	mgr, err := NewManager(cfg, NewLibExecutor())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	err = mgr.Unlock(context.Background(), "passphrase")
	if !errors.Is(err, ErrOperationFailed) {
		t.Fatalf("Unlock() err = %v, want wrapped ErrOperationFailed", err)
	}
	if !errors.Is(err, ErrVolumeNotFound) {
		t.Fatalf("Unlock() err = %v, want wrapped ErrVolumeNotFound", err)
	}
}

// TestNewTPMSealer_InvalidSealParent proves the sdk re-export surfaces the
// same typed SealParentInvalidError pkg/luks returns.
func TestNewTPMSealer_InvalidSealParent(t *testing.T) {
	_, err := NewTPMSealer(nil, TPMSealerConfig{})
	if !errors.Is(err, ErrTPMNoTransport) {
		t.Fatalf("NewTPMSealer(nil, ...) err = %v, want ErrTPMNoTransport", err)
	}
}

// TestEncodeDecodeTPMSealBlobs_RoundTrip proves the sdk re-export of the
// token blob codec round-trips.
func TestEncodeDecodeTPMSealBlobs_RoundTrip(t *testing.T) {
	pub := []byte{1, 2, 3}
	priv := []byte{4, 5}
	encoded := EncodeTPMSealBlobs(pub, priv)
	gotPub, gotPriv, err := DecodeTPMSealBlobs(encoded)
	if err != nil {
		t.Fatalf("DecodeTPMSealBlobs: %v", err)
	}
	if string(gotPub) != string(pub) || string(gotPriv) != string(priv) {
		t.Fatalf("round trip mismatch: got (%x, %x), want (%x, %x)", gotPub, gotPriv, pub, priv)
	}
}

// TestParseSealParent_Default proves the sdk re-export resolves an empty
// config string to SealParentPSRK, the documented default.
func TestParseSealParent_Default(t *testing.T) {
	parent, err := ParseSealParent("")
	if err != nil {
		t.Fatalf("ParseSealParent(\"\"): %v", err)
	}
	if parent != SealParentPSRK {
		t.Fatalf("ParseSealParent(\"\") = %v, want SealParentPSRK", parent)
	}
}

// TestParseSealParent_Invalid proves the sdk re-export surfaces the typed
// SealParentInvalidError for an unrecognised value.
func TestParseSealParent_Invalid(t *testing.T) {
	_, err := ParseSealParent("bogus")
	var target *SealParentInvalidError
	if !errors.As(err, &target) {
		t.Fatalf("ParseSealParent(\"bogus\") err = %v, want *SealParentInvalidError", err)
	}
}
