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

package trustedca

import (
	"errors"
	"testing"
)

var errProfileStoreDown = errors.New("profile store unavailable")

func tcgHookContext() *ACMEPreIssuanceHookContext {
	return &ACMEPreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &ACMETCGEnrollmentData{
			ProductSerial: "SN-0001",
			ProductModel:  "edge-node",
		},
	}
}

func TestNewACMEDeviceProfileHook_AdmitsMatchingDevice(t *testing.T) {
	var gotSerial, gotModel string
	hook := NewACMEDeviceProfileHook(func(serial, model string) (*ACMEDeviceProfile, error) {
		gotSerial, gotModel = serial, model
		return &ACMEDeviceProfile{ProductSerial: serial, ProductModel: model}, nil
	})

	if err := hook(tcgHookContext()); err != nil {
		t.Fatalf("hook rejected a device matching its profile: %v", err)
	}
	if gotSerial != "SN-0001" || gotModel != "edge-node" {
		t.Fatalf("lookup called with (%q, %q), want (SN-0001, edge-node)", gotSerial, gotModel)
	}
}

func TestNewACMEDeviceProfileHook_SkipsNonTCGEnrollment(t *testing.T) {
	hook := NewACMEDeviceProfileHook(func(string, string) (*ACMEDeviceProfile, error) {
		t.Fatal("lookup must not run for a non-TCG enrollment")
		return nil, nil
	})

	if err := hook(&ACMEPreIssuanceHookContext{}); err != nil {
		t.Fatalf("hook rejected a non-TCG enrollment: %v", err)
	}
}

func TestNewACMEDeviceProfileHook_LookupError(t *testing.T) {
	hook := NewACMEDeviceProfileHook(func(string, string) (*ACMEDeviceProfile, error) {
		return nil, errProfileStoreDown
	})

	err := hook(tcgHookContext())
	var profileErr *ACMEDeviceProfileError
	if !errors.As(err, &profileErr) {
		t.Fatalf("err = %v, want *ACMEDeviceProfileError", err)
	}
	if profileErr.Op != "lookup" {
		t.Fatalf("Op = %q, want lookup", profileErr.Op)
	}
	if !errors.Is(err, errProfileStoreDown) {
		t.Fatalf("err = %v, want it to wrap the lookup error", err)
	}
}

func TestNewACMEDeviceProfileHook_RejectsUnverifiablePCRs(t *testing.T) {
	hook := NewACMEDeviceProfileHook(func(string, string) (*ACMEDeviceProfile, error) {
		return &ACMEDeviceProfile{ExpectedPCRs: map[int][]byte{0: make([]byte, 32)}}, nil
	})

	ctx := tcgHookContext()
	ctx.TCGData.ProdCaData = []byte("not prodCaData")
	if err := hook(ctx); err == nil {
		t.Fatal("hook admitted a device whose PCRs cannot be checked against the profile")
	}
}
