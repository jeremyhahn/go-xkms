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
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// sameType fails t unless A and B are the same type.
func sameType[A, B any](t *testing.T) {
	t.Helper()
	if reflect.TypeFor[A]() != reflect.TypeFor[B]() {
		t.Errorf("%v is not %v", reflect.TypeFor[A](), reflect.TypeFor[B]())
	}
}

// TestConsumerExports_Entities asserts the acme entity symbols go-quicbaas
// consumes are aliases of pkg/acme/entities.
func TestConsumerExports_Entities(t *testing.T) {
	sameType[EABDeviceInfo, entities.EABDeviceInfo](t)
	sameType[ExternalAccountBindingJWS, entities.ExternalAccountBindingJWS](t)
	sameType[ExternalAccountBindingProtectedHeader, entities.ExternalAccountBindingProtectedHeader](t)
	sameType[InvalidSerialError, entities.InvalidSerialError](t)
	sameType[SigningCAInfo, entities.SigningCAInfo](t)
	sameType[SubProblem, entities.SubProblem](t)
	sameType[TenantIntermediateCA, entities.TenantIntermediateCA](t)
	sameType[TenantRootCA, entities.TenantRootCA](t)
	sameType[TenantSettings, entities.TenantSettings](t)

	for name, pair := range map[string][2]any{
		"NormalizeSerial":  {NormalizeSerial, entities.NormalizeSerial},
		"StringToEntityID": {StringToEntityID, entities.StringToEntityID},
	} {
		if reflect.ValueOf(pair[0]).Pointer() != reflect.ValueOf(pair[1]).Pointer() {
			t.Errorf("%s is not the entities function", name)
		}
	}

	consts := map[string][2]string{
		"AUTHORIZATION_INDEX_URL":   {AUTHORIZATION_INDEX_URL, entities.AUTHORIZATION_INDEX_URL},
		"CAParentTypeGlobal":        {CAParentTypeGlobal, entities.CAParentTypeGlobal},
		"CAParentTypeTenant":        {CAParentTypeTenant, entities.CAParentTypeTenant},
		"CAPurposeClientAuth":       {CAPurposeClientAuth, entities.CAPurposeClientAuth},
		"CAPurposeCodeSigning":      {CAPurposeCodeSigning, entities.CAPurposeCodeSigning},
		"CAPurposeGeneral":          {CAPurposeGeneral, entities.CAPurposeGeneral},
		"CAPurposeServerAuth":       {CAPurposeServerAuth, entities.CAPurposeServerAuth},
		"CAPurposeTPMEndorsement":   {CAPurposeTPMEndorsement, entities.CAPurposeTPMEndorsement},
		"CAStatusActive":            {CAStatusActive, entities.CAStatusActive},
		"CAStatusPendingRotation":   {CAStatusPendingRotation, entities.CAStatusPendingRotation},
		"CAStatusRevoked":           {CAStatusRevoked, entities.CAStatusRevoked},
		"EABPurposeAccountBinding":  {EABPurposeAccountBinding, entities.EABPurposeAccountBinding},
		"EABPurposeEndorse01":       {EABPurposeEndorse01, entities.EABPurposeEndorse01},
		"EABPurposeEnroll01":        {EABPurposeEnroll01, entities.EABPurposeEnroll01},
		"EABStatusActive":           {EABStatusActive, entities.EABStatusActive},
		"EABStatusExpired":          {EABStatusExpired, entities.EABStatusExpired},
		"EABStatusRevoked":          {EABStatusRevoked, entities.EABStatusRevoked},
		"EABStatusUsed":             {EABStatusUsed, entities.EABStatusUsed},
		"SigningCATypeGlobal":       {SigningCATypeGlobal, entities.SigningCATypeGlobal},
		"SigningCATypeIntermediate": {SigningCATypeIntermediate, entities.SigningCATypeIntermediate},
		"SigningCATypeRoot":         {SigningCATypeRoot, entities.SigningCATypeRoot},
		"TenantStatusActive":        {TenantStatusActive, entities.TenantStatusActive},
		"TenantStatusDeleted":       {TenantStatusDeleted, entities.TenantStatusDeleted},
		"TenantStatusSuspended":     {TenantStatusSuspended, entities.TenantStatusSuspended},
	}
	for name, pair := range consts {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}
}
