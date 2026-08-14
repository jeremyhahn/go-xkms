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

package module

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// requireCode asserts that err is a PKCS11Error carrying the expected return
// value. Every enforcement rule in this file is only worth anything if the
// caller can tell which rule fired, so the code is always checked rather than
// just the presence of an error.
func requireCode(t *testing.T, err error, want CK_RV, context string) {
	t.Helper()

	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) {
		t.Fatalf("%s: expected a PKCS11Error, got %v", context, err)
	}
	if pkcsErr.Code != want {
		t.Fatalf("%s: expected %s, got %s", context, want.String(), pkcsErr.Code.String())
	}
}

// enforcementTemplate returns a minimal valid CKO_DATA creation template with the
// given extra attributes appended.
func enforcementTemplate(extra ...Attribute) []Attribute {
	template := []Attribute{NewUint32Attribute(CKA_CLASS, uint32(CKO_DATA))}
	return append(template, extra...)
}

// unenforceableAttributes are the attributes whose entire meaning is an
// enforcement promise this module cannot keep, and which must therefore be
// refused rather than stored and ignored.
func unenforceableAttributes() []AttributeType {
	return []AttributeType{
		CKA_HSS_KEYS_REMAINING,
		CKA_TRUST_SERVER_AUTH,
		CKA_TRUST_CLIENT_AUTH,
		CKA_TRUST_CODE_SIGNING,
		CKA_TRUST_EMAIL_PROTECTION,
		CKA_TRUST_IPSEC_IKE,
		CKA_TRUST_TIME_STAMPING,
		CKA_TRUST_OCSP_SIGNING,
		CKA_OBJECT_VALIDATION_FLAGS,
		CKA_VALIDATION_TYPE,
		CKA_VALIDATION_VERSION,
		CKA_VALIDATION_LEVEL,
		CKA_VALIDATION_MODULE_ID,
		CKA_VALIDATION_FLAG,
		CKA_VALIDATION_AUTHORITY_TYPE,
		CKA_VALIDATION_COUNTRY,
		CKA_VALIDATION_CERTIFICATE_IDENTIFIER,
		CKA_VALIDATION_CERTIFICATE_URI,
		CKA_VALIDATION_VENDOR_URI,
		CKA_VALIDATION_PROFILE,
	}
}

// TestCreateObject_RefusesUnenforceableAttributes proves that an attribute the
// token cannot act on is refused at creation rather than accepted and ignored.
// PKCS#11 v3.2 §5.7.5 gives CKR_ATTRIBUTE_TYPE_INVALID for an attribute type
// the token does not support.
func TestCreateObject_RefusesUnenforceableAttributes(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	for _, attrType := range unenforceableAttributes() {
		t.Run(attrType.String(), func(t *testing.T) {
			_, err := om.CreateObject(ctx, enforcementTemplate(NewAttribute(attrType, []byte{1})))
			requireCode(t, err, CKR_ATTRIBUTE_TYPE_INVALID, "CreateObject")
		})
	}
}

// TestSetAttributeValue_RefusesUnenforceableAttributes proves the same
// attributes cannot be added to an object after it exists, which is the path
// that made the omission invisible: an ignored attribute and an enforced one
// round-trip identically through C_SetAttributeValue and C_GetAttributeValue.
func TestSetAttributeValue_RefusesUnenforceableAttributes(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	handle, err := om.CreateObject(ctx, enforcementTemplate())
	if err != nil {
		t.Fatalf("CreateObject: %v", err)
	}

	for _, attrType := range unenforceableAttributes() {
		t.Run(attrType.String(), func(t *testing.T) {
			err := om.SetAttributeValue(ctx, handle, []Attribute{NewAttribute(attrType, []byte{1})})
			requireCode(t, err, CKR_ATTRIBUTE_TYPE_INVALID, "SetAttributeValue")

			read, readErr := om.GetAttributeValue(ctx, handle, []Attribute{{Type: attrType}})
			requireCode(t, readErr, CKR_ATTRIBUTE_TYPE_INVALID, "GetAttributeValue")
			if len(read) != 1 || !read[0].Unavailable {
				t.Fatalf("refused attribute %s must not be readable afterwards: %+v", attrType, read)
			}
		})
	}
}

// TestCopyObject_RefusesUnenforceableAttributes proves the copy template is
// held to the same rule; a copy is a creation and may not acquire a
// restriction the token would not honour.
func TestCopyObject_RefusesUnenforceableAttributes(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	handle, err := om.CreateObject(ctx, enforcementTemplate())
	if err != nil {
		t.Fatalf("CreateObject: %v", err)
	}

	_, err = om.CopyObject(ctx, handle, []Attribute{NewAttribute(CKA_TRUST_SERVER_AUTH, []byte{1})})
	requireCode(t, err, CKR_ATTRIBUTE_TYPE_INVALID, "CopyObject")
}

// TestCreateObject_AttributeAllowlist proves the check is an allowlist: an
// attribute type the module has never defined is refused, while the
// vendor-defined range PKCS#11 v3.2 §4.4 reserves for a token's own attributes
// is admitted, and an ordinary descriptive attribute still round-trips.
func TestCreateObject_AttributeAllowlist(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	t.Run("undefined attribute type is refused", func(t *testing.T) {
		_, err := om.CreateObject(ctx, enforcementTemplate(NewAttribute(AttributeType(0x0000FFFE), []byte{1})))
		requireCode(t, err, CKR_ATTRIBUTE_TYPE_INVALID, "CreateObject")
	})

	t.Run("vendor-defined attribute is accepted", func(t *testing.T) {
		vendor := CKA_VENDOR_DEFINED + 7
		handle, err := om.CreateObject(ctx, enforcementTemplate(NewAttribute(vendor, []byte{9})))
		if err != nil {
			t.Fatalf("CreateObject: %v", err)
		}
		read, err := om.GetAttributeValue(ctx, handle, []Attribute{{Type: vendor}})
		if err != nil {
			t.Fatalf("GetAttributeValue: %v", err)
		}
		if !bytes.Equal(read[0].Value, []byte{9}) {
			t.Fatalf("vendor attribute round-trip: got %v", read[0].Value)
		}
	})

	t.Run("descriptive attribute is stored", func(t *testing.T) {
		handle, err := om.CreateObject(ctx, enforcementTemplate(NewStringAttribute(CKA_LABEL, "payroll")))
		if err != nil {
			t.Fatalf("CreateObject: %v", err)
		}
		obj, err := om.GetObjectFor(ctx, handle)
		if err != nil {
			t.Fatalf("GetObjectFor: %v", err)
		}
		if obj.GetLabel() != "payroll" {
			t.Fatalf("expected label to be stored, got %q", obj.GetLabel())
		}
	})
}

// TestAttributeHandlers_AreExhaustive proves the allowlist covers every
// attribute the module names.
//
// This is the regression guard for the defect the table replaced: a deny-list
// silently admitted every attribute nobody had thought to deny, so a new
// constant must not be able to arrive without a deliberate decision about
// whether the token stores it, enforces it, or refuses it.
func TestAttributeHandlers_AreExhaustive(t *testing.T) {
	for attrType, name := range attributeTypeNames {
		if _, ok := attributeHandlers[attrType]; !ok {
			t.Errorf("%s has no entry in attributeHandlers: decide whether the token stores, enforces or refuses it", name)
		}
	}
}

// TestValidateDateValue covers the CK_DATE format rule: an eight-digit
// calendar day, or empty for "no date" (PKCS#11 v3.2 §4.8.2 default).
func TestValidateDateValue(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, value := range []string{"", "20260806", "20240229"} {
			if err := validateDateValue([]byte(value)); err != nil {
				t.Fatalf("validateDateValue(%q): %v", value, err)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, value := range []string{"2026080", "202608061", "2026-8-6", "20261306", "20250230", "yyyymmdd"} {
			err := validateDateValue([]byte(value))
			requireCode(t, err, CKR_ATTRIBUTE_VALUE_INVALID, "validateDateValue("+value+")")
		}
	})
}

// TestCreateObject_DateAttributes proves a malformed date is refused at
// creation and a well-formed one is stored, and that a window which can never
// be open is refused as inconsistent.
func TestCreateObject_DateAttributes(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	t.Run("well-formed window is accepted", func(t *testing.T) {
		_, err := om.CreateObject(ctx, enforcementTemplate(
			NewStringAttribute(CKA_START_DATE, "20260101"),
			NewStringAttribute(CKA_END_DATE, "20261231"),
		))
		if err != nil {
			t.Fatalf("CreateObject: %v", err)
		}
	})

	t.Run("malformed date is refused", func(t *testing.T) {
		_, err := om.CreateObject(ctx, enforcementTemplate(NewStringAttribute(CKA_END_DATE, "next tuesday")))
		requireCode(t, err, CKR_ATTRIBUTE_VALUE_INVALID, "CreateObject")
	})

	t.Run("end before start is refused", func(t *testing.T) {
		_, err := om.CreateObject(ctx, enforcementTemplate(
			NewStringAttribute(CKA_START_DATE, "20261231"),
			NewStringAttribute(CKA_END_DATE, "20260101"),
		))
		requireCode(t, err, CKR_TEMPLATE_INCONSISTENT, "CreateObject")
	})
}

// TestSetAttributeValue_DateAttributes proves a modification is judged against
// the window the object will hold afterwards, not just the attribute supplied.
func TestSetAttributeValue_DateAttributes(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	handle, err := om.CreateObject(ctx, enforcementTemplate(
		NewStringAttribute(CKA_START_DATE, "20260101"),
		NewStringAttribute(CKA_END_DATE, "20261231"),
	))
	if err != nil {
		t.Fatalf("CreateObject: %v", err)
	}

	t.Run("end date moved before the existing start is refused", func(t *testing.T) {
		err := om.SetAttributeValue(ctx, handle, []Attribute{NewStringAttribute(CKA_END_DATE, "20251231")})
		requireCode(t, err, CKR_TEMPLATE_INCONSISTENT, "SetAttributeValue")
	})

	t.Run("malformed date is refused", func(t *testing.T) {
		err := om.SetAttributeValue(ctx, handle, []Attribute{NewStringAttribute(CKA_END_DATE, "20261232")})
		requireCode(t, err, CKR_ATTRIBUTE_VALUE_INVALID, "SetAttributeValue")
	})

	t.Run("end date extended is accepted", func(t *testing.T) {
		if err := om.SetAttributeValue(ctx, handle, []Attribute{NewStringAttribute(CKA_END_DATE, "20271231")}); err != nil {
			t.Fatalf("SetAttributeValue: %v", err)
		}
		obj, err := om.GetObjectFor(ctx, handle)
		if err != nil {
			t.Fatalf("GetObjectFor: %v", err)
		}
		if string(obj.GetAttribute(CKA_END_DATE)) != "20271231" {
			t.Fatalf("expected the new end date to be stored, got %q", obj.GetAttribute(CKA_END_DATE))
		}
	})
}

// TestObject_CheckValidityPeriod covers the validity-window check itself.
func TestObject_CheckValidityPeriod(t *testing.T) {
	day := func(value string) time.Time {
		parsed, err := time.Parse(ckDateLayout, value)
		if err != nil {
			t.Fatalf("parse %q: %v", value, err)
		}
		return parsed
	}

	windowed := NewKeyObject(CKO_PRIVATE_KEY, CKK_RSA)
	windowed.SetAttribute(CKA_START_DATE, []byte("20260101"))
	windowed.SetAttribute(CKA_END_DATE, []byte("20261231"))

	t.Run("inside the window", func(t *testing.T) {
		for _, when := range []string{"20260101", "20260806", "20261231"} {
			if err := windowed.CheckValidityPeriod(day(when)); err != nil {
				t.Fatalf("CheckValidityPeriod(%s): %v", when, err)
			}
		}
	})

	t.Run("outside the window", func(t *testing.T) {
		for _, when := range []string{"20251231", "20270101"} {
			err := windowed.CheckValidityPeriod(day(when))
			requireCode(t, err, CKR_KEY_FUNCTION_NOT_PERMITTED, "CheckValidityPeriod("+when+")")
		}
	})

	t.Run("absent dates are unbounded", func(t *testing.T) {
		open := NewKeyObject(CKO_PRIVATE_KEY, CKK_RSA)
		if err := open.CheckValidityPeriod(day("19700101")); err != nil {
			t.Fatalf("CheckValidityPeriod on an undated key: %v", err)
		}
	})

	t.Run("one-sided windows", func(t *testing.T) {
		notYet := NewKeyObject(CKO_PRIVATE_KEY, CKK_RSA)
		notYet.SetAttribute(CKA_START_DATE, []byte("20260101"))
		if err := notYet.CheckValidityPeriod(day("20991231")); err != nil {
			t.Fatalf("open-ended end date should never expire: %v", err)
		}
		requireCode(t, notYet.CheckValidityPeriod(day("20251231")),
			CKR_KEY_FUNCTION_NOT_PERMITTED, "before start")

		expired := NewKeyObject(CKO_PRIVATE_KEY, CKK_RSA)
		expired.SetAttribute(CKA_END_DATE, []byte("20260101"))
		if err := expired.CheckValidityPeriod(day("19700101")); err != nil {
			t.Fatalf("absent start date should not bound the past: %v", err)
		}
		requireCode(t, expired.CheckValidityPeriod(day("20260102")),
			CKR_KEY_FUNCTION_NOT_PERMITTED, "after end")
	})
}

// TestMechanismList covers the CKA_ALLOWED_MECHANISMS encoding and the per-key
// mechanism check it drives.
func TestMechanismList(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		want := []MechanismType{CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS}
		got, err := DecodeMechanismList(EncodeMechanismList(want))
		if err != nil {
			t.Fatalf("DecodeMechanismList: %v", err)
		}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("round trip: got %v want %v", got, want)
		}
	})

	t.Run("truncated element is refused", func(t *testing.T) {
		_, err := DecodeMechanismList([]byte{1, 2, 3, 4})
		requireCode(t, err, CKR_ATTRIBUTE_VALUE_INVALID, "DecodeMechanismList")
	})
}

// TestObject_CheckAllowedMechanism proves a key restricted to named mechanisms
// refuses every other one, which is the whole point of the attribute.
func TestObject_CheckAllowedMechanism(t *testing.T) {
	restricted := NewKeyObject(CKO_PRIVATE_KEY, CKK_RSA)
	restricted.SetAttribute(CKA_ALLOWED_MECHANISMS, EncodeMechanismList([]MechanismType{CKM_SHA256_RSA_PKCS}))

	t.Run("listed mechanism is allowed", func(t *testing.T) {
		if err := restricted.CheckAllowedMechanism(CKM_SHA256_RSA_PKCS); err != nil {
			t.Fatalf("CheckAllowedMechanism: %v", err)
		}
	})

	t.Run("unlisted mechanism is refused", func(t *testing.T) {
		err := restricted.CheckAllowedMechanism(CKM_RSA_PKCS)
		requireCode(t, err, CKR_MECHANISM_INVALID, "CheckAllowedMechanism")
	})

	t.Run("absent attribute leaves the key unrestricted", func(t *testing.T) {
		open := NewKeyObject(CKO_PRIVATE_KEY, CKK_RSA)
		if err := open.CheckAllowedMechanism(CKM_RSA_PKCS); err != nil {
			t.Fatalf("CheckAllowedMechanism: %v", err)
		}
	})

	t.Run("empty list permits nothing", func(t *testing.T) {
		none := NewKeyObject(CKO_PRIVATE_KEY, CKK_RSA)
		none.SetAttribute(CKA_ALLOWED_MECHANISMS, EncodeMechanismList(nil))
		err := none.CheckAllowedMechanism(CKM_RSA_PKCS)
		requireCode(t, err, CKR_MECHANISM_INVALID, "CheckAllowedMechanism")
	})
}

// TestCreateObject_AllowedMechanismsValue proves a value the token could not
// read as a mechanism list is refused rather than stored as an unenforceable
// restriction.
func TestCreateObject_AllowedMechanismsValue(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	t.Run("valid list is accepted", func(t *testing.T) {
		handle, err := om.CreateObject(ctx, enforcementTemplate(
			NewAttribute(CKA_ALLOWED_MECHANISMS, EncodeMechanismList([]MechanismType{CKM_AES_GCM})),
		))
		if err != nil {
			t.Fatalf("CreateObject: %v", err)
		}
		obj, err := om.GetObjectFor(ctx, handle)
		if err != nil {
			t.Fatalf("GetObjectFor: %v", err)
		}
		if err := obj.CheckAllowedMechanism(CKM_AES_GCM); err != nil {
			t.Fatalf("stored list must be enforceable: %v", err)
		}
	})

	t.Run("misaligned list is refused", func(t *testing.T) {
		_, err := om.CreateObject(ctx, enforcementTemplate(NewAttribute(CKA_ALLOWED_MECHANISMS, []byte{1, 2, 3})))
		requireCode(t, err, CKR_ATTRIBUTE_VALUE_INVALID, "CreateObject")
	})
}

// TestAttributeArrayCodec covers the flattened nested-template encoding the
// *_TEMPLATE attributes are carried in.
func TestAttributeArrayCodec(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		want := []Attribute{
			NewBoolAttribute(CKA_EXTRACTABLE, false),
			NewStringAttribute(CKA_LABEL, "wrapped"),
		}
		got, err := DecodeAttributeArray(EncodeAttributeArray(want))
		if err != nil {
			t.Fatalf("DecodeAttributeArray: %v", err)
		}
		if len(got) != len(want) {
			t.Fatalf("expected %d attributes, got %d", len(want), len(got))
		}
		for i := range want {
			if got[i].Type != want[i].Type || !bytes.Equal(got[i].Value, want[i].Value) {
				t.Fatalf("entry %d: got %+v want %+v", i, got[i], want[i])
			}
		}
	})

	t.Run("empty array", func(t *testing.T) {
		got, err := DecodeAttributeArray(EncodeAttributeArray(nil))
		if err != nil {
			t.Fatalf("DecodeAttributeArray: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected no attributes, got %d", len(got))
		}
	})

	t.Run("malformed values are refused", func(t *testing.T) {
		encoded := EncodeAttributeArray([]Attribute{NewStringAttribute(CKA_LABEL, "wrapped")})

		cases := map[string][]byte{
			"short header":     {0, 0},
			"count overflow":   {9, 0, 0, 0},
			"truncated entry":  encoded[:len(encoded)-1],
			"trailing bytes":   append(append([]byte{}, encoded...), 0),
			"length past end":  {1, 0, 0, 0, 3, 0, 0, 0, 255, 255, 255, 255, 1},
			"missing declared": {2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0},
		}
		for name, value := range cases {
			_, err := DecodeAttributeArray(value)
			requireCode(t, err, CKR_ATTRIBUTE_VALUE_INVALID, name)
		}
	})
}

// TestObject_CheckWrapTemplate proves a wrapping key constrained by
// CKA_WRAP_TEMPLATE will not wrap a key outside the constraint. PKCS#11 v3.2
// §5.14.3 requires CKR_KEY_HANDLE_INVALID on a mismatch.
func TestObject_CheckWrapTemplate(t *testing.T) {
	wrapper := NewKeyObject(CKO_SECRET_KEY, CKK_AES)
	wrapper.SetAttribute(CKA_WRAP_TEMPLATE, EncodeAttributeArray([]Attribute{
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
	}))

	t.Run("matching key may be wrapped", func(t *testing.T) {
		target := NewKeyObject(CKO_SECRET_KEY, CKK_AES)
		target.SetAttribute(CKA_EXTRACTABLE, boolAttributeValue(true))
		if err := wrapper.CheckWrapTemplate(target); err != nil {
			t.Fatalf("CheckWrapTemplate: %v", err)
		}
	})

	t.Run("mismatching value is refused", func(t *testing.T) {
		target := NewKeyObject(CKO_SECRET_KEY, CKK_AES)
		target.SetAttribute(CKA_EXTRACTABLE, boolAttributeValue(false))
		err := wrapper.CheckWrapTemplate(target)
		requireCode(t, err, CKR_KEY_HANDLE_INVALID, "CheckWrapTemplate")
	})

	t.Run("wrong class is refused", func(t *testing.T) {
		target := NewKeyObject(CKO_PRIVATE_KEY, CKK_RSA)
		target.SetAttribute(CKA_EXTRACTABLE, boolAttributeValue(true))
		err := wrapper.CheckWrapTemplate(target)
		requireCode(t, err, CKR_KEY_HANDLE_INVALID, "CheckWrapTemplate")
	})

	t.Run("missing constrained attribute is refused", func(t *testing.T) {
		target := NewObject(CKO_SECRET_KEY)
		err := wrapper.CheckWrapTemplate(target)
		requireCode(t, err, CKR_KEY_HANDLE_INVALID, "CheckWrapTemplate")
	})

	t.Run("unconstrained wrapping key wraps anything", func(t *testing.T) {
		open := NewKeyObject(CKO_SECRET_KEY, CKK_AES)
		if err := open.CheckWrapTemplate(NewObject(CKO_PRIVATE_KEY)); err != nil {
			t.Fatalf("CheckWrapTemplate: %v", err)
		}
	})
}

// TestObject_ApplyAttributeTemplate proves the unwrap and derive constraint
// templates are added to the caller's template, and that a caller cannot
// contradict them. PKCS#11 v3.2 §5.14.4 requires CKR_TEMPLATE_INCONSISTENT on
// a conflict.
func TestObject_ApplyAttributeTemplate(t *testing.T) {
	unwrapper := NewKeyObject(CKO_SECRET_KEY, CKK_AES)
	unwrapper.SetAttribute(CKA_UNWRAP_TEMPLATE, EncodeAttributeArray([]Attribute{
		NewBoolAttribute(CKA_EXTRACTABLE, false),
	}))

	t.Run("constraint is added to the caller template", func(t *testing.T) {
		merged, err := unwrapper.ApplyAttributeTemplate(CKA_UNWRAP_TEMPLATE,
			[]Attribute{NewStringAttribute(CKA_LABEL, "imported")})
		if err != nil {
			t.Fatalf("ApplyAttributeTemplate: %v", err)
		}
		if len(merged) != 2 {
			t.Fatalf("expected the constraint to be added, got %+v", merged)
		}
		if merged[1].Type != CKA_EXTRACTABLE || merged[1].Value[0] != 0 {
			t.Fatalf("expected CKA_EXTRACTABLE=false to be added, got %+v", merged[1])
		}
	})

	t.Run("agreeing caller value is not a conflict", func(t *testing.T) {
		merged, err := unwrapper.ApplyAttributeTemplate(CKA_UNWRAP_TEMPLATE,
			[]Attribute{NewBoolAttribute(CKA_EXTRACTABLE, false)})
		if err != nil {
			t.Fatalf("ApplyAttributeTemplate: %v", err)
		}
		if len(merged) != 1 {
			t.Fatalf("an agreeing attribute must not be duplicated: %+v", merged)
		}
	})

	t.Run("contradicting caller value is refused", func(t *testing.T) {
		_, err := unwrapper.ApplyAttributeTemplate(CKA_UNWRAP_TEMPLATE,
			[]Attribute{NewBoolAttribute(CKA_EXTRACTABLE, true)})
		requireCode(t, err, CKR_TEMPLATE_INCONSISTENT, "ApplyAttributeTemplate")
	})

	t.Run("unconstrained key returns the template unchanged", func(t *testing.T) {
		open := NewKeyObject(CKO_SECRET_KEY, CKK_AES)
		template := []Attribute{NewStringAttribute(CKA_LABEL, "derived")}
		merged, err := open.ApplyAttributeTemplate(CKA_DERIVE_TEMPLATE, template)
		if err != nil {
			t.Fatalf("ApplyAttributeTemplate: %v", err)
		}
		if len(merged) != 1 || merged[0].Type != CKA_LABEL {
			t.Fatalf("expected the caller template unchanged, got %+v", merged)
		}
	})
}

// TestCreateObject_TemplateAttributeValue proves a nested template must be
// readable and must not smuggle in an attribute the token cannot enforce.
func TestCreateObject_TemplateAttributeValue(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	t.Run("well-formed nested template is accepted", func(t *testing.T) {
		_, err := om.CreateObject(ctx, enforcementTemplate(NewAttribute(CKA_WRAP_TEMPLATE,
			EncodeAttributeArray([]Attribute{NewBoolAttribute(CKA_EXTRACTABLE, true)}))))
		if err != nil {
			t.Fatalf("CreateObject: %v", err)
		}
	})

	t.Run("unreadable nested template is refused", func(t *testing.T) {
		_, err := om.CreateObject(ctx, enforcementTemplate(NewAttribute(CKA_WRAP_TEMPLATE, []byte{7, 7, 7})))
		requireCode(t, err, CKR_ATTRIBUTE_VALUE_INVALID, "CreateObject")
	})

	t.Run("nested unenforceable attribute is refused", func(t *testing.T) {
		_, err := om.CreateObject(ctx, enforcementTemplate(NewAttribute(CKA_UNWRAP_TEMPLATE,
			EncodeAttributeArray([]Attribute{NewAttribute(CKA_TRUST_SERVER_AUTH, []byte{1})}))))
		requireCode(t, err, CKR_ATTRIBUTE_TYPE_INVALID, "CreateObject")
	})
}

// uniqueIDOf reads CKA_UNIQUE_ID from an object the manager holds, failing the
// test if the token never assigned one.
func uniqueIDOf(t *testing.T, om *ObjectManager, ctx AccessContext, handle ObjectHandle) string {
	t.Helper()

	read, err := om.GetAttributeValue(ctx, handle, []Attribute{{Type: CKA_UNIQUE_ID}})
	if err != nil {
		t.Fatalf("GetAttributeValue(CKA_UNIQUE_ID): %v", err)
	}
	if len(read) != 1 || len(read[0].Value) == 0 {
		t.Fatalf("object %d has no CKA_UNIQUE_ID: %+v", handle, read)
	}
	return string(read[0].Value)
}

// TestUniqueID_GeneratedOnEveryCreationPath proves PKCS#11 v3.2 §4.4.1 — "any
// time a new object is created, a value for CKA_UNIQUE_ID MUST be generated by
// the token and stored with the object" — holds for every path that creates
// one, and that the values differ.
func TestUniqueID_GeneratedOnEveryCreationPath(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	created, err := om.CreateObject(ctx, enforcementTemplate())
	if err != nil {
		t.Fatalf("CreateObject: %v", err)
	}

	generated, err := om.CreateGeneratedObject(ctx, CKO_SECRET_KEY, CKK_AES, nil)
	if err != nil {
		t.Fatalf("CreateGeneratedObject: %v", err)
	}

	base, err := om.GetObjectFor(ctx, generated)
	if err != nil {
		t.Fatalf("GetObjectFor: %v", err)
	}
	derived, err := om.CreateDerivedObject(ctx, base, CKO_SECRET_KEY, CKK_AES, nil)
	if err != nil {
		t.Fatalf("CreateDerivedObject: %v", err)
	}

	copied, err := om.CopyObject(ctx, created, nil)
	if err != nil {
		t.Fatalf("CopyObject: %v", err)
	}

	restored := NewObject(CKO_DATA)
	restored.SlotID = ctx.Slot
	if err := om.AddObject(restored); err != nil {
		t.Fatalf("AddObject: %v", err)
	}

	ids := map[string]string{
		"CreateObject":          uniqueIDOf(t, om, ctx, created),
		"CreateGeneratedObject": uniqueIDOf(t, om, ctx, generated),
		"CreateDerivedObject":   uniqueIDOf(t, om, ctx, derived),
		"CopyObject":            uniqueIDOf(t, om, ctx, copied),
		"AddObject":             uniqueIDOf(t, om, ctx, restored.Handle),
	}

	seen := make(map[string]string, len(ids))
	for path, id := range ids {
		if other, clash := seen[id]; clash {
			t.Fatalf("%s and %s were given the same CKA_UNIQUE_ID %q", path, other, id)
		}
		seen[id] = path
	}
}

// TestUniqueID_CopyGetsItsOwnValue proves the rule copies get wrong: PKCS#11
// v3.2 §5.7.2 requires that "whenever an object is copied, a new value for
// CKA_UNIQUE_ID is generated and assigned to the new object".
func TestUniqueID_CopyGetsItsOwnValue(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	source, err := om.CreateObject(ctx, enforcementTemplate(NewStringAttribute(CKA_LABEL, "original")))
	if err != nil {
		t.Fatalf("CreateObject: %v", err)
	}
	copied, err := om.CopyObject(ctx, source, nil)
	if err != nil {
		t.Fatalf("CopyObject: %v", err)
	}

	if uniqueIDOf(t, om, ctx, source) == uniqueIDOf(t, om, ctx, copied) {
		t.Fatal("a copy must not inherit its source's CKA_UNIQUE_ID")
	}
}

// TestUniqueID_NotReusedAfterDestroy proves a destroyed object's identifier is
// not handed to a later object; §4.4.1 permits reuse only after the token is
// reinitialized.
func TestUniqueID_NotReusedAfterDestroy(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	retired := make(map[string]bool)
	for i := 0; i < 32; i++ {
		handle, err := om.CreateObject(ctx, enforcementTemplate())
		if err != nil {
			t.Fatalf("CreateObject: %v", err)
		}
		id := uniqueIDOf(t, om, ctx, handle)
		if retired[id] {
			t.Fatalf("CKA_UNIQUE_ID %q was reused after the object holding it was destroyed", id)
		}
		retired[id] = true

		if err := om.DestroyObject(ctx, handle); err != nil {
			t.Fatalf("DestroyObject: %v", err)
		}
	}
}

// TestUniqueID_ZeroValuedObject proves the restore path accepts an Object
// built as a bare composite literal, whose attribute map is nil.
//
// The zero value of Object is usable by design and several callers rely on it,
// so assigning the identifier it is owed must not depend on a map somebody
// else remembered to allocate. A panic here would cross the C boundary as
// CKR_FUNCTION_FAILED, which tells the application nothing at all.
func TestUniqueID_ZeroValuedObject(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	bare := &Object{Handle: ObjectHandle(4242), Class: CKO_DATA}
	if err := om.AddObject(bare); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if got := uniqueIDOf(t, om, ctx, bare.Handle); got == "" {
		t.Fatal("an object restored from a bare literal must still be given a CKA_UNIQUE_ID")
	}

	t.Run("SetAttribute allocates the map", func(t *testing.T) {
		empty := &Object{}
		empty.SetAttribute(CKA_LABEL, []byte("late"))
		if empty.GetLabel() != "late" {
			t.Fatalf("expected the attribute to be stored, got %q", empty.GetLabel())
		}
	})
}

// TestUniqueID_RestoredValueIsPreserved proves an object restored from storage
// keeps the identifier it was created with, which is what makes CKA_UNIQUE_ID
// stable across a restart.
func TestUniqueID_RestoredValueIsPreserved(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	restored := NewObject(CKO_DATA)
	restored.SlotID = ctx.Slot
	restored.SetAttribute(CKA_UNIQUE_ID, []byte("0123456789abcdef0123456789abcdef"))
	if err := om.AddObject(restored); err != nil {
		t.Fatalf("AddObject: %v", err)
	}

	if got := uniqueIDOf(t, om, ctx, restored.Handle); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("restored CKA_UNIQUE_ID was rewritten to %q", got)
	}
}

// TestUniqueID_IsReadOnlyToTheCaller proves the caller can neither supply nor
// change the identifier: §4.4.1 requires both attempts to fail with
// CKR_ATTRIBUTE_READ_ONLY.
func TestUniqueID_IsReadOnlyToTheCaller(t *testing.T) {
	om := NewObjectManager()
	ctx := fullAccessCtx(SessionHandle(1))

	_, err := om.CreateObject(ctx, enforcementTemplate(NewStringAttribute(CKA_UNIQUE_ID, "forged")))
	requireCode(t, err, CKR_ATTRIBUTE_READ_ONLY, "CreateObject")

	handle, err := om.CreateObject(ctx, enforcementTemplate())
	if err != nil {
		t.Fatalf("CreateObject: %v", err)
	}
	err = om.SetAttributeValue(ctx, handle, []Attribute{NewStringAttribute(CKA_UNIQUE_ID, "forged")})
	requireCode(t, err, CKR_ATTRIBUTE_READ_ONLY, "SetAttributeValue")
}
