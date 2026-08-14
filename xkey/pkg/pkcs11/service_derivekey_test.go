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

package pkcs11

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// deriveBackend is the backend name AutoInitialize registers in every build:
// the in-memory software backend, which holds its own symmetric key material
// and therefore implements types.SymmetricKeyDeriver.
const deriveBackend = "software"

// newDeriveTestTransport brings up the process-global xkms service with
// in-memory storage and returns an embedded transport bound to it.
//
// The service is a process singleton, so these tests must not run in parallel
// with each other; the cleanup tears it down so an ordering change cannot leave
// a half-configured service behind for the next test.
func newDeriveTestTransport(t *testing.T) *EmbeddedTransport {
	t.Helper()

	xkms.Reset()
	if err := xkms.AutoInitialize(&xkms.AutoConfig{}); err != nil {
		t.Fatalf("AutoInitialize() error = %v", err)
	}
	t.Cleanup(xkms.Reset)

	tr, err := NewEmbeddedTransport()
	if err != nil {
		t.Fatalf("NewEmbeddedTransport() error = %v", err)
	}
	return tr
}

// newSymmetricKey generates an AES-256 key in the software backend and returns
// its key identifier. exportable controls CKA_EXTRACTABLE's analogue: a
// non-exportable key is one whose material the backend refuses to release, and
// derivation from it must still succeed.
func newSymmetricKey(t *testing.T, cn string, exportable bool) *xkms.KeyAttributes {
	t.Helper()

	backend, err := xkms.GetBackend(deriveBackend)
	if err != nil {
		t.Fatalf("GetBackend(%q) error = %v", deriveBackend, err)
	}

	provider, ok := backend.KeyProvider().(xkms.SymmetricKeyProvider)
	if !ok {
		t.Fatalf("backend %q key provider %T does not generate symmetric keys", deriveBackend, backend.KeyProvider())
	}

	attrs := &xkms.KeyAttributes{
		CN:                 cn,
		KeyType:            xkms.KeyTypeSecret,
		StoreType:          xkms.StoreType(deriveBackend),
		SymmetricAlgorithm: xkms.SymmetricAES256GCM,
		Exportable:         exportable,
	}
	if _, err := provider.GenerateSymmetricKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey() error = %v", err)
	}
	return attrs
}

// exportedKeyMaterial reads back the raw bytes of an exportable key so a test
// can compute an oracle over the material the backend actually holds.
func exportedKeyMaterial(t *testing.T, attrs *xkms.KeyAttributes) []byte {
	t.Helper()

	backend, err := xkms.GetBackend(deriveBackend)
	if err != nil {
		t.Fatalf("GetBackend(%q) error = %v", deriveBackend, err)
	}
	exporter, ok := backend.KeyProvider().(xkms.ImportExportBackend)
	if !ok {
		t.Fatalf("backend %q key provider %T cannot export key material", deriveBackend, backend.KeyProvider())
	}
	material, err := exporter.ExportKeyMaterial(context.Background(), attrs)
	if err != nil {
		t.Fatalf("ExportKeyMaterial() error = %v", err)
	}
	return material
}

// sp800108CounterOracle is an independent implementation of NIST SP 800-108r1
// Section 4.1, KDF in Counter Mode, with the parameter choices the xkms KDF
// defaults to: HMAC-SHA-256 as the PRF, a 32-bit counter placed before the
// fixed input data, and [L]_2 encoded as 32 bits.
//
//	K(i) = HMAC(KDK, [i]_32 || Label || 0x00 || Context || [L]_32)
//	KM   = K(1) || K(2) || ... truncated to length bytes
//
// It is written out here rather than called through pkg/crypto/kdf on purpose:
// an oracle that shares an implementation with the code under test agrees with
// it no matter what either of them computes.
func sp800108CounterOracle(kdk, label, context []byte, length int) []byte {
	fixed := make([]byte, 0, len(label)+1+len(context)+4)
	fixed = append(fixed, label...)
	fixed = append(fixed, 0x00)
	fixed = append(fixed, context...)

	lengthBits := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBits, uint32(length)*8)
	fixed = append(fixed, lengthBits...)

	counter := make([]byte, 4)
	out := make([]byte, 0, length+sha256.Size)
	for i := 1; len(out) < length; i++ {
		binary.BigEndian.PutUint32(counter, uint32(i))
		mac := hmac.New(sha256.New, kdk)
		mac.Write(counter)
		mac.Write(fixed)
		out = mac.Sum(out)
	}
	return out[:length]
}

// hkdfOracle is RFC 5869 extract-then-expand over golang.org/x/crypto/hkdf,
// the construction the embedded transport used to run for every request
// regardless of the algorithm it was asked for.
func hkdfOracle(t *testing.T, ikm, salt, info []byte, length int) []byte {
	t.Helper()

	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, info), out); err != nil {
		t.Fatalf("hkdf oracle error = %v", err)
	}
	return out
}

// TestDeriveKeyRunsSP800108AndNotHKDF is the decisive test for the algorithm
// defect: the embedded transport hardcoded HKDF and never read req.Algorithm,
// so a CKM_SP800_108_COUNTER_KDF request derived HKDF bytes and reported
// CKR_OK. Both halves of the assertion matter — matching the SP 800-108 oracle
// proves the right construction ran, and differing from the HKDF oracle proves
// the old behaviour is gone rather than coincidentally agreeing.
func TestDeriveKeyRunsSP800108AndNotHKDF(t *testing.T) {
	tr := newDeriveTestTransport(t)

	ikm := []byte("base key material for the counter mode kdf")
	label := []byte("xkms-sp800-108-label")
	kdfContext := []byte("xkms-sp800-108-context")

	resp, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm:        "SP800-108-COUNTER",
		Hash:             "SHA-256",
		InputKeyMaterial: ikm,
		Label:            label,
		Context:          kdfContext,
		KeyLength:        48,
	})
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	want := sp800108CounterOracle(ikm, label, kdfContext, 48)
	if !bytes.Equal(resp.DerivedKey, want) {
		t.Errorf("DeriveKey() = %x, want the SP 800-108 counter-mode oracle %x", resp.DerivedKey, want)
	}

	hkdfBytes := hkdfOracle(t, ikm, nil, nil, 48)
	if bytes.Equal(resp.DerivedKey, hkdfBytes) {
		t.Errorf("DeriveKey() returned HKDF output %x for an SP800-108-COUNTER request", hkdfBytes)
	}
}

// TestDeriveKeyHKDFMatchesItsOracle proves the delegation did not disturb the
// construction that always worked: an HKDF request still produces RFC 5869
// extract-then-expand over the caller's salt and info.
func TestDeriveKeyHKDFMatchesItsOracle(t *testing.T) {
	tr := newDeriveTestTransport(t)

	ikm := []byte("base key material for hkdf")
	salt := []byte("hkdf-salt")
	info := []byte("hkdf-info")

	resp, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm:        "HKDF",
		Hash:             "SHA-256",
		InputKeyMaterial: ikm,
		Salt:             salt,
		Info:             info,
		KeyLength:        32,
	})
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	want := hkdfOracle(t, ikm, salt, info, 32)
	if !bytes.Equal(resp.DerivedKey, want) {
		t.Errorf("DeriveKey() = %x, want the HKDF oracle %x", resp.DerivedKey, want)
	}
}

// TestDeriveKeyFromStoredKeyDerivesOverTheStoredMaterial proves the identity
// form derives from the key the backend holds, using the requested algorithm.
// The oracle's input is the key's own material, read back through
// ExportKeyMaterial purely to obtain it: a derivation that ran over the key's
// name, its identifier or an empty string also returns a well-formed 32-byte
// key, and only this comparison rejects it.
func TestDeriveKeyFromStoredKeyDerivesOverTheStoredMaterial(t *testing.T) {
	tr := newDeriveTestTransport(t)
	attrs := newSymmetricKey(t, "derive-stored-exportable", true)
	material := exportedKeyMaterial(t, attrs)

	label := []byte("stored-key-label")
	kdfContext := []byte("stored-key-context")

	resp, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend:   deriveBackend,
		KeyID:     attrs.CN,
		Algorithm: "SP800-108-COUNTER",
		Hash:      "SHA-256",
		Label:     label,
		Context:   kdfContext,
		KeyLength: 32,
	})
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}

	want := sp800108CounterOracle(material, label, kdfContext, 32)
	if !bytes.Equal(resp.DerivedKey, want) {
		t.Errorf("DeriveKey() = %x, want the SP 800-108 oracle over the stored key %x", resp.DerivedKey, want)
	}
}

// TestDeriveKeyFromNonExportableKeySucceeds is the decisive test for the export
// defect. The old embedded path called ExportKeyMaterial to pull the base key
// into this process, so it failed for exactly the keys C_DeriveKey exists to
// serve — the ones whose material the backend will not release. The export is
// asserted to fail first, so the derivation that follows cannot have used it.
func TestDeriveKeyFromNonExportableKeySucceeds(t *testing.T) {
	tr := newDeriveTestTransport(t)
	attrs := newSymmetricKey(t, "derive-stored-sealed", false)

	backend, err := xkms.GetBackend(deriveBackend)
	if err != nil {
		t.Fatalf("GetBackend(%q) error = %v", deriveBackend, err)
	}
	exporter, ok := backend.KeyProvider().(xkms.ImportExportBackend)
	if !ok {
		t.Fatalf("backend %q key provider %T cannot export key material", deriveBackend, backend.KeyProvider())
	}
	if _, err := exporter.ExportKeyMaterial(context.Background(), attrs); err == nil {
		t.Fatal("ExportKeyMaterial() succeeded for a non-exportable key; the test cannot prove the derivation avoided it")
	}

	resp, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend:   deriveBackend,
		KeyID:     attrs.CN,
		Algorithm: "SP800-108-COUNTER",
		Hash:      "SHA-256",
		Label:     []byte("sealed-key-label"),
		Context:   []byte("sealed-key-context"),
		KeyLength: 32,
	})
	if err != nil {
		t.Fatalf("DeriveKey() error = %v, want a derivation that never exports the base key", err)
	}
	if len(resp.DerivedKey) != 32 {
		t.Errorf("DeriveKey() returned %d bytes, want 32", len(resp.DerivedKey))
	}
}

// TestDeriveKeyFromNonExportableKeyIsBoundToTheKey proves the non-exportable
// derivation is a function of the base key and not of its non-secret name: two
// keys derived with identical parameters must not agree.
func TestDeriveKeyFromNonExportableKeyIsBoundToTheKey(t *testing.T) {
	tr := newDeriveTestTransport(t)
	first := newSymmetricKey(t, "derive-sealed-first", false)
	second := newSymmetricKey(t, "derive-sealed-second", false)

	derive := func(attrs *xkms.KeyAttributes) []byte {
		t.Helper()
		resp, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
			Backend:   deriveBackend,
			KeyID:     attrs.CN,
			Algorithm: "SP800-108-COUNTER",
			Hash:      "SHA-256",
			Label:     []byte("shared-label"),
			Context:   []byte("shared-context"),
			KeyLength: 32,
		})
		if err != nil {
			t.Fatalf("DeriveKey(%s) error = %v", attrs.CN, err)
		}
		return resp.DerivedKey
	}

	if bytes.Equal(derive(first), derive(second)) {
		t.Error("two different base keys derived the same key; the derivation is not bound to the key material")
	}
}

// TestDeriveKeyRejectsUnknownAlgorithm covers the bad-input path the old code
// had none of: an algorithm the service does not implement was silently
// answered with HKDF bytes and a success status.
func TestDeriveKeyRejectsUnknownAlgorithm(t *testing.T) {
	tr := newDeriveTestTransport(t)

	_, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm:        "NOT-A-REAL-KDF",
		Hash:             "SHA-256",
		InputKeyMaterial: []byte("base key material"),
		KeyLength:        32,
	})
	if err == nil {
		t.Fatal("DeriveKey() accepted an unknown algorithm")
	}
	if !errors.Is(err, xkms.ServiceErrOperationNotSupported) {
		t.Errorf("DeriveKey() error = %v, want ErrOperationNotSupported", err)
	}
}

// TestDeriveKeyRejectsTwoBaseKeys covers a request naming both a raw base key
// and a stored one. They are two different keys, and answering with either
// returns key material the caller did not select under a success status.
func TestDeriveKeyRejectsTwoBaseKeys(t *testing.T) {
	tr := newDeriveTestTransport(t)
	attrs := newSymmetricKey(t, "derive-two-base-keys", true)

	_, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend:          deriveBackend,
		KeyID:            attrs.CN,
		Algorithm:        "HKDF",
		Hash:             "SHA-256",
		InputKeyMaterial: []byte("a second, different base key"),
		KeyLength:        32,
	})
	if err == nil {
		t.Fatal("DeriveKey() accepted both input_key_material and key_id")
	}
}

// TestDeriveKeyRejectsInapplicableParameter covers a salt supplied with
// SP 800-108 counter mode, which has no salt input. The old code consumed it as
// HKDF's salt, so a caller who believed the salt separated its key from someone
// else's got a key that did depend on it — but derived by the wrong function.
func TestDeriveKeyRejectsInapplicableParameter(t *testing.T) {
	tr := newDeriveTestTransport(t)

	_, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm:        "SP800-108-COUNTER",
		Hash:             "SHA-256",
		InputKeyMaterial: []byte("base key material"),
		Salt:             []byte("a salt counter mode has no input for"),
		KeyLength:        32,
	})
	if err == nil {
		t.Fatal("DeriveKey() accepted a salt for SP800-108-COUNTER")
	}
}

// TestDeriveKeyRejectsMissingBaseKey covers a request that names neither form
// of base key. Every construction here derives happily from zero bytes and
// returns a well-formed key anyone can recompute.
func TestDeriveKeyRejectsMissingBaseKey(t *testing.T) {
	tr := newDeriveTestTransport(t)

	_, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm: "HKDF",
		Hash:      "SHA-256",
		KeyLength: 32,
	})
	if err == nil {
		t.Fatal("DeriveKey() accepted a request with no base key")
	}
}

// TestDeriveKeyRejectsNilRequest covers the nil request guard.
func TestDeriveKeyRejectsNilRequest(t *testing.T) {
	tr := newDeriveTestTransport(t)

	if _, err := tr.DeriveKey(context.Background(), nil); !errors.Is(err, ErrNilRequest) {
		t.Errorf("DeriveKey(nil) error = %v, want ErrNilRequest", err)
	}
}

// TestDeriveKeyWithoutServiceReportsNotInitialized covers the transport being
// driven after the service singleton is gone, which is what a C_DeriveKey
// arriving after teardown looks like.
func TestDeriveKeyWithoutServiceReportsNotInitialized(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	tr := &EmbeddedTransport{}
	_, err := tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm:        "HKDF",
		InputKeyMaterial: []byte("base key material"),
		KeyLength:        32,
	})
	if !errors.Is(err, ErrServiceNotInitialized) {
		t.Errorf("DeriveKey() error = %v, want ErrServiceNotInitialized", err)
	}
}
