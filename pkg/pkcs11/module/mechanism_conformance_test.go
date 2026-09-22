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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"sort"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// The mechanism registry is what C_GetMechanismList and C_GetMechanismInfo
// report and what every *Init call validates against, so a descriptor that
// disagrees with the code behind it is a lie told to a conformant application
// in one of two directions: a capability advertised and then refused, or a
// capability implemented and unreachable. The tests in this file assert both
// directions for the two families where the registry and the implementation had
// drifted, and they are deliberately bidirectional so that neither half of a
// future change can land without the other.

// digestReferenceHashers gives, for every digest mechanism this module might
// register, the standard-library hash the mechanism denotes.
//
// It is a reference rather than a length table so the test catches a mechanism
// wired to the wrong hasher, not merely to one of the right width:
// CKM_SHA512_256 and CKM_SHA256 both produce 32 bytes but are different
// functions (FIPS 180-4 §6.7 versus §6.2), and a token that returned one for
// the other would satisfy any length check while interoperating with nothing.
//
// SHA-3 (FIPS 202, PKCS#11 v3.2 §6.29) is present so that the day
// newDigestOperation grows its SHA-3 cases the entries can be restored to the
// registry and validated here without a second edit. crypto/sha3 is the
// standard library as of Go 1.24, so no external dependency is involved.
var digestReferenceHashers = map[MechanismType]func() hash.Hash{
	CKM_SHA_1:      sha1.New,
	CKM_SHA224:     sha256.New224,
	CKM_SHA256:     sha256.New,
	CKM_SHA384:     sha512.New384,
	CKM_SHA512:     sha512.New,
	CKM_SHA512_224: sha512.New512_224,
	CKM_SHA512_256: sha512.New512_256,
}

// TestEveryDigestMechanismIsBothRegisteredAndImplemented asserts that the set of
// mechanisms the registry describes as digests is exactly the set
// newDigestOperation can perform.
//
// Both directions were violated at once. CKM_SHA3_256, CKM_SHA3_384 and
// CKM_SHA3_512 were registered with CKF_DIGEST although newDigestOperation has
// no SHA-3 case, so C_DigestInit passed the flag check and the operation then
// failed with CKR_MECHANISM_INVALID. In the other direction CKM_SHA512_224 and
// CKM_SHA512_256 had working hashers that no application could reach, because
// neither had a registry entry for validateInitMechanism to resolve.
func TestEveryDigestMechanismIsBothRegisteredAndImplemented(t *testing.T) {
	const message = "the quick brown fox jumps over the lazy dog"

	// Direction one: everything the registry calls a digest must digest.
	for mechType, desc := range mechanismRegistry {
		if desc.Flags&CKF_DIGEST == 0 {
			continue
		}

		reference, known := digestReferenceHashers[mechType]
		if !known {
			t.Errorf("%s is registered with CKF_DIGEST but digestReferenceHashers has no "+
				"entry for it, so nothing checks that the module computes the digest the "+
				"mechanism names; add the standard-library hash it denotes", desc.Name)
			continue
		}

		op, err := newDigestOperation(&Mechanism{Type: mechType})
		if err != nil {
			t.Errorf("%s is registered with CKF_DIGEST but newDigestOperation refused it "+
				"(%v); C_DigestInit accepts the mechanism on the strength of that flag and "+
				"the operation then fails, which is the advertised-but-not-implemented "+
				"defect", desc.Name, err)
			continue
		}

		if _, err := op.hasher.Write([]byte(message)); err != nil {
			t.Errorf("%s: writing to the hasher failed: %v", desc.Name, err)
			continue
		}
		got := op.hasher.Sum(nil)

		want := reference()
		if _, err := want.Write([]byte(message)); err != nil {
			t.Fatalf("%s: writing to the reference hasher failed: %v", desc.Name, err)
		}
		if !bytes.Equal(got, want.Sum(nil)) {
			t.Errorf("%s digests to a different value than the algorithm it names; the "+
				"mechanism is wired to the wrong hasher", desc.Name)
		}
	}

	// Direction two: everything that digests must be registered as one. The
	// universe is every mechanism constant this module names, which is the
	// widest set an application could pass as a raw constant.
	for mechType, name := range mechanismNames {
		if _, err := newDigestOperation(&Mechanism{Type: mechType}); err != nil {
			continue
		}
		desc, registered := mechanismRegistry[mechType]
		if !registered {
			t.Errorf("newDigestOperation implements %s but it has no registry entry, so "+
				"validateInitMechanism refuses it with CKR_MECHANISM_INVALID and no "+
				"application can reach the implementation", name)
			continue
		}
		if desc.Flags&CKF_DIGEST == 0 {
			t.Errorf("newDigestOperation implements %s but its descriptor does not carry "+
				"CKF_DIGEST, so C_GetMechanismInfo tells applications it cannot digest",
				name)
		}
	}
}

// TestDigestOperationRefusesAnUnregisteredMechanism is the bad-input half: a
// mechanism the registry does not describe as a digest must not be digestible,
// or the bidirectional assertion above would be satisfied vacuously by a
// newDigestOperation that accepted everything.
func TestDigestOperationRefusesAnUnregisteredMechanism(t *testing.T) {
	notDigests := []MechanismType{
		CKM_SHA3_256,            // registered nowhere, implemented nowhere
		CKM_AES_GCM,             // registered, but as an encryption mechanism
		CKM_RSA_PKCS,            // registered, but as a signature mechanism
		MechanismType(0xFFFF0F), // no such mechanism
	}

	for _, mechType := range notDigests {
		op, err := newDigestOperation(&Mechanism{Type: mechType})
		if err == nil {
			t.Errorf("newDigestOperation(%s) returned an operation; a mechanism the "+
				"registry does not describe as a digest must be refused",
				GetMechanismName(mechType))
			continue
		}
		if op != nil {
			t.Errorf("newDigestOperation(%s) returned both an error and an operation",
				GetMechanismName(mechType))
		}
		var pkcsErr *PKCS11Error
		if !errors.As(err, &pkcsErr) {
			t.Errorf("newDigestOperation(%s) returned %T, want *PKCS11Error carrying a "+
				"CK_RV the caller can return", GetMechanismName(mechType), err)
			continue
		}
		if pkcsErr.Code != CKR_MECHANISM_INVALID {
			t.Errorf("newDigestOperation(%s) returned %s, want CKR_MECHANISM_INVALID",
				GetMechanismName(mechType), pkcsErr.Code.String())
		}
	}
}

// TestWrappingDescriptorsMatchTheWrapRouting asserts that the mechanisms whose
// descriptors carry CKF_WRAP and CKF_UNWRAP are exactly the mechanisms
// C_WrapKey and C_UnwrapKey can route to an algorithm.
//
// CKM_AES_CBC, CKM_AES_CBC_PAD and CKM_AES_GCM advertised CKF_ENCRYPT|CKF_DECRYPT
// and nothing else while module.go's wrapAlgorithmNames routed all three through
// C_WrapKey, so C_GetMechanismInfo told a conformant application these
// mechanisms could not wrap and the module wrapped with them anyway. Because the
// descriptors now match the routing, CanWrap and CanUnwrap can be used to gate
// C_WrapKey and C_UnwrapKey; this test is what keeps that gate from starting to
// refuse a mechanism the module still routes.
//
// CKM_RSA_PKCS_OAEP is the one deliberate exception in the routing table: its
// algorithm name depends on the digest in CK_RSA_PKCS_OAEP_PARAMS, so
// oaepWrapAlgorithm resolves it instead of wrapAlgorithmNames.
func TestWrappingDescriptorsMatchTheWrapRouting(t *testing.T) {
	routed := make(map[MechanismType]bool, len(wrapAlgorithmNames)+1)
	for mechType := range wrapAlgorithmNames {
		routed[mechType] = true
	}
	routed[CKM_RSA_PKCS_OAEP] = true

	for mechType := range routed {
		desc := GetMechanismDescriptor(mechType)
		if desc == nil {
			t.Errorf("%s is routed to a wrapping algorithm but has no registry "+
				"descriptor, so C_WrapKey refuses it at validateInitMechanism",
				GetMechanismName(mechType))
			continue
		}
		if desc.Flags&CKF_WRAP == 0 {
			t.Errorf("%s is routed through C_WrapKey but its descriptor omits CKF_WRAP, "+
				"so C_GetMechanismInfo tells applications it cannot wrap", desc.Name)
		}
		if desc.Flags&CKF_UNWRAP == 0 {
			t.Errorf("%s is routed through C_UnwrapKey but its descriptor omits "+
				"CKF_UNWRAP, so C_GetMechanismInfo tells applications it cannot unwrap",
				desc.Name)
		}
	}

	for mechType, desc := range mechanismRegistry {
		if desc.Flags&(CKF_WRAP|CKF_UNWRAP) == 0 {
			continue
		}
		if !routed[mechType] {
			t.Errorf("%s advertises CKF_WRAP/CKF_UNWRAP but nothing in module.go's "+
				"wrapAlgorithmNames routes it, so C_WrapKey resolves it to a name the "+
				"service refuses; either route it or stop claiming the capability",
				desc.Name)
		}
	}
}

// TestAESKeyWrapKWPAndPADDescribeTheSameConstruction pins the v3.2 §6.10
// relationship between the two RFC 5649 identifiers.
//
// CKM_AES_KEY_WRAP_KWP is the current identifier and CKM_AES_KEY_WRAP_PAD the
// deprecated alias, so an application must get the same wrapping from either.
// KWP had been declared and name-mapped but never registered, which made the
// current identifier the one that failed.
func TestAESKeyWrapKWPAndPADDescribeTheSameConstruction(t *testing.T) {
	kwp := GetMechanismDescriptor(CKM_AES_KEY_WRAP_KWP)
	pad := GetMechanismDescriptor(CKM_AES_KEY_WRAP_PAD)

	if kwp == nil {
		t.Fatal("CKM_AES_KEY_WRAP_KWP has no registry descriptor; every use of the " +
			"current RFC 5649 identifier returns CKR_MECHANISM_INVALID")
	}
	if pad == nil {
		t.Fatal("CKM_AES_KEY_WRAP_PAD has no registry descriptor; the deprecated alias " +
			"must keep working for existing callers")
	}

	if kwp.Flags != pad.Flags {
		t.Errorf("CKM_AES_KEY_WRAP_KWP advertises flags 0x%x and CKM_AES_KEY_WRAP_PAD "+
			"0x%x; they name the same RFC 5649 construction", kwp.Flags, pad.Flags)
	}
	if kwp.MinKeySize != pad.MinKeySize || kwp.MaxKeySize != pad.MaxKeySize {
		t.Errorf("CKM_AES_KEY_WRAP_KWP accepts key sizes %d-%d and CKM_AES_KEY_WRAP_PAD "+
			"%d-%d; they wrap with the same kind of AES key encryption key",
			kwp.MinKeySize, kwp.MaxKeySize, pad.MinKeySize, pad.MaxKeySize)
	}
	if kwp.Advertised != pad.Advertised {
		t.Errorf("CKM_AES_KEY_WRAP_KWP is advertised=%v and CKM_AES_KEY_WRAP_PAD is "+
			"advertised=%v; the current identifier must be at least as discoverable as "+
			"the deprecated alias", kwp.Advertised, pad.Advertised)
	}

	if got, want := wrapAlgorithmNames[CKM_AES_KEY_WRAP_KWP], types.WrapAESKWP; got != want {
		t.Errorf("CKM_AES_KEY_WRAP_KWP routes to %q, want %q; RFC 5649 is what both "+
			"identifiers name", got, want)
	}
	if got, want := wrapAlgorithmNames[CKM_AES_KEY_WRAP_PAD], types.WrapAESKWP; got != want {
		t.Errorf("CKM_AES_KEY_WRAP_PAD routes to %q, want %q; the deprecated alias must "+
			"keep the RFC 5649 behaviour it already had", got, want)
	}
}

// postQuantumRegistered reports whether mechType belongs to one of the
// post-quantum families this registry describes: ML-DSA and its pre-hashed
// variants (FIPS 204), ML-KEM (FIPS 203), SLH-DSA and its pre-hashed variants
// (FIPS 205), HSS/LMS (RFC 8554), XMSS and XMSS^MT (RFC 8391), and the
// vendor-defined mechanisms these standard identifiers replaced.
//
// It exists only to scope TestNoMechanismIsUndiscoverableButUsable; see that
// test for why the families are excepted and what has to happen for the
// exception to be removed.
func postQuantumRegistered(mechType MechanismType) bool {
	if mechType >= CKM_VENDOR_DEFINED {
		return true
	}
	// v32KeyTypeMap holds more than the post-quantum mechanisms, so membership
	// alone is not the test; the key type it maps to is.
	switch v32KeyTypeMap[mechType] {
	case CKK_ML_KEM, CKK_ML_DSA, CKK_SLH_DSA, CKK_HSS, CKK_XMSS, CKK_XMSSMT:
		return true
	}
	switch mechType {
	case CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_DSA_KEY_PAIR_GEN, CKM_SLH_DSA_KEY_PAIR_GEN,
		CKM_HSS_KEY_PAIR_GEN, CKM_XMSS_KEY_PAIR_GEN, CKM_XMSSMT_KEY_PAIR_GEN:
		return true
	}
	return false
}

// mechanismsAwaitingAnImplementation enumerates the mechanisms this registry
// describes and this module implements, but that no backend in this deployment
// can complete. Each is registered so the implementation is not deleted, and
// unadvertised so no application is told to rely on it.
//
// The list is explicit, and every entry carries the evidence that put it here,
// because the alternative -- a blanket allowance -- is how "unadvertised"
// becomes a place to park anything. An entry leaves this list in one of two
// directions only: it starts working end to end and becomes advertised, or it
// is shown to have no implementation path and its descriptor is removed.
//
// The post-quantum families are excepted separately, by postQuantumRegistered,
// because there are 54 of them and they share one cause.
var mechanismsAwaitingAnImplementation = map[MechanismType]string{
	// Only verify-recover is performed, and that direction is correct: s^e mod n
	// computed locally from a public key and returned unprocessed, which is what
	// v3.2 §6.1.7 defines. Sign, verify, encrypt and decrypt are refused by
	// withholding their flags, because this token reaches keys through
	// crypto.Signer and crypto.Decrypter -- neither of which has a raw-primitive
	// form, and a key in a TPM, an HSM or a cloud KMS could not expose one.
	// Unadvertised because raw RSA is not FIPS-approved and a mechanism offering
	// verify-recover alone is not worth putting in C_GetMechanismList.
	// See TestRSAX509RefusesTheOperationsItCannotPerform.
	CKM_RSA_X_509: "only verify-recover is performed; the other directions are refused",

	// CryptoManager builds a correct HMAC signing request for each, but C_Sign
	// fails with CKR_FUNCTION_FAILED: no backend here performs a symmetric MAC.
	CKM_SHA256_HMAC: "no backend performs a symmetric MAC",
	CKM_SHA384_HMAC: "no backend performs a symmetric MAC",
	CKM_SHA512_HMAC: "no backend performs a symmetric MAC",

	// The mechanism maps to the X25519 key type and a request is built, but
	// C_GenerateKeyPair returns CKR_GENERAL_ERROR from the backend.
	CKM_EC_MONTGOMERY_KEY_PAIR_GEN: "no backend generates a Montgomery key pair",

	// C_GenerateKey succeeds only at 16 and 32 bytes -- the backend treats the
	// request as an ordinary symmetric key and accepts only AES key sizes --
	// while v3.2 §6.9 defines the mechanism as generating a secret of arbitrary
	// caller-chosen length. No contiguous ulMinKeySize/ulMaxKeySize pair
	// describes that, so CK_MECHANISM_INFO cannot be filled in truthfully.
	CKM_GENERIC_SECRET_KEY_GEN: "only AES key sizes generate; §6.9 requires arbitrary lengths",
}

// TestNoMechanismIsUndiscoverableButUsable asserts that every classical
// mechanism the registry will resolve is either one C_GetMechanismList offers or
// one explicitly recorded as awaiting an implementation.
//
// An unadvertised registry entry is the worst of both states: an application
// cannot discover the mechanism, yet one that names the raw constant reaches an
// implementation nobody has committed to, and the failure surfaces deep inside
// the operation instead of at C_*Init. Withholding advertisement is a way to
// withhold a promise, not a way to ship a half-finished mechanism.
//
// Every mechanism that had no implementation path at all has been removed from
// the registry rather than left unadvertised. What remains unadvertised is
// enumerated above with its reason, so the set is reviewable rather than
// accidental.
func TestNoMechanismIsUndiscoverableButUsable(t *testing.T) {
	var offenders []string
	for mechType, desc := range mechanismRegistry {
		if desc.Advertised || postQuantumRegistered(mechType) {
			continue
		}
		if _, known := mechanismsAwaitingAnImplementation[mechType]; known {
			continue
		}
		offenders = append(offenders, desc.Name)
	}
	sort.Strings(offenders)

	for _, name := range offenders {
		t.Errorf("%s is registered but not advertised: C_GetMechanismList hides it while "+
			"GetMechanismDescriptor still resolves it for any caller that names the raw "+
			"constant. Advertise it once it is proven end to end, remove the entry so the "+
			"module refuses it, or record it in mechanismsAwaitingAnImplementation with "+
			"the evidence", name)
	}
}

// TestMechanismsAwaitingAnImplementationStayUnadvertised is the other half: the
// list must not accumulate entries that no longer belong on it.
//
// A mechanism recorded as awaiting an implementation and then advertised anyway
// is a contradiction, and one recorded here but absent from the registry is a
// stale note that would silently stop excusing anything.
func TestMechanismsAwaitingAnImplementationStayUnadvertised(t *testing.T) {
	for mechType, reason := range mechanismsAwaitingAnImplementation {
		desc, registered := mechanismRegistry[mechType]
		if !registered {
			t.Errorf("%s is recorded as awaiting an implementation (%q) but is not in the "+
				"registry; delete the entry, it excuses nothing",
				GetMechanismName(mechType), reason)
			continue
		}
		if desc.Advertised {
			t.Errorf("%s is advertised and also recorded as awaiting an implementation "+
				"(%q); if it works end to end, remove it from the list", desc.Name, reason)
		}
		if reason == "" {
			t.Errorf("%s is excused without a reason; the evidence is the point of the list",
				desc.Name)
		}
	}
}

// TestPostQuantumExceptionStaysNarrow keeps the exception above from becoming a
// place to park any unadvertised mechanism.
//
// postQuantumRegistered treats the whole vendor range as post-quantum, which is
// true of this registry today and is the only reason the coarse bound is safe.
// If a non-PQC vendor mechanism is ever registered, the exception would swallow
// it silently and the invariant would quietly stop being enforced.
func TestPostQuantumExceptionStaysNarrow(t *testing.T) {
	for mechType, desc := range mechanismRegistry {
		if mechType < CKM_VENDOR_DEFINED {
			continue
		}
		if !strings.Contains(desc.Name, "ML_DSA") && !strings.Contains(desc.Name, "ML_KEM") {
			t.Errorf("%s is a vendor-defined mechanism that is not post-quantum, but "+
				"postQuantumRegistered exempts the entire vendor range from the "+
				"advertising invariant; narrow the predicate before registering it",
				desc.Name)
		}
	}
}

// TestAdvertisedKeySizeRangesAreNonEmpty asserts that every advertised
// mechanism reports a CK_MECHANISM_INFO an application can act on.
//
// PKCS#11 v3.2 §5.5 makes ulMinKeySize/ulMaxKeySize how an application chooses
// what to ask for, so ulMinKeySize > ulMaxKeySize describes an empty range and
// tells the caller no key size is acceptable. This registry uses MaxKeySize: 0
// internally to mean "no maximum I enforce", which is the right answer for
// IsValidKeySize and an untruthful one for CK_MECHANISM_INFO -- the two readings
// are opposite. A mechanism carrying the sentinel alongside a non-zero minimum
// therefore cannot be advertised until it can state a real ceiling.
//
// CKM_GENERIC_SECRET_KEY_GEN is the mechanism that made this concrete: it was
// advertised with MinKeySize 1 and the sentinel, and a conformant reader saw an
// empty range.
func TestAdvertisedKeySizeRangesAreNonEmpty(t *testing.T) {
	for mechType, info := range defaultMechanismInfo() {
		if info.MinKeySize > info.MaxKeySize {
			t.Errorf("%s advertises ulMinKeySize=%d and ulMaxKeySize=%d, an empty range; "+
				"an application reading CK_MECHANISM_INFO to choose a key size is told "+
				"none is acceptable", GetMechanismName(mechType),
				info.MinKeySize, info.MaxKeySize)
		}
	}
}

// TestUnadvertisedSentinelIsStillTheRegistrysNoMaximum is the bad-input half of
// the rule above: the sentinel must keep meaning "no enforced maximum" for the
// mechanisms that are not advertised, or IsValidKeySize would start refusing
// every key size those mechanisms accept.
func TestUnadvertisedSentinelIsStillTheRegistrysNoMaximum(t *testing.T) {
	withFIPSMode(t, false)

	desc := GetMechanismDescriptor(CKM_SHA256_HMAC)
	if desc == nil {
		t.Fatal("CKM_SHA256_HMAC is missing from the registry; it is the family this rule " +
			"is about")
	}
	if desc.Advertised {
		t.Fatal("CKM_SHA256_HMAC is advertised, so it must state a real ceiling and this " +
			"test no longer describes it")
	}
	if desc.MaxKeySize != 0 {
		t.Fatal("CKM_SHA256_HMAC no longer uses the no-maximum sentinel; this test is " +
			"testing nothing")
	}
	for _, size := range []uint32{1, 32, 1 << 20} {
		if !IsValidKeySize(CKM_SHA256_HMAC, size) {
			t.Errorf("IsValidKeySize(CKM_SHA256_HMAC, %d) = false; MaxKeySize 0 means no "+
				"enforced maximum, not a maximum of zero", size)
		}
	}
	if IsValidKeySize(CKM_SHA256_HMAC, 0) {
		t.Error("IsValidKeySize(CKM_SHA256_HMAC, 0) = true, below the declared minimum of 1; " +
			"the absent maximum must not disable the minimum")
	}
}

// TestRSAX509RefusesTheOperationsItCannotPerform pins the one thing that made
// CKM_RSA_X_509 dangerous: it used to claim CKF_SIGN, CKF_VERIFY, CKF_ENCRYPT
// and CKF_DECRYPT, and then perform PKCS#1 v1.5 instead of the raw RSA §6.1.12
// defines.
//
// The substitution was undetectable from the application's side. C_Sign
// returned CKR_OK, and recovering s^e mod n from the signature yielded
// 00 01 FF..FF 00 || M rather than M -- so no conformant verifier accepted it
// and nothing anywhere said why. The cause is structural rather than a missing
// case: this token reaches its keys through crypto.Signer and crypto.Decrypter,
// which have no raw-primitive form, and a key in a TPM, an HSM or a cloud KMS
// could not expose one even in principle.
//
// So the mechanism carries CKF_VERIFY_RECOVER and nothing else. That direction
// is real -- s^e mod n computed locally from a public key, returned unprocessed
// -- and it is the only direction this token can honour.
//
// The refusals are asserted through the Module entry points rather than through
// CryptoManager, because that is where C_VerifyInit and C_VerifyRecoverInit
// become distinguishable: they share one constructor, which admits either verify
// flag, and only the Module layer knows which verb the application called.
func TestRSAX509RefusesTheOperationsItCannotPerform(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)

	// An RSA public key object, so the refusal under test is the mechanism and
	// not a missing or unusable key.
	keyHandle, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_PUBLIC_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_RSA)),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewBoolAttribute(CKA_SIGN, true),
		NewBoolAttribute(CKA_VERIFY, true),
		NewBoolAttribute(CKA_VERIFY_RECOVER, true),
		NewBoolAttribute(CKA_ENCRYPT, true),
		NewBoolAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_MODULUS, make([]byte, 256)),
		NewAttribute(CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
	})
	require.Equal(t, CKR_OK, rv)

	refusals := []struct {
		name string
		init func() CK_RV
	}{
		{"C_SignInit", func() CK_RV {
			return m.SignInit(session, &Mechanism{Type: CKM_RSA_X_509}, keyHandle)
		}},
		{"C_VerifyInit", func() CK_RV {
			return m.VerifyInit(session, &Mechanism{Type: CKM_RSA_X_509}, keyHandle)
		}},
		{"C_EncryptInit", func() CK_RV {
			return m.EncryptInit(session, &Mechanism{Type: CKM_RSA_X_509}, keyHandle)
		}},
		{"C_DecryptInit", func() CK_RV {
			return m.DecryptInit(session, &Mechanism{Type: CKM_RSA_X_509}, keyHandle)
		}},
	}

	for _, r := range refusals {
		t.Run(r.name, func(t *testing.T) {
			if rv := r.init(); rv != CKR_MECHANISM_INVALID {
				t.Fatalf("%s answered %s for CKM_RSA_X_509, want CKR_MECHANISM_INVALID; "+
					"this token cannot perform raw RSA in that direction and would "+
					"substitute PKCS#1 v1.5 under CKR_OK", r.name, rv)
			}
		})
	}

	// The capability that IS real must still be reachable, or the refusals above
	// would be satisfied by deleting the mechanism outright.
	t.Run("C_VerifyRecoverInit is still accepted", func(t *testing.T) {
		if rv := m.VerifyRecoverInit(session, &Mechanism{Type: CKM_RSA_X_509}, keyHandle); rv != CKR_OK {
			t.Fatalf("C_VerifyRecoverInit answered %s for CKM_RSA_X_509, want CKR_OK; "+
				"verify-recover is the one direction this token performs correctly", rv)
		}
	})
}
