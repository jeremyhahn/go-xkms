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

package oath

import (
	"bytes"
	"crypto/fips140"
	"encoding/base32"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
)

// The tests here run against the process's real FIPS mode. Under
// GODEBUG=fips140=only each one asserts the typed refusal and then re-runs
// itself under fips140=off to prove the round trip (fipstest).

func sha1Credential(t *testing.T) *Credential {
	t.Helper()

	return withSecret(&Credential{
		Name:      "acme",
		Type:      TypeTOTP,
		Algorithm: AlgorithmSHA1,
		Digits:    DefaultDigits,
		Period:    DefaultPeriod,
	}, "JBSWY3DPEHPK3PXP")
}

// Under GODEBUG=fips140=only, crypto/hmac rejects SHA-1 by PANICKING. Every
// default TOTP generation and validation in a FIPS deployment was therefore a
// process kill on a path a user drives, not a failure it could report (#22).
//
// The refusal must be an error, and it must happen BEFORE hmac.New. Outside
// that mode SHA-1 is the RFC 6238 default and what every enrolled credential
// in the field uses, so it must still produce codes.
//
// Refused at CONSTRUCTION: NewGenerator validates, and Validate applies the
// FIPS policy so the failure lands at enrolment rather than on every later use.
func TestNewGenerator_SHA1(t *testing.T) {
	g, err := NewGenerator(sha1Credential(t))
	if !fipstest.OutsideFIPSAfterRefusal(t, err, ErrAlgorithmNotFIPSApproved) {
		return
	}
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	code, err := g.GenerateCounter(0)
	if err != nil {
		t.Fatalf("SHA-1 TOTP refused outside FIPS mode: %v", err)
	}
	if len(code) != DefaultDigits {
		t.Fatalf("code = %q, want %d digits", code, DefaultDigits)
	}
}

// And still refused at GENERATION, for data that predates the policy: a
// credential already on disk reaches a Generator without passing through
// Validate on the read path, and must not be able to generate.
func TestGenerateCounter_SHA1(t *testing.T) {
	cred := sha1Credential(t)
	withSecret(cred, longFIPSSecret)

	code, err := (&Generator{cred: cred}).GenerateCounter(0)
	if err != nil && code != "" {
		t.Errorf("a refused generation returned a code: %q", code)
	}
	if !fipstest.OutsideFIPSAfterRefusal(t, err, ErrAlgorithmNotFIPSApproved) {
		return
	}
	if err != nil {
		t.Fatalf("SHA-1 TOTP refused outside FIPS mode: %v", err)
	}
	if len(code) != DefaultDigits {
		t.Fatalf("code = %q, want %d digits", code, DefaultDigits)
	}
}

// A credential that can be created but never used is a broken contract: the
// public API reported success and every later Generate fails. Enrolment must
// refuse under FIPS, and accept outside it.
func TestCredential_SHA1Enrolment(t *testing.T) {
	err := sha1Credential(t).Validate()
	if !fipstest.OutsideFIPSAfterRefusal(t, err, ErrAlgorithmNotFIPSApproved) {
		return
	}
	if err != nil {
		t.Fatalf("SHA-1 credential refused outside FIPS mode: %v", err)
	}
}

// An imported SHA-1 credential parses -- the URI is well-formed and ParseURI's
// job is to report what it says -- and is refused when stored under FIPS.
func TestParseURI_SHA1ImportEnrolment(t *testing.T) {
	uri := "otpauth://totp/ACME:user@example.com?secret=" + longFIPSSecret + "&algorithm=SHA1"
	cred, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	err = cred.Validate()
	if !fipstest.OutsideFIPSAfterRefusal(t, err, ErrAlgorithmNotFIPSApproved) {
		return
	}
	if err != nil {
		t.Fatalf("an imported SHA-1 credential was refused outside FIPS mode: %v", err)
	}
}

// A newly GENERATED credential is the one case where choosing the algorithm is
// ours to make: NewCredential generates the secret, so no issuer has already
// decided. Under FIPS it must produce something usable rather than something
// that validates today and fails on first use. Outside FIPS the default is
// untouched -- changing it is a product decision (#22 option 2) that breaks
// every already-enrolled credential.
func TestNewCredential_AlgorithmFollowsFIPSMode(t *testing.T) {
	want := AlgorithmSHA1
	if fips140.Enforced() {
		want = AlgorithmSHA256
	}

	cred, err := NewCredential("acme", "ACME", TypeTOTP)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	if cred.Algorithm != want {
		t.Fatalf("Algorithm = %q, want %q (fips140.Enforced = %v)", cred.Algorithm, want, fips140.Enforced())
	}
	if err := cred.Validate(); err != nil {
		t.Fatalf("NewCredential produced a credential its own Validate refuses: %v", err)
	}
	// Usable, not merely valid.
	g, err := NewGenerator(cred)
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	if _, err := g.GenerateCounter(0); err != nil {
		t.Fatalf("a credential created under FIPS could not generate: %v", err)
	}
}

// The gate is scoped to SHA-1. Refusing an approved algorithm under FIPS would
// be the opposite failure — a compliance control that breaks compliant
// deployments — so both approved hashes must keep working in every mode.
func TestGenerator_ApprovedAlgorithmsUnaffectedByFIPS(t *testing.T) {
	for _, alg := range []string{AlgorithmSHA256, AlgorithmSHA512} {
		t.Run(alg, func(t *testing.T) {
			// The RFC 4226 secret is 160 bits; the 80-bit sha1Credential
			// secret is under the 112-bit HMAC key floor that strict FIPS
			// mode enforces on every hash, approved or not.
			cred := withSecret(&Credential{
				Name:      "acme",
				Type:      TypeTOTP,
				Algorithm: alg,
				Digits:    DefaultDigits,
				Period:    DefaultPeriod,
			}, rfcTestSecret)

			g, err := NewGenerator(cred)
			if err != nil {
				t.Fatalf("NewGenerator: %v", err)
			}
			code, err := g.GenerateCounter(0)
			if err != nil {
				t.Fatalf("%s refused under FIPS mode: %v", alg, err)
			}
			if len(code) != DefaultDigits {
				t.Fatalf("code = %q, want %d digits", code, DefaultDigits)
			}
		})
	}
}

// DefaultAlgorithm stays SHA-1 deliberately. Changing it is a product decision
// (#22 option 2) that silently breaks every already-enrolled credential, and
// this PR is explicitly not making it. If someone changes it, this fails and
// they are pointed at the issue rather than discovering the breakage in the
// field.
func TestDefaultAlgorithmIsStillSHA1(t *testing.T) {
	if DefaultAlgorithm != AlgorithmSHA1 {
		t.Fatalf("DefaultAlgorithm = %q, want %q -- changing it breaks every "+
			"enrolled credential and is a product decision (#22 option 2)",
			DefaultAlgorithm, AlgorithmSHA1)
	}
}

// The refusal must happen BEFORE the secret is decoded, so a rejected request
// never materializes the key in the clear (protected-memory rule; raised in
// review on PR #76).
//
// "Did it decode?" is not directly observable, so this asks a question whose
// answer differs depending on the order: the credential carries a secret that
// CANNOT be Base32-decoded. Gate first yields ErrAlgorithmNotFIPSApproved;
// decode first yields ErrInvalidSecret. The error that comes back names which
// line ran, and no assertion about internal state is needed.
//
// Outside FIPS there is no gate, so the same credential reports the bad
// secret -- which also proves the fixture really cannot be decoded.
func TestGenerator_FIPSRefusalPrecedesSecretDecode(t *testing.T) {
	cred := sha1Credential(t)
	withSecret(cred, "1811!!!!not-base32!!!!")

	g := &Generator{cred: cred}

	_, err := g.GenerateCounter(0)
	if fips140.Enforced() && errors.Is(err, ErrInvalidSecret) {
		t.Fatal("the secret was decoded before the FIPS gate: a refused request " +
			"must not put plaintext key material on the heap")
	}
	if !fipstest.OutsideFIPSAfterRefusal(t, err, ErrAlgorithmNotFIPSApproved) {
		return
	}
	if !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("error = %v, want ErrInvalidSecret outside FIPS", err)
	}
}

// The ordering above must not swallow a genuinely bad secret when the
// algorithm IS permitted -- otherwise "gate first" would have turned a decode
// error into silence.
func TestGenerator_InvalidSecretStillReportedForApprovedAlgorithm(t *testing.T) {
	cred := sha1Credential(t)
	cred.Algorithm = AlgorithmSHA256
	withSecret(cred, "1811!!!!not-base32!!!!")

	g := &Generator{cred: cred}

	if _, err := g.GenerateCounter(0); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("error = %v, want ErrInvalidSecret", err)
	}
}

// The tests above assert the gate one entry point at a time. This one proves
// no panic is reachable past it, by running every short-key and SHA-1 path in
// a subprocess under GODEBUG=fips140=only -- the only configuration where
// crypto/hmac actually enforces its rules -- so a plain run covers it too.
//
// Two distinct panics live behind that setting, and passing the first says
// nothing about the second:
//
//	SHA-1, any key length   -> refused by algorithm
//	any hash, key < 112 bits -> refused by key length
//
// The 16-character Base32 secret in every TOTP worked example decodes to 10
// bytes, so the second is reachable with an entirely ordinary SHA-256
// credential (raised in review on PR #76).
func TestGenerator_NoPanicUnderStrictFIPS(t *testing.T) {
	if os.Getenv(strictFIPSChildEnv) == "1" {
		strictFIPSChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestGenerator_NoPanicUnderStrictFIPS", "-test.v")
	cmd.Env = append(os.Environ(), strictFIPSChildEnv+"=1", "GODEBUG=fips140=only")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the generator did not survive GODEBUG=fips140=only: %v\n%s", err, out)
	}
	if bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("panic under GODEBUG=fips140=only:\n%s", out)
	}
}

const strictFIPSChildEnv = "OATH_STRICT_FIPS_CHILD"

// strictFIPSChild runs inside the GODEBUG=fips140=only subprocess. Every case
// here must return an ERROR; any panic fails the parent.
func strictFIPSChild(t *testing.T) {
	t.Helper()

	if !fipsMode() {
		t.Fatal("GODEBUG=fips140=only did not put the child in FIPS mode; " +
			"the subprocess proves nothing")
	}

	// Short secret (10 bytes) with an APPROVED hash: the algorithm gate lets
	// this through, so only the length check stands between it and a panic.
	short := sha1Credential(t)
	short.Algorithm = AlgorithmSHA256
	if _, err := (&Generator{cred: short}).GenerateCounter(0); !errors.Is(err, ErrSecretTooShortForFIPS) {
		t.Fatalf("short SHA-256 secret: error = %v, want ErrSecretTooShortForFIPS", err)
	}

	// SHA-1 with a long secret: refused by algorithm, not by length.
	long := sha1Credential(t)
	withSecret(long, longFIPSSecret)
	if _, err := (&Generator{cred: long}).GenerateCounter(0); !errors.Is(err, ErrAlgorithmNotFIPSApproved) {
		t.Fatalf("SHA-1 with a long secret: error = %v, want ErrAlgorithmNotFIPSApproved", err)
	}

	// A SHORT secret with an approved hash must be refused at ENROLMENT, not
	// deferred to first use. The length check used to live only in
	// GenerateCounter, so Validate, NewGenerator and store Add all accepted a
	// 10-byte SHA-256 credential that could never generate a code -- the same
	// "created but guaranteed to fail" defect the algorithm gate closed, in
	// the other dimension.
	shortApproved := sha1Credential(t)
	shortApproved.Algorithm = AlgorithmSHA256

	if err := shortApproved.Validate(); !errors.Is(err, ErrSecretTooShortForFIPS) {
		t.Fatalf("Validate on a short SHA-256 secret: error = %v, want ErrSecretTooShortForFIPS", err)
	}
	if _, err := NewGenerator(shortApproved); !errors.Is(err, ErrSecretTooShortForFIPS) {
		t.Fatalf("NewGenerator on a short SHA-256 secret: error = %v, want ErrSecretTooShortForFIPS", err)
	}
	shortStore := NewMemoryStore()
	if err := shortStore.Add(shortApproved); !errors.Is(err, ErrSecretTooShortForFIPS) {
		t.Fatalf("Add of a short SHA-256 secret: error = %v, want ErrSecretTooShortForFIPS", err)
	}
	if creds, err := shortStore.List(); err != nil || len(creds) != 0 {
		t.Fatalf("a refused short credential was stored anyway (%d present, err=%v)", len(creds), err)
	}

	// The length gate must measure the SECRET, not the string it is written
	// in. normalizeSecretBytes strips grouping separators, whitespace and padding,
	// so the raw string's length is not the key's length -- and the gap is
	// chosen by whoever supplies the credential.
	//
	// Measuring the raw string made this fail OPEN. A 12-byte secret is 20
	// Base32 characters; written "MFRGG-ZDFMZ-TWQ2L-KNNWA" it is 23, and
	// DecodedLen(23) is 14 -- exactly the minimum the real key misses by two
	// bytes. That is the form a human is most likely to type, since grouping
	// separators are the reason normalizeSecretBytes exists. Raised in review on
	// PR #76 and reproduced before fixing: Validate returned nil for it.
	//
	// Asserted HERE because the gate is only active under
	// GODEBUG=fips140=only, so this child is where a plain run reaches it.
	undersized := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString([]byte("abcdefghijkl")) // 12 bytes -> 20 chars
	for _, spelling := range []struct{ name, secret string }{
		{"hyphens", undersized[:5] + "-" + undersized[5:10] + "-" + undersized[10:15] + "-" + undersized[15:]},
		{"spaces", undersized[:4] + " " + undersized[4:8] + " " + undersized[8:12] + " " + undersized[12:]},
		{"underscores", undersized[:5] + "_" + undersized[5:10] + "_" + undersized[10:15] + "_" + undersized[15:]},
		{"base32 padding", undersized + "===="},
	} {
		// The spelling must actually clear the gate arithmetically, or the
		// case would pass for the wrong reason -- there would be nothing to
		// bypass.
		if got := base32.StdEncoding.WithPadding(base32.NoPadding).DecodedLen(len(spelling.secret)); got < fipsMinSecretBytes {
			t.Fatalf("%s: fixture does not inflate past the gate (DecodedLen = %d, need >= %d), "+
				"so this case cannot discriminate", spelling.name, got, fipsMinSecretBytes)
		}

		inflated := sha1Credential(t)
		inflated.Algorithm = AlgorithmSHA256 // keep the algorithm gate out of it
		withSecret(inflated, spelling.secret)

		if err := inflated.Validate(); !errors.Is(err, ErrSecretTooShortForFIPS) {
			t.Fatalf("%s: Validate = %v, want ErrSecretTooShortForFIPS -- a 12-byte secret "+
				"written as %d characters cleared the FIPS key-length gate",
				spelling.name, err, len(spelling.secret))
		}
		// And through a store write, since that is how a caller reaches it.
		inflatedStore := NewMemoryStore()
		if err := inflatedStore.Add(inflated); !errors.Is(err, ErrSecretTooShortForFIPS) {
			t.Fatalf("%s: Add = %v, want ErrSecretTooShortForFIPS", spelling.name, err)
		}
		if creds, err := inflatedStore.List(); err != nil || len(creds) != 0 {
			t.Fatalf("%s: a refused credential was stored anyway (%d present, err=%v)",
				spelling.name, len(creds), err)
		}
	}

	// A separated secret that is genuinely long enough must still be ACCEPTED
	// -- the fix must reject short keys, not every key containing a separator.
	separatedLong := sha1Credential(t)
	separatedLong.Algorithm = AlgorithmSHA256
	withSecret(separatedLong, longFIPSSecret[:8]+"-"+longFIPSSecret[8:16]+" "+longFIPSSecret[16:])
	if _, err := (&Generator{cred: separatedLong}).GenerateCounter(0); err != nil {
		t.Fatalf("a long secret written with separators was refused under FIPS: %v", err)
	}

	// The permitted combination must still WORK under strict FIPS -- a gate
	// that refuses everything would pass every assertion above and be useless.
	ok := sha1Credential(t)
	ok.Algorithm = AlgorithmSHA256
	withSecret(ok, longFIPSSecret)
	code, err := (&Generator{cred: ok}).GenerateCounter(0)
	if err != nil {
		t.Fatalf("approved algorithm with a long secret was refused under FIPS: %v", err)
	}
	if len(code) != DefaultDigits {
		t.Fatalf("code = %q, want %d digits", code, DefaultDigits)
	}
}

// longFIPSSecret is 20 bytes decoded, the RFC 4226 recommended length.
const longFIPSSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// Enrolment is refused through a STORE, not just through Validate.
//
// Validate is the gate, but a caller reaches it via Add/Update on whichever
// store the deployment uses, and "the policy is applied somewhere" is not the
// same claim as "the credential cannot be persisted". This pins the second:
// under FIPS a SHA-1 credential cannot enter the store, so it can never be
// read back and fail at generation time -- which was the contract defect
// raised on PR #76.
//
// The read paths stay open on purpose. A deployment that turns FIPS on with
// SHA-1 credentials already stored must still be able to list and delete them;
// refusing there would strand the data with no way to clear it.
//
// Outside FIPS the same import must still work: SHA-1 is the RFC 6238 default
// and what essentially every credential in the field was enrolled with.
func TestStore_SHA1Enrolment(t *testing.T) {
	store := NewMemoryStore()

	sha1Cred := sha1Credential(t)
	withSecret(sha1Cred, longFIPSSecret)
	err := store.Add(sha1Cred)
	if err != nil {
		// Nothing was persisted, so nothing can be read back and fail later.
		if creds, listErr := store.List(); listErr != nil {
			t.Fatalf("List: %v", listErr)
		} else if len(creds) != 0 {
			t.Fatalf("a refused credential was stored anyway: %d present", len(creds))
		}

		// The approved equivalent still enrols, or the gate is refusing
		// everything.
		approved := sha1Credential(t)
		approved.Algorithm = AlgorithmSHA256
		withSecret(approved, longFIPSSecret)
		approved.Name = "approved"
		approved.ID = "approved"
		if addErr := store.Add(approved); addErr != nil {
			t.Fatalf("an approved credential was refused under FIPS: %v", addErr)
		}
	}
	if !fipstest.OutsideFIPSAfterRefusal(t, err, ErrAlgorithmNotFIPSApproved) {
		return
	}
	if err != nil {
		t.Fatalf("SHA-1 credential refused outside FIPS mode: %v", err)
	}
}

// Update is a write path too, and it was the one store method that did not
// validate. Under FIPS a caller could enrol an approved SHA-256 credential and
// then update the same ID to SHA-1, and it was stored -- which defeats the
// enrolment gate entirely, since anything refused at Add could be introduced
// by Update instead. Outside FIPS the same update is allowed, so the gate
// withdraws nothing from a normal deployment.
func TestStore_SHA1Update(t *testing.T) {
	store := NewMemoryStore()

	approved := sha1Credential(t)
	approved.Algorithm = AlgorithmSHA256
	withSecret(approved, longFIPSSecret)
	if err := store.Add(approved); err != nil {
		t.Fatalf("Add of an approved credential: %v", err)
	}

	downgrade := sha1Credential(t)
	downgrade.ID = approved.ID
	downgrade.Name = approved.Name
	withSecret(downgrade, longFIPSSecret)
	err := store.Update(downgrade)

	stored, getErr := store.Get(approved.ID)
	if getErr != nil {
		t.Fatalf("Get after Update: %v", getErr)
	}
	// A refused update must leave the stored credential UNCHANGED -- one that
	// mutated the store anyway would be worse than one that succeeded.
	if err != nil && stored.Algorithm != AlgorithmSHA256 {
		t.Fatalf("stored algorithm = %q after a refused update, want %q",
			stored.Algorithm, AlgorithmSHA256)
	}
	if !fipstest.OutsideFIPSAfterRefusal(t, err, ErrAlgorithmNotFIPSApproved) {
		return
	}
	if err != nil {
		t.Fatalf("SHA-1 update refused outside FIPS mode: %v", err)
	}
	if stored.Algorithm != AlgorithmSHA1 {
		t.Fatalf("stored algorithm = %q after the update, want %q", stored.Algorithm, AlgorithmSHA1)
	}
}

// Validate and GenerateCounter must agree on what a credential's secret IS.
//
// They did not. Validate canonicalises before checking, so a secret written
// with grouping separators was accepted; GenerateCounter decoded the stored
// string with only strings.ToUpper applied and failed on the separators. A
// credential could be enrolled successfully and then be unable to produce a
// single code -- the same "created but can never generate" defect the FIPS
// gates exist to prevent, reached by a different route.
func TestGenerator_AcceptsAnySecretValidateAccepts(t *testing.T) {
	// 20 bytes, comfortably over any minimum, written with separators.
	raw := []byte("abcdefghijklmnopqrst")
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	separated := encoded[:8] + "-" + encoded[8:16] + " " + encoded[16:]

	cred := sha1Credential(t)
	cred.Algorithm = AlgorithmSHA256
	withSecret(cred, separated)

	if err := cred.Validate(); err != nil {
		t.Fatalf("Validate() rejected the separated secret (%v); this case is about "+
			"a secret Validate ACCEPTS", err)
	}

	got, err := (&Generator{cred: cred}).GenerateCounter(0)
	if err != nil {
		t.Fatalf("GenerateCounter() = %v on a secret Validate accepted: enrolment "+
			"and generation disagree about what this credential's secret is", err)
	}

	// And it must be the code the canonical secret produces, not merely "a"
	// code -- a canonicalisation that changed the key would still return here.
	canonical := sha1Credential(t)
	canonical.Algorithm = AlgorithmSHA256
	withSecret(canonical, encoded)
	want, err := (&Generator{cred: canonical}).GenerateCounter(0)
	if err != nil {
		t.Fatalf("GenerateCounter() on the canonical secret = %v", err)
	}
	if got != want {
		t.Fatalf("code from the separated secret = %s, from the canonical secret = %s; "+
			"canonicalisation changed the derived key", got, want)
	}
}
