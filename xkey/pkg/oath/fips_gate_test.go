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
	"encoding/base32"
	"errors"
	"os"
	"os/exec"
	"testing"
)

// withFIPSMode drives the gate from both sides. Running the suite twice under
// different environments is the alternative, and no CI job here does that — an
// ungated branch is one nobody ever executes.
func withFIPSMode(t *testing.T, on bool) {
	t.Helper()

	original := fipsMode
	t.Cleanup(func() { fipsMode = original })
	fipsMode = func() bool { return on }
}

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
// The refusal must be an error, and it must happen BEFORE hmac.New.
func TestGenerator_SHA1RefusedUnderFIPS(t *testing.T) {
	withFIPSMode(t, true)

	// Refused at CONSTRUCTION now: NewGenerator validates, and Validate
	// applies the FIPS policy so the failure lands at enrolment rather than on
	// every later use.
	if _, err := NewGenerator(sha1Credential(t)); !errors.Is(err, ErrAlgorithmNotFIPSApproved) {
		t.Fatalf("NewGenerator error = %v, want ErrAlgorithmNotFIPSApproved", err)
	}

	// And still refused at GENERATION, for data that predates the policy: a
	// credential already on disk reaches a Generator without passing through
	// Validate on the read path, and must not be able to generate.
	code, err := (&Generator{cred: sha1Credential(t)}).GenerateCounter(0)
	if err == nil {
		t.Fatalf("SHA-1 TOTP was generated under FIPS mode: %q", code)
	}
	if !errors.Is(err, ErrAlgorithmNotFIPSApproved) {
		t.Fatalf("error = %v, want ErrAlgorithmNotFIPSApproved", err)
	}
	if code != "" {
		t.Errorf("a refused generation returned a code: %q", code)
	}
}

// A credential that can be created but never used is a broken contract: the
// public API reported success and every later Generate fails. Enrolment must
// refuse under FIPS -- through every door into a store, since Add and Update
// both validate.
func TestCredential_SHA1RefusedAtEnrolmentUnderFIPS(t *testing.T) {
	withFIPSMode(t, true)

	if err := sha1Credential(t).Validate(); !errors.Is(err, ErrAlgorithmNotFIPSApproved) {
		t.Fatalf("Validate error = %v, want ErrAlgorithmNotFIPSApproved", err)
	}

	// An imported SHA-1 credential parses -- the URI is well-formed and
	// ParseURI's job is to report what it says -- and is refused when stored.
	uri := "otpauth://totp/ACME:user@example.com?secret=" + longFIPSSecret + "&algorithm=SHA1"
	cred, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if err := cred.Validate(); !errors.Is(err, ErrAlgorithmNotFIPSApproved) {
		t.Fatalf("an imported SHA-1 credential was accepted for storage: %v", err)
	}
}

// The mirror: outside FIPS none of this withdraws anything. SHA-1 is the RFC
// 6238 default and what every enrolled credential in the field uses.
func TestCredential_SHA1StillEnrolsOutsideFIPS(t *testing.T) {
	withFIPSMode(t, false)

	if err := sha1Credential(t).Validate(); err != nil {
		t.Fatalf("SHA-1 credential refused outside FIPS mode: %v", err)
	}
}

// A newly GENERATED credential is the one case where choosing the algorithm is
// ours to make: NewCredential generates the secret, so no issuer has already
// decided. Under FIPS it must produce something usable rather than something
// that validates today and fails on first use.
func TestNewCredential_UsesAnApprovedAlgorithmUnderFIPS(t *testing.T) {
	withFIPSMode(t, true)

	cred, err := NewCredential("acme", "ACME", TypeTOTP)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	if cred.Algorithm != AlgorithmSHA256 {
		t.Fatalf("Algorithm = %q, want %q under FIPS", cred.Algorithm, AlgorithmSHA256)
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

// And outside FIPS the default is untouched -- changing it is a product
// decision (#22 option 2) that breaks every already-enrolled credential.
func TestNewCredential_KeepsSHA1OutsideFIPS(t *testing.T) {
	withFIPSMode(t, false)

	cred, err := NewCredential("acme", "ACME", TypeTOTP)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	if cred.Algorithm != AlgorithmSHA1 {
		t.Fatalf("Algorithm = %q, want %q outside FIPS", cred.Algorithm, AlgorithmSHA1)
	}
}

// The mirror, and the more important half: this must withdraw NOTHING from a
// normal deployment. RFC 6238 and every mainstream authenticator assume SHA-1,
// and an enrolled credential only keeps working with the algorithm it was
// enrolled under — so outside FIPS mode the default must still produce codes.
func TestGenerator_SHA1StillWorksOutsideFIPS(t *testing.T) {
	withFIPSMode(t, false)

	g, err := NewGenerator(sha1Credential(t))
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

// The gate is scoped to SHA-1. Refusing an approved algorithm under FIPS would
// be the opposite failure — a compliance control that breaks compliant
// deployments — so both approved hashes must keep working with FIPS on.
func TestGenerator_ApprovedAlgorithmsUnaffectedByFIPS(t *testing.T) {
	withFIPSMode(t, true)

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
func TestGenerator_FIPSRefusalPrecedesSecretDecode(t *testing.T) {
	withFIPSMode(t, true)

	cred := sha1Credential(t)
	withSecret(cred, "1811!!!!not-base32!!!!")

	g := &Generator{cred: cred}

	_, err := g.GenerateCounter(0)
	if errors.Is(err, ErrInvalidSecret) {
		t.Fatal("the secret was decoded before the FIPS gate: a refused request " +
			"must not put plaintext key material on the heap")
	}
	if !errors.Is(err, ErrAlgorithmNotFIPSApproved) {
		t.Fatalf("error = %v, want ErrAlgorithmNotFIPSApproved", err)
	}
}

// The ordering above must not swallow a genuinely bad secret when the
// algorithm IS permitted -- otherwise "gate first" would have turned a decode
// error into silence.
func TestGenerator_InvalidSecretStillReportedForApprovedAlgorithm(t *testing.T) {
	withFIPSMode(t, true)

	cred := sha1Credential(t)
	cred.Algorithm = AlgorithmSHA256
	withSecret(cred, "1811!!!!not-base32!!!!")

	g := &Generator{cred: cred}

	if _, err := g.GenerateCounter(0); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("error = %v, want ErrInvalidSecret", err)
	}
}

// The tests above drive fipsMode through a stub, which proves the GATE but not
// that the gate is in the right PLACE: a stub never invokes the standard
// library's own FIPS enforcement, so a panic reachable past the gate stays
// invisible. This one runs the real thing in a subprocess under
// GODEBUG=fips140=only, which is the only configuration where crypto/hmac
// actually enforces its rules.
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
	// Asserted HERE rather than in a stubbed test because the gate is
	// conditioned on shortHMACKeysRefused(), which is only true under
	// GODEBUG=fips140=only. A version of this case outside the child skips,
	// and a skipping test defends nothing.
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
func TestStore_RefusesSHA1EnrolmentUnderFIPS(t *testing.T) {
	withFIPSMode(t, true)

	store := NewMemoryStore()

	sha1Cred := sha1Credential(t)
	withSecret(sha1Cred, longFIPSSecret)
	if err := store.Add(sha1Cred); !errors.Is(err, ErrAlgorithmNotFIPSApproved) {
		t.Fatalf("Add error = %v, want ErrAlgorithmNotFIPSApproved", err)
	}

	// Nothing was persisted, so nothing can be read back and fail later.
	if creds, err := store.List(); err != nil {
		t.Fatalf("List: %v", err)
	} else if len(creds) != 0 {
		t.Fatalf("a refused credential was stored anyway: %d present", len(creds))
	}

	// The approved equivalent still enrols, or the gate is refusing everything.
	approved := sha1Credential(t)
	approved.Algorithm = AlgorithmSHA256
	withSecret(approved, longFIPSSecret)
	approved.Name = "approved"
	approved.ID = "approved"
	if err := store.Add(approved); err != nil {
		t.Fatalf("an approved credential was refused under FIPS: %v", err)
	}
}

// Outside FIPS the same import must still work: SHA-1 is the RFC 6238 default
// and what essentially every credential in the field was enrolled with.
func TestStore_AcceptsSHA1EnrolmentOutsideFIPS(t *testing.T) {
	withFIPSMode(t, false)

	store := NewMemoryStore()
	if err := store.Add(sha1Credential(t)); err != nil {
		t.Fatalf("SHA-1 credential refused outside FIPS mode: %v", err)
	}
}

// Update is a write path too, and it was the one store method that did not
// validate. Under FIPS a caller could enrol an approved SHA-256 credential and
// then update the same ID to SHA-1, and it was stored -- which defeats the
// enrolment gate entirely, since anything refused at Add could be introduced
// by Update instead.
func TestStore_RefusesSHA1UpdateUnderFIPS(t *testing.T) {
	withFIPSMode(t, true)

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
	if err := store.Update(downgrade); !errors.Is(err, ErrAlgorithmNotFIPSApproved) {
		t.Fatalf("Update to SHA-1 under FIPS: error = %v, want ErrAlgorithmNotFIPSApproved", err)
	}

	// And the stored credential must be UNCHANGED -- a refused update that
	// mutated the store anyway would be worse than one that succeeded.
	stored, err := store.Get(approved.ID)
	if err != nil {
		t.Fatalf("Get after a refused update: %v", err)
	}
	if stored.Algorithm != AlgorithmSHA256 {
		t.Fatalf("stored algorithm = %q after a refused update, want %q",
			stored.Algorithm, AlgorithmSHA256)
	}
}

// Outside FIPS the same update is allowed, so the gate withdraws nothing from
// a normal deployment.
func TestStore_AllowsSHA1UpdateOutsideFIPS(t *testing.T) {
	withFIPSMode(t, false)

	store := NewMemoryStore()
	cred := sha1Credential(t)
	if err := store.Add(cred); err != nil {
		t.Fatalf("Add: %v", err)
	}

	updated := sha1Credential(t)
	updated.ID = cred.ID
	updated.Name = cred.Name
	updated.Digits = 8
	if err := store.Update(updated); err != nil {
		t.Fatalf("SHA-1 update refused outside FIPS mode: %v", err)
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
	withFIPSMode(t, false)

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
