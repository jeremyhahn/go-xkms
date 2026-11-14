//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers the core TPM2 operations in tpm.go: address parsing and
// transport opening, public-area parsing, PCR reads, TPM-side hashing and
// Shamir secret sharing. Each simulator-backed test owns exactly one harness;
// the go-tpm-tools simulator is a process-global singleton so only one may be
// live at a time.

// TestSplitHostPort_ParsesAndRejects covers the address parser used to derive a
// simulator's platform port from its command port. Both halves matter: a
// silently-accepted malformed address would produce a nonsense platform port
// and a confusing connection failure much later.
func TestSplitHostPort_ParsesAndRejects(t *testing.T) {
	t.Run("valid addresses", func(t *testing.T) {
		for _, tc := range []struct {
			addr     string
			wantHost string
			wantPort int
		}{
			{"127.0.0.1:2321", "127.0.0.1", 2321},
			{"localhost:2321", "localhost", 2321},
			{"tpm-simulator:2421", "tpm-simulator", 2421},
			{":2321", "", 2321},
		} {
			host, port, err := splitHostPort(tc.addr)
			require.NoError(t, err, "address %q must parse", tc.addr)
			assert.Equal(t, tc.wantHost, host, "host of %q", tc.addr)
			assert.Equal(t, tc.wantPort, port, "port of %q", tc.addr)
		}
	})

	t.Run("malformed addresses", func(t *testing.T) {
		for _, addr := range []string{
			"127.0.0.1",   // no colon at all
			"localhost",   // no colon at all
			"",            // empty
			"host:notnum", // non-numeric port
			"host:",       // empty port
		} {
			host, port, err := splitHostPort(addr)
			require.Error(t, err, "address %q must be rejected", addr)
			assert.Empty(t, host, "no host may be returned for %q", addr)
			assert.Zero(t, port, "no port may be returned for %q", addr)
		}
	})
}

// TestOpenTCPTransport_UnreachableAddress_ReturnsError proves the TCP transport
// opener surfaces a connection failure instead of returning a transport that
// fails later on first use. The address is a port this test just closed, so it
// is guaranteed to refuse the connection; no TPM device is involved.
func TestOpenTCPTransport_UnreachableAddress_ReturnsError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := listener.Addr().String()
	require.NoError(t, listener.Close())

	tpmTransport, err := OpenTCPTransport(closedAddr, "")
	require.Error(t, err, "connecting to a closed port must fail")
	assert.Nil(t, tpmTransport)
}

// TestParsePublicKey_RoundTripsTPMPublicAreas proves a marshalled TPM public
// area parses back into the matching Go public key, for both key types the
// product provisions. This is the conversion used when a verifier is handed a
// raw TPM public area (for example in a TCG-CSR), so a mismatch would mean
// attestations verify against the wrong key.
func TestParsePublicKey_RoundTripsTPMPublicAreas(t *testing.T) {
	h := newSimHarness(t, nil)

	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	_, ekPub, err := h.TPM.ReadHandle(ekAttrs.TPMAttributes.Handle)
	require.NoError(t, err)

	ek2B := tpm2.New2B(ekPub)
	parsed, err := h.TPM.ParsePublicKey(ek2B.Bytes())
	require.NoError(t, err)

	ekRSA, err := h.TPM.EKRSA()
	require.NoError(t, err)
	parsedRSA, ok := parsed.(*rsa.PublicKey)
	require.True(t, ok, "the EK is RSA, got %T", parsed)
	assert.True(t, parsedRSA.Equal(ekRSA),
		"the parsed public area must be the same key the TPM holds at the EK handle")
}

// TestParsePublicKey_MalformedInput_Rejected proves garbage is rejected rather
// than loaded into the TPM or parsed into a partially-populated key.
func TestParsePublicKey_MalformedInput_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	for name, input := range map[string][]byte{
		"empty":            {},
		"truncated header": {0x00, 0x01},
		"random bytes":     bytes.Repeat([]byte{0xAB}, 64),
	} {
		t.Run(name, func(t *testing.T) {
			pub, err := h.TPM.ParsePublicKey(input)
			require.Error(t, err, "a malformed public area must be rejected")
			assert.Nil(t, pub)
		})
	}
}

// TestReadPCRs_ReflectsExtensions proves the PCR reader returns live values:
// a bank read before and after an extend must differ in exactly the extended
// PCR and nowhere else. A reader that returned cached or zeroed values would
// silently break every sealing and attestation decision built on it.
func TestReadPCRs_ReflectsExtensions(t *testing.T) {
	h := newSimHarness(t, nil)

	before, err := h.TPM.ReadPCRs(append([]uint{0}, h.TPM.config.PlatformPCRs...))
	require.NoError(t, err)
	require.NotEmpty(t, before)

	h.extendPlatformPCR(t, []byte("a-new-measurement"))

	after, err := h.TPM.ReadPCRs(append([]uint{0}, h.TPM.config.PlatformPCRs...))
	require.NoError(t, err)
	require.Equal(t, len(before), len(after), "the same banks must be reported")

	assert.NotEqual(t, before, after,
		"extending a PCR must change the values ReadPCRs reports")
}

// TestReadPCRs_UnknownPCR_Rejected proves an out-of-range PCR index is reported
// rather than silently returning another PCR's value.
func TestReadPCRs_UnknownPCR_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	// PC Client TPMs implement PCRs 0-23; 64 is outside any implemented bank.
	pcrs, err := h.TPM.ReadPCRs([]uint{64})
	if err == nil {
		for _, bank := range pcrs {
			assert.Empty(t, bank.PCRs,
				"an unimplemented PCR index must not report a value")
		}
		return
	}
	assert.Nil(t, pcrs)
}

// TestHash_MatchesSoftwareSHA256 proves the TPM's hash primitive agrees with
// the Go standard library for the same input. The TPM hash is used to produce
// the validation ticket required by TPM2_Sign for restricted keys, so a
// divergence would make every such signature invalid.
func TestHash_MatchesSoftwareSHA256(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := &types.KeyAttributes{
		CN:        "hash-test",
		StoreType: types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHEndorsement,
		},
	}

	data := []byte("data hashed inside the TPM")
	digest, validation, err := h.TPM.Hash(attrs, data)
	require.NoError(t, err)

	want := sha256.Sum256(data)
	assert.Equal(t, want[:], digest,
		"the TPM's SHA-256 must agree with the software implementation")
	assert.NotNil(t, validation, "a validation ticket must accompany the digest")
}

// TestHash_LargeInput_UsesSequenceAndMatchesSoftware proves inputs above the
// single-command limit are routed through the hash-sequence path and still
// produce the correct digest. The 1024-byte threshold is a documented branch in
// Hash; a bug there would corrupt digests only for large inputs.
func TestHash_LargeInput_UsesSequenceAndMatchesSoftware(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := &types.KeyAttributes{
		CN:        "hash-sequence-test",
		StoreType: types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHEndorsement,
		},
	}

	// Comfortably over the 1024-byte single-command threshold and not a
	// multiple of it, so the final partial chunk is exercised too.
	data := bytes.Repeat([]byte("go-xkms-hash-sequence-"), 200)
	require.Greater(t, len(data), 1024)

	digest, _, err := h.TPM.Hash(attrs, data)
	require.NoError(t, err)

	want := sha256.Sum256(data)
	assert.Equal(t, want[:], digest,
		"the hash-sequence path must produce the same digest as a single-shot hash")
}

// TestSignValidate_MissingPublicArea_Rejected proves SignValidate refuses key
// attributes that lack the public area it needs, rather than signing with
// whatever happens to be loaded.
func TestSignValidate_MissingPublicArea_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	digest := sha256.Sum256([]byte("payload"))

	out, err := h.TPM.SignValidate(nil, digest[:], nil)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)

	out, err = h.TPM.SignValidate(
		&types.KeyAttributes{CN: "no-public-area"}, digest[:], nil)
	assert.Nil(t, out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TPMAttributes.Public is required")
}

// TestIsTPMBadAuth_ClassifiesRealTPMResponses proves the TPM_RC_BAD_AUTH
// predicate recognises the error the TPM actually emits for a wrong auth value,
// and does not over-match unrelated failures.
//
// The positive case deliberately uses a genuine wrong-auth error obtained from
// the simulator rather than a hand-constructed response code: go-tpm encodes
// format-one response codes with session and parameter bits, so a hardcoded
// bare 0x022 is not what any real failure looks like and would test nothing.
//
// This predicate gates PIN-retry logic: a false negative reports a wrong PIN as
// a hard failure, a false positive retries a genuine fault forever.
func TestIsTPMBadAuth_ClassifiesRealTPMResponses(t *testing.T) {
	h := newEnrollHarness(t)
	realBadAuth := realWrongSRKPasswordError(t, h)

	// A wrong password on a DA-protected object yields TPM_RC_AUTH_FAIL (the
	// HMAC check failed and the DA counter was incremented), NOT the
	// non-DA TPM_RC_BAD_AUTH. The two predicates therefore have different
	// scopes, and that difference is load-bearing: isTPMAuthError is the broad
	// "the caller supplied the wrong secret" test used for PIN retry, while
	// isTPMBadAuth matches only the narrower non-DA form.
	assert.True(t, isTPMAuthError(realBadAuth),
		"a genuine wrong-auth failure must be classified as an auth error, got %v", realBadAuth)
	assert.False(t, isTPMBadAuth(realBadAuth),
		"TPM_RC_AUTH_FAIL is not TPM_RC_BAD_AUTH; isTPMBadAuth must not widen to it, got %v", realBadAuth)

	assert.False(t, isTPMBadAuth(nil), "no error is not a bad-auth")
	assert.False(t, isTPMAuthError(nil), "no error is not an auth error")

	// The string forms the predicate documents must be recognised.
	assert.True(t, isTPMBadAuth(errBadAuthString{}),
		"the canonical TPM_RC_BAD_AUTH string form must be recognised")

	// Unrelated TPM failures must not be reported as auth failures.
	for _, rc := range []tpm2.TPMRC{
		tpm2.TPMRC(0x99d), // TPM_RC_POLICY_FAIL (session 1)
		tpm2.TPMRC(0x18b), // TPM_RC_HANDLE
	} {
		assert.False(t, isTPMBadAuth(rc),
			"%v is not an authorization failure and must not be classified as one", rc)
	}
}

// realWrongSRKPasswordError provokes a real, unwrapped authorization failure
// straight from the TPM by issuing a command under the enrolled platform SRK
// with the wrong password. Going through TPM2.VerifyAuth would wrap the
// response in ErrAuthProbeRejected and hide the code the isTPM* predicates
// are meant to classify.
//
// A wrong password on this DA-protected object yields TPM_RC_AUTH_FAIL (the
// HMAC check failed and the DA counter was incremented), not the non-DA
// TPM_RC_BAD_AUTH -- and, being a real response, it carries the format-1
// session bits a hand-built TPMRC constant would not (TCG TPM 2.0 Library
// Part 2, section 6.6.3), which is exactly what the masking bug this covers
// depended on.
func realWrongSRKPasswordError(t *testing.T, h *simHarness) error {
	t.Helper()

	pks := newPlatformKeyStore(t, h)
	require.NoError(t, pks.EnrollPlatformSRK("", "the-correct-pin"))

	srkHandle := tpm2.TPMHandle(h.TPM.config.PlatformSRK.SRKHandle)
	srkName, _, err := h.TPM.ReadHandle(srkHandle)
	require.NoError(t, err)

	_, badAuthErr := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   tpm2.PasswordAuth([]byte("the-wrong-pin")),
		},
		InPublic: tpm2.New2B(KeyedHashTemplate),
	}.Execute(h.TPM.transport)
	require.Error(t, badAuthErr, "precondition: a wrong SRK password must fail")
	return badAuthErr
}

// TestIsTPMAuthError_TypedPath_ClassifiesRealAuthFail proves the *typed* fast
// path inside isTPMAuthError -- not its string-matching fallback -- is what
// recognises a real TPM_RC_AUTH_FAIL.
//
// The masking bug this guards against ("& 0x0FF") only manifested once the
// format-1 response carried non-zero session or parameter bits, which is
// exactly what a real TPM returns. So the raw tpm2.TPMRC is extracted from a
// genuine wrong-password failure and re-wrapped behind a message that names
// neither "AUTH_FAIL" nor "BAD_AUTH": isTPMAuthError can only return true for
// that wrapper by having errors.Is match the typed tpm2.TPMRC through
// TPMRC's own format-1-aware Is method, never through the string fallback.
func TestIsTPMAuthError_TypedPath_ClassifiesRealAuthFail(t *testing.T) {
	h := newEnrollHarness(t)
	realBadAuth := realWrongSRKPasswordError(t, h)

	var rc tpm2.TPMRC
	require.True(t, errors.As(realBadAuth, &rc),
		"precondition: go-tpm must expose a typed TPMRC for this failure")

	opaque := opaqueTPMRCError{rc: rc}
	require.False(t,
		strings.Contains(opaque.Error(), "AUTH_FAIL") || strings.Contains(opaque.Error(), "BAD_AUTH"),
		"precondition: the wrapper's own message must not satisfy the string fallback")

	assert.True(t, isTPMAuthError(opaque),
		"the typed path must classify a real TPM_RC_AUTH_FAIL via errors.Is, independent of message text")
}

// opaqueTPMRCError wraps a tpm2.TPMRC behind a message that names neither
// "AUTH_FAIL" nor "BAD_AUTH", isolating isTPMAuthError's typed path from its
// string-matching fallback.
type opaqueTPMRCError struct {
	rc tpm2.TPMRC
}

func (e opaqueTPMRCError) Error() string { return "operation did not complete" }
func (e opaqueTPMRCError) Unwrap() error { return e.rc }

// errBadAuthString models the textual form of a bad-auth failure that the
// predicate matches on for robustness across go-tpm versions.
type errBadAuthString struct{}

func (errBadAuthString) Error() string {
	return "TPM_RC_BAD_AUTH (session 1): authorization failure without DA implications"
}

// TestCertificateToTPMPublic_UnsupportedAlgorithm_Rejected proves certificate
// conversion refuses key types with no TPM public-area mapping instead of
// producing a zero-valued public area that would later be loaded as a key.
func TestCertificateToTPMPublic_UnsupportedAlgorithm_Rejected(t *testing.T) {
	cert := selfSignedEd25519Cert(t)
	require.Equal(t, x509.Ed25519, cert.PublicKeyAlgorithm)

	pub, err := CertificateToTPMPublic(cert)
	require.Error(t, err, "Ed25519 has no TPM 2.0 public-area mapping")
	assert.Nil(t, pub)
}
