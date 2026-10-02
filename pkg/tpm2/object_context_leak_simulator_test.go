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

//go:build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A TPM holds a fixed, very small number of transient object slots -- three on
// a typical device and on the reference simulator. Anything that loads an object
// without releasing it therefore does not leak slowly: it bricks the connection
// within a handful of operations, and the failure surfaces on a later,
// unrelated command as TPM_RC_OBJECT_MEMORY.
//
// crypto_ops_simulator_test.go already covers the rejected-create error paths.
// The tests here cover the SUCCESS paths, which is where the object contexts
// were actually being stranded: CreateRSA loaded the new key with
// TPM2_CreateLoaded, documented the handle as the caller's to flush, and no
// caller ever did -- so a working key generation cost a slot permanently and the
// third one failed.
//
// Each test owns one simulator via newSimHarness; the go-tpm-tools simulator is
// a process-global singleton, so only one may be live at a time.

// objectSlotBudget is comfortably more iterations than any TPM has transient
// object slots, so a leak of even one handle per operation is caught. Under the
// pre-fix code CreateRSA failed on the third iteration.
const objectSlotBudget = 16

// TestCreateRSA_SuccessfulCreates_DoNotExhaustTPMObjectMemory is the primary
// regression test for the leak. Generating keys is the most ordinary thing a
// key-management daemon does, and before the fix the third RSA key generation on
// a connection failed with TPM_RC_OBJECT_MEMORY -- which is how certificate
// issuance died in the live matrix run.
func TestCreateRSA_SuccessfulCreates_DoNotExhaustTPMObjectMemory(t *testing.T) {
	h := newSimHarness(t, nil)

	before, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	for i := 0; i < objectSlotBudget; i++ {
		attrs := signingKeyAttrs(t, h, fmt.Sprintf("leak-rsa-%d", i), x509.RSA, nil)
		_, createErr := h.TPM.CreateRSA(attrs, h.Backend, true)
		require.NoError(t, createErr,
			"iteration %d: a successful create must not consume a transient object slot", i)
		require.False(t, isObjectMemoryError(createErr),
			"iteration %d: TPM object memory exhausted", i)
	}

	after, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)
	assert.Len(t, after, len(before),
		"%d successful RSA key creations must leave the transient object count unchanged",
		objectSlotBudget)
}

// TestCreateECDSA_SuccessfulCreates_DoNotExhaustTPMObjectMemory is the same
// guard for the ECDSA path, which shares the shape.
func TestCreateECDSA_SuccessfulCreates_DoNotExhaustTPMObjectMemory(t *testing.T) {
	h := newSimHarness(t, nil)

	before, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	for i := 0; i < objectSlotBudget; i++ {
		attrs := signingKeyAttrs(t, h, fmt.Sprintf("leak-ecc-%d", i), x509.ECDSA, elliptic.P256())
		_, createErr := h.TPM.CreateECDSA(attrs, h.Backend, true)
		require.NoError(t, createErr,
			"iteration %d: a successful create must not consume a transient object slot", i)
	}

	after, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)
	assert.Len(t, after, len(before),
		"%d successful ECDSA key creations must leave the transient object count unchanged",
		objectSlotBudget)
}

// TestGenerateThenSign_Repeated_SurvivesObjectSlotBudget reproduces the failing
// operation from the live report rather than its component: certificate
// issuance is generate-a-key-then-sign-with-it, repeated, and it died on the
// TPM2_Load inside Sign because the generations before it had eaten every slot.
//
// The loop runs far past the slot budget and every signature has to verify, so a
// leak cannot be hidden by an operation that merely returns no error.
func TestGenerateThenSign_Repeated_SurvivesObjectSlotBudget(t *testing.T) {
	h := newSimHarness(t, nil)

	before, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("certificate TBS bytes"))

	for i := 0; i < objectSlotBudget; i++ {
		attrs := signingKeyAttrs(t, h, fmt.Sprintf("issue-%d", i), x509.ECDSA, elliptic.P256())
		_, createErr := h.TPM.CreateECDSA(attrs, h.Backend, true)
		require.NoError(t, createErr, "iteration %d: key generation", i)

		attrs.Hash = crypto.SHA256
		signature, signErr := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
			KeyAttributes: attrs,
			Backend:       h.Backend,
		})
		require.NoError(t, signErr,
			"iteration %d: signing must not fail on exhausted TPM object memory", i)
		require.NotEmpty(t, signature, "iteration %d", i)

		tpmPub := eccPublicKeyFromTPM(t, h, attrs)
		require.True(t, ecdsa.VerifyASN1(tpmPub, digest[:], signature),
			"iteration %d: signature must verify against the key the TPM holds", i)
	}

	after, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)
	assert.Len(t, after, len(before),
		"%d generate-then-sign cycles must leave the transient object count unchanged",
		objectSlotBudget)
}

// TestSign_RepeatedOnOneKey_DoesNotLeakObjectContexts covers the signing path on
// its own: every Sign performs a TPM2_Load, and a Load whose handle is not
// flushed exhausts the device just as fast as a create that leaks.
func TestSign_RepeatedOnOneKey_DoesNotLeakObjectContexts(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "repeat-sign", x509.ECDSA, elliptic.P256())
	_, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)

	before, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("repeatedly signed payload"))
	attrs.Hash = crypto.SHA256
	for i := 0; i < objectSlotBudget; i++ {
		_, signErr := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
			KeyAttributes: attrs,
			Backend:       h.Backend,
		})
		require.NoError(t, signErr, "iteration %d", i)
	}

	after, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)
	assert.Len(t, after, len(before),
		"%d signatures with one key must leave the transient object count unchanged",
		objectSlotBudget)
}

// TestHashSequence_TransportFault_DoesNotLeakSequenceObject covers the error
// path of the hash-sequence code.
//
// TPM2_HashSequenceStart allocates an object slot for the sequence context (TCG
// TPM 2.0 Library Part 3, section 17.3), and TPM2_SequenceComplete releases it
// only when it succeeds. Failing TPM2_SequenceComplete at the transport -- the
// "device or resource busy" shape a shared /dev/tpmrm0 produces -- previously
// stranded one object slot per failed hash, and this path is reached by signing
// any attestation payload larger than one TPM2B_MAX_BUFFER.
func TestHashSequence_TransportFault_DoesNotLeakSequenceObject(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := signingKeyAttrs(t, h, "hashseq-leak", x509.RSA, nil)
	attrs.TPMAttributes.HashAlg = tpm2.TPMAlgSHA256

	faulty := &createFaultyTransport{
		inner:  h.TPM.transport,
		failCC: tpm2.TPMCCSequenceComplete,
	}
	h.TPM.transport = faulty

	before, err := transientHandles(faulty.inner)
	require.NoError(t, err)

	// Larger than the 1024-byte threshold, so Hash dispatches to HashSequence.
	data := make([]byte, 4096)
	_, err = rand.Read(data)
	require.NoError(t, err)

	const iterations = 8
	for i := 0; i < iterations; i++ {
		_, _, hashErr := h.TPM.HashSequence(attrs, data)
		require.Error(t, hashErr, "iteration %d: the injected fault must surface", i)

		// Every iteration must fail for the reason that was injected. Once the
		// sequence objects start accumulating, TPM2_HashSequenceStart itself
		// begins failing with TPM_RC_OBJECT_MEMORY before the injected fault is
		// ever reached -- which is precisely the leak, arriving one operation
		// earlier than the caller expects.
		require.False(t, isObjectMemoryError(hashErr),
			"iteration %d: TPM object memory exhausted -- a failed hash sequence "+
				"stranded its sequence object: %v", i, hashErr)
	}
	require.Equal(t, iterations, faulty.failCount,
		"the injected fault must have fired on every iteration")

	after, err := transientHandles(faulty.inner)
	require.NoError(t, err)
	assert.Len(t, after, len(before),
		"%d failed hash sequences must leave no sequence object behind", iterations)
}

// keyedHashPublicArea returns a marshalled TPMT_PUBLIC for a public-only
// keyed-hash object.
//
// TPM2_LoadExternal accepts it -- it is a structurally valid public area, so the
// object becomes resident and occupies a transient slot -- but it is neither RSA
// nor ECC, so TPM2.KeyAttributes fails when it tries to turn it into a
// crypto.PublicKey. That is precisely the window the CSR verifiers had between
// loading a caller-supplied public area and releasing it, reached with an input
// any client could send rather than with an injected fault.
func keyedHashPublicArea() []byte {
	public := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BDigest{Buffer: make([]byte, 32)},
		),
	}
	wrapped := tpm2.New2B(public)
	return wrapped.Bytes()
}

// withKeyedHashAttestPub copies a CSR and swaps its attestation public area for
// a keyed-hash one, keeping the declared size field consistent so the CSR still
// unpacks -- otherwise UnpackIDevIDCSR rejects it as a corrupt copy and the
// verification never reaches the load the test is about.
func withKeyedHashAttestPub(csr *TCG_CSR_IDEVID) *TCG_CSR_IDEVID {
	bad := *csr
	bad.CsrContents = csr.CsrContents
	bad.CsrContents.AttestPub = keyedHashPublicArea()
	binary.BigEndian.PutUint32(
		bad.CsrContents.AttestPubSZ[:],
		uint32(len(bad.CsrContents.AttestPub)),
	)
	return &bad
}

// TestVerifyTCG_CSR_IDevID_UnusableAttestKey_DoesNotLeakLoadedPublicArea covers
// the CSR verification path's object slots.
//
// The public areas in a TCG-CSR-IDEVID are supplied by whoever sent the CSR, so
// a verifier that strands an object slot on a rejected CSR hands any client a
// way to disable the enrolling TPM: a few rejected CSRs and every later
// operation on that connection fails with TPM_RC_OBJECT_MEMORY, including
// enrollment of well-formed CSRs from other devices.
func TestVerifyTCG_CSR_IDevID_UnusableAttestKey_DoesNotLeakLoadedPublicArea(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	bad := withKeyedHashAttestPub(csr)

	before, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	const iterations = 8
	for i := 0; i < iterations; i++ {
		attrs, unpacked, verifyErr := h.TPM.VerifyTCG_CSR_IDevID(bad, x509.SHA256WithRSAPSS)
		require.Error(t, verifyErr, "iteration %d: an unusable attestation key must be rejected", i)
		require.Nil(t, attrs)
		require.Nil(t, unpacked)
		require.False(t, isObjectMemoryError(verifyErr),
			"iteration %d: TPM object memory exhausted -- a rejected CSR stranded a "+
				"loaded public area: %v", i, verifyErr)
	}

	after, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)
	assert.Len(t, after, len(before),
		"%d rejected CSR verifications must leave no loaded public area behind", iterations)
}

// TestVerifyTCG_CSR_IDevID_UnusableSigningKey_DoesNotLeakLoadedPublicArea
// covers the verifier's SECOND caller-supplied public area.
//
// VerifyTCG_CSR_IDevID loads two: the attestation key and the signing key. The
// test above cannot reach the second one, because a bad attestation key is
// rejected first, so this one leaves the attestation key intact and corrupts the
// signing key instead. Both loads had the same unflushed-on-failure shape.
func TestVerifyTCG_CSR_IDevID_UnusableSigningKey_DoesNotLeakLoadedPublicArea(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	bad := *csr
	bad.CsrContents = csr.CsrContents
	bad.CsrContents.SigningPub = keyedHashPublicArea()
	binary.BigEndian.PutUint32(
		bad.CsrContents.SigningPubSZ[:],
		uint32(len(bad.CsrContents.SigningPub)),
	)

	before, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	const iterations = 8
	for i := 0; i < iterations; i++ {
		attrs, unpacked, verifyErr := h.TPM.VerifyTCG_CSR_IDevID(&bad, x509.SHA256WithRSAPSS)
		require.Error(t, verifyErr, "iteration %d: an unusable signing key must be rejected", i)
		require.Nil(t, attrs)
		require.Nil(t, unpacked)
		require.False(t, isObjectMemoryError(verifyErr),
			"iteration %d: TPM object memory exhausted -- a rejected CSR stranded a "+
				"loaded public area: %v", i, verifyErr)
	}

	after, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)
	assert.Len(t, after, len(before),
		"%d rejected CSR verifications must leave no loaded public area behind", iterations)
}

// TestVerifyTCG_CSR_IAK_UnusableAttestKey_DoesNotLeakLoadedPublicArea is the
// same guard for the IAK verifier, which loads a caller-supplied public area
// through the identical sequence.
func TestVerifyTCG_CSR_IAK_UnusableAttestKey_DoesNotLeakLoadedPublicArea(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	bad := withKeyedHashAttestPub(csr)

	before, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	const iterations = 8
	for i := 0; i < iterations; i++ {
		attrs, unpacked, verifyErr := h.TPM.VerifyTCG_CSR_IAK(bad, x509.SHA256WithRSAPSS)
		require.Error(t, verifyErr, "iteration %d: an unusable attestation key must be rejected", i)
		require.Nil(t, attrs)
		require.Nil(t, unpacked)
		require.False(t, isObjectMemoryError(verifyErr),
			"iteration %d: TPM object memory exhausted -- a rejected CSR stranded a "+
				"loaded public area: %v", i, verifyErr)
	}

	after, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)
	assert.Len(t, after, len(before),
		"%d rejected CSR verifications must leave no loaded public area behind", iterations)
}

// TestCreateKeySession_InvalidPassword_ReturnsCallableCloser is the panic half
// of "survives error returns and panics".
//
// UnsealKey registers its deferred closer call BEFORE inspecting the error, so a
// nil closer meant a bad password panicked inside the deferred function instead
// of being reported. A panic unwinding through the unseal path skips the
// transient-object flushes registered below it, which is the leak this file is
// about, arriving by a different route.
func TestCreateKeySession_InvalidPassword_ReturnsCallableCloser(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := &types.KeyAttributes{
		CN:        "bad-password-key",
		StoreType: types.StoreTPM2,
		// A password that fails to render is the condition this path reports.
		Password: unreadablePassword{},
	}

	session, closer, err := h.TPM.createKeySession(attrs, h.Backend)
	assert.Error(t, err, "an unusable password must be reported")
	assert.Nil(t, session)
	require.NotNil(t, closer,
		"the closer must be callable even on the error return: callers register it "+
			"in a defer before they inspect the error")
	assert.NoError(t, closer())
}

// errUnreadablePassword is what unreadablePassword.WithBytes reports.
var errUnreadablePassword = errors.New("tpm2: test password is unreadable")

// unreadablePassword is a types.Password whose WithBytes fails, which is the
// condition createKeySession reports rather than authorizing with.
type unreadablePassword struct{}

func (unreadablePassword) WithBytes(func([]byte) error) error { return errUnreadablePassword }
func (unreadablePassword) String() string                     { return types.PasswordRedacted }
func (unreadablePassword) Bytes() []byte                      { return nil }
func (unreadablePassword) Clear()                             {}
