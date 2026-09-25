//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

// TestHMACSession_EncryptedBranch_VerifiesCorrectAuth proves HMACSession's
// session-bus-encrypted branch (tpm.config.EncryptSession == true) produces
// a session that VerifyAuth can actually use to authenticate against the
// TPM, not just a session object that constructs without error. Every other
// VerifyAuth/HMACSession simulator test in this package runs with session
// encryption disabled; this is the one path that proves the AES-CFB bus
// encryption wrapping does not itself break the auth handshake.
func TestHMACSession_EncryptedBranch_VerifiesCorrectAuth(t *testing.T) {
	_, tpm := createSim(true, false) // encrypt=true
	defer func() { _ = tpm.Close() }()

	srkAttrs := createKey(tpm, false).Parent
	tpmImpl := tpm.(*TPM2)

	require.NoError(t, tpmImpl.VerifyAuth(srkAttrs.TPMAttributes.Handle, []byte("srk-pass")),
		"the correct SRK auth must verify over an encrypted HMAC session")
	require.Error(t, tpmImpl.VerifyAuth(srkAttrs.TPMAttributes.Handle, []byte("wrong-pin")),
		"an incorrect SRK auth must still be rejected over an encrypted HMAC session")
}

// TestHMACSaltedSession_UnencryptedBranch_ProducesUsableSession proves
// HMACSaltedSession's own tpm.config.EncryptSession==false branch produces a
// session that genuinely authorizes the parent key it was salted against.
// CreateSession never reaches this branch itself (it only calls
// HMACSaltedSession when EncryptSession is already true), but
// HMACSaltedSession is exported on the TrustedPlatformModule interface and
// must honor its own config check correctly for any caller that reaches it
// directly.
func TestHMACSaltedSession_UnencryptedBranch_ProducesUsableSession(t *testing.T) {
	_, tpm := createSim(false, false) // encrypt=false
	defer func() { _ = tpm.Close() }()

	srkAttrs := createKey(tpm, false).Parent
	tpmImpl := tpm.(*TPM2)

	_, srkPub, err := tpmImpl.SSRKPublic()
	require.NoError(t, err)

	session, closer, err := tpmImpl.HMACSaltedSession(
		srkAttrs.TPMAttributes.Handle, srkPub, []byte("srk-pass"))
	require.NoError(t, err)
	require.NotNil(t, session)
	defer func() {
		if closer != nil {
			_ = closer()
		}
	}()

	srkName, _, err := tpmImpl.ReadHandle(srkAttrs.TPMAttributes.Handle)
	require.NoError(t, err)

	// A minimal, valid HMAC key template: TPM2_Create rejects KeyedHashTemplate
	// on its own (TPM_RC_ATTRIBUTES -- it sets neither Sign/Decrypt nor
	// SensitiveDataOrigin) regardless of auth, so a bare copy of it would not
	// distinguish an authorization failure from an attribute failure.
	hmacKeyTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			UserWithAuth:        true,
			SensitiveDataOrigin: true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme: tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
		}),
	}

	// Prove the session genuinely authorizes the parent, rather than merely
	// constructing without error: TPM2_Create under the SRK succeeds only if
	// the session's HMAC actually proves knowledge of the SRK's auth value.
	_, err = tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkAttrs.TPMAttributes.Handle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2B(hmacKeyTemplate),
	}.Execute(tpmImpl.transport)
	require.NoError(t, err, "an unencrypted salted session must still authorize a real command under its parent")
}
