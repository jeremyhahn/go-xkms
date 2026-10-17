//go:build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// fipsSubprocessEnv marks the re-executed test binary that runs the
// enrollment under GODEBUG=fips140=only.
const fipsSubprocessEnv = "XKMS_FIPS_SUBPROCESS"

// TestFIPS140Only_IDevIDSignerSignsWithTheTPMKey runs the device-identity
// enrollment path -- provisioning (EK, IAK), CreateIDevID's TPM2_Certify
// under the IAK, and a signature from each of the IDevID and the IAK -- in a
// GODEBUG=fips140=only process (#1591). go-tpm's session machinery is on that
// path: HMAC session authorization and AES-CFB parameter encryption both
// panicked in crypto/hmac and crypto/cipher under fips140=only, and one such
// panic aborts the whole test binary. Running the path in a re-executed
// child keeps that failure on this one test and lets every default-mode
// simulator run also prove the FIPS-only mode.
func TestFIPS140Only_IDevIDSignerSignsWithTheTPMKey(t *testing.T) {
	if os.Getenv(fipsSubprocessEnv) == "1" {
		require.True(t, fips140.Enforced(), "the child must run under GODEBUG=fips140=only")
		enrollAndSignWithDeviceIdentity(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFIPS140Only_IDevIDSignerSignsWithTheTPMKey$", "-test.v")
	cmd.Env = append(os.Environ(), fipsSubprocessEnv+"=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "fips140=only enrollment failed:\n%s", out)
	require.True(t, strings.Contains(string(out), "PASS"), "fips140=only enrollment did not pass:\n%s", out)
}

// enrollAndSignWithDeviceIdentity provisions the simulator, mints the
// IDevID and signs with the IDevID (a caller-supplied digest) and the IAK
// (the hash-ticket path), verifying both signatures.
func enrollAndSignWithDeviceIdentity(t *testing.T) {
	t.Helper()

	h := newSignHarness(t)

	digest := sha256.Sum256([]byte("fips140=only handshake transcript"))
	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: h.IDevID,
		Backend:       h.Backend,
	})
	require.NoError(t, err, "the IDevID must sign under fips140=only")
	require.NoError(t, rsa.VerifyPKCS1v15(h.IDevIDPublic, crypto.SHA256, digest[:], signature),
		"the IDevID signature must verify over the caller's digest")

	h.IAK.Hash = crypto.SHA256
	data := []byte("fips140=only attestation payload")
	hashed := sha256.Sum256(data)
	signature, err = h.TPM.Sign(rand.Reader, data, &store.SignerOpts{
		KeyAttributes: h.IAK,
		Backend:       h.Backend,
	})
	require.NoError(t, err, "the IAK must sign under fips140=only")
	require.NoError(t, rsa.VerifyPKCS1v15(h.IAKPublic, crypto.SHA256, hashed[:], signature),
		"the IAK signature must verify over the digest the TPM produced")
}
