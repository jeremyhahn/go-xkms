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

package xkms

import (
	"context"
	"crypto/fips140"
	"crypto/x509"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// rawSignSubprocess marks the re-exec'd child of the FIPS-only test below.
// GODEBUG=fips140 is fixed when the process starts, so the activated mode can
// only be exercised in a separate process.
const rawSignSubprocess = "XKMS_SERVICE_RAW_SIGN_SUBPROCESS"

// rawSignData is a caller-built input signed verbatim under hash "NONE" --
// what a PKCS#11 client's CKM_RSA_PKCS C_Sign sends the service.
var rawSignData = []byte("caller-built DigestInfo stands in here")

// generateRawSignKey installs an in-process 2048-bit RSA key in the software
// mock store, the backend whose signer is a crypto/rsa value.
func generateRawSignKey(t *testing.T, software *mockKeyStore) {
	t.Helper()
	_, err := software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "raw-rsa",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)
}

// The service must answer for the process it runs in, so hash "NONE" on an
// in-process RSA key is asserted against crypto/fips140.Enforced rather than
// an expected constant: this test is meaningful with and without
// GODEBUG=fips140=only (go-xkms#486).
func TestSign_RSA_RawPKCS1v15_AgreesWithRuntime(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	generateRawSignKey(t, software)
	ctx := context.Background()

	signResp, signErr := svc.Sign(ctx, &transport.SignRequest{
		Backend: "software", KeyID: "raw-rsa", Data: rawSignData, Hash: "NONE",
	})
	if fips140.Enforced() {
		require.ErrorIs(t, signErr, ErrSigningFailed)
		require.ErrorIs(t, signErr, types.ErrRawPKCS1v15Enforced)
		_, verifyErr := svc.Verify(ctx, &transport.VerifyRequest{
			Backend: "software", KeyID: "raw-rsa", Data: rawSignData, Signature: make([]byte, 256), Hash: "NONE",
		})
		require.ErrorIs(t, verifyErr, ErrVerificationFailed)
		require.ErrorIs(t, verifyErr, types.ErrRawPKCS1v15Enforced)
		return
	}

	require.NoError(t, signErr)
	verifyResp, verifyErr := svc.Verify(ctx, &transport.VerifyRequest{
		Backend: "software", KeyID: "raw-rsa", Data: rawSignData, Signature: signResp.Signature, Hash: "NONE",
	})
	require.NoError(t, verifyErr)
	require.True(t, verifyResp.Valid, "the service's own raw signature must verify against its own key")
}

// TestSign_RSA_RawPKCS1v15_FIPS140Only re-execs this binary with
// GODEBUG=fips140=only and asserts Sign and Verify under hash "NONE" return
// the typed errors and the process survives. Before go-xkms#486 the sign
// reached crypto/rsa, which panics at that site instead of returning an error.
func TestSign_RSA_RawPKCS1v15_FIPS140Only(t *testing.T) {
	if os.Getenv(rawSignSubprocess) == "1" {
		if !fips140.Enforced() {
			t.Fatal("child is not enforcing FIPS 140-only mode; GODEBUG=fips140=only was not honored")
		}
		software, _ := setupService(t)
		svc, err := Get()
		require.NoError(t, err)
		generateRawSignKey(t, software)
		ctx := context.Background()

		_, err = svc.Sign(ctx, &transport.SignRequest{
			Backend: "software", KeyID: "raw-rsa", Data: rawSignData, Hash: "NONE",
		})
		require.ErrorIs(t, err, ErrSigningFailed)
		require.ErrorIs(t, err, types.ErrRawPKCS1v15Enforced)

		_, err = svc.Verify(ctx, &transport.VerifyRequest{
			Backend: "software", KeyID: "raw-rsa", Data: rawSignData, Signature: make([]byte, 256), Hash: "NONE",
		})
		require.ErrorIs(t, err, ErrVerificationFailed)
		require.ErrorIs(t, err, types.ErrRawPKCS1v15Enforced)

		// Control: the approved form of the same key still round-trips, so
		// the refusal is scoped to the absent digest and nothing wider.
		signResp, err := svc.Sign(ctx, &transport.SignRequest{
			Backend: "software", KeyID: "raw-rsa", Data: rawSignData, Hash: "SHA-256",
		})
		require.NoError(t, err)
		verifyResp, err := svc.Verify(ctx, &transport.VerifyRequest{
			Backend: "software", KeyID: "raw-rsa", Data: rawSignData, Signature: signResp.Signature, Hash: "SHA-256",
		})
		require.NoError(t, err)
		require.True(t, verifyResp.Valid, "the SHA-256 signature must verify under fips140=only")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSign_RSA_RawPKCS1v15_FIPS140Only$", "-test.v")
	cmd.Env = append(os.Environ(), rawSignSubprocess+"=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "panic:") {
		t.Fatalf("fips140=only child panicked:\n%s", out)
	}
	if err != nil {
		t.Fatalf("fips140=only child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("fips140=only child did not pass:\n%s", out)
	}
}
