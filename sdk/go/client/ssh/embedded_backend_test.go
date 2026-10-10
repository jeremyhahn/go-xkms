// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh_test

import (
	"context"
	"crypto/rand"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	sshbackend "github.com/jeremyhahn/go-xkms/pkg/ssh/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestEmbedded_BackendBackedKey verifies the embedded SDK client mints a
// backend-backed key when GenerateRequest.Backend is set, persists it, and
// signs through the backend on Signer().
func TestEmbedded_BackendBackedKey(t *testing.T) {
	ctx := context.Background()

	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	provider, err := sshbackend.New(sshbackend.ResolverFunc(func(_ context.Context, id string) (types.KeyProvider, error) {
		return kp, nil
	}))
	if err != nil {
		t.Fatalf("sshbackend.New: %v", err)
	}

	client, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{
		Stores:          newStores(t),
		BackendProvider: provider,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	defer client.Close()

	key, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "alice",
		Name:      "laptop",
		Algorithm: "ecdsa-p256",
		Backend:   "software",
	})
	if err != nil {
		t.Fatalf("Generate (backend): %v", err)
	}
	if key.Backend != "software" {
		t.Fatalf("expected Backend=software, got %q", key.Backend)
	}
	if key.PublicKey == "" || key.Fingerprint == "" {
		t.Fatal("expected public key + fingerprint")
	}

	// The key lists with its backend reference.
	list, err := client.Keys().List(ctx, sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Backend != "software" {
		t.Fatalf("List did not surface backend ref: %+v", list)
	}

	// Signer delegates to the backend; the produced signature verifies.
	signer, err := client.Keys().Signer(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: "laptop"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	sshPub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(key.PublicKey))
	if perr != nil {
		t.Fatalf("parse public: %v", perr)
	}
	msg := []byte("backend-backed ssh")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sshPub.Verify(msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestEmbedded_DefaultAlgorithms verifies the cross-backend default algorithms
// — RSA-2048 and ECDSA-P256, which TPM 2.0, SoftHSM2, and the software backend
// all support — generate, persist, and sign+verify end-to-end through the SDK
// embedded client's backend path. RSA exercises the rsa-sha2-256 signature
// (modern servers reject the legacy SHA-1 ssh-rsa).
func TestEmbedded_DefaultAlgorithms(t *testing.T) {
	ctx := context.Background()

	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	provider, err := sshbackend.New(sshbackend.ResolverFunc(func(_ context.Context, _ string) (types.KeyProvider, error) {
		return kp, nil
	}))
	if err != nil {
		t.Fatalf("sshbackend.New: %v", err)
	}
	client, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Stores: newStores(t), BackendProvider: provider})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	defer client.Close()

	cases := []struct {
		name      string
		algorithm string
		rsaBits   int
		rsaSHA2   string // non-empty ⇒ sign via SignWithAlgorithm at this algorithm
	}{
		{"ecdsa-p256", "ecdsa-p256", 0, ""},
		{"rsa-2048", "rsa", 2048, gossh.KeyAlgoRSASHA256},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
				Scope:     "user",
				Owner:     "alice",
				Name:      tc.name,
				Algorithm: tc.algorithm,
				RSABits:   tc.rsaBits,
				Backend:   "software",
			})
			if err != nil {
				t.Fatalf("Generate %s: %v", tc.name, err)
			}
			if key.Backend != "software" {
				t.Fatalf("expected backend software, got %q", key.Backend)
			}

			sshPub, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(key.PublicKey))
			if perr != nil {
				t.Fatalf("parse public: %v", perr)
			}
			signer, err := client.Keys().Signer(ctx, sdkssh.GetKeyRequest{Scope: "user", Owner: "alice", Name: tc.name})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}

			msg := []byte("default-algorithm ssh")
			var sig *gossh.Signature
			if tc.rsaSHA2 != "" {
				as, ok := signer.(gossh.AlgorithmSigner)
				if !ok {
					t.Fatalf("%s signer is not an ssh.AlgorithmSigner", tc.name)
				}
				sig, err = as.SignWithAlgorithm(rand.Reader, msg, tc.rsaSHA2)
				if err == nil && sig.Format != tc.rsaSHA2 {
					t.Fatalf("expected %s signature, got %s", tc.rsaSHA2, sig.Format)
				}
			} else {
				sig, err = signer.Sign(rand.Reader, msg)
			}
			if err != nil {
				t.Fatalf("Sign %s: %v", tc.name, err)
			}
			if err := sshPub.Verify(msg, sig); err != nil {
				t.Fatalf("verify %s: %v", tc.name, err)
			}
		})
	}
}

// TestEmbedded_BackendRequestedButUnavailable verifies a Backend request with
// no provider configured is rejected rather than silently downgraded.
func TestEmbedded_BackendRequestedButUnavailable(t *testing.T) {
	ctx := context.Background()
	client, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Stores: newStores(t)})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	defer client.Close()

	_, err = client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope:     "user",
		Owner:     "bob",
		Name:      "k",
		Algorithm: "ed25519",
		Backend:   "tpm2",
	})
	if err == nil {
		t.Fatal("expected error generating on a backend with no provider")
	}
}
