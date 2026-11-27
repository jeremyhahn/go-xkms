package keys_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
)

// plainSigner hides the ssh.AlgorithmSigner methods of the signer it wraps.
type plainSigner struct{ ssh.Signer }

func rsaTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}

func ecdsaTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}

func TestSignWithAlgorithm_RSAAlgorithms(t *testing.T) {
	signer := rsaTestSigner(t)
	data := []byte("session data")
	for _, algo := range []string{ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512} {
		t.Run(algo, func(t *testing.T) {
			sig, err := keys.SignWithAlgorithm(signer, rand.Reader, data, algo)
			if err != nil {
				t.Fatalf("SignWithAlgorithm: %v", err)
			}
			if sig.Format != algo {
				t.Fatalf("Format = %q, want %q", sig.Format, algo)
			}
			if err := signer.PublicKey().Verify(data, sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestSignWithAlgorithm_EmptyKeepsDefault(t *testing.T) {
	signer := ecdsaTestSigner(t)
	data := []byte("session data")
	sig, err := keys.SignWithAlgorithm(signer, rand.Reader, data, "")
	if err != nil {
		t.Fatalf("SignWithAlgorithm: %v", err)
	}
	if sig.Format != ssh.KeyAlgoECDSA256 {
		t.Fatalf("Format = %q, want %q", sig.Format, ssh.KeyAlgoECDSA256)
	}
	if err := signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSignWithAlgorithm_OwnTypeForNonRSA(t *testing.T) {
	signer := ecdsaTestSigner(t)
	sig, err := keys.SignWithAlgorithm(signer, rand.Reader, []byte("d"), ssh.KeyAlgoECDSA256)
	if err != nil {
		t.Fatalf("SignWithAlgorithm: %v", err)
	}
	if sig.Format != ssh.KeyAlgoECDSA256 {
		t.Fatalf("Format = %q, want %q", sig.Format, ssh.KeyAlgoECDSA256)
	}
}

func TestSignWithAlgorithm_Refusals(t *testing.T) {
	tests := []struct {
		name   string
		signer ssh.Signer
		algo   string
		want   any
	}{
		{"unknown algorithm", rsaTestSigner(t), "rsa-sha2-1024", &keys.SignatureAlgorithmError{}},
		{"rsa algorithm for ecdsa key", ecdsaTestSigner(t), ssh.KeyAlgoRSASHA256, &keys.SignatureAlgorithmError{}},
		{"signer cannot select", plainSigner{rsaTestSigner(t)}, ssh.KeyAlgoRSASHA512, &keys.AlgorithmSignerError{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := keys.SignWithAlgorithm(tt.signer, rand.Reader, []byte("d"), tt.algo)
			if !keys.IsSignatureAlgorithmRefusal(err) {
				t.Fatalf("err = %v, want a signature algorithm refusal", err)
			}
			switch tt.want.(type) {
			case *keys.SignatureAlgorithmError:
				var target *keys.SignatureAlgorithmError
				if !errors.As(err, &target) || target.Algorithm != tt.algo {
					t.Fatalf("err = %#v, want *SignatureAlgorithmError for %q", err, tt.algo)
				}
			case *keys.AlgorithmSignerError:
				var target *keys.AlgorithmSignerError
				if !errors.As(err, &target) || target.KeyType != ssh.KeyAlgoRSA {
					t.Fatalf("err = %#v, want *AlgorithmSignerError for ssh-rsa", err)
				}
			}
		})
	}
}

func TestSignWithAlgorithm_NilSigner(t *testing.T) {
	_, err := keys.SignWithAlgorithm(nil, rand.Reader, []byte("d"), ssh.KeyAlgoRSASHA256)
	var nilErr *keys.NilInputError
	if !errors.As(err, &nilErr) {
		t.Fatalf("err = %v, want *NilInputError", err)
	}
	if keys.IsSignatureAlgorithmRefusal(err) {
		t.Fatal("a nil signer is not an algorithm refusal")
	}
}

func TestSignatureAlgorithmErrors_Messages(t *testing.T) {
	algErr := &keys.SignatureAlgorithmError{Algorithm: "rsa-sha2-256", KeyType: "ssh-ed25519"}
	if algErr.Error() != "ssh/keys: signature algorithm rsa-sha2-256 not allowed for key type ssh-ed25519" {
		t.Fatalf("Error() = %q", algErr.Error())
	}
	signerErr := &keys.AlgorithmSignerError{KeyType: "ssh-rsa"}
	if signerErr.Error() != "ssh/keys: signer for key type ssh-rsa cannot select a signature algorithm" {
		t.Fatalf("Error() = %q", signerErr.Error())
	}
}
