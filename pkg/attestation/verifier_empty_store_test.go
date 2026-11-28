package attestation_test

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

// withdrawableLister models a trust store whose last root of a purpose is
// withdrawn: quarantine and removal both make the purpose list empty.
type withdrawableLister struct {
	roots []*x509.Certificate
}

func (l *withdrawableLister) CertificatesByPurpose(truststore.CertPurpose) ([]*x509.Certificate, error) {
	return l.roots, nil
}

// TestVerify_EmptyStorePoolRefused covers Codex P1 (round 2): once the last
// store root of the configured chain purpose is withdrawn, VerifyChain and
// Verify return ErrNoTrustAnchors instead of a structural-only success.
func TestVerify_EmptyStorePoolRefused(t *testing.T) {
	for _, step := range []string{"quarantined", "removed"} {
		t.Run(step, func(t *testing.T) {
			root := snapshotTestRoot(t, "store root")
			lister := &withdrawableLister{roots: []*x509.Certificate{root}}
			v := attestation.NewVerifier(nil,
				attestation.WithTrustStore(lister, nil),
				attestation.WithChainPurpose(truststore.PurposeTPMManufacturer))
			stmt := &attestation.AttestationStatement{Format: "tpm2", CertificateChain: []*x509.Certificate{root}}
			if err := v.VerifyChain(stmt, nil); err != nil {
				t.Fatalf("chain to a live store root: %v", err)
			}
			lister.roots = nil // the last root is withdrawn
			if err := v.VerifyChain(stmt, nil); !errors.Is(err, attestation.ErrNoTrustAnchors) {
				t.Fatalf("VerifyChain after withdrawal: got %v, want ErrNoTrustAnchors", err)
			}
			minted := snapshotTestRoot(t, "caller-minted root")
			stmt.CertificateChain = []*x509.Certificate{minted}
			stmt.AttestingKeyPublic = minted.PublicKey
			stmt.AttestedKeyPublic = minted.PublicKey
			stmt.Signature = []byte{0x01}
			stmt.SignatureAlgorithm = x509.ECDSAWithSHA256
			if err := v.VerifyChain(stmt, nil); !errors.Is(err, attestation.ErrNoTrustAnchors) {
				t.Fatalf("VerifyChain of a minted chain: got %v, want ErrNoTrustAnchors", err)
			}
			if _, err := v.Verify(stmt, &attestation.VerifyOptions{}); !errors.Is(err, attestation.ErrNoTrustAnchors) {
				t.Fatalf("Verify after withdrawal: got %v, want ErrNoTrustAnchors", err)
			}
		})
	}
}

// TestVerifyChain_UnanchoredVerifierStaysStructural keeps the
// structural-only behaviour of a verifier built without any anchor source.
func TestVerifyChain_UnanchoredVerifierStaysStructural(t *testing.T) {
	v := attestation.NewVerifier(nil)
	stmt := &attestation.AttestationStatement{Format: "tpm2", CertificateChain: []*x509.Certificate{snapshotTestRoot(t, "any root")}}
	if err := v.VerifyChain(stmt, nil); err != nil {
		t.Fatalf("unanchored verifier: %v", err)
	}
}
