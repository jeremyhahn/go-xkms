package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// maxSerialOctets is the RFC 5280 §4.1.2.2 bound on a serial number's
// length.
const maxSerialOctets = 20

// Linter lints a certificate before the CA signs it. CA/Browser Forum
// Baseline Requirements §4.3.1.2 requires the CA to lint the
// tbsCertificate before signing; the CA hands Lint a certificate with the
// final tbsCertificate signed by a throwaway key, and signs for real only
// when Lint returns nil.
type Linter interface {
	Lint(lintCertDER []byte) error
}

// LintFunc adapts a function to the Linter interface.
type LintFunc func(lintCertDER []byte) error

// Lint calls f.
func (f LintFunc) Lint(lintCertDER []byte) error {
	return f(lintCertDER)
}

// validateReservedSerial checks a caller-supplied serial against RFC 5280
// §4.1.2.2: a positive integer of at most 20 octets.
func validateReservedSerial(serial *big.Int) error {
	if serial == nil || serial.Sign() <= 0 {
		return ErrInvalidSerial
	}
	// The DER encoding adds a leading zero octet when the high bit is set.
	if octets := serial.BitLen()/8 + 1; octets > maxSerialOctets {
		return &errs.Detail{Err: ErrInvalidSerial, Detail: fmt.Sprintf("%d octets", octets)}
	}
	return nil
}

// lintAndSign implements Baseline Requirements §4.3.1.2: it signs template
// with a throwaway key of the issuing key's algorithm, size and curve, has
// linter lint the result, and only then signs with the issuing key. The
// lint parent is the issuing certificate with the throwaway public key, so
// the issuer name and authority key identifier stay those of the issuer and
// the two tbsCertificates are byte-identical, which VerifyTBSDeterminism
// checks before the signed certificate is returned.
func (iss *Issuer) lintAndSign(randReader io.Reader, template *x509.Certificate, publicKey crypto.PublicKey) ([]byte, error) {
	if iss == nil || iss.Signer == nil {
		return nil, ErrInvalidIssuer
	}
	// A nil publicKey certifies the issuer's own key (Sign). Resolve it here,
	// or the lint certificate would certify the throwaway lint key and its
	// TBSCertificate would differ from the one the issuer signs.
	if publicKey == nil {
		publicKey = iss.Signer.Public()
	}
	lintKey, err := newLintSigner(iss.Signer.Public())
	if err != nil {
		return nil, err
	}
	parent := iss.Certificate
	if parent == nil {
		parent = template
	}
	lintParent := *parent
	lintParent.PublicKey = lintKey.Public()
	lintIssuer := &Issuer{Signer: lintKey, Certificate: &lintParent}
	lintDER, err := lintIssuer.Sign(randReader, template, publicKey)
	if err != nil {
		return nil, err
	}
	if err := iss.Linter.Lint(lintDER); err != nil {
		return nil, &errs.Joined{Lead: ErrLintFailed, Cause: err}
	}

	der, err := iss.Sign(randReader, template, publicKey)
	if err != nil {
		return nil, err
	}
	if err := VerifyTBSDeterminism(lintDER, der); err != nil {
		return nil, err
	}
	return der, nil
}

// newLintSigner generates a throwaway key of the same algorithm as the
// issuing key: an RSA key of the same modulus size, an ECDSA key on the same
// curve, or an Ed25519 key. It is used for one lint certificate and dropped.
func newLintSigner(issuingKey crypto.PublicKey) (crypto.Signer, error) {
	var (
		signer crypto.Signer
		err    error
	)
	switch key := issuingKey.(type) {
	case *rsa.PublicKey:
		signer, err = rsa.GenerateKey(rand.Reader, key.N.BitLen())
	case *ecdsa.PublicKey:
		signer, err = ecdsa.GenerateKey(key.Curve, rand.Reader)
	case ed25519.PublicKey:
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, &errs.Detail{Err: ErrLintKey, Detail: fmt.Sprintf("unsupported issuing key %T", issuingKey)}
	}
	if err != nil {
		return nil, &errs.Detail{Err: ErrLintKey, Detail: err.Error()}
	}
	return signer, nil
}
