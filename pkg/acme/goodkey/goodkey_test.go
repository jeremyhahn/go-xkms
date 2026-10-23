package goodkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"
)

// rsaKey2048 is generated once: key generation dominates this package's
// test time.
var rsaKey2048 = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}()

func TestCheckKeyAcceptsGoodKeys(t *testing.T) {
	v := New(DefaultPolicy())
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]any{
		"rsa-2048": &rsaKey2048.PublicKey,
		"p-256":    &ecKey.PublicKey,
		"ed25519":  edKey,
	} {
		if err := v.CheckKey(context.Background(), key); err != nil {
			t.Errorf("%s: CheckKey() = %v, want nil", name, err)
		}
	}
}

func TestCheckKeyRefusesRSAParameters(t *testing.T) {
	v := New(DefaultPolicy())
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	// An odd 2048-bit modulus with the factor 751, the largest prime the
	// trial division covers.
	withFactor := new(big.Int).Lsh(big.NewInt(1), 2038)
	withFactor.Add(withFactor, big.NewInt(1))
	withFactor.Mul(withFactor, big.NewInt(751))

	tests := map[string]struct {
		key  *rsa.PublicKey
		want error
	}{
		"1024 bits":    {&small.PublicKey, ErrRSAKeySize},
		"no modulus":   {&rsa.PublicKey{E: 65537}, ErrRSAKeySize},
		"e=3":          {&rsa.PublicKey{N: rsaKey2048.N, E: 3}, ErrRSAExponent},
		"even e":       {&rsa.PublicKey{N: rsaKey2048.N, E: 65538}, ErrRSAExponent},
		"small factor": {&rsa.PublicKey{N: withFactor, E: 65537}, ErrRSASmallFactor},
	}
	for name, tc := range tests {
		if err := v.CheckKey(context.Background(), tc.key); !errors.Is(err, tc.want) {
			t.Errorf("%s: CheckKey() = %v, want %v", name, err, tc.want)
		}
	}
}

func TestCheckKeyRefusesROCAModulus(t *testing.T) {
	v := New(DefaultPolicy())
	n := rocaModulus(t, v)
	if !v.hasROCAFingerprint(n) {
		t.Fatal("constructed RSALib modulus has no ROCA fingerprint")
	}
	if err := v.CheckKey(context.Background(), &rsa.PublicKey{N: n, E: 65537}); !errors.Is(err, ErrROCA) {
		t.Fatalf("CheckKey() = %v, want ErrROCA", err)
	}
	if v.hasROCAFingerprint(rsaKey2048.N) {
		t.Fatal("a crypto/rand modulus carries the ROCA fingerprint")
	}
}

func TestCheckKeyRefusesFermatFactorableModulus(t *testing.T) {
	v := New(DefaultPolicy())
	p, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	q := new(big.Int).Add(p, big.NewInt(2))
	for !q.ProbablyPrime(20) {
		q.Add(q, big.NewInt(2))
	}
	n := new(big.Int).Mul(p, q)
	if err := v.CheckKey(context.Background(), &rsa.PublicKey{N: n, E: 65537}); !errors.Is(err, ErrFermatFactorable) {
		t.Fatalf("CheckKey() = %v, want ErrFermatFactorable", err)
	}
}

func TestCheckKeyRefusesECAndOtherKeys(t *testing.T) {
	v := New(DefaultPolicy())
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Only the deprecated raw coordinates can express a point off the curve;
	// every parser refuses one, so this is the one way to reach the check.
	offCurve := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Add(p256.X, big.NewInt(1)), Y: p256.Y} //nolint:staticcheck // SA1019: see above.
	noEd := New(Policy{RSAKeySizes: []int{2048}})

	tests := map[string]struct {
		v    *Validator
		key  any
		want error
	}{
		"p-224":           {v, &p224.PublicKey, ErrCurveNotAllowed},
		"off curve":       {v, offCurve, ErrInvalidECPoint},
		"nil":             {v, nil, ErrNilKey},
		"nil rsa":         {v, (*rsa.PublicKey)(nil), ErrNilKey},
		"nil ecdsa":       {v, (*ecdsa.PublicKey)(nil), ErrNilKey},
		"short ed25519":   {v, ed25519.PublicKey(make([]byte, 31)), ErrInvalidECPoint},
		"ed25519 refused": {noEd, ed25519.PublicKey(make([]byte, 32)), ErrUnsupportedKeyType},
		"other type":      {v, "not a key", ErrUnsupportedKeyType},
	}
	for name, tc := range tests {
		if err := tc.v.CheckKey(context.Background(), tc.key); !errors.Is(err, tc.want) {
			t.Errorf("%s: CheckKey() = %v, want %v", name, err, tc.want)
		}
	}
}

func TestPrimesBelow(t *testing.T) {
	got := primesBelow(30)
	want := []int{2, 3, 5, 7, 11, 13, 17, 19, 23, 29}
	if len(got) != len(want) {
		t.Fatalf("primesBelow(30) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("primesBelow(30) = %v, want %v", got, want)
		}
	}
	if primesBelow(2) != nil {
		t.Fatal("primesBelow(2) returned primes")
	}
}

// rocaModulus builds a 2048-bit modulus of the RSALib form k*M + 65537^a mod
// M, M the primorial of the fingerprint primes, that has no factor below
// 752 so CheckKey reaches the ROCA rule.
func rocaModulus(t *testing.T, v *Validator) *big.Int {
	t.Helper()
	m := primorial(rocaPrimeBound)
	k := new(big.Int).Lsh(big.NewInt(1), uint(2048-m.BitLen()))
	g := big.NewInt(rocaGenerator)
	for a := int64(1); a < 10000; a++ {
		n := new(big.Int).Mul(k, m)
		n.Add(n, new(big.Int).Exp(g, big.NewInt(a), m))
		if n.BitLen() == 2048 && new(big.Int).GCD(nil, nil, n, v.primorial).Cmp(big.NewInt(1)) == 0 {
			return n
		}
		k.Add(k, big.NewInt(1))
	}
	t.Fatal("no RSALib modulus without a small factor")
	return nil
}
