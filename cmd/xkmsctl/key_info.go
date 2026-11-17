package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// keyAttributesFromInfo converts the server's key description into the
// attributes the printer shows, keeping the algorithm, curve and RSA size
// (#2257: the get path printed "Algorithm: 0" for a P-256 key).
func keyAttributesFromInfo(info *client.KeyInfo) *client.KeyAttributes {
	attrs := &client.KeyAttributes{
		CN:           info.KeyID,
		KeyType:      client.ParseKeyType(info.KeyType),
		KeyAlgorithm: parseInfoKeyAlgorithm(info.Algorithm),
	}
	if curve := parseInfoCurve(info.Curve); curve != nil {
		attrs.ECCAttributes = &client.ECCAttributes{Curve: curve}
		if attrs.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			attrs.KeyAlgorithm = x509.ECDSA
		}
	}
	if info.KeySize > 0 && attrs.KeyAlgorithm == x509.RSA {
		attrs.RSAAttributes = &client.RSAAttributes{KeySize: info.KeySize}
	}
	return attrs
}

// parseInfoKeyAlgorithm maps a wire algorithm name ("ECDSA", "ecdsa", "EC",
// "RSA", "Ed25519") to its x509 value; anything else is unknown.
func parseInfoKeyAlgorithm(name string) x509.PublicKeyAlgorithm {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "RSA":
		return x509.RSA
	case "ECDSA", "EC", "ECC":
		return x509.ECDSA
	case "ED25519":
		return x509.Ed25519
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// parseInfoCurve maps a wire curve name ("P-256", "p256", "secp256r1") to
// its curve; anything else is nil.
func parseInfoCurve(name string) elliptic.Curve {
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(name), "-", "")) {
	case "P256", "SECP256R1", "PRIME256V1":
		return elliptic.P256()
	case "P384", "SECP384R1":
		return elliptic.P384()
	case "P521", "SECP521R1":
		return elliptic.P521()
	default:
		return nil
	}
}

// curveName names a curve for output; empty for nil.
func curveName(curve elliptic.Curve) string {
	if curve == nil {
		return ""
	}
	return curve.Params().Name
}
