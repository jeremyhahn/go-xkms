// Package issuance issues the certificate of an ACME finalize request (RFC
// 8555 §7.4) through pkg/ca.SignCSR, the one signer, profile and SAN path of
// the CA (owner ruling m956).
//
// An Issuer validates the request's public key with goodkey, reserves the
// certificate's serial number (RFC 5280 §4.1.2.2), and has the CA sign an RFC
// 6962 §3.1 precertificate and then the final certificate under that serial.
// The CA lints each tbsCertificate before it signs it, as CA/Browser Forum
// Baseline Requirements §4.3.1.2 requires: a zlint error or fatal refuses
// the certificate, a warning is logged and audited. The issuer then checks
// that the two tbsCertificates differ only in the poison and SCT list
// extensions.
//
// Certificate Transparency submission (go-xkms#745) slots in between the
// precertificate and the final certificate.
package issuance
