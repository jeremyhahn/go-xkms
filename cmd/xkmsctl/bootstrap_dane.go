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

package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// TLSA certificate usage values per RFC 6698.
const (
	// TLSAUsageCAConstraint (0) constrains which CA can validate the certificate.
	TLSAUsageCAConstraint = 0

	// TLSAUsageServiceCertConstraint (1) constrains which service certificate is valid.
	TLSAUsageServiceCertConstraint = 1

	// TLSAUsageTrustAnchorAssertion (2) specifies a trust anchor (DANE-TA).
	TLSAUsageTrustAnchorAssertion = 2

	// TLSAUsageDomainIssuedCert (3) specifies the exact end-entity certificate (DANE-EE).
	TLSAUsageDomainIssuedCert = 3
)

// TLSA selector values per RFC 6698.
const (
	// TLSASelectorFullCert (0) matches against the full DER-encoded certificate.
	TLSASelectorFullCert = 0

	// TLSASelectorSPKI (1) matches against the SubjectPublicKeyInfo.
	TLSASelectorSPKI = 1
)

// TLSA matching type values per RFC 6698.
const (
	// TLSAMatchExact (0) uses exact match (no hash).
	TLSAMatchExact = 0

	// TLSAMatchSHA256 (1) uses SHA-256 hash.
	TLSAMatchSHA256 = 1

	// TLSAMatchSHA512 (2) uses SHA-512 hash.
	TLSAMatchSHA512 = 2
)

// defaultDNSServer is the fallback DNS resolver when no server is specified.
const defaultDNSServer = "8.8.8.8:53"

// tlsaRecord holds the fields of a TLSA DNS record.
type tlsaRecord struct {
	Usage        int
	Selector     int
	MatchingType int
	Data         string
}

// tlsaResolver performs DNS TLSA record lookups. The default implementation
// uses miekg/dns; tests can substitute a mock implementation.
type tlsaResolver interface {
	// LookupTLSA queries DNS for TLSA records at the given FQDN using
	// the specified DNS server address (host:port).
	LookupTLSA(tlsaName, dnsServer string) ([]tlsaRecord, error)
}

// dnsResolver is the production DNS TLSA resolver using miekg/dns.
type dnsResolver struct{}

// LookupTLSA queries a DNS server for TLSA records at the given name.
func (r *dnsResolver) LookupTLSA(tlsaName, dnsServer string) ([]tlsaRecord, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(tlsaName), dns.TypeTLSA)
	msg.RecursionDesired = true

	client := new(dns.Client)
	resp, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrDNSQuery, tlsaName, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("%w: %s (rcode=%s)",
			ErrDNSResponseCode, tlsaName, dns.RcodeToString[resp.Rcode])
	}

	records := make([]tlsaRecord, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		tlsa, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		records = append(records, tlsaRecord{
			Usage:        int(tlsa.Usage),
			Selector:     int(tlsa.Selector),
			MatchingType: int(tlsa.MatchingType),
			Data:         strings.ToLower(tlsa.Certificate),
		})
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrDNSNoRecords, tlsaName)
	}

	return records, nil
}

// resolver is the active TLSA resolver. Tests can replace this with a mock.
var resolver tlsaResolver = &dnsResolver{}

// tlsaUsageLabels maps TLSA usage values to human-readable descriptions.
var tlsaUsageLabels = map[int]string{
	TLSAUsageCAConstraint:          "PKIX-TA (CA Constraint)",
	TLSAUsageServiceCertConstraint: "PKIX-EE (Service Certificate Constraint)",
	TLSAUsageTrustAnchorAssertion:  "DANE-TA (Trust Anchor Assertion)",
	TLSAUsageDomainIssuedCert:      "DANE-EE (Domain-Issued Certificate)",
}

// tlsaSelectorLabels maps TLSA selector values to human-readable descriptions.
var tlsaSelectorLabels = map[int]string{
	TLSASelectorFullCert: "Full Certificate",
	TLSASelectorSPKI:     "SubjectPublicKeyInfo",
}

// tlsaMatchingTypeLabels maps TLSA matching type values to human-readable descriptions.
var tlsaMatchingTypeLabels = map[int]string{
	TLSAMatchExact:  "Exact Match",
	TLSAMatchSHA256: "SHA-256",
	TLSAMatchSHA512: "SHA-512",
}

// daneCmd represents the dane subcommand group under bootstrap
var daneCmd = &cobra.Command{
	Use:   "dane",
	Short: "DANE/TLSA record management",
	Long:  `Tools for generating, verifying, and displaying DANE TLSA records for DNS-based certificate authentication.`,
}

// daneGenerateTLSACmd generates TLSA records from a certificate file
var daneGenerateTLSACmd = &cobra.Command{
	Use:   "generate-tlsa",
	Short: "Generate TLSA record(s) for DNS publishing",
	Long: `Generate DANE TLSA record(s) from a PEM-encoded certificate file for DNS zone publishing.

By default, generates a single TLSA record using the specified usage, selector, and matching type.
Use --all to generate all common TLSA record combinations.`,
	Run: func(cmd *cobra.Command, args []string) {
		certFile, _ := cmd.Flags().GetString("cert-file")
		hostname, _ := cmd.Flags().GetString("hostname")
		port, _ := cmd.Flags().GetInt("port")
		usage, _ := cmd.Flags().GetInt("usage")
		selector, _ := cmd.Flags().GetInt("selector")
		matchingType, _ := cmd.Flags().GetInt("matching-type")
		all, _ := cmd.Flags().GetBool("all")

		generateTLSA(certFile, hostname, port, usage, selector, matchingType, all)
	},
}

// daneVerifyTLSACmd verifies TLSA records against a certificate
var daneVerifyTLSACmd = &cobra.Command{
	Use:   "verify-tlsa",
	Short: "Verify TLSA records against a certificate",
	Long: `Verify that DANE TLSA records match a given certificate file.

Reads the certificate from --cert-file and verifies it would match
TLSA records for the specified hostname and port.`,
	Run: func(cmd *cobra.Command, args []string) {
		certFile, _ := cmd.Flags().GetString("cert-file")
		hostname, _ := cmd.Flags().GetString("hostname")
		port, _ := cmd.Flags().GetInt("port")
		dnsServer, _ := cmd.Flags().GetString("dns-server")

		verifyTLSA(certFile, hostname, port, dnsServer)
	},
}

// daneShowTLSACmd displays TLSA records for a domain
var daneShowTLSACmd = &cobra.Command{
	Use:   "show-tlsa",
	Short: "Display TLSA records for a domain",
	Long: `Query and display DANE TLSA records for a given hostname and port.

This queries DNS for _<port>._tcp.<hostname> TLSA records and displays
them in a human-readable format.`,
	Run: func(cmd *cobra.Command, args []string) {
		hostname, _ := cmd.Flags().GetString("hostname")
		port, _ := cmd.Flags().GetInt("port")
		dnsServer, _ := cmd.Flags().GetString("dns-server")

		showTLSA(hostname, port, dnsServer)
	},
}

func init() {
	// Register DANE subcommands
	daneCmd.AddCommand(daneGenerateTLSACmd)
	daneCmd.AddCommand(daneVerifyTLSACmd)
	daneCmd.AddCommand(daneShowTLSACmd)

	// Flags for generate-tlsa
	daneGenerateTLSACmd.Flags().String("cert-file", "", "path to PEM certificate file")
	daneGenerateTLSACmd.Flags().String("hostname", "", "hostname for the TLSA record (e.g., kms.example.com)")
	daneGenerateTLSACmd.Flags().Int("port", 443, "port number for the TLSA record")
	daneGenerateTLSACmd.Flags().Int("usage", TLSAUsageTrustAnchorAssertion, "TLSA certificate usage (0-3)")
	daneGenerateTLSACmd.Flags().Int("selector", TLSASelectorSPKI, "TLSA selector (0=full cert, 1=SPKI)")
	daneGenerateTLSACmd.Flags().Int("matching-type", TLSAMatchSHA256, "TLSA matching type (0=exact, 1=SHA-256, 2=SHA-512)")
	daneGenerateTLSACmd.Flags().Bool("all", false, "generate all common TLSA record combinations")

	// Flags for verify-tlsa
	daneVerifyTLSACmd.Flags().String("cert-file", "", "path to PEM certificate file to verify")
	daneVerifyTLSACmd.Flags().String("hostname", "", "hostname to verify TLSA records for")
	daneVerifyTLSACmd.Flags().Int("port", 443, "port number for the TLSA record")
	daneVerifyTLSACmd.Flags().String("dns-server", "", "DNS server for TLSA lookups (e.g., 8.8.8.8:53)")

	// Flags for show-tlsa
	daneShowTLSACmd.Flags().String("hostname", "", "hostname to query TLSA records for")
	daneShowTLSACmd.Flags().Int("port", 443, "port number for the TLSA record")
	daneShowTLSACmd.Flags().String("dns-server", "", "DNS server for TLSA lookups (e.g., 8.8.8.8:53)")
}

// generateTLSA generates TLSA record(s) from a certificate file.
func generateTLSA(certFile, hostname string, port, usage, selector, matchingType int, all bool) {
	if certFile == "" {
		handleError(fmt.Errorf("--cert-file is required"))
		return
	}
	if hostname == "" {
		handleError(fmt.Errorf("--hostname is required"))
		return
	}

	cert, err := loadCertFromPEM(certFile)
	if err != nil {
		handleError(err)
		return
	}

	tlsaName := formatTLSAName(hostname, port)

	if all {
		records := generateCommonTLSARecords(cert)
		for _, rec := range records {
			fmt.Printf("%s IN TLSA %d %d %d %s\n", tlsaName, rec.Usage, rec.Selector, rec.MatchingType, rec.Data)
		}
		return
	}

	data, err := computeTLSAData(cert, selector, matchingType)
	if err != nil {
		handleError(err)
		return
	}

	fmt.Printf("%s IN TLSA %d %d %d %s\n", tlsaName, usage, selector, matchingType, data)
}

// verifyTLSA verifies TLSA records against a certificate by querying DNS
// and comparing the returned records against computed certificate data.
func verifyTLSA(certFile, hostname string, port int, dnsServer string) {
	if hostname == "" {
		handleError(fmt.Errorf("--hostname is required"))
		return
	}

	if certFile == "" {
		handleError(fmt.Errorf("--cert-file is required for verification"))
		return
	}

	cert, err := loadCertFromPEM(certFile)
	if err != nil {
		handleError(err)
		return
	}

	tlsaName := formatTLSAName(hostname, port)

	if dnsServer == "" {
		dnsServer = defaultDNSServer
	}

	fmt.Printf("TLSA verification for: %s\n", tlsaName)
	fmt.Printf("Certificate subject:   %s\n", cert.Subject.String())
	fmt.Printf("DNS server:            %s\n", dnsServer)
	fmt.Println()

	// Query DNS for TLSA records
	dnsRecords, err := resolver.LookupTLSA(tlsaName, dnsServer)
	if err != nil {
		fmt.Printf("DNS lookup: %v\n", err)
		fmt.Println()
		fmt.Println("Falling back to local verification against expected records:")
		fmt.Println()

		// Fall back to showing expected records from the certificate
		records := generateCommonTLSARecords(cert)
		fmt.Println("Expected TLSA records from certificate:")
		for _, rec := range records {
			fmt.Printf("  %d %d %d %s\n", rec.Usage, rec.Selector, rec.MatchingType, rec.Data)
		}
		return
	}

	// Compare each DNS record against the certificate
	matchCount := 0
	fmt.Printf("Found %d TLSA record(s) in DNS:\n\n", len(dnsRecords))

	for i, rec := range dnsRecords {
		fmt.Printf("Record %d:\n", i+1)
		printTLSARecordDetails(rec)

		expected, err := computeTLSAData(cert, rec.Selector, rec.MatchingType)
		if err != nil {
			fmt.Printf("  Verification:  SKIP (unsupported selector/matching type)\n")
			fmt.Println()
			continue
		}

		if strings.EqualFold(expected, rec.Data) {
			fmt.Printf("  Verification:  MATCH\n")
			matchCount++
		} else {
			fmt.Printf("  Verification:  MISMATCH\n")
			fmt.Printf("  Expected:      %s\n", expected)
		}
		fmt.Println()
	}

	fmt.Printf("Result: %d of %d record(s) matched the certificate.\n", matchCount, len(dnsRecords))

	if matchCount == 0 {
		handleError(ErrTLSAVerificationFailed)
	}
}

// showTLSA queries DNS for TLSA records and displays them in a human-readable format.
func showTLSA(hostname string, port int, dnsServer string) {
	if hostname == "" {
		handleError(fmt.Errorf("--hostname is required"))
		return
	}

	tlsaName := formatTLSAName(hostname, port)

	if dnsServer == "" {
		dnsServer = defaultDNSServer
	}

	fmt.Printf("TLSA record query: %s\n", tlsaName)
	fmt.Printf("DNS server:        %s\n", dnsServer)
	fmt.Println()

	records, err := resolver.LookupTLSA(tlsaName, dnsServer)
	if err != nil {
		handleError(err)
		return
	}

	fmt.Printf("Found %d TLSA record(s):\n\n", len(records))

	for i, rec := range records {
		fmt.Printf("Record %d:\n", i+1)
		printTLSARecordDetails(rec)
		fmt.Printf("  DNS RR:        %s IN TLSA %d %d %d %s\n",
			tlsaName, rec.Usage, rec.Selector, rec.MatchingType, rec.Data)
		fmt.Println()
	}
}

// printTLSARecordDetails outputs the human-readable details for a single TLSA record.
func printTLSARecordDetails(rec tlsaRecord) {
	usageLabel, ok := tlsaUsageLabels[rec.Usage]
	if !ok {
		usageLabel = fmt.Sprintf("Unknown (%d)", rec.Usage)
	}

	selectorLabel, ok := tlsaSelectorLabels[rec.Selector]
	if !ok {
		selectorLabel = fmt.Sprintf("Unknown (%d)", rec.Selector)
	}

	matchLabel, ok := tlsaMatchingTypeLabels[rec.MatchingType]
	if !ok {
		matchLabel = fmt.Sprintf("Unknown (%d)", rec.MatchingType)
	}

	fmt.Printf("  Usage:         %d - %s\n", rec.Usage, usageLabel)
	fmt.Printf("  Selector:      %d - %s\n", rec.Selector, selectorLabel)
	fmt.Printf("  Matching Type: %d - %s\n", rec.MatchingType, matchLabel)
	fmt.Printf("  Data:          %s\n", rec.Data)
}

// loadCertFromPEM reads and parses a PEM-encoded certificate file.
func loadCertFromPEM(certFile string) (*x509.Certificate, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found in file: %s", certFile)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// formatTLSAName constructs the DNS TLSA record name: _port._tcp.hostname
func formatTLSAName(hostname string, port int) string {
	// Ensure hostname ends with a dot for FQDN
	h := strings.TrimSuffix(hostname, ".")
	return fmt.Sprintf("_%d._tcp.%s.", port, h)
}

// computeTLSAData computes the TLSA association data for a certificate
// given the selector and matching type.
func computeTLSAData(cert *x509.Certificate, selector, matchingType int) (string, error) {
	var input []byte

	switch selector {
	case TLSASelectorFullCert:
		input = cert.Raw
	case TLSASelectorSPKI:
		input = cert.RawSubjectPublicKeyInfo
	default:
		return "", fmt.Errorf("%w: %d (must be 0 or 1)", ErrTLSAInvalidSelector, selector)
	}

	switch matchingType {
	case TLSAMatchExact:
		return hex.EncodeToString(input), nil
	case TLSAMatchSHA256:
		hash := sha256.Sum256(input)
		return hex.EncodeToString(hash[:]), nil
	case TLSAMatchSHA512:
		hash := sha512.Sum512(input)
		return hex.EncodeToString(hash[:]), nil
	default:
		return "", fmt.Errorf("%w: %d (must be 0, 1, or 2)", ErrTLSAInvalidMatchingType, matchingType)
	}
}

// generateCommonTLSARecords generates the commonly used TLSA record combinations:
//   - DANE-TA (2) SPKI (1) SHA-256 (1)
//   - DANE-TA (2) Full (0) SHA-256 (1)
//   - DANE-EE (3) SPKI (1) SHA-256 (1)
//   - DANE-EE (3) Full (0) SHA-256 (1)
//   - DANE-EE (3) SPKI (1) SHA-512 (2)
//   - DANE-EE (3) Full (0) SHA-512 (2)
func generateCommonTLSARecords(cert *x509.Certificate) []tlsaRecord {
	type combo struct {
		usage        int
		selector     int
		matchingType int
	}

	combos := []combo{
		{TLSAUsageTrustAnchorAssertion, TLSASelectorSPKI, TLSAMatchSHA256},
		{TLSAUsageTrustAnchorAssertion, TLSASelectorFullCert, TLSAMatchSHA256},
		{TLSAUsageDomainIssuedCert, TLSASelectorSPKI, TLSAMatchSHA256},
		{TLSAUsageDomainIssuedCert, TLSASelectorFullCert, TLSAMatchSHA256},
		{TLSAUsageDomainIssuedCert, TLSASelectorSPKI, TLSAMatchSHA512},
		{TLSAUsageDomainIssuedCert, TLSASelectorFullCert, TLSAMatchSHA512},
	}

	records := make([]tlsaRecord, 0, len(combos))
	for _, c := range combos {
		data, err := computeTLSAData(cert, c.selector, c.matchingType)
		if err != nil {
			continue
		}
		records = append(records, tlsaRecord{
			Usage:        c.usage,
			Selector:     c.selector,
			MatchingType: c.matchingType,
			Data:         data,
		})
	}

	return records
}
