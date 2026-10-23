// Package linter lints certificates with zlint before the CA signs them, as
// CA/Browser Forum Baseline Requirements §4.3.1.2 requires. It is the
// issuance CertificateLinter of the ACME server
// (pkg/acme/issuance.CertificateLinter), the go-trusted-ca linter port.
//
// A lint error or fatal refuses the certificate; a lint warning does not, and
// is returned so the issuer can log and audit it (owner ruling m956).
package linter

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	zx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

var (
	// ErrConfig reports a lint selection zlint cannot build a registry from.
	ErrConfig = errors.New("linter: invalid lint selection")

	// ErrParse reports a certificate zlint cannot parse.
	ErrParse = errors.New("linter: certificate does not parse")

	// ErrRefused reports a certificate with at least one lint error or fatal.
	ErrRefused = errors.New("linter: certificate fails lint")
)

// Config selects the lints that run. The zero value runs every lint zlint
// registers; a private CA whose certificates are outside the Baseline
// Requirements excludes the lints or sources that do not apply to it.
type Config struct {
	// ExcludeLints names lints that do not run, such as
	// "w_subject_common_name_included".
	ExcludeLints []string

	// ExcludeSources names lint sources that do not run, such as
	// "CABF_EV" or "Mozilla".
	ExcludeSources []string
}

// PrivatePKIConfig returns the Config of the go-xkms ACME CA, a private PKI
// that issues under its operator's policy rather than the CA/Browser Forum
// Baseline Requirements. It excludes the lints that policy decides
// differently and runs every other one:
//
//   - the tenant is the subject's organizationalUnitName on every layer, with
//     no organizationName;
//   - the CA asserts no certificate policy OID;
//   - authorityInformationAccess and cRLDistributionPoints are present only
//     when the CA identity configures them;
//   - the validity period is the operator's, not BR §6.3.2's 200 days;
//   - the signature algorithm is the CA key's, which may be Ed25519
//     (pkg/ca determineSignatureAlgorithm), not only the Baseline
//     Requirements' RSA and ECDSA.
func PrivatePKIConfig() Config {
	return Config{ExcludeLints: []string{
		"e_organizational_unit_name_prohibited",
		"e_subject_contains_organizational_unit_name_and_no_organization_name",
		"e_sub_cert_cert_policy_empty",
		"e_sub_cert_certificate_policies_missing",
		"e_sub_cert_aia_missing",
		"e_missing_crl_distrib_point",
		"e_server_cert_valid_time_longer_than_200_days",
		"e_signature_algorithm_not_supported",
	}}
}

// Identifiers states which identifiers the Baseline Requirements prohibit in
// a subscriber certificate's subjectAltName an ACME identifier policy
// (pkg/acme/policy.PolicyConfig) nonetheless authorizes.
type Identifiers struct {
	// InternalNames is true when DNS names need not end in a public suffix
	// (RequirePublicSuffix false), such as "db.internal" or "localhost".
	InternalNames bool

	// ReservedIPs is true when IP addresses in IANA reserved ranges are
	// authorized (RejectReservedIPs false), such as 10.0.0.1 or fd00::1.
	ReservedIPs bool

	// DeviceIdentity is true for a device-attest-01 certificate, whose
	// subjectAltName carries the verified device identity as an RFC 4043
	// permanentIdentifier otherName. Set it only on that verified path.
	DeviceIdentity bool
}

// internalNameLints and reservedIPLints are the lints that refuse an
// internal name or a reserved IP address in the subject or subjectAltName.
// deviceIdentityLints refuses any otherName in the subjectAltName.
var (
	internalNameLints   = []string{"e_dnsname_not_valid_tld"}
	reservedIPLints     = []string{"e_ext_san_contains_reserved_ip", "e_subject_contains_reserved_ip"}
	deviceIdentityLints = []string{"e_ext_san_other_name_present"}
)

// Admit returns c with the lints excluded that refuse the identifiers ids
// authorizes, so finalize issues every identifier an order was authorized
// for. c is not modified.
func (c Config) Admit(ids Identifiers) Config {
	admitted := Config{
		ExcludeLints:   slices.Clone(c.ExcludeLints),
		ExcludeSources: slices.Clone(c.ExcludeSources),
	}
	if ids.InternalNames {
		admitted.ExcludeLints = append(admitted.ExcludeLints, internalNameLints...)
	}
	if ids.ReservedIPs {
		admitted.ExcludeLints = append(admitted.ExcludeLints, reservedIPLints...)
	}
	if ids.DeviceIdentity {
		admitted.ExcludeLints = append(admitted.ExcludeLints, deviceIdentityLints...)
	}
	return admitted
}

// Finding is one lint that did not pass.
type Finding struct {
	// Lint is the zlint lint name.
	Lint string

	// Status is the lint status: "warn", "error" or "fatal".
	Status string

	// Details is zlint's description of the finding, possibly empty.
	Details string
}

// String formats the finding as "lint: details".
func (f Finding) String() string {
	if f.Details == "" {
		return f.Lint
	}
	return f.Lint + ": " + f.Details
}

// Result holds the findings of one lint run, sorted by lint name.
type Result struct {
	// Errors are the error and fatal findings; any refuses the certificate.
	Errors []Finding

	// Warnings are the warning findings; they do not refuse it.
	Warnings []Finding
}

// Linter runs a fixed zlint registry. It is safe for concurrent use.
type Linter struct {
	registry lint.Registry
}

// New returns a Linter running every registered lint config does not
// exclude. It returns ErrConfig when config names a lint or a source zlint
// does not register.
func New(config Config) (*Linter, error) {
	global := lint.GlobalRegistry()
	opts := lint.FilterOptions{ExcludeNames: config.ExcludeLints}
	// Filter checks lint names but not sources, so a misspelt source would
	// leave the real one running.
	known := global.Sources()
	for _, source := range config.ExcludeSources {
		if !slices.Contains(known, lint.LintSource(source)) {
			return nil, &errs.Detail{Err: ErrConfig, Detail: "unknown lint source " + strconv.Quote(source)}
		}
		opts.ExcludeSources = append(opts.ExcludeSources, lint.LintSource(source))
	}
	registry, err := global.Filter(opts)
	if err != nil {
		return nil, &errs.Detail{Err: ErrConfig, Detail: err.Error()}
	}
	return &Linter{registry: registry}, nil
}

// Lint lints the DER certificate der. It returns the findings and, when any
// is an error or a fatal, an ErrRefused naming them.
func (l *Linter) Lint(der []byte) (*Result, error) {
	cert, err := zx509.ParseCertificate(der)
	if err != nil {
		return nil, &errs.Detail{Err: ErrParse, Detail: err.Error()}
	}

	result := &Result{}
	for name, r := range zlint.LintCertificateEx(cert, l.registry).Results {
		finding := Finding{Lint: name, Status: r.Status.String(), Details: r.Details}
		switch r.Status {
		case lint.Error, lint.Fatal:
			result.Errors = append(result.Errors, finding)
		case lint.Warn:
			result.Warnings = append(result.Warnings, finding)
		}
	}
	byName := func(a, b Finding) int { return strings.Compare(a.Lint, b.Lint) }
	slices.SortFunc(result.Errors, byName)
	slices.SortFunc(result.Warnings, byName)

	if len(result.Errors) > 0 {
		return result, &errs.Detail{Err: ErrRefused, Detail: Summary(result.Errors)}
	}
	return result, nil
}

// Summary joins findings into one line.
func Summary(findings []Finding) string {
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = f.String()
	}
	return strings.Join(parts, "; ")
}
