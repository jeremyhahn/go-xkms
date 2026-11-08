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

package android

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// This file implements the Android attestation certificate revocation
// status list, as specified in docs/references/android-key-attestation.md
// §Certificate revocation status list.

// GoogleStatusListURL is where Google publishes the attestation certificate
// revocation status list (§Certificate revocation status list).
const GoogleStatusListURL = "https://android.googleapis.com/attestation/status"

// DefaultMaxStatusListBytes bounds the size of a status list read from the
// network or a file. Google's list is a few hundred kilobytes; the bound
// leaves ample headroom while refusing an unbounded body.
const DefaultMaxStatusListBytes int64 = 8 << 20

// CertificateStatus is the status of a listed attestation certificate.
type CertificateStatus string

// The statuses the schema allows (§Certificate revocation status list,
// "status" enum). A certificate the list does not name has a normal valid
// status.
const (
	CertificateStatusRevoked   CertificateStatus = "REVOKED"
	CertificateStatusSuspended CertificateStatus = "SUSPENDED"
)

// RevocationReason is the optional reason a listed certificate carries.
type RevocationReason string

// The reasons the schema allows (§Certificate revocation status list,
// "reason" enum).
const (
	RevocationReasonUnspecified   RevocationReason = "UNSPECIFIED"
	RevocationReasonKeyCompromise RevocationReason = "KEY_COMPROMISE"
	RevocationReasonCACompromise  RevocationReason = "CA_COMPROMISE"
	RevocationReasonSuperseded    RevocationReason = "SUPERSEDED"
	RevocationReasonSoftwareFlaw  RevocationReason = "SOFTWARE_FLAW"
)

var (
	// ErrCertificateRevoked is the sentinel a RevokedCertificateError wraps.
	ErrCertificateRevoked = errors.New("android: attestation certificate is on the revocation status list")

	// ErrStatusListMalformed is returned for a document that does not
	// conform to the status list schema.
	ErrStatusListMalformed = errors.New("android: malformed attestation status list")

	// ErrStatusListTooLarge is returned for a status list over the size
	// bound.
	ErrStatusListTooLarge = errors.New("android: attestation status list exceeds the size limit")

	// ErrStatusListUnavailable is returned when no status list fresh enough
	// to rely on can be obtained. Verification fails closed on it.
	ErrStatusListUnavailable = errors.New("android: attestation status list unavailable")

	// ErrNilStatusListSource is returned when a revocation check is asked
	// of a nil source.
	ErrNilStatusListSource = errors.New("android: nil attestation status list source")
)

// statusListKeyPattern is the schema's propertyNames pattern: lowercase
// hex with no leading zero (§Certificate revocation status list).
var statusListKeyPattern = regexp.MustCompile(`^[a-f1-9][a-f0-9]*$`)

// maxCommentLength is the schema's maxLength for "comment".
const maxCommentLength = 140

// statusListDateLayout is the "expires" format, an ISO 8601 date.
const statusListDateLayout = "2006-01-02"

var validStatuses = map[CertificateStatus]bool{
	CertificateStatusRevoked:   true,
	CertificateStatusSuspended: true,
}

var validReasons = map[RevocationReason]bool{
	RevocationReasonUnspecified:   true,
	RevocationReasonKeyCompromise: true,
	RevocationReasonCACompromise:  true,
	RevocationReasonSuperseded:    true,
	RevocationReasonSoftwareFlaw:  true,
}

// StatusEntry is the status of one listed attestation certificate.
type StatusEntry struct {
	Status  CertificateStatus `json:"status"`
	Expires string            `json:"expires,omitempty"`
	Reason  RevocationReason  `json:"reason,omitempty"`
	Comment string            `json:"comment,omitempty"`
}

// StatusList is a parsed attestation certificate revocation status list,
// keyed by certificate serial number in lowercase hex.
type StatusList struct {
	entries map[string]StatusEntry
}

// StatusListSource supplies the status list a chain is checked against.
// Current returns a list fresh enough to rely on, or an error wrapping
// ErrStatusListUnavailable.
type StatusListSource interface {
	Current() (*StatusList, error)
}

var _ StatusListSource = (*StatusList)(nil)

// RevokedCertificateError reports a chain certificate the status list names.
type RevokedCertificateError struct {
	// Serial is the certificate serial number in the list's encoding.
	Serial string
	Status CertificateStatus
	Reason RevocationReason
}

// Error implements error.
func (e *RevokedCertificateError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("%v: serial %s is %s", ErrCertificateRevoked, e.Serial, e.Status)
	}
	return fmt.Sprintf("%v: serial %s is %s (%s)", ErrCertificateRevoked, e.Serial, e.Status, e.Reason)
}

// Unwrap returns ErrCertificateRevoked.
func (e *RevokedCertificateError) Unwrap() error {
	return ErrCertificateRevoked
}

// ParseStatusList parses and validates a status list document against the
// schema of §Certificate revocation status list. The schema forbids
// additional properties at both levels, so an unknown field is malformed.
func ParseStatusList(data []byte) (*StatusList, error) {
	var doc struct {
		Entries *map[string]StatusEntry `json:"entries"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, &errs.Detail{Err: ErrStatusListMalformed, Detail: err.Error()}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, &errs.Detail{Err: ErrStatusListMalformed, Detail: "data after the document"}
	}
	if doc.Entries == nil {
		return nil, &errs.Detail{Err: ErrStatusListMalformed, Detail: `"entries" is required`}
	}

	for serial, entry := range *doc.Entries {
		if err := validateStatusEntry(serial, entry); err != nil {
			return nil, err
		}
	}
	return &StatusList{entries: *doc.Entries}, nil
}

// validateStatusEntry checks one entry against the schema.
func validateStatusEntry(serial string, entry StatusEntry) error {
	if !statusListKeyPattern.MatchString(serial) {
		return &errs.Detail{Err: ErrStatusListMalformed, Detail: fmt.Sprintf("serial %q is not lowercase hex without a leading zero", serial)}
	}
	if !validStatuses[entry.Status] {
		return &errs.Detail{Err: ErrStatusListMalformed, Detail: fmt.Sprintf("serial %s: status %q", serial, entry.Status)}
	}
	if entry.Reason != "" && !validReasons[entry.Reason] {
		return &errs.Detail{Err: ErrStatusListMalformed, Detail: fmt.Sprintf("serial %s: reason %q", serial, entry.Reason)}
	}
	if entry.Expires != "" {
		if _, err := time.Parse(statusListDateLayout, entry.Expires); err != nil {
			return &errs.Detail{Err: ErrStatusListMalformed, Detail: fmt.Sprintf("serial %s: expires %q", serial, entry.Expires)}
		}
	}
	if utf8.RuneCountInString(entry.Comment) > maxCommentLength {
		return &errs.Detail{Err: ErrStatusListMalformed, Detail: fmt.Sprintf("serial %s: comment over %d characters", serial, maxCommentLength)}
	}
	return nil
}

// LoadStatusListFile reads and parses a status list from a file, for hosts
// that cannot reach Google: the operator copies the list in. The file is
// bounded by DefaultMaxStatusListBytes.
func LoadStatusListFile(path string) (_ *StatusList, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &StatusListUnavailableError{Source: path, Cause: err}
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, &StatusListUnavailableError{Source: path, Cause: closeErr})
		}
	}()

	data, err := readBounded(f, DefaultMaxStatusListBytes)
	if err != nil {
		return nil, &StatusListUnavailableError{Source: path, Cause: err}
	}
	// A file that does not parse supplies no list, the way an HTTP body that
	// does not parse does: the error matches ErrStatusListUnavailable as well
	// as ErrStatusListMalformed, so a caller treats it as an outage of the
	// source and not as a verdict on the certificate chain.
	list, err := ParseStatusList(data)
	if err != nil {
		return nil, &StatusListUnavailableError{Source: path, Cause: err}
	}
	return list, nil
}

// readBounded reads r to the end, refusing more than limit bytes.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &errs.Detail{Err: ErrStatusListTooLarge, Detail: fmt.Sprintf("over %d bytes", limit)}
	}
	return data, nil
}

// StatusListUnavailableError reports a status list that could not be
// obtained from its source. It matches both ErrStatusListUnavailable and
// its cause under errors.Is.
type StatusListUnavailableError struct {
	// Source is the URL or file the list was read from.
	Source string
	Cause  error
}

// Error implements error.
func (e *StatusListUnavailableError) Error() string {
	return fmt.Sprintf("%v: %s: %v", ErrStatusListUnavailable, e.Source, e.Cause)
}

// Unwrap returns ErrStatusListUnavailable and the cause.
func (e *StatusListUnavailableError) Unwrap() []error {
	return []error{ErrStatusListUnavailable, e.Cause}
}

// Current returns the list itself: a parsed list is its own source, which
// is how a list loaded from a file or bytes is configured.
func (l *StatusList) Current() (*StatusList, error) {
	if l == nil {
		return nil, ErrNilStatusListSource
	}
	return l, nil
}

// Lookup returns the entry the list holds for a certificate serial number.
func (l *StatusList) Lookup(serial *big.Int) (StatusEntry, bool) {
	entry, ok := l.entries[StatusListSerial(serial)]
	return entry, ok
}

// Len returns the number of listed certificates.
func (l *StatusList) Len() int {
	return len(l.entries)
}

// StatusListSerial encodes a certificate serial number the way the list
// keys it: lowercase hex with no leading zero (§Certificate revocation
// status list, "propertyNames"). A DER serial with a leading zero octet,
// which DER requires when the high bit is set, encodes without it.
func StatusListSerial(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return serial.Text(16)
}

// CheckRevocation checks every certificate of every chain against the
// source's current list. §Certificate revocation status list requires the
// status of "each certificate in an attestation chain" to be checked, and
// §Before you begin says not to trust the attestation unless all are
// valid, so a SUSPENDED certificate fails as a REVOKED one does, and a
// list that cannot be obtained fails the check (fail closed).
func CheckRevocation(source StatusListSource, chains ...[]*x509.Certificate) error {
	if source == nil {
		return ErrNilStatusListSource
	}
	list, err := source.Current()
	if err != nil {
		return err
	}
	if list == nil {
		return ErrNilStatusListSource
	}
	for _, chain := range chains {
		for _, cert := range chain {
			if cert == nil {
				return ErrNilCertificate
			}
			if entry, listed := list.Lookup(cert.SerialNumber); listed {
				return &RevokedCertificateError{
					Serial: StatusListSerial(cert.SerialNumber),
					Status: entry.Status,
					Reason: entry.Reason,
				}
			}
		}
	}
	return nil
}
