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

package providers

import (
	"context"
	"fmt"
	"strings"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/miekg/dns"
)

// PropagationChecker provides DNS propagation verification functionality.
type PropagationChecker struct {
	nameservers []string
}

// NewPropagationChecker creates a new PropagationChecker with the given nameservers.
// If no nameservers are provided, DefaultNameservers will be used.
func NewPropagationChecker(nameservers []string) *PropagationChecker {
	if len(nameservers) == 0 {
		nameservers = DefaultNameservers
	}
	return &PropagationChecker{
		nameservers: nameservers,
	}
}

// CheckDNSPropagation verifies that a TXT record exists at the specified nameservers
// with the expected value. It returns true if the record is found with the correct
// value at all nameservers, false otherwise.
func CheckDNSPropagation(ctx context.Context, fqdn, value string, nameservers []string) (bool, error) {
	if fqdn == "" {
		return false, &PropagationError{
			FQDN:    fqdn,
			Message: "fqdn cannot be empty",
		}
	}

	if value == "" {
		return false, &PropagationError{
			FQDN:    fqdn,
			Message: "value cannot be empty",
		}
	}

	if len(nameservers) == 0 {
		nameservers = DefaultNameservers
	}

	// Ensure FQDN has trailing dot
	fqdn = ToFQDN(fqdn)

	// Track successful checks to ensure we got at least one successful response
	successCount := 0
	var lastErr error

	// Query TXT records from each nameserver
	for _, ns := range nameservers {
		found, err := checkTXTRecord(ctx, fqdn, value, ns)
		if err != nil {
			// Track error and continue to next nameserver
			lastErr = err
			continue
		}
		successCount++
		if !found {
			// Record not propagated to this nameserver yet
			return false, nil
		}
	}

	// If we didn't get any successful responses, report the error
	if successCount == 0 {
		if lastErr != nil {
			return false, lastErr
		}
		return false, &PropagationError{
			FQDN:    fqdn,
			Message: "all nameservers failed to respond",
		}
	}

	return true, nil
}

// checkTXTRecord checks if a specific TXT record value exists at the given nameserver.
func checkTXTRecord(ctx context.Context, fqdn, expectedValue, nameserver string) (bool, error) {
	resp, err := DNSQuery(ctx, fqdn, dns.TypeTXT, []string{nameserver}, true)
	if err != nil {
		return false, caerrors.DNSError("dns query failed: %v", err)
	}

	if resp.Rcode == dns.RcodeNameError {
		// NXDOMAIN - record doesn't exist yet
		return false, nil
	}

	if resp.Rcode != dns.RcodeSuccess {
		return false, caerrors.DNSError("dns query returned rcode: %s", dns.RcodeToString[resp.Rcode])
	}

	// Check all TXT records in the answer
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}

		// TXT records may be split into multiple strings, join them
		recordValue := strings.Join(txt.Txt, "")

		if recordValue == expectedValue {
			return true, nil
		}
	}

	return false, nil
}

// WaitForPropagation polls the nameservers until the TXT record has propagated
// or the timeout is reached. It returns ErrPropagationTimeout if the timeout
// is exceeded before the record propagates.
func WaitForPropagation(ctx context.Context, fqdn, value string, timeout, interval time.Duration, nameservers []string) error {
	if fqdn == "" {
		return &PropagationError{
			FQDN:    fqdn,
			Message: "fqdn cannot be empty",
		}
	}

	if value == "" {
		return &PropagationError{
			FQDN:    fqdn,
			Message: "value cannot be empty",
		}
	}

	if timeout <= 0 {
		timeout = PropagationTimeout
	}

	if interval <= 0 {
		interval = PropagationPoll
	}

	if len(nameservers) == 0 {
		nameservers = DefaultNameservers
	}

	return WaitForCtx(ctx, timeout, interval, func() (bool, error) {
		propagated, err := CheckDNSPropagation(ctx, fqdn, value, nameservers)
		if err != nil {
			// Return error but keep waiting - might be transient
			return false, err
		}
		return propagated, nil
	})
}

// GetAuthoritativeNameservers resolves the authoritative nameservers for a domain
// by querying for NS records. It returns the list of nameserver hostnames.
func GetAuthoritativeNameservers(ctx context.Context, fqdn string) ([]string, error) {
	if fqdn == "" {
		return nil, &PropagationError{
			FQDN:    fqdn,
			Message: "fqdn cannot be empty",
		}
	}

	// Ensure FQDN has trailing dot
	fqdn = ToFQDN(fqdn)

	// First, find the zone for this FQDN
	zone, err := FindZoneByFQDN(ctx, fqdn, DefaultNameservers)
	if err != nil {
		return nil, caerrors.DNSError("failed to find zone for %s: %v", fqdn, err)
	}

	// Query NS records for the zone
	resp, err := DNSQuery(ctx, zone, dns.TypeNS, DefaultNameservers, true)
	if err != nil {
		return nil, caerrors.DNSError("failed to query NS records: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, caerrors.DNSError("ns query returned rcode: %s", dns.RcodeToString[resp.Rcode])
	}

	var nameservers []string

	// Extract NS records from answer section
	for _, rr := range resp.Answer {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		// Convert nameserver to host:port format
		nsHost := UnFQDN(ns.Ns)
		nameservers = append(nameservers, nsHost+":"+DefaultDNSPort)
	}

	// If no NS records in answer, check authority section
	if len(nameservers) == 0 {
		for _, rr := range resp.Ns {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}
			nsHost := UnFQDN(ns.Ns)
			nameservers = append(nameservers, nsHost+":"+DefaultDNSPort)
		}
	}

	if len(nameservers) == 0 {
		return nil, &PropagationError{
			FQDN:    fqdn,
			Message: "no authoritative nameservers found",
		}
	}

	return nameservers, nil
}

// PropagationError represents an error during DNS propagation checking.
type PropagationError struct {
	FQDN    string
	Message string
	Err     error
}

// Error implements the error interface.
func (e *PropagationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("propagation check for %s: %s: %v", e.FQDN, e.Message, e.Err)
	}
	if e.FQDN != "" {
		return fmt.Sprintf("propagation check for %s: %s", e.FQDN, e.Message)
	}
	return fmt.Sprintf("propagation check: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *PropagationError) Unwrap() error {
	return e.Err
}
