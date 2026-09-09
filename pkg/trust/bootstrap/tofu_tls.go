// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

// ErrTOFUPinStoreRequired is returned by NewTOFUTLSConfig when no pin store
// is supplied: trust-on-first-use without persistence is trust-on-every-use.
var ErrTOFUPinStoreRequired = errors.New("trust bootstrap: tofu requires a pin store")

// tofuPinSource is the Pin.Source value truststrap's own TOFU bootstrapper
// records, so a pin captured on the TLS path and one captured on the
// bundle-fetch path are indistinguishable in the store.
const tofuPinSource = "tofu"

// TOFUEndpointError reports an endpoint that is not a "host:port" the TOFU
// verifier can key a pin by.
type TOFUEndpointError struct {
	Endpoint string
	Reason   string
}

func (e *TOFUEndpointError) Error() string {
	return fmt.Sprintf("trust bootstrap: tofu endpoint %q: %s", e.Endpoint, e.Reason)
}

// TOFUPinStoreError reports a pin store operation that failed for a reason
// other than "no pin recorded". It is never treated as first use: a store
// that cannot answer must not be answered with a fresh capture.
type TOFUPinStoreError struct {
	Op   string
	Host string
	Port int
	Err  error
}

func (e *TOFUPinStoreError) Error() string {
	return fmt.Sprintf("trust bootstrap: tofu pin store %s for %s:%d: %v", e.Op, e.Host, e.Port, e.Err)
}

// Unwrap returns the pin store's own error.
func (e *TOFUPinStoreError) Unwrap() error { return e.Err }

// TOFUPinMismatchError reports a presented chain whose SubjectPublicKeyInfo
// pin does not match the pin recorded for the endpoint on first use.
type TOFUPinMismatchError struct {
	Host      string
	Port      int
	Stored    string
	Presented string
	Err       error
}

func (e *TOFUPinMismatchError) Error() string {
	return fmt.Sprintf("trust bootstrap: tofu pin mismatch for %s:%d: stored %s, presented %s",
		e.Host, e.Port, e.Stored, e.Presented)
}

// Unwrap returns the underlying spkipin verification error.
func (e *TOFUPinMismatchError) Unwrap() error { return e.Err }

// NewTOFUTLSConfig returns a client *tls.Config whose sole certificate
// verification is trust-on-first-use SPKI pinning against pinStore, keyed
// by endpoint ("host:port").
//
// On the first connection to the endpoint the presented leaf's SHA-256
// SubjectPublicKeyInfo pin is captured, offered to confirm (when non-nil;
// an error from it refuses the connection and persists nothing), and
// persisted through pinStore. On every later connection the presented chain
// must carry the recorded pin. This is the endpoint-level counterpart of
// NewDANETLSConfig and NewSPKIPinTLSConfig, and the TLS-path counterpart of
// truststrap's bundle-fetching TOFU bootstrapper: the pin record it writes
// is the same shape, so the two paths share one store.
//
// The verifier runs in VerifyConnection, not VerifyPeerCertificate, and
// session tickets are disabled, so a resumed session cannot bypass the pin.
// A pin store that fails for any reason other than "no pin recorded" is an
// error, never a fresh capture (#139).
func NewTOFUTLSConfig(ctx context.Context, pinStore truststrap.PinStore, endpoint string,
	confirm func(ctx context.Context, pin *truststrap.Pin) error) (*tls.Config, error) {
	if pinStore == nil {
		return nil, ErrTOFUPinStoreRequired
	}
	host, port, err := tofuEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	verifier := &tofuVerifier{ctx: ctx, store: pinStore, host: host, port: port, confirm: confirm}
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		InsecureSkipVerify:     true, // #nosec G402 -- CA chain skipped; VerifyConnection is the sole verifier (TOFU SPKI pin). Allowlisted in Makefile check-insecure-tls.
		SessionTicketsDisabled: true,
		VerifyConnection:       verifier.verify,
	}, nil
}

// tofuEndpoint parses "host:port" into the pin store's key.
func tofuEndpoint(endpoint string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", 0, &TOFUEndpointError{Endpoint: endpoint, Reason: err.Error()}
	}
	if host == "" {
		return "", 0, &TOFUEndpointError{Endpoint: endpoint, Reason: "empty host"}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, &TOFUEndpointError{Endpoint: endpoint, Reason: "port must be 1-65535"}
	}
	return host, port, nil
}

// tofuVerifier is the VerifyConnection callback's state.
type tofuVerifier struct {
	ctx     context.Context
	store   truststrap.PinStore
	host    string
	port    int
	confirm func(ctx context.Context, pin *truststrap.Pin) error
}

func (v *tofuVerifier) verify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return spkipin.ErrNoCertificates
	}
	stored, err := v.store.Get(v.ctx, v.host, v.port)
	if err != nil {
		var notFound truststrap.PinNotFoundError
		if !errors.As(err, &notFound) {
			return &TOFUPinStoreError{Op: "get", Host: v.host, Port: v.port, Err: err}
		}
		return v.captureFirstUse(cs.PeerCertificates[0])
	}
	if verr := spkipin.VerifySPKIPin(cs.PeerCertificates, stored.SPKISHA256); verr != nil {
		return &TOFUPinMismatchError{
			Host:      v.host,
			Port:      v.port,
			Stored:    stored.SPKISHA256,
			Presented: spkipin.ComputeSPKIPin(cs.PeerCertificates[0]),
			Err:       verr,
		}
	}
	return nil
}

// captureFirstUse records the leaf's pin the way truststrap's TOFU
// bootstrapper does: computed, offered to the confirm hook, persisted.
func (v *tofuVerifier) captureFirstUse(leaf *x509.Certificate) error {
	fingerprint := sha256.Sum256(leaf.Raw)
	pin := &truststrap.Pin{
		Host:            v.host,
		Port:            v.port,
		SPKISHA256:      spkipin.ComputeSPKIPin(leaf),
		CertFingerprint: hex.EncodeToString(fingerprint[:]),
		FirstSeen:       time.Now(),
		Source:          tofuPinSource,
	}
	if v.confirm != nil {
		if cerr := v.confirm(v.ctx, pin); cerr != nil {
			return truststrap.TOFURejectedError{Host: v.host, Port: v.port, Pin: pin, Err: cerr}
		}
	}
	if perr := v.store.Put(v.ctx, pin); perr != nil {
		return &TOFUPinStoreError{Op: "put", Host: v.host, Port: v.port, Err: perr}
	}
	return nil
}
