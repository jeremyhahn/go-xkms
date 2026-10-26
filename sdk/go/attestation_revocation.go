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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
)

// The Android attestation certificate revocation status list an
// AndroidDeviceTrust checks every chain certificate against
// (docs/references/android-key-attestation.md §Certificate revocation
// status list).

// AndroidStatusListSource supplies the status list. Set one on
// AndroidDeviceTrust.Revocation: an *AndroidHTTPStatusList, or an
// *AndroidStatusList loaded from a file or bytes.
type AndroidStatusListSource = android.StatusListSource

// AndroidStatusList is a parsed status list; it is its own source.
type AndroidStatusList = android.StatusList

// AndroidHTTPStatusList fetches the status list and caches it for the
// freshness the response allows. A stale, unfetchable list fails closed.
type AndroidHTTPStatusList = android.HTTPStatusList

// AndroidHTTPStatusListOptions configures an AndroidHTTPStatusList.
type AndroidHTTPStatusListOptions = android.HTTPStatusListOptions

// AndroidRevokedCertificateError names a listed chain certificate's
// serial and status.
type AndroidRevokedCertificateError = android.RevokedCertificateError

// AndroidGoogleStatusListURL is where Google publishes the status list.
const AndroidGoogleStatusListURL = android.GoogleStatusListURL

var (
	// ErrAndroidCertificateRevoked is the sentinel a listed chain
	// certificate fails with.
	ErrAndroidCertificateRevoked = android.ErrCertificateRevoked

	// ErrAndroidStatusListUnavailable is returned when no fresh status list
	// can be obtained.
	ErrAndroidStatusListUnavailable = android.ErrStatusListUnavailable

	// ErrAndroidStatusListMalformed is returned for a document that does
	// not conform to the status list schema.
	ErrAndroidStatusListMalformed = android.ErrStatusListMalformed

	// ErrNoAndroidRevocationSource is returned by VerifyAndroidDeviceKey
	// when AndroidDeviceTrust.Revocation is nil.
	ErrNoAndroidRevocationSource = attestation.ErrNoRevocationSource
)

// NewAndroidHTTPStatusList returns a status list source fetching over
// HTTP. It makes no request until the list is first needed.
func NewAndroidHTTPStatusList(opts AndroidHTTPStatusListOptions) (*AndroidHTTPStatusList, error) {
	return android.NewHTTPStatusList(opts)
}

// ParseAndroidStatusList parses and validates a status list document.
func ParseAndroidStatusList(data []byte) (*AndroidStatusList, error) {
	return android.ParseStatusList(data)
}

// LoadAndroidStatusListFile reads and parses a status list file, for a
// host that cannot reach the published list.
func LoadAndroidStatusListFile(path string) (*AndroidStatusList, error) {
	return android.LoadStatusListFile(path)
}
