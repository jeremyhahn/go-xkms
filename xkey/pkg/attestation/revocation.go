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

package attestation

import (
	"sync"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// statusLists holds one HTTP status list source per URL for the life of the
// process. The attestation trust is loaded afresh for every verification,
// so the source, and the list it caches for as long as the response's
// Cache-Control allows, has to outlive any one of them.
var statusLists sync.Map // URL -> *xkms.AndroidHTTPStatusList

// RevocationSource resolves the Android attestation certificate revocation
// status list the phone section configures: the copy at
// attestation_status_file when it is set, else the list fetched from
// attestation_status_url, Google's when that is empty. It makes no network
// request; the HTTP list is fetched when a chain is first checked.
func RevocationSource(phone config.PhoneConfig) (xkms.AndroidStatusListSource, error) {
	if phone.AttestationStatusFile != "" {
		list, err := xkms.LoadAndroidStatusListFile(phone.AttestationStatusFile)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: err}
		}
		return list, nil
	}

	url := phone.AttestationStatusURL
	if url == "" {
		url = xkms.AndroidGoogleStatusListURL
	}
	if cached, ok := statusLists.Load(url); ok {
		return cached.(*xkms.AndroidHTTPStatusList), nil
	}
	source, err := xkms.NewAndroidHTTPStatusList(xkms.AndroidHTTPStatusListOptions{URL: url})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDeviceAttestVerifyFailed, Cause: err}
	}
	actual, _ := statusLists.LoadOrStore(url, source)
	return actual.(*xkms.AndroidHTTPStatusList), nil
}
