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

//go:build gcpkms

package gcpkms

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/enclaveprovider/enclaveprovidertest"
)

// TestEnclaveProvider_Conformance runs go-enclave's provider conformance
// suite, in both modes, over GCP Cloud KMS against the in-process KMS double.
func TestEnclaveProvider_Conformance(t *testing.T) {
	f := newGCPSealAuthFixture(t)
	enclaveprovidertest.Run(t, enclaveprovidertest.Backend{Sealer: f.backend, KeyAttributes: f.keyA})
}
