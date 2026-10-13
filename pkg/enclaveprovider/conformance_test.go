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

package enclaveprovider_test

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/enclaveprovider"
	"github.com/jeremyhahn/go-xkms/pkg/enclaveprovider/enclaveprovidertest"
)

// TestConformance_SoftwareBackend runs go-enclave's provider conformance
// suite, in both modes, over the software backend. The other backends run the
// same suite from their own packages, beside the in-memory fixtures they
// already use.
func TestConformance_SoftwareBackend(t *testing.T) {
	backend, attrs := enclaveprovider.NewSoftwareSealer(t)
	enclaveprovidertest.Run(t, enclaveprovidertest.Backend{Sealer: backend, KeyAttributes: attrs})
}
