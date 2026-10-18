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

package clusterca

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// hsmStrategy keeps the cluster CA signing key inside a shared PKCS#11 HSM that
// every node reaches under the same key label. Key material never leaves the
// HSM: the first node generates the CA hierarchy keys in it (via the provisioner
// signing through the HSM backend), and every node — including joiners — signs
// through the same HSM by referencing the keys by their configured labels. There
// is no promotion because the HSM is the durable, shared store both before and
// after the datastore exists.
//
// The CA identities' keystore type must be pkcs11 so the CA resolves its signing
// keys from the HSM. The shared HSM backend is supplied via StrategyDeps.
type hsmStrategy struct{}

// Name reports the strategy identifier.
func (s *hsmStrategy) Name() KeyStrategyName { return KeyStrategyHSM }

// BootstrapBackends returns a resolver that resolves every keystore lookup to
// the shared HSM backend, so the pre-stage generates the CA hierarchy inside
// the HSM. The node's transport key resolves separately, from KeyBackend.
func (s *hsmStrategy) BootstrapBackends(ctx context.Context, deps *StrategyDeps) (func(string) (xkms.Backend, error), error) {
	if deps.HSMBackend == nil {
		return nil, ErrStrategyMisconfigured
	}
	hsm := deps.HSMBackend
	return func(string) (xkms.Backend, error) { return hsm, nil }, nil
}

// RuntimeBackend returns the shared HSM backend. Every node signs through the
// same HSM, so any node can issue; the CA loads the existing HSM-resident keys
// by their configured labels.
func (s *hsmStrategy) RuntimeBackend(ctx context.Context, deps *StrategyDeps) (xkms.Backend, error) {
	if deps.HSMBackend == nil {
		return nil, ErrStrategyMisconfigured
	}
	return deps.HSMBackend, nil
}
