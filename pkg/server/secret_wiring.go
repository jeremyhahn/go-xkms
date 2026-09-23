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

package server

import (
	"errors"

	qrdbsecret "github.com/jeremyhahn/go-qrdb/sdk/go/secret"
)

// buildSecretRegistry constructs the server's secret resolver registry for
// resolving URI-addressed secrets at startup. When the credential service
// is available, a credential:// resolver backed by that service is registered.
// Literal passthrough is automatic via the registry's fallback behaviour.
//
// The CA is system-scoped, so only the system credential service is wired here;
// per-tenant credential routing is not required for CA key passwords.
func (s *Server) buildSecretRegistry() *qrdbsecret.ResolverRegistry {
	reg := qrdbsecret.NewResolverRegistry()
	if svc := s.CredentialService(); svc != nil {
		reg.Register(qrdbsecret.NewCredentialResolver(svc.RetrieveCredential))
	}
	return reg
}

// resolveConfigSecrets runs go-qrdb's canonical ConfigProcessor once over the
// entire loaded configuration (s.config), the single resolution point for
// every types.SecretValue field reachable from it: the CA identity and
// software-keystore passwords, the cluster CA key passphrase, and the phone
// backend's Noise static key all resolve here now, in place of their own
// former buildSecretRegistry().Resolve call.
//
// The walker treats a protected SecretValue target strictly: it must
// reference a secret a registered resolver actually claims, or the walk
// reports it via qrdbsecret.UnresolvableTargetError. That is the expected,
// non-fatal outcome for the overwhelming majority of fields on any given
// boot -- an unconfigured field (empty Raw) or an operator-supplied literal
// (a bare passphrase, a bare PIN) is not a reference at all. Both are left
// exactly as decoded; types.SecretValueBytes already treats an empty or
// literal SecretValue correctly without ever going through this processor,
// so nothing here needs to touch them. Only a reference this registry DID
// claim but could not fetch -- a genuine credential-store failure -- is a
// real problem, and that is the one case this function reports.
//
// Fields consumed earlier in Server.New than the credential service exists
// to back this call (barrier.passphrase, rng/pkcs11 pins, the AWS/Azure/Vault
// credentials) are read before resolveConfigSecrets can run and so are
// unaffected by it: a literal value for them still works exactly as before,
// and a credential:// reference for them still fails closed the moment it is
// read, via types.SecretValueBytes's own *types.SecretReferenceUnresolvedError
// guard -- the same behaviour as before this function existed. Giving those
// fields real resolution requires a bootstrap-time resolver that does not
// depend on the barrier the credential service itself needs, which is a
// separate, scoped change.
func (s *Server) resolveConfigSecrets() error {
	reg := s.buildSecretRegistry()
	proc := qrdbsecret.NewConfigProcessor(reg)
	result, err := proc.Process(s.ctx, s.config)
	if err == nil {
		return nil
	}

	// Partition result.Errors: an UnresolvableTargetError is the tolerated
	// "nothing to resolve here" outcome described above; anything else (a
	// ResolutionFailedError from a claimed-but-failed lookup, an
	// UnwritableTargetError, a MaxDepthExceededError) is a real failure.
	var genuine []error
	for _, walkErr := range result.Errors {
		var unresolvable *qrdbsecret.UnresolvableTargetError
		if errors.As(walkErr, &unresolvable) {
			continue
		}
		genuine = append(genuine, walkErr)
	}
	if len(genuine) == 0 {
		return nil
	}
	return &ErrConfigSecretResolution{Err: errors.Join(genuine...)}
}
