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

//go:build awskms

package server

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// buildAWSKMSPlatformSealer resolves the types.Sealer for the awskms
// credential strategy. Unlike pkcs11/vault, AWS KMS needs no operator
// secret this phase of startup could fail to resolve: it authenticates with
// ambient credentials (IAM role, environment, instance profile), the same
// "optional -- uses IAM role or environment credentials when absent" mode
// awskms.Config.AccessKeyID/SecretAccessKey already document, so no
// AccessKeyID/SecretAccessKey is set here at all -- this call runs before
// resolveConfigSecrets, so backends.awskms.secret_key is not resolved yet in
// any case.
//
// The backend gets its own dedicated metadata storage (separate from the
// general "awskms" backend's, initAWSKMSBackend/backend_awskms.go), but
// resolves the SAME self-provisioned wrapping key
// (seal_strategies.go's sealKeyAttributesFor/ensureSealKey, sealKeyCN) the
// barrier's own awskms strategy uses when configured: a CMK is not a
// per-purpose object, so sharing one is deliberate reuse.
func (s *Server) buildAWSKMSPlatformSealer() (types.Sealer, error) {
	if s.config.Backends.AWSKMS == nil {
		return nil, &ErrPlatformStoreStrategyUnavailable{
			Strategy: "awskms",
			Reason:   "backends.awskms is not configured",
		}
	}

	metadataStorage, err := s.createStorage("platform-store-awskms")
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "platform store awskms storage", Err: err}
	}

	backend, err := awskms.NewBackend(&awskms.Config{
		Region:      s.config.Backends.AWSKMS.Region,
		Endpoint:    s.config.Backends.AWSKMS.Endpoint,
		KeyStorage:  metadataStorage,
		CertStorage: metadataStorage,
	})
	if err != nil {
		return nil, err
	}

	keyAttrs := sealKeyAttributesFor(types.StoreAWSKMS)
	if err := s.ensureSealKey(seal.StrategyAWSKMS, backend, keyAttrs); err != nil {
		return nil, err
	}

	return &fixedKeyAttrsSealer{inner: backend, attrs: keyAttrs}, nil
}
