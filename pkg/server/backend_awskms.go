// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build awskms

package server

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/awskms"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// initAWSKMSBackend initializes the AWS KMS backend if enabled in configuration
func (s *Server) initAWSKMSBackend() error {
	if s.config.Backends.AWSKMS == nil || !s.config.Backends.AWSKMS.Enabled {
		return nil
	}

	// Create storage for AWS KMS metadata
	storage, err := file.New(s.config.Storage.Path + "/awskms")
	if err != nil {
		return fmt.Errorf("failed to create AWS KMS storage: %w", err)
	}

	awsBackend, err := awskms.NewBackend(&awskms.Config{
		Region:          s.config.Backends.AWSKMS.Region,
		AccessKeyID:     s.config.Backends.AWSKMS.AccessKey,
		SecretAccessKey: s.config.Backends.AWSKMS.SecretKey,
		Endpoint:        s.config.Backends.AWSKMS.Endpoint,
		KeyStorage:      storage,
	})
	if err != nil {
		return fmt.Errorf("failed to create AWS KMS backend: %w", err)
	}

	s.backends["awskms"] = awsBackend
	s.logger.Info("AWS KMS backend initialized", "backend", "awskms", "region", s.config.Backends.AWSKMS.Region)
	return nil
}
