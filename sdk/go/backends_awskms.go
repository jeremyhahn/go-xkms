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

//go:build awskms

package xkms

import awskmsbackend "github.com/jeremyhahn/go-xkms/pkg/backend/awskms"

// AWS KMS crypto backend re-exported behind the awskms build tag, matching
// the gating of pkg/backend/awskms. It conforms to the same Backend contract
// as the local backends.

// AWSKMSBackend is the AWS KMS crypto backend.
type AWSKMSBackend = awskmsbackend.Backend

// AWSKMSBackendConfig configures the AWS KMS crypto backend.
type AWSKMSBackendConfig = awskmsbackend.Config

// NewAWSKMSBackend constructs an AWS KMS crypto backend.
var NewAWSKMSBackend = awskmsbackend.NewBackend

// AWSKMSClient is the AWS KMS client interface the backend operates against.
type AWSKMSClient = awskmsbackend.KMSClient

// AWSKMSMockClient is the in-memory AWS KMS client used to exercise the
// backend without reaching the real AWS API.
type AWSKMSMockClient = awskmsbackend.MockKMSClient

// NewAWSKMSBackendWithClient constructs an AWS KMS crypto backend using the
// supplied client instead of building one from the AWS config chain.
var NewAWSKMSBackendWithClient = awskmsbackend.NewBackendWithClient
