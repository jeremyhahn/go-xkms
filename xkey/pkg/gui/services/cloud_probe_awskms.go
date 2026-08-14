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

package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// awsProbeKeyLimit keeps the liveness call to the smallest possible response.
const awsProbeKeyLimit = 1

// The AWS KMS liveness probe is only compiled when the awskms backend is, so
// availability reported to the Add Backend dialog is genuine.
//
// The probe talks to the AWS KMS API directly rather than through the xkms
// SDK backend because the SDK exposes no read-only call that reaches AWS:
// AWSKMSBackend.ListKeys only walks in-process metadata, and GetKey short
// circuits on that same metadata before issuing a request. Replace this with
// the canonical backend liveness call once the xkms SDK exposes one.
func init() {
	registerCloudProbe(CloudProviderAWSKMS, probeAWSKMS)
}

// probeAWSKMS verifies connectivity to AWS KMS with a kms:ListKeys call
// limited to a single key. The call is read-only and proves the credentials
// resolve, are accepted by the region endpoint, and carry ListKeys authority.
func probeAWSKMS(ctx context.Context, config map[string]string) error {
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(config["region"]),
	}
	if profile := config["profile"]; profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(profile))
	}
	accessKeyID, secretAccessKey := config["access_key_id"], config["secret_access_key"]
	if accessKeyID != "" && secretAccessKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, config["session_token"])))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return &WrappedError{Msg: "AWS credential chain", Err: err}
	}

	var clientOpts []func(*kms.Options)
	if endpoint := config["endpoint"]; endpoint != "" {
		clientOpts = append(clientOpts, func(o *kms.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	client := kms.NewFromConfig(awsCfg, clientOpts...)
	if _, err := client.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(awsProbeKeyLimit)}); err != nil {
		return &WrappedError{Msg: "AWS KMS ListKeys", Err: err}
	}
	return nil
}
