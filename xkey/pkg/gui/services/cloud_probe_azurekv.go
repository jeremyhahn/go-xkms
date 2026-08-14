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

//go:build azurekv

package services

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// The Azure Key Vault liveness probe is only compiled when the azurekv
// backend is, so availability reported to the Add Backend dialog is genuine.
//
// The probe talks to the Key Vault data plane directly rather than through the
// xkms SDK backend because the SDK exposes no read-only call that reaches
// Azure: AzureKVBackend.ListKeys only walks in-process metadata, and GetKey
// short circuits on that same metadata before issuing a request. Replace this
// with the canonical backend liveness call once the xkms SDK exposes one.
func init() {
	registerCloudProbe(CloudProviderAzureKV, probeAzureKV)
}

// probeAzureKV verifies connectivity to Azure Key Vault by requesting the
// first page of key properties. The call is read-only and proves the vault
// URL resolves, the credential is accepted, and the identity may list keys.
func probeAzureKV(ctx context.Context, config map[string]string) error {
	cred, err := azureKVCredential(config)
	if err != nil {
		return err
	}

	client, err := azkeys.NewClient(config["vault_url"], cred, nil)
	if err != nil {
		return &WrappedError{Msg: "Azure Key Vault client", Err: err}
	}

	pager := client.NewListKeyPropertiesPager(nil)
	if _, err := pager.NextPage(ctx); err != nil {
		return &WrappedError{Msg: "Azure Key Vault list keys", Err: err}
	}
	return nil
}

// azureKVCredential builds a service principal credential when the tenant,
// client, and secret are all configured, and otherwise falls back to the
// ambient credential chain (environment, managed identity, Azure CLI).
func azureKVCredential(config map[string]string) (azcore.TokenCredential, error) {
	tenantID, clientID, clientSecret := config["tenant_id"], config["client_id"], config["client_secret"]
	if tenantID != "" && clientID != "" && clientSecret != "" {
		cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret,
			&azidentity.ClientSecretCredentialOptions{AdditionallyAllowedTenants: []string{"*"}})
		if err != nil {
			return nil, &WrappedError{Msg: "Azure service principal credential", Err: err}
		}
		return cred, nil
	}

	cred, err := azidentity.NewDefaultAzureCredential(
		&azidentity.DefaultAzureCredentialOptions{AdditionallyAllowedTenants: []string{"*"}})
	if err != nil {
		return nil, &WrappedError{Msg: "Azure default credential", Err: err}
	}
	return cred, nil
}
