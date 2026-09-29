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

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/handlers"
)

func TestAWSOutputDefaults(t *testing.T) {
	tests := []struct {
		name            string
		entry           *OIDCProviderEntry
		wantProfile     string
		wantCredentials string
	}{
		{
			name:            "both fields set use the entry's values",
			entry:           &OIDCProviderEntry{AWSProfile: "custom-profile", AWSCredentialsFile: "/tmp/creds"},
			wantProfile:     "custom-profile",
			wantCredentials: "/tmp/creds",
		},
		{
			name:            "both fields empty fall back to package defaults",
			entry:           &OIDCProviderEntry{},
			wantProfile:     handlers.DefaultAWSProfile,
			wantCredentials: handlers.DefaultAWSCredentialsPath,
		},
		{
			name:            "only the profile is set",
			entry:           &OIDCProviderEntry{AWSProfile: "custom-profile"},
			wantProfile:     "custom-profile",
			wantCredentials: handlers.DefaultAWSCredentialsPath,
		},
		{
			name:            "only the credentials file is set",
			entry:           &OIDCProviderEntry{AWSCredentialsFile: "/tmp/creds"},
			wantProfile:     handlers.DefaultAWSProfile,
			wantCredentials: "/tmp/creds",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile, credentialsFile := awsOutputDefaults(tc.entry)
			assert.Equal(t, tc.wantProfile, profile)
			assert.Equal(t, tc.wantCredentials, credentialsFile)
		})
	}
}
