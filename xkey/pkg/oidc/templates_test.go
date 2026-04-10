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

package oidc

import (
	"errors"
	"testing"
)

func TestGetTemplate(t *testing.T) {
	tests := []struct {
		name        string
		templateKey string
		wantErr     bool
		checkName   string
	}{
		{
			name:        "aws template",
			templateKey: "aws",
			wantErr:     false,
			checkName:   "aws",
		},
		{
			name:        "aws-exec template",
			templateKey: "aws-exec",
			wantErr:     false,
			checkName:   "aws-exec",
		},
		{
			name:        "google template",
			templateKey: "google",
			wantErr:     false,
			checkName:   "google",
		},
		{
			name:        "microsoft template",
			templateKey: "microsoft",
			wantErr:     false,
			checkName:   "microsoft",
		},
		{
			name:        "okta template",
			templateKey: "okta",
			wantErr:     false,
			checkName:   "okta",
		},
		{
			name:        "case insensitive",
			templateKey: "AWS",
			wantErr:     false,
			checkName:   "aws",
		},
		{
			name:        "not found",
			templateKey: "nonexistent",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template, err := GetTemplate(tt.templateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if template == nil {
					t.Error("GetTemplate() returned nil template")
					return
				}
				if template.Name != tt.checkName {
					t.Errorf("Template name = %s, want %s", template.Name, tt.checkName)
				}
			}
			if tt.wantErr && !errors.Is(err, ErrTemplateNotFound) {
				t.Errorf("Expected ErrTemplateNotFound, got %v", err)
			}
		})
	}
}

func TestListTemplates(t *testing.T) {
	templates := ListTemplates()
	if len(templates) == 0 {
		t.Error("ListTemplates() returned empty list")
	}

	// Check for expected templates
	expected := map[string]bool{
		"aws":       false,
		"aws-exec":  false,
		"google":    false,
		"microsoft": false,
		"okta":      false,
		"auth0":     false,
		"keycloak":  false,
	}

	for _, name := range templates {
		expected[name] = true
	}

	for name, found := range expected {
		if !found {
			t.Errorf("Expected template '%s' not found in list", name)
		}
	}
}

func TestProviderTemplate_AWSProperties(t *testing.T) {
	template, err := GetTemplate("aws")
	if err != nil {
		t.Fatalf("GetTemplate(aws) error = %v", err)
	}

	// Verify AWS-specific properties
	if template.DPoP != true {
		t.Error("AWS template should have DPoP enabled")
	}

	if template.RequiresRegion != true {
		t.Error("AWS template should require region")
	}

	if template.CustomResponseHandler != "aws" {
		t.Errorf("AWS template handler = %s, want 'aws'", template.CustomResponseHandler)
	}

	if template.DefaultOutput != OutputModeAWSCredentials {
		t.Errorf("AWS template output = %s, want aws-credentials", template.DefaultOutput)
	}

	if template.ClientID != "arn:aws:signin:::devtools/same-device" {
		t.Errorf("AWS template ClientID = %s, unexpected", template.ClientID)
	}

	if template.ClientIDCrossDevice != "arn:aws:signin:::devtools/cross-device" {
		t.Errorf("AWS template ClientIDCrossDevice = %s, unexpected", template.ClientIDCrossDevice)
	}

	if template.DefaultAutoRefresh != 840 {
		t.Errorf("AWS template DefaultAutoRefresh = %d, want 840", template.DefaultAutoRefresh)
	}
}

func TestProviderTemplate_ResolveEndpoints(t *testing.T) {
	template, err := GetTemplate("aws")
	if err != nil {
		t.Fatalf("GetTemplate(aws) error = %v", err)
	}

	tests := []struct {
		region        string
		wantAuthorize string
		wantToken     string
	}{
		{
			region:        "us-east-1",
			wantAuthorize: "https://us-east-1.signin.aws.amazon.com/v1/authorize",
			wantToken:     "https://us-east-1.signin.aws.amazon.com/v1/token",
		},
		{
			region:        "eu-west-1",
			wantAuthorize: "https://eu-west-1.signin.aws.amazon.com/v1/authorize",
			wantToken:     "https://eu-west-1.signin.aws.amazon.com/v1/token",
		},
		{
			region:        "ap-northeast-1",
			wantAuthorize: "https://ap-northeast-1.signin.aws.amazon.com/v1/authorize",
			wantToken:     "https://ap-northeast-1.signin.aws.amazon.com/v1/token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			authEndpoint := template.ResolveAuthorizeEndpoint(tt.region)
			if authEndpoint != tt.wantAuthorize {
				t.Errorf("ResolveAuthorizeEndpoint() = %s, want %s", authEndpoint, tt.wantAuthorize)
			}

			tokenEndpoint := template.ResolveTokenEndpoint(tt.region)
			if tokenEndpoint != tt.wantToken {
				t.Errorf("ResolveTokenEndpoint() = %s, want %s", tokenEndpoint, tt.wantToken)
			}
		})
	}
}

func TestProviderTemplate_GetClientID(t *testing.T) {
	template, err := GetTemplate("aws")
	if err != nil {
		t.Fatalf("GetTemplate(aws) error = %v", err)
	}

	// Same-device flow
	clientID := template.GetClientID(false)
	if clientID != "arn:aws:signin:::devtools/same-device" {
		t.Errorf("GetClientID(false) = %s, want same-device client", clientID)
	}

	// Cross-device flow
	clientID = template.GetClientID(true)
	if clientID != "arn:aws:signin:::devtools/cross-device" {
		t.Errorf("GetClientID(true) = %s, want cross-device client", clientID)
	}
}

func TestProviderTemplate_GoogleProperties(t *testing.T) {
	template, err := GetTemplate("google")
	if err != nil {
		t.Fatalf("GetTemplate(google) error = %v", err)
	}

	if template.Issuer != "https://accounts.google.com" {
		t.Errorf("Google issuer = %s, unexpected", template.Issuer)
	}

	if template.DPoP != false {
		t.Error("Google template should not require DPoP")
	}

	if template.RequiresRegion != false {
		t.Error("Google template should not require region")
	}

	// Should have standard scopes
	hasOpenID := false
	for _, scope := range template.Scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		t.Error("Google template should have openid scope")
	}
}

func TestNewExtendedProviderConfig(t *testing.T) {
	config, err := NewExtendedProviderConfig("aws")
	if err != nil {
		t.Fatalf("NewExtendedProviderConfig() error = %v", err)
	}

	if config.Template != "aws" {
		t.Errorf("Template = %s, want aws", config.Template)
	}

	if config.DPoP != true {
		t.Error("DPoP should be enabled for AWS")
	}

	if config.Output != OutputModeAWSCredentials {
		t.Errorf("Output = %s, want aws-credentials", config.Output)
	}

	if config.AutoRefresh != 840 {
		t.Errorf("AutoRefresh = %d, want 840", config.AutoRefresh)
	}

	if config.ProviderConfig.ClientID == "" {
		t.Error("ClientID should be set from template")
	}
}

func TestNewExtendedProviderConfig_NotFound(t *testing.T) {
	_, err := NewExtendedProviderConfig("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent template")
	}
	if !errors.Is(err, ErrTemplateNotFound) {
		t.Errorf("Expected ErrTemplateNotFound, got %v", err)
	}
}

func TestExtendedProviderConfig_ApplyTemplate(t *testing.T) {
	template, _ := GetTemplate("aws")

	config := &ExtendedProviderConfig{
		ProviderConfig: ProviderConfig{
			ClientID: "custom-client-id", // Should not be overwritten
		},
		Output: "", // Should be set from template
	}

	config.ApplyTemplate(template)

	// ClientID should remain as custom (not overwritten)
	if config.ProviderConfig.ClientID != "custom-client-id" {
		t.Error("ApplyTemplate should not overwrite existing ClientID")
	}

	// Output should be set from template
	if config.Output != OutputModeAWSCredentials {
		t.Errorf("Output = %s, want aws-credentials", config.Output)
	}

	// Scopes should be set from template
	if len(config.ProviderConfig.Scopes) == 0 {
		t.Error("Scopes should be set from template")
	}
}

func TestExtendedProviderConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ExtendedProviderConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid AWS config with region",
			config: &ExtendedProviderConfig{
				ProviderConfig: ProviderConfig{
					ClientID: "test-client",
				},
				Template: "aws",
				Region:   "us-east-1",
			},
			wantErr: false,
		},
		{
			name: "AWS config missing region",
			config: &ExtendedProviderConfig{
				ProviderConfig: ProviderConfig{
					ClientID: "test-client",
				},
				Template: "aws",
				Region:   "",
			},
			wantErr: true,
			errMsg:  "requires --region",
		},
		{
			name: "missing client ID",
			config: &ExtendedProviderConfig{
				ProviderConfig: ProviderConfig{
					ClientID: "",
				},
				Template: "",
			},
			wantErr: true,
		},
		{
			name: "valid non-AWS config without region",
			config: &ExtendedProviderConfig{
				ProviderConfig: ProviderConfig{
					ClientID: "test-client",
				},
				Template: "google",
			},
			wantErr: false,
		},
		{
			name: "invalid template",
			config: &ExtendedProviderConfig{
				ProviderConfig: ProviderConfig{
					ClientID: "test-client",
				},
				Template: "nonexistent",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtendedProviderConfig_ResolveEndpoints(t *testing.T) {
	template, _ := GetTemplate("aws")

	config := &ExtendedProviderConfig{
		ProviderConfig: ProviderConfig{
			ClientID: "test-client",
		},
	}

	authEndpoint, tokenEndpoint := config.ResolveEndpoints(template, "us-west-2")

	if authEndpoint != "https://us-west-2.signin.aws.amazon.com/v1/authorize" {
		t.Errorf("authEndpoint = %s, unexpected", authEndpoint)
	}

	if tokenEndpoint != "https://us-west-2.signin.aws.amazon.com/v1/token" {
		t.Errorf("tokenEndpoint = %s, unexpected", tokenEndpoint)
	}
}

func TestExtendedProviderConfig_ResolveEndpoints_RemoteFlow(t *testing.T) {
	template, _ := GetTemplate("aws")

	config := &ExtendedProviderConfig{
		ProviderConfig: ProviderConfig{
			ClientID: "initial-client",
		},
		RemoteFlow: true,
	}

	config.ResolveEndpoints(template, "us-east-1")

	// ClientID should be updated to cross-device
	if config.ProviderConfig.ClientID != "arn:aws:signin:::devtools/cross-device" {
		t.Errorf("ClientID = %s, want cross-device client", config.ProviderConfig.ClientID)
	}
}

func TestOutputMode_Constants(t *testing.T) {
	// Verify output mode constants
	if OutputModeExec != "exec" {
		t.Errorf("OutputModeExec = %s, want 'exec'", OutputModeExec)
	}
	if OutputModeAWSCredentials != "aws-credentials" {
		t.Errorf("OutputModeAWSCredentials = %s, want 'aws-credentials'", OutputModeAWSCredentials)
	}
	if OutputModeJSON != "json" {
		t.Errorf("OutputModeJSON = %s, want 'json'", OutputModeJSON)
	}
	if OutputModeNone != "none" {
		t.Errorf("OutputModeNone = %s, want 'none'", OutputModeNone)
	}
}

func TestProviderTemplate_SupportsRemoteFlow(t *testing.T) {
	tests := []struct {
		templateName string
		wantSupport  bool
	}{
		{"aws", true},
		{"aws-exec", true},
		{"google", false},
		{"okta", false},
	}

	for _, tt := range tests {
		t.Run(tt.templateName, func(t *testing.T) {
			template, err := GetTemplate(tt.templateName)
			if err != nil {
				t.Fatalf("GetTemplate() error = %v", err)
			}

			if template.SupportsRemoteFlow != tt.wantSupport {
				t.Errorf("SupportsRemoteFlow = %v, want %v", template.SupportsRemoteFlow, tt.wantSupport)
			}
		})
	}
}

func TestProviderTemplate_ResolveEndpoint_Empty(t *testing.T) {
	template := &ProviderTemplate{
		AuthorizeEndpointTemplate: "",
	}

	result := template.ResolveEndpoint("", "us-east-1")
	if result != "" {
		t.Error("ResolveEndpoint should return empty string for empty template")
	}
}
