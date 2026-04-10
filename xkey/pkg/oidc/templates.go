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
	"fmt"
	"strings"
)

// OutputMode defines how tokens/credentials are output after login.
type OutputMode string

const (
	// OutputModeExec runs a custom exec script with tokens.
	OutputModeExec OutputMode = "exec"

	// OutputModeAWSCredentials writes credentials to ~/.aws/credentials.
	OutputModeAWSCredentials OutputMode = "aws-credentials"

	// OutputModeJSON prints tokens as JSON to stdout.
	OutputModeJSON OutputMode = "json"

	// OutputModeNone does not output tokens (just stores them).
	OutputModeNone OutputMode = "none"
)

// ProviderTemplate represents a built-in provider configuration template.
// Templates provide sensible defaults for known providers like AWS, Google, etc.
type ProviderTemplate struct {
	// Name is the template identifier.
	Name string

	// Description describes the provider.
	Description string

	// Issuer is the OIDC issuer URL (for standard OIDC providers).
	// Empty for AWS since it uses regional endpoints.
	Issuer string

	// AuthorizeEndpointTemplate is the authorization endpoint URL template.
	// May contain {region} placeholder for regional endpoints.
	AuthorizeEndpointTemplate string

	// TokenEndpointTemplate is the token endpoint URL template.
	// May contain {region} placeholder for regional endpoints.
	TokenEndpointTemplate string

	// ClientID is the default client ID for this provider.
	ClientID string

	// ClientIDCrossDevice is the client ID for cross-device flow.
	ClientIDCrossDevice string

	// Scopes are the default scopes to request.
	Scopes []string

	// DPoP indicates whether DPoP is required.
	DPoP bool

	// DefaultOutput is the default output mode.
	DefaultOutput OutputMode

	// DefaultAWSProfile is the default AWS profile name (for AWS template).
	DefaultAWSProfile string

	// DefaultAutoRefresh is the default auto-refresh interval in seconds.
	// 0 means no auto-refresh.
	DefaultAutoRefresh int

	// SupportsRemoteFlow indicates whether cross-device flow is supported.
	SupportsRemoteFlow bool

	// CustomResponseHandler is the name of a custom response handler (e.g., "aws").
	// Empty means standard OIDC response handling.
	CustomResponseHandler string

	// RequiresRegion indicates the provider requires a region parameter.
	RequiresRegion bool
}

// BuiltinTemplates contains pre-configured provider templates.
var BuiltinTemplates = map[string]*ProviderTemplate{
	"aws": {
		Name:                      "aws",
		Description:               "AWS Console credentials (native AWS OIDC)",
		AuthorizeEndpointTemplate: "https://{region}.signin.aws.amazon.com/v1/authorize",
		TokenEndpointTemplate:     "https://{region}.signin.aws.amazon.com/v1/token",
		ClientID:                  "arn:aws:signin:::devtools/same-device",
		ClientIDCrossDevice:       "arn:aws:signin:::devtools/cross-device",
		Scopes:                    []string{"openid"},
		DPoP:                      true,
		DefaultOutput:             OutputModeAWSCredentials,
		DefaultAWSProfile:         "default",
		DefaultAutoRefresh:        840, // 14 minutes (credentials last 15 min)
		SupportsRemoteFlow:        true,
		CustomResponseHandler:     "aws",
		RequiresRegion:            true,
	},
	"aws-exec": {
		Name:                      "aws-exec",
		Description:               "AWS Console credentials with exec script",
		AuthorizeEndpointTemplate: "https://{region}.signin.aws.amazon.com/v1/authorize",
		TokenEndpointTemplate:     "https://{region}.signin.aws.amazon.com/v1/token",
		ClientID:                  "arn:aws:signin:::devtools/same-device",
		ClientIDCrossDevice:       "arn:aws:signin:::devtools/cross-device",
		Scopes:                    []string{"openid"},
		DPoP:                      true,
		DefaultOutput:             OutputModeExec,
		DefaultAutoRefresh:        840,
		SupportsRemoteFlow:        true,
		CustomResponseHandler:     "aws",
		RequiresRegion:            true,
	},
	"google": {
		Name:               "google",
		Description:        "Google accounts",
		Issuer:             "https://accounts.google.com",
		Scopes:             []string{"openid", "profile", "email", "offline_access"},
		DPoP:               false,
		DefaultOutput:      OutputModeExec,
		SupportsRemoteFlow: false,
	},
	"microsoft": {
		Name:               "microsoft",
		Description:        "Microsoft Entra ID (Azure AD)",
		Issuer:             "https://login.microsoftonline.com/common/v2.0",
		Scopes:             []string{"openid", "profile", "email", "offline_access"},
		DPoP:               false,
		DefaultOutput:      OutputModeExec,
		SupportsRemoteFlow: false,
	},
	"okta": {
		Name:               "okta",
		Description:        "Okta (requires issuer URL)",
		Scopes:             []string{"openid", "profile", "email", "offline_access"},
		DPoP:               false,
		DefaultOutput:      OutputModeExec,
		SupportsRemoteFlow: false,
	},
	"auth0": {
		Name:               "auth0",
		Description:        "Auth0 (requires issuer URL)",
		Scopes:             []string{"openid", "profile", "email", "offline_access"},
		DPoP:               false,
		DefaultOutput:      OutputModeExec,
		SupportsRemoteFlow: false,
	},
	"keycloak": {
		Name:               "keycloak",
		Description:        "Keycloak (requires issuer URL)",
		Scopes:             []string{"openid", "profile", "email", "offline_access"},
		DPoP:               false,
		DefaultOutput:      OutputModeExec,
		SupportsRemoteFlow: false,
	},
}

// GetTemplate returns a provider template by name.
func GetTemplate(name string) (*ProviderTemplate, error) {
	name = strings.ToLower(name)
	template, ok := BuiltinTemplates[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrTemplateNotFound, name)
	}
	return template, nil
}

// ListTemplates returns all available template names.
func ListTemplates() []string {
	names := make([]string, 0, len(BuiltinTemplates))
	for name := range BuiltinTemplates {
		names = append(names, name)
	}
	return names
}

// ResolveEndpoint resolves a template endpoint URL by replacing placeholders.
func (t *ProviderTemplate) ResolveEndpoint(template string, region string) string {
	if template == "" {
		return ""
	}
	return strings.ReplaceAll(template, "{region}", region)
}

// ResolveAuthorizeEndpoint resolves the authorization endpoint for the given region.
func (t *ProviderTemplate) ResolveAuthorizeEndpoint(region string) string {
	return t.ResolveEndpoint(t.AuthorizeEndpointTemplate, region)
}

// ResolveTokenEndpoint resolves the token endpoint for the given region.
func (t *ProviderTemplate) ResolveTokenEndpoint(region string) string {
	return t.ResolveEndpoint(t.TokenEndpointTemplate, region)
}

// GetClientID returns the appropriate client ID based on flow type.
func (t *ProviderTemplate) GetClientID(remoteFlow bool) string {
	if remoteFlow && t.ClientIDCrossDevice != "" {
		return t.ClientIDCrossDevice
	}
	return t.ClientID
}

// ExtendedProviderConfig extends ProviderConfig with template and output options.
type ExtendedProviderConfig struct {
	ProviderConfig

	// Template is the name of the built-in template to use.
	// If set, defaults are loaded from the template.
	Template string

	// Region is the AWS region (for AWS template).
	Region string

	// DPoP enables DPoP token binding.
	DPoP bool

	// RemoteFlow enables cross-device authentication flow.
	RemoteFlow bool

	// Output specifies how to output tokens after login.
	Output OutputMode

	// AWSProfile is the target AWS profile name (for aws-credentials output).
	AWSProfile string

	// Exec is the command to execute after login (for exec output).
	Exec string

	// AutoRefresh is the auto-refresh interval in seconds.
	AutoRefresh int

	// Background runs auto-refresh in background.
	Background bool

	// LogFile is the log file for background refresh.
	LogFile string

	// DPoPKey is the DPoP key for this provider (populated during login).
	DPoPKey *DPoPKey
}

// NewExtendedProviderConfig creates a new extended provider config from a template.
func NewExtendedProviderConfig(templateName string) (*ExtendedProviderConfig, error) {
	template, err := GetTemplate(templateName)
	if err != nil {
		return nil, err
	}

	config := &ExtendedProviderConfig{
		ProviderConfig: ProviderConfig{
			ClientID: template.ClientID,
			Scopes:   template.Scopes,
		},
		Template:    templateName,
		DPoP:        template.DPoP,
		Output:      template.DefaultOutput,
		AWSProfile:  template.DefaultAWSProfile,
		AutoRefresh: template.DefaultAutoRefresh,
	}

	return config, nil
}

// ApplyTemplate applies template defaults to the config, without overwriting existing values.
func (c *ExtendedProviderConfig) ApplyTemplate(template *ProviderTemplate) {
	if c.ProviderConfig.ClientID == "" {
		c.ProviderConfig.ClientID = template.ClientID
	}
	if len(c.ProviderConfig.Scopes) == 0 {
		c.ProviderConfig.Scopes = template.Scopes
	}
	if c.Output == "" {
		c.Output = template.DefaultOutput
	}
	if c.AWSProfile == "" {
		c.AWSProfile = template.DefaultAWSProfile
	}
	if c.AutoRefresh == 0 {
		c.AutoRefresh = template.DefaultAutoRefresh
	}
	// DPoP from template if not explicitly set
	if !c.DPoP && template.DPoP {
		c.DPoP = template.DPoP
	}
}

// ResolveEndpoints resolves template endpoint placeholders and sets up the provider.
func (c *ExtendedProviderConfig) ResolveEndpoints(template *ProviderTemplate, region string) (authorizeEndpoint, tokenEndpoint string) {
	authorizeEndpoint = template.ResolveAuthorizeEndpoint(region)
	tokenEndpoint = template.ResolveTokenEndpoint(region)

	// Update client ID for remote flow
	if c.RemoteFlow {
		c.ProviderConfig.ClientID = template.GetClientID(true)
	}

	return authorizeEndpoint, tokenEndpoint
}

// Validate validates the extended provider config.
func (c *ExtendedProviderConfig) Validate() error {
	// Check template-specific requirements
	if c.Template != "" {
		template, err := GetTemplate(c.Template)
		if err != nil {
			return err
		}

		if template.RequiresRegion && c.Region == "" {
			return fmt.Errorf("oidc: template '%s' requires --region", c.Template)
		}
	}

	// Standard validation
	if c.ProviderConfig.ClientID == "" {
		return ErrInvalidClientID
	}

	return nil
}
