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

package ipc

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAutofillPayload_Validate_SearchAction_Valid(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillSearch,
		Domain: "example.com",
	}
	assert.NoError(t, p.Validate())
}

func TestAutofillPayload_Validate_SearchAction_MissingDomain(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillSearch,
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "domain is required for search action")
}

func TestAutofillPayload_Validate_GetAction_Valid(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillGet,
		ID:     "cred-123",
	}
	assert.NoError(t, p.Validate())
}

func TestAutofillPayload_Validate_GetAction_MissingID(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillGet,
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "id is required for get action")
}

func TestAutofillPayload_Validate_TOTPAction_Valid(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillTOTP,
		Domain: "github.com",
	}
	assert.NoError(t, p.Validate())
}

func TestAutofillPayload_Validate_TOTPAction_MissingDomain(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillTOTP,
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "domain is required for totp action")
}

func TestAutofillPayload_Validate_TOTPByIDAction_Valid(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillTOTPByID,
		ID:     "oath-456",
	}
	assert.NoError(t, p.Validate())
}

func TestAutofillPayload_Validate_TOTPByIDAction_MissingID(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillTOTPByID,
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "id is required for totp_by_id action")
}

func TestAutofillPayload_Validate_StatusAction_Valid(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillStatus,
	}
	assert.NoError(t, p.Validate())
}

func TestAutofillPayload_Validate_PolicyAction_Valid(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillPolicy,
	}
	assert.NoError(t, p.Validate())
}

func TestAutofillPayload_Validate_EmptyAction(t *testing.T) {
	p := &AutofillPayload{}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "autofill action is required")
}

func TestAutofillPayload_Validate_UnknownAction(t *testing.T) {
	p := &AutofillPayload{
		Action: "delete_everything",
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "unknown autofill action")
}

func TestAutofillPayload_Validate_SearchAction_WithOptionalChallenge(t *testing.T) {
	p := &AutofillPayload{
		Action:    ActionAutofillSearch,
		Domain:    "example.com",
		Challenge: "dGVzdC1jaGFsbGVuZ2U=",
	}
	assert.NoError(t, p.Validate())
}

func TestAutofillPayload_Validate_GetAction_WithOptionalChallenge(t *testing.T) {
	p := &AutofillPayload{
		Action:    ActionAutofillGet,
		ID:        "cred-789",
		Challenge: "dGVzdC1jaGFsbGVuZ2U=",
	}
	assert.NoError(t, p.Validate())
}

func TestAutofillPayload_JSONRoundtrip_Search(t *testing.T) {
	original := &AutofillPayload{
		Action: ActionAutofillSearch,
		Domain: "example.com",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded AutofillPayload
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.Action, decoded.Action)
	assert.Equal(t, original.Domain, decoded.Domain)
}

func TestAutofillPayload_JSONRoundtrip_Get(t *testing.T) {
	original := &AutofillPayload{
		Action:    ActionAutofillGet,
		ID:        "cred-abc",
		Challenge: "dGVzdC1jaGFsbGVuZ2U=",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded AutofillPayload
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.Action, decoded.Action)
	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.Challenge, decoded.Challenge)
}

func TestAutofillPayload_JSONOmitsEmptyFields(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillStatus,
	}
	data, err := json.Marshal(p)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.NotContains(t, jsonStr, "domain")
	assert.NotContains(t, jsonStr, "\"id\"")
	assert.NotContains(t, jsonStr, "challenge")
}

func TestAutofillResult_JSONRoundtrip_Credentials(t *testing.T) {
	original := &AutofillResult{
		Credentials: []AutofillCredential{
			{
				ID:       "cred-1",
				Title:    "Example Account",
				Username: "user@example.com",
				URL:      "https://example.com",
				HasTOTP:  true,
				TOTPID:   "oath-1",
			},
			{
				ID:       "cred-2",
				Title:    "Another Account",
				Username: "admin@example.com",
				URL:      "https://example.com/admin",
				HasTOTP:  false,
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded AutofillResult
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.Len(t, decoded.Credentials, 2)
	assert.Equal(t, "cred-1", decoded.Credentials[0].ID)
	assert.Equal(t, "user@example.com", decoded.Credentials[0].Username)
	assert.True(t, decoded.Credentials[0].HasTOTP)
	assert.Equal(t, "oath-1", decoded.Credentials[0].TOTPID)
	assert.Equal(t, "cred-2", decoded.Credentials[1].ID)
	assert.False(t, decoded.Credentials[1].HasTOTP)
	assert.Empty(t, decoded.Credentials[1].TOTPID)
}

func TestAutofillResult_JSONRoundtrip_Fill(t *testing.T) {
	original := &AutofillResult{
		Fill: &AutofillFillResult{
			Username: "user@example.com",
			Password: "s3cret",
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded AutofillResult
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.NotNil(t, decoded.Fill)
	assert.Equal(t, "user@example.com", decoded.Fill.Username)
	assert.Equal(t, "s3cret", decoded.Fill.Password)
	assert.Nil(t, decoded.Credentials)
	assert.Nil(t, decoded.TOTP)
	assert.Nil(t, decoded.Status)
	assert.Nil(t, decoded.Policy)
}

func TestAutofillResult_JSONRoundtrip_TOTP(t *testing.T) {
	original := &AutofillResult{
		TOTP: &AutofillTOTP{
			Code:      "123456",
			TimeLeft:  15,
			Period:    30,
			AccountID: "oath-abc",
			Issuer:    "GitHub",
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded AutofillResult
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.NotNil(t, decoded.TOTP)
	assert.Equal(t, "123456", decoded.TOTP.Code)
	assert.Equal(t, 15, decoded.TOTP.TimeLeft)
	assert.Equal(t, 30, decoded.TOTP.Period)
	assert.Equal(t, "oath-abc", decoded.TOTP.AccountID)
	assert.Equal(t, "GitHub", decoded.TOTP.Issuer)
}

func TestAutofillResult_JSONRoundtrip_Status(t *testing.T) {
	original := &AutofillResult{
		Status: &AutofillStatus{
			Available:        true,
			AppLocked:        false,
			FillMode:         "auto",
			ExtensionEnabled: true,
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded AutofillResult
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.NotNil(t, decoded.Status)
	assert.True(t, decoded.Status.Available)
	assert.False(t, decoded.Status.AppLocked)
	assert.Equal(t, "auto", decoded.Status.FillMode)
	assert.True(t, decoded.Status.ExtensionEnabled)
}

func TestAutofillResult_JSONRoundtrip_Policy(t *testing.T) {
	original := &AutofillResult{
		Policy: &AutofillPolicyResult{
			FillMode:              "manual",
			TOTPPolicy:            "auto_copy",
			SessionTimeoutSec:     300,
			RequireAuthentication: true,
			AllowedDomains:        []string{"example.com", "corp.internal"},
			BlockedDomains:        []string{"evil.com"},
			MaxFillsPerMinute:     10,
			AuditEnabled:          true,
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded AutofillResult
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.NotNil(t, decoded.Policy)
	assert.Equal(t, "manual", decoded.Policy.FillMode)
	assert.Equal(t, "auto_copy", decoded.Policy.TOTPPolicy)
	assert.Equal(t, 300, decoded.Policy.SessionTimeoutSec)
	assert.True(t, decoded.Policy.RequireAuthentication)
	assert.Equal(t, []string{"example.com", "corp.internal"}, decoded.Policy.AllowedDomains)
	assert.Equal(t, []string{"evil.com"}, decoded.Policy.BlockedDomains)
	assert.Equal(t, 10, decoded.Policy.MaxFillsPerMinute)
	assert.True(t, decoded.Policy.AuditEnabled)
}

func TestAutofillResult_JSONOmitsEmptyFields(t *testing.T) {
	r := &AutofillResult{}
	data, err := json.Marshal(r)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.NotContains(t, jsonStr, "credentials")
	assert.NotContains(t, jsonStr, "fill")
	assert.NotContains(t, jsonStr, "totp")
	assert.NotContains(t, jsonStr, "status")
	assert.NotContains(t, jsonStr, "policy")
}

func TestAutofillCredential_JSONOmitsTOTPIDWhenEmpty(t *testing.T) {
	c := &AutofillCredential{
		ID:       "cred-1",
		Title:    "Test",
		Username: "user",
		URL:      "https://test.com",
		HasTOTP:  false,
	}
	data, err := json.Marshal(c)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.NotContains(t, jsonStr, "totp_id")
}
