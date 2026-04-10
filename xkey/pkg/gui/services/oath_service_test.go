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
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOATHService(t *testing.T) {
	svc := NewOATHService(nil)
	assert.NotNil(t, svc)
}

func TestOATHService_SetContext(t *testing.T) {
	svc := NewOATHService(nil)
	svc.SetContext(context.Background())
}

func TestOATHService_ListAccounts_NoStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.ListAccounts()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHStoreNotSet))
}

func TestOATHService_ListAccounts_Empty(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)
	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	assert.Empty(t, accounts)
}

func TestOATHService_AddAccount(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)
	assert.NotNil(t, acct)
	assert.Equal(t, "totp", acct.Type)
	assert.Equal(t, "GitHub", acct.Issuer)

	// Verify it shows up in list.
	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	assert.Len(t, accounts, 1)
}

func TestOATHService_AddAccount_NoStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.AddAccount("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHStoreNotSet))
}

func TestOATHService_AddAccount_EmptyURI(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)
	_, err := svc.AddAccount("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHInvalidURI))
}

func TestOATHService_AddAccount_InvalidURI(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)
	_, err := svc.AddAccount("not-a-valid-uri")
	assert.Error(t, err)
}

func TestOATHService_DeleteAccount(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)

	err = svc.DeleteAccount(acct.ID)
	assert.NoError(t, err)

	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	assert.Empty(t, accounts)
}

func TestOATHService_DeleteAccount_NoStore(t *testing.T) {
	svc := NewOATHService(nil)
	err := svc.DeleteAccount("some-id")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHStoreNotSet))
}

func TestOATHService_DeleteAccount_EmptyID(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)
	err := svc.DeleteAccount("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHInvalidID))
}

func TestOATHService_GenerateTOTP(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)

	code, err := svc.GenerateTOTP(acct.ID)
	require.NoError(t, err)
	assert.Len(t, code.Code, 6)
	assert.Equal(t, 30, code.Period)
	assert.True(t, code.TimeLeft > 0 && code.TimeLeft <= 30)
}

func TestOATHService_GenerateTOTP_NoStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.GenerateTOTP("some-id")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHStoreNotSet))
}

func TestOATHService_GenerateTOTP_EmptyID(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)
	_, err := svc.GenerateTOTP("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHInvalidID))
}

func TestOATHService_GenerateTOTP_WrongType(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	// Add an HOTP account.
	uri := "otpauth://hotp/Test:user?secret=JBSWY3DPEHPK3PXP&counter=0"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)

	_, err = svc.GenerateTOTP(acct.ID)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHGenerateFailed))
}

func TestOATHService_GenerateHOTP(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	uri := "otpauth://hotp/Test:user?secret=JBSWY3DPEHPK3PXP&counter=0"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)

	code, err := svc.GenerateHOTP(acct.ID)
	require.NoError(t, err)
	assert.Len(t, code.Code, 6)
	assert.Equal(t, uint64(1), code.Counter) // Counter incremented.
}

func TestOATHService_GenerateHOTP_NoStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.GenerateHOTP("some-id")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHStoreNotSet))
}

func TestOATHService_GenerateHOTP_EmptyID(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)
	_, err := svc.GenerateHOTP("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHInvalidID))
}

func TestOATHService_GenerateHOTP_WrongType(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)

	_, err = svc.GenerateHOTP(acct.ID)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHGenerateFailed))
}

func TestOATHService_ScanQR_NoStore(t *testing.T) {
	// ScanQR doesn't require store, it only scans the screen.
	// In CI without a display, it should return ErrOATHQRNotFound or ErrOATHQRScanFailed.
	svc := NewOATHService(nil)
	_, err := svc.ScanQR(-1)
	assert.Error(t, err)
}

func TestOATHService_AddAccountFromURI_Valid(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	uri := "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	acct, err := svc.AddAccountFromURI(uri)
	require.NoError(t, err)
	assert.NotNil(t, acct)
	assert.Equal(t, "GitHub", acct.Issuer)
	assert.Equal(t, "totp", acct.Type)
}

func TestOATHService_AddAccountFromURI_InvalidScheme(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	_, err := svc.AddAccountFromURI("https://example.com")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHQRInvalidURI))
}

func TestOATHService_AddAccountFromURI_Empty(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	_, err := svc.AddAccountFromURI("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHInvalidURI))
}

func TestOATHService_AddAccountFromURI_NoStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.AddAccountFromURI("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOATHStoreNotSet))
}

// --- Full lifecycle regression tests ---

func TestOATHService_FullLifecycle_TOTP(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	// Add an account.
	uri := "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)
	assert.Equal(t, "GitHub", acct.Issuer)
	assert.Equal(t, 6, acct.Digits)
	assert.Equal(t, 30, acct.Period)

	// List should contain exactly one account.
	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	assert.Equal(t, acct.ID, accounts[0].ID)

	// Generate a code.
	code, err := svc.GenerateTOTP(acct.ID)
	require.NoError(t, err)
	assert.Len(t, code.Code, 6)
	assert.Equal(t, 30, code.Period)

	// Delete the account.
	require.NoError(t, svc.DeleteAccount(acct.ID))

	// List should be empty.
	accounts, err = svc.ListAccounts()
	require.NoError(t, err)
	assert.Empty(t, accounts)

	// Generating a code for the deleted account should fail.
	_, err = svc.GenerateTOTP(acct.ID)
	assert.Error(t, err)
}

func TestOATHService_FullLifecycle_HOTP(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	// Add an HOTP account.
	uri := "otpauth://hotp/AWS:admin@corp.com?secret=JBSWY3DPEHPK3PXP&issuer=AWS&counter=0"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)
	assert.Equal(t, "hotp", acct.Type)
	assert.Equal(t, "AWS", acct.Issuer)

	// Generate two codes - counter should increment.
	code1, err := svc.GenerateHOTP(acct.ID)
	require.NoError(t, err)
	assert.Len(t, code1.Code, 6)
	assert.Equal(t, uint64(1), code1.Counter)

	code2, err := svc.GenerateHOTP(acct.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), code2.Counter)
	// Codes should differ since the counter incremented.
	// (They could theoretically collide but it's extremely unlikely.)

	// Delete and verify.
	require.NoError(t, svc.DeleteAccount(acct.ID))
	_, err = svc.GenerateHOTP(acct.ID)
	assert.Error(t, err)
}

func TestOATHService_MultipleAccounts(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	uris := []string{
		"otpauth://totp/GitHub:user1@test.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
		"otpauth://totp/Google:user2@test.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Google",
		"otpauth://totp/AWS:admin@corp.com?secret=JBSWY3DPEHPK3PXP&issuer=AWS",
	}

	ids := make([]string, 0, len(uris))
	for _, uri := range uris {
		acct, err := svc.AddAccount(uri)
		require.NoError(t, err)
		ids = append(ids, acct.ID)
	}

	// All three should be listed.
	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	assert.Len(t, accounts, 3)

	// Delete the middle one.
	require.NoError(t, svc.DeleteAccount(ids[1]))

	// Two should remain.
	accounts, err = svc.ListAccounts()
	require.NoError(t, err)
	assert.Len(t, accounts, 2)

	// Delete the rest.
	require.NoError(t, svc.DeleteAccount(ids[0]))
	require.NoError(t, svc.DeleteAccount(ids[2]))

	accounts, err = svc.ListAccounts()
	require.NoError(t, err)
	assert.Empty(t, accounts)
}

func TestOATHService_DeleteAccount_NonExistent(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)
	err := svc.DeleteAccount("non-existent-id")
	assert.Error(t, err)
}

func TestOATHService_AddAccountFromURI_CaseInsensitive(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	// otpauth:// scheme should be case-insensitive.
	acct, err := svc.AddAccountFromURI("OTPAUTH://totp/Test:user?secret=JBSWY3DPEHPK3PXP&issuer=Test")
	require.NoError(t, err)
	assert.Equal(t, "Test", acct.Issuer)
}

func TestOATHService_SetStore(t *testing.T) {
	// Start with nil store.
	svc := NewOATHService(nil)
	_, err := svc.ListAccounts()
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)

	// Wire a real store.
	store, storeErr := oath.NewFileStore(filepath.Join(t.TempDir(), "oath.json"))
	require.NoError(t, storeErr)
	svc.SetStore(store)

	// Now listing should work (empty list, no error).
	accounts, err := svc.ListAccounts()
	assert.NoError(t, err)
	assert.Empty(t, accounts)
}

func TestOATHService_AddAccountManual_Success(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	acct, err := svc.AddAccountManual("user@okta.com", "Okta", "AENQRKXVV3NCGL73")
	require.NoError(t, err)
	require.NotNil(t, acct)

	assert.Equal(t, "Okta (user@okta.com)", acct.Name)
	assert.Equal(t, "Okta", acct.Issuer)
	assert.Equal(t, "user@okta.com", acct.AccountName)
	assert.Equal(t, "totp", acct.Type)
	assert.Equal(t, "SHA1", acct.Algorithm)
	assert.Equal(t, 6, acct.Digits)
	assert.Equal(t, 30, acct.Period)
	assert.False(t, acct.CreatedAt.IsZero())

	// Verify it shows up in list.
	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	assert.Len(t, accounts, 1)
}

func TestOATHService_AddAccountManual_Errors(t *testing.T) {
	tests := []struct {
		name        string
		store       oath.Store
		accountName string
		issuer      string
		secret      string
		wantErr     string
		setupFunc   func(svc *OATHService)
	}{
		{
			name:        "nil store",
			store:       nil,
			accountName: "user@test.com",
			issuer:      "Test",
			secret:      "JBSWY3DPEHPK3PXP",
			wantErr:     ErrOATHStoreNotSet.Error(),
		},
		{
			name:        "empty secret",
			store:       oath.NewMemoryStore(),
			accountName: "user@test.com",
			issuer:      "Test",
			secret:      "",
			wantErr:     ErrOATHMissingSecret.Error(),
		},
		{
			name:        "invalid secret",
			store:       oath.NewMemoryStore(),
			accountName: "user@test.com",
			issuer:      "Test",
			secret:      "!!!bad!!!",
			wantErr:     oath.ErrInvalidSecret.Error(),
		},
		{
			name:        "duplicate",
			store:       oath.NewMemoryStore(),
			accountName: "user@test.com",
			issuer:      "Dup",
			secret:      "JBSWY3DPEHPK3PXP",
			wantErr:     oath.ErrCredentialExists.Error(),
			setupFunc: func(svc *OATHService) {
				_, _ = svc.AddAccountManual("user@test.com", "Dup", "JBSWY3DPEHPK3PXP")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewOATHService(tc.store)
			if tc.setupFunc != nil {
				tc.setupFunc(svc)
			}

			_, err := svc.AddAccountManual(tc.accountName, tc.issuer, tc.secret)
			require.Error(t, err)
			assert.True(t, strings.Contains(err.Error(), tc.wantErr),
				"expected error containing %q, got %q", tc.wantErr, err.Error())
		})
	}
}

func TestOATHService_BackendID_MappedToAccount(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	// Create a credential with BackendID set (simulating what the service
	// layer does after construction).
	cred := &oath.Credential{
		ID:          "backend-svc-test:admin",
		Name:        "BackendSvcTest (admin)",
		Issuer:      "BackendSvcTest",
		AccountName: "admin",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        oath.TypeTOTP,
		Algorithm:   oath.AlgorithmSHA1,
		Digits:      oath.DefaultDigits,
		Period:      oath.DefaultPeriod,
		CreatedAt:   time.Now(),
		BackendID:   "tpm2-default",
	}

	require.NoError(t, store.Add(cred))

	// List and verify BackendID comes through to the DTO.
	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	assert.Equal(t, "tpm2-default", accounts[0].BackendID)
	assert.Equal(t, "BackendSvcTest (admin)", accounts[0].Name)
	assert.Equal(t, "BackendSvcTest", accounts[0].Issuer)
}

func TestOATHService_BackendID_EmptyByDefault(t *testing.T) {
	store := oath.NewMemoryStore()
	svc := NewOATHService(store)

	// Add via URI (no BackendID set).
	uri := "otpauth://totp/DefaultBackend:user@test.com?secret=JBSWY3DPEHPK3PXP&issuer=DefaultBackend"
	acct, err := svc.AddAccount(uri)
	require.NoError(t, err)
	assert.Equal(t, "", acct.BackendID)

	// Verify listing also shows empty BackendID.
	accounts, err := svc.ListAccounts()
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	assert.Equal(t, "", accounts[0].BackendID)
}
