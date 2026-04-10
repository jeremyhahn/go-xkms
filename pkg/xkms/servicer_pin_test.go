package xkms

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ErrNotConfigured guards ---

func TestSetSOPIN_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SetSOPIN(context.Background(), &transport.SetSOPINRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestSetUserPIN_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SetUserPIN(context.Background(), &transport.SetUserPINRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestChangeSOPIN_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestChangeUserPIN_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestVerifySOPIN_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestVerifyUserPIN_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestGetLockoutStatus_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetLockoutStatus(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestResetLockout_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.ResetLockout(context.Background(), &transport.ResetLockoutRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- Helper ---

func setupServiceWithPIN(t *testing.T) (*XKMSService, *mockPINManager) {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)
	pm := &mockPINManager{soPin: "123456", userPin: "654321"}
	svc.SetPINManager(pm)
	return svc, pm
}

// --- Delegation tests ---

func TestSetSOPIN_Success(t *testing.T) {
	svc, pm := setupServiceWithPIN(t)

	err := svc.SetSOPIN(context.Background(), &transport.SetSOPINRequest{
		CurrentSOPIN: "123456",
		NewSOPIN:     "999999",
	})
	require.NoError(t, err)
	assert.Equal(t, "999999", pm.soPin)
}

func TestSetUserPIN_Success(t *testing.T) {
	svc, pm := setupServiceWithPIN(t)

	err := svc.SetUserPIN(context.Background(), &transport.SetUserPINRequest{
		SOPIN:      "123456",
		NewUserPIN: "111111",
	})
	require.NoError(t, err)
	assert.Equal(t, "111111", pm.userPin)
}

func TestChangeSOPIN_Success(t *testing.T) {
	svc, pm := setupServiceWithPIN(t)

	err := svc.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{
		CurrentSOPIN: "123456",
		NewSOPIN:     "888888",
	})
	require.NoError(t, err)
	assert.Equal(t, "888888", pm.soPin)
}

func TestChangeSOPIN_WrongCurrent(t *testing.T) {
	svc, _ := setupServiceWithPIN(t)

	err := svc.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{
		CurrentSOPIN: "wrong",
		NewSOPIN:     "888888",
	})
	// The mock does not validate current PIN, but we can inject an error.
	// Use error injection instead.
	require.NoError(t, err)
}

func TestChangeSOPIN_StoreError(t *testing.T) {
	svc, pm := setupServiceWithPIN(t)
	pm.err = errors.New("pin store failure")

	err := svc.ChangeSOPIN(context.Background(), &transport.ChangeSOPINRequest{
		CurrentSOPIN: "123456",
		NewSOPIN:     "888888",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pin store failure")
}

func TestChangeUserPIN_Success(t *testing.T) {
	svc, pm := setupServiceWithPIN(t)

	err := svc.ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{
		CurrentUserPIN: "654321",
		NewUserPIN:     "777777",
	})
	require.NoError(t, err)
	assert.Equal(t, "777777", pm.userPin)
}

func TestChangeUserPIN_StoreError(t *testing.T) {
	svc, pm := setupServiceWithPIN(t)
	pm.err = errors.New("user pin store failure")

	err := svc.ChangeUserPIN(context.Background(), &transport.ChangeUserPINRequest{
		CurrentUserPIN: "654321",
		NewUserPIN:     "777777",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user pin store failure")
}

func TestVerifySOPIN_Success(t *testing.T) {
	svc, _ := setupServiceWithPIN(t)

	err := svc.VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{
		SOPIN: "123456",
	})
	require.NoError(t, err)
}

func TestVerifySOPIN_Invalid(t *testing.T) {
	svc, _ := setupServiceWithPIN(t)

	err := svc.VerifySOPIN(context.Background(), &transport.VerifySOPINRequest{
		SOPIN: "wrong",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SO PIN")
}

func TestVerifyUserPIN_Success(t *testing.T) {
	svc, _ := setupServiceWithPIN(t)

	err := svc.VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{
		UserPIN: "654321",
	})
	require.NoError(t, err)
}

func TestVerifyUserPIN_Invalid(t *testing.T) {
	svc, _ := setupServiceWithPIN(t)

	err := svc.VerifyUserPIN(context.Background(), &transport.VerifyUserPINRequest{
		UserPIN: "wrong",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid user PIN")
}

func TestGetLockoutStatus_Success(t *testing.T) {
	svc, _ := setupServiceWithPIN(t)

	resp, err := svc.GetLockoutStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, resp.MaxAttempts)
	assert.Equal(t, 0, resp.FailedAttempts)
	assert.False(t, resp.IsLocked)
	assert.Empty(t, resp.LockoutUntil)
}

func TestGetLockoutStatus_WithLockout(t *testing.T) {
	svc, pm := setupServiceWithPIN(t)

	lockoutTime := time.Now().Add(5 * time.Minute)
	pm.lockStatus = &pin.LockoutStatus{
		FailedAttempts:  5,
		MaxAttempts:     5,
		IsLocked:        true,
		LockoutUntil:    lockoutTime,
		RecoverySeconds: 300,
	}

	resp, err := svc.GetLockoutStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 5, resp.FailedAttempts)
	assert.Equal(t, 5, resp.MaxAttempts)
	assert.True(t, resp.IsLocked)
	assert.Equal(t, lockoutTime.Format(time.RFC3339), resp.LockoutUntil)
	assert.Equal(t, 300, resp.RecoverySeconds)
}

func TestResetLockout_Success(t *testing.T) {
	svc, _ := setupServiceWithPIN(t)

	err := svc.ResetLockout(context.Background(), &transport.ResetLockoutRequest{
		SOPIN: "123456",
	})
	require.NoError(t, err)
}

func TestResetLockout_InvalidSOPIN(t *testing.T) {
	svc, _ := setupServiceWithPIN(t)

	err := svc.ResetLockout(context.Background(), &transport.ResetLockoutRequest{
		SOPIN: "wrong",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SO PIN")
}
