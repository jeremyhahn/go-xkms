package xkms

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ErrNotConfigured guards ---

func TestSubmitCredential_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{
		Name:  "db-password",
		Value: base64.StdEncoding.EncodeToString([]byte("secret")),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestGetCredentialStrategy_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetCredentialStrategy(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- Helper to create a service with credential service ---

func setupServiceWithCredentials(t *testing.T) *XKMSService {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)

	credSvc, err := credentialspkg.New(
		&credentialspkg.Config{Strategy: "manual"},
		nil,
		nil,
		slog.Default(),
	)
	require.NoError(t, err)

	svc.SetCredentialService(credSvc)
	return svc
}

// --- ErrNilRequest guards ---

func TestSubmitCredential_NilRequest(t *testing.T) {
	svc := setupServiceWithCredentials(t)

	_, err := svc.SubmitCredential(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

// --- ErrInvalidEncoding guard ---

func TestSubmitCredential_InvalidEncoding(t *testing.T) {
	svc := setupServiceWithCredentials(t)

	_, err := svc.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{
		Name:  "db-password",
		Value: "%%%not-valid-base64%%%",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidEncoding))
}

// --- Successful operations ---

func TestGetCredentialStrategy_Success(t *testing.T) {
	svc := setupServiceWithCredentials(t)

	resp, err := svc.GetCredentialStrategy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "manual", resp.Strategy)
	assert.False(t, resp.AutoUnseal)
}

func TestSubmitCredential_Success(t *testing.T) {
	svc := setupServiceWithCredentials(t)

	encoded := base64.StdEncoding.EncodeToString([]byte("my-secret-password"))
	resp, err := svc.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{
		Name:  "db-password",
		Value: encoded,
	})
	require.NoError(t, err)
	assert.Equal(t, "accepted", resp.Status)
}

// --- Submit duplicate credential ---

func TestSubmitCredential_AlreadySubmitted(t *testing.T) {
	svc := setupServiceWithCredentials(t)

	encoded := base64.StdEncoding.EncodeToString([]byte("my-secret"))
	_, err := svc.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{
		Name:  "db-password",
		Value: encoded,
	})
	require.NoError(t, err)

	// Submitting the same credential name again should fail.
	_, err = svc.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{
		Name:  "db-password",
		Value: encoded,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, credentialspkg.ErrCredentialAlreadySubmitted))
}

// --- Submit credential with empty name ---

func TestSubmitCredential_EmptyName(t *testing.T) {
	svc := setupServiceWithCredentials(t)

	encoded := base64.StdEncoding.EncodeToString([]byte("my-secret"))
	_, err := svc.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{
		Name:  "",
		Value: encoded,
	})
	require.Error(t, err)
	// The base64 decode succeeds, then the credential service validates the
	// empty name and returns ErrEmptyCredentialName.
	assert.True(t, errors.Is(err, credentialspkg.ErrEmptyCredentialName))
}

// --- Submit credential with empty value after decoding ---

func TestSubmitCredential_EmptyValue(t *testing.T) {
	svc := setupServiceWithCredentials(t)

	// base64 encoding of an empty byte slice is an empty string, which will
	// decode to an empty []byte.
	_, err := svc.SubmitCredential(context.Background(), &transport.CredentialSubmitRequest{
		Name:  "db-password",
		Value: "",
	})
	require.Error(t, err)
	// Empty string base64 decodes to empty []byte successfully, then the
	// credential service validates and returns ErrEmptyCredentialValue.
	assert.True(t, errors.Is(err, credentialspkg.ErrEmptyCredentialValue))
}
