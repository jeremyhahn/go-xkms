//go:build awskms

package awskms

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	awstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func newDeleteFailureBackend(t *testing.T, scheduleErr error) (*Backend, *types.KeyAttributes, *bool) {
	t.Helper()
	called := false
	mockClient := &MockKMSClient{
		ScheduleKeyDeletionFunc: func(_ context.Context, _ *kms.ScheduleKeyDeletionInput, _ ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
			called = true
			if scheduleErr != nil {
				return nil, scheduleErr
			}
			return &kms.ScheduleKeyDeletionOutput{}, nil
		},
	}
	config := &Config{
		Region:      "us-east-1",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient: %v", err)
	}
	attrs := &types.KeyAttributes{
		CN:           "delete-failure-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AWSKMS,
		KeyAlgorithm: x509.RSA,
	}
	if err := b.Save(attrs, []byte(`{"key_id":"delete-failure-key-id"}`), backend.FSEXT_PRIVATE_BLOB, false); err != nil {
		t.Fatalf("Save metadata: %v", err)
	}
	return b, attrs, &called
}

func listedCN(t *testing.T, b *Backend, cn string) bool {
	t.Helper()
	keys, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	for _, k := range keys {
		if k != nil && k.CN == cn {
			return true
		}
	}
	return false
}

// A ScheduleKeyDeletion failure other than "already gone" must surface and
// leave the key discoverable, so callers never report a live KMS key as
// destroyed.
func TestDeleteScheduleFailureKeepsMetadata(t *testing.T) {
	b, attrs, called := newDeleteFailureBackend(t, errors.New("AccessDeniedException: not authorized to perform kms:ScheduleKeyDeletion"))
	if err := b.Delete(attrs); err == nil {
		t.Fatal("Delete returned nil for an access-denied ScheduleKeyDeletion")
	}
	if !*called {
		t.Fatal("Delete did not call ScheduleKeyDeletion")
	}
	if !listedCN(t, b, attrs.CN) {
		t.Fatal("key metadata removed although the KMS deletion failed")
	}

	b2, attrs2, _ := newDeleteFailureBackend(t, errors.New("service unavailable"))
	if err := b2.Delete(attrs2); err == nil {
		t.Fatal("Delete returned nil for an outage")
	}
	if !listedCN(t, b2, attrs2.CN) {
		t.Fatal("key metadata removed although the KMS deletion failed (outage)")
	}
}

func TestDeleteAlreadyGoneIsSuccess(t *testing.T) {
	cases := map[string]error{
		"not found":        &awstypes.NotFoundException{Message: aws.String("key does not exist")},
		"pending deletion": &awstypes.KMSInvalidStateException{Message: aws.String("arn:aws:kms:us-east-1:1:key/x is pending deletion.")},
	}
	for name, scheduleErr := range cases {
		t.Run(name, func(t *testing.T) {
			b, attrs, _ := newDeleteFailureBackend(t, scheduleErr)
			if err := b.Delete(attrs); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if listedCN(t, b, attrs.CN) {
				t.Fatal("metadata still listed after an already-gone deletion")
			}
		})
	}
}
