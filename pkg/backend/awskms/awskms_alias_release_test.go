//go:build awskms

package awskms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	awstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// aliasKMS models the KMS state the alias release depends on: keys with a
// pending-deletion state, and aliases that keep pointing at a key until they
// are deleted (as real KMS does: scheduling deletion leaves the alias).
type aliasKMS struct {
	*MockKMSClient
	mu           sync.Mutex
	next         int
	pub          map[string][]byte
	pending      map[string]bool
	aliases      map[string]string
	deletedAlias []string
}

func newAliasKMS(t *testing.T) *aliasKMS {
	t.Helper()
	f := &aliasKMS{pub: map[string][]byte{}, pending: map[string]bool{}, aliases: map[string]string{}}
	f.MockKMSClient = &MockKMSClient{
		CreateKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, err
			}
			der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
			if err != nil {
				return nil, err
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			f.next++
			id := fmt.Sprintf("key-%d", f.next)
			f.pub[id] = der
			return &kms.CreateKeyOutput{KeyMetadata: &awstypes.KeyMetadata{KeyId: aws.String(id)}}, nil
		},
		CreateAliasFunc: func(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			name := aws.ToString(params.AliasName)
			if _, ok := f.aliases[name]; ok {
				return nil, &awstypes.AlreadyExistsException{Message: aws.String(name + " exists")}
			}
			f.aliases[name] = aws.ToString(params.TargetKeyId)
			return &kms.CreateAliasOutput{}, nil
		},
		GetPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			id, err := f.resolve(aws.ToString(params.KeyId))
			if err != nil {
				return nil, err
			}
			if f.pending[id] {
				return nil, &awstypes.KMSInvalidStateException{Message: aws.String(id + " is pending deletion")}
			}
			return &kms.GetPublicKeyOutput{KeyId: aws.String(id), PublicKey: f.pub[id]}, nil
		},
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			id, err := f.resolve(aws.ToString(params.KeyId))
			if err != nil {
				return nil, err
			}
			state := awstypes.KeyStateEnabled
			if f.pending[id] {
				state = awstypes.KeyStatePendingDeletion
			}
			return &kms.DescribeKeyOutput{KeyMetadata: &awstypes.KeyMetadata{KeyId: aws.String(id), KeyState: state}}, nil
		},
		ScheduleKeyDeletionFunc: func(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			id, err := f.resolve(aws.ToString(params.KeyId))
			if err != nil {
				return nil, err
			}
			f.pending[id] = true
			return &kms.ScheduleKeyDeletionOutput{KeyId: aws.String(id)}, nil
		},
	}
	return f
}

// resolve maps an alias or key ID to a key ID; the caller holds f.mu.
func (f *aliasKMS) resolve(keyID string) (string, error) {
	id := keyID
	if strings.HasPrefix(keyID, "alias/") {
		target, ok := f.aliases[keyID]
		if !ok {
			return "", &awstypes.NotFoundException{Message: aws.String(keyID + " not found")}
		}
		id = target
	}
	if _, ok := f.pub[id]; !ok {
		return "", &awstypes.NotFoundException{Message: aws.String(id + " not found")}
	}
	return id, nil
}

func (f *aliasKMS) DeleteAlias(ctx context.Context, params *kms.DeleteAliasInput, optFns ...func(*kms.Options)) (*kms.DeleteAliasOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := aws.ToString(params.AliasName)
	f.deletedAlias = append(f.deletedAlias, name)
	if _, ok := f.aliases[name]; !ok {
		return nil, &awstypes.NotFoundException{Message: aws.String(name + " not found")}
	}
	delete(f.aliases, name)
	return &kms.DeleteAliasOutput{}, nil
}

func newAliasReleaseBackend(t *testing.T, client KMSClient) *Backend {
	t.Helper()
	b, err := NewBackendWithClient(&Config{Region: "us-east-1", KeyStorage: storage.New(), CertStorage: storage.New()}, client)
	if err != nil {
		t.Fatalf("NewBackendWithClient: %v", err)
	}
	return b
}

func TestBackend_DeleteReleasesAliasForReprovisioning(t *testing.T) {
	ctx := context.Background()
	fake := newAliasKMS(t)
	b := newAliasReleaseBackend(t, fake)
	attrs := &types.KeyAttributes{CN: "qrdb-login-ca-tenant-a", KeyType: backend.KEY_TYPE_SIGNING, KeyAlgorithm: x509.ECDSA, StoreType: backend.STORE_AWSKMS}

	first, err := b.CreateKey(attrs)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if err := b.DeleteKey(ctx, attrs); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	released := false
	for _, name := range fake.deletedAlias {
		if name == "alias/"+attrs.CN {
			released = true
		}
	}
	if !released {
		t.Fatalf("DeleteAlias calls = %v, want alias/%s released with the key", fake.deletedAlias, attrs.CN)
	}
	if _, err := b.Signer(ctx, attrs); !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("Signer() after delete error = %v, want ErrKeyNotFound so the tenant can be provisioned again", err)
	}

	second, err := b.CreateKey(attrs)
	if err != nil {
		t.Fatalf("second CreateKey: %v", err)
	}
	if second == first {
		t.Fatalf("second CreateKey returned the deleted key %s", first)
	}
	fake.mu.Lock()
	target := fake.aliases["alias/"+attrs.CN]
	fake.mu.Unlock()
	if target != second {
		t.Fatalf("alias/%s -> %q, want the new key %q", attrs.CN, target, second)
	}
	signer, err := b.Signer(ctx, attrs)
	if err != nil {
		t.Fatalf("Signer() for the new key: %v", err)
	}
	if got := signer.(*kmsSigner).keyID; got != second {
		t.Fatalf("Signer() resolved %q, want the new key %q", got, second)
	}
}

func TestBackend_DeleteKeepsAliasOfNewerKey(t *testing.T) {
	ctx := context.Background()
	fake := newAliasKMS(t)
	b := newAliasReleaseBackend(t, fake)
	attrs := &types.KeyAttributes{CN: "qrdb-login-ca-tenant-b", KeyType: backend.KEY_TYPE_SIGNING, KeyAlgorithm: x509.ECDSA, StoreType: backend.STORE_AWSKMS}

	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	// A newer generation re-pointed the alias at its own key.
	newer, err := fake.CreateKey(ctx, &kms.CreateKeyInput{})
	if err != nil {
		t.Fatalf("fake CreateKey: %v", err)
	}
	newerID := aws.ToString(newer.KeyMetadata.KeyId)
	fake.mu.Lock()
	fake.aliases["alias/"+attrs.CN] = newerID
	fake.mu.Unlock()

	if err := b.DeleteKey(ctx, attrs); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	fake.mu.Lock()
	target := fake.aliases["alias/"+attrs.CN]
	fake.mu.Unlock()
	if target != newerID {
		t.Fatalf("alias/%s -> %q after deleting the older key, want the newer key %q kept", attrs.CN, target, newerID)
	}
}

func TestBackend_DeleteAliasFailureIsReturned(t *testing.T) {
	ctx := context.Background()
	fake := newAliasKMS(t)
	b := newAliasReleaseBackend(t, &failingDeleteAliasKMS{aliasKMS: fake})
	attrs := &types.KeyAttributes{CN: "qrdb-login-ca-tenant-c", KeyType: backend.KEY_TYPE_SIGNING, KeyAlgorithm: x509.ECDSA, StoreType: backend.STORE_AWSKMS}

	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if err := b.DeleteKey(ctx, attrs); err == nil {
		t.Fatal("DeleteKey() error = nil, want the alias release failure returned")
	}
}

// failingDeleteAliasKMS refuses every alias deletion with an access denial.
type failingDeleteAliasKMS struct{ *aliasKMS }

func (f *failingDeleteAliasKMS) DeleteAlias(ctx context.Context, params *kms.DeleteAliasInput, optFns ...func(*kms.Options)) (*kms.DeleteAliasOutput, error) {
	return nil, &awstypes.KMSInternalException{Message: aws.String("denied")}
}
