package webauthn

import (
	"context"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pausingClaimDAO runs afterRead once, after the first claim read returns a
// claim, before the caller acts on it.
type pausingClaimDAO struct {
	qrdbsdk.GenericDAO[*firstCredentialClaimEntity]
	once      sync.Once
	afterRead func()
}

func (p *pausingClaimDAO) GetByNaturalKey(ctx context.Context, key string) (*firstCredentialClaimEntity, error) {
	claim, err := p.GenericDAO.GetByNaturalKey(ctx, key)
	if err == nil {
		p.once.Do(p.afterRead)
	}
	return claim, err
}

// Two cleanups read the same committed claim. One deletes it (with the
// account's last credential), an invite retry claims, saves and commits a
// replacement, and only then does the stale cleanup act on what it read. The
// replacement claim and its credential must stay visible.
func TestCredentialStore_StaleClaimCleanupKeepsReplacementClaim(t *testing.T) {
	ctx := context.Background()
	factory := newTestDAOFactory()
	live := newTestCredentialStore(t, factory)

	claim, err := live.ClaimFirstCredential(ctx, uniquenessOwner)
	require.NoError(t, err)
	first := &Credential{ID: []byte("first-passkey"), UserID: uniquenessOwner}
	require.NoError(t, claim.Save(ctx, first))
	require.NoError(t, claim.Commit(ctx, first))

	replacement := &Credential{ID: []byte("replacement-passkey"), UserID: uniquenessOwner}
	stale := newTestCredentialStore(t, factory)
	stale.claims = &pausingClaimDAO{GenericDAO: stale.claims, afterRead: func() {
		// The other cleanup: the last credential goes, and its claim with it.
		require.NoError(t, live.Delete(ctx, first.ID))
		// The invite retry enrols again.
		retry, err := live.ClaimFirstCredential(ctx, uniquenessOwner)
		require.NoError(t, err)
		require.NoError(t, retry.Save(ctx, replacement))
		require.NoError(t, retry.Commit(ctx, replacement))
	}}
	require.NoError(t, stale.dropClaim(ctx, encodeID(uniquenessOwner)))

	_, err = live.claims.GetByNaturalKey(credentialScope(ctx), encodeID(uniquenessOwner))
	require.NoError(t, err, "the replacement first-credential claim must survive the stale cleanup")
	owned, err := live.GetByUserID(ctx, uniquenessOwner)
	require.NoError(t, err)
	require.Len(t, owned, 1, "the replacement passkey must stay visible")
	assert.Equal(t, replacement.ID, owned[0].ID)
}
