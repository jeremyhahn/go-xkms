<script lang="ts">
  /**
   * SecurityFactors — Account → Security page for xkey desktop.
   *
   * Pixel-equivalent to the web admin UI /account/security page per §5e.
   * Lists registered auth factors grouped by type, with Add / Rotate / Remove
   * actions and a tenant-admin MFA policy toggle.
   */

  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import Toggle from '$lib/components/Toggle.svelte';
  import Input from '$lib/components/Input.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import {
    mdiKey, mdiFingerprint, mdiCreditCardOutline, mdiPlus,
    mdiRefresh, mdiDelete, mdiPencil, mdiCheck, mdiClose,
    mdiShieldCheckOutline, mdiAlert,
  } from '$lib/utils/icons';
  import {
    factorState, activeFactors, factorsByType,
    loadFactors, appendFactor, markFactorRevoked, updateFactorLabel,
    SecurityFactorService,
    type AuthFactor, type AuthFactorType,
  } from '$lib/stores/auth-factors';
  import { resolveVendorBadge } from '$lib/utils/vendor-badge';
  import { formatRelativeTime } from '$lib/utils/format';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable } from '$lib/api/backend';

  import AddFactorWizard from '$lib/components/AddFactorWizard.svelte';

  // ----- component props -----

  /** User ID to load factors for. */
  export let userId: string = '';

  /** Tenant ID for MFA policy (tenant admin only). */
  export let tenantId: string = '';

  /** Whether the signed-in user is the tenant owner. */
  export let isTenantAdmin: boolean = false;

  // ----- local state -----

  let removeTarget: AuthFactor | null = null;
  let showRemoveModal = false;

  let relabelTarget: AuthFactor | null = null;
  let relabelDraft = '';

  let rotateTarget: AuthFactor | null = null;
  let showWizard = false;

  let requireMFA = false;
  let mfaPolicyBusy = false;

  // ----- lifecycle -----

  onMount(() => {
    if (userId) loadFactors(userId);
  });

  // ----- helpers -----

  function typeIcon(type: AuthFactorType): string {
    switch (type) {
      case 'mtls': return mdiKey;
      case 'fido2': return mdiFingerprint;
      case 'piv': return mdiCreditCardOutline;
    }
  }

  function typeLabel(type: AuthFactorType): string {
    switch (type) {
      case 'mtls': return 'mTLS Certificate';
      case 'fido2': return 'FIDO2 / Passkey';
      case 'piv': return 'PIV Smartcard';
    }
  }

  function typeColor(type: AuthFactorType): string {
    switch (type) {
      case 'mtls': return '#3b82f6';
      case 'fido2': return '#8b5cf6';
      case 'piv': return '#22c55e';
    }
  }

  function relativeTime(ts: string | null | undefined): string {
    if (!ts) return 'Never';
    try { return formatRelativeTime(ts); } catch { return ts; }
  }

  // ----- actions -----

  function startRemove(factor: AuthFactor): void {
    removeTarget = factor;
    showRemoveModal = true;
  }

  async function confirmRemove(): Promise<void> {
    if (!removeTarget || !userId) return;
    const ok = await SecurityFactorService.remove(userId, removeTarget.id);
    showRemoveModal = false;
    if (ok) {
      markFactorRevoked(removeTarget.id);
      addNotification('success', `Factor "${removeTarget.label}" removed`);
    } else {
      addNotification('error', 'Failed to remove factor');
    }
    removeTarget = null;
  }

  function startRelabel(factor: AuthFactor): void {
    relabelTarget = factor;
    relabelDraft = factor.label;
  }

  async function commitRelabel(): Promise<void> {
    if (!relabelTarget || !userId) return;
    const trimmed = relabelDraft.trim();
    if (!trimmed || trimmed === relabelTarget.label) {
      cancelRelabel();
      return;
    }
    const ok = await SecurityFactorService.relabel(userId, relabelTarget.id, trimmed);
    if (ok) {
      updateFactorLabel(relabelTarget.id, trimmed);
    } else {
      addNotification('error', 'Failed to update label');
    }
    relabelTarget = null;
    relabelDraft = '';
  }

  function handleMFAChange(e: CustomEvent<boolean>): void {
    handleMFAToggle(e.detail);
  }

  function handleRelabelInput(e: Event): void {
    const t = e.target as HTMLInputElement | null;
    if (t) relabelDraft = t.value;
  }

  function cancelRelabel(): void {
    relabelTarget = null;
    relabelDraft = '';
  }

  function startRotate(factor: AuthFactor): void {
    rotateTarget = factor;
    showWizard = true;
  }

  function handleWizardAdded(event: CustomEvent<AuthFactor>): void {
    const factor = event.detail;
    if (rotateTarget) {
      markFactorRevoked(rotateTarget.id);
    }
    appendFactor(factor);
    rotateTarget = null;
  }

  function handleAddFactor(): void {
    rotateTarget = null;
    showWizard = true;
  }

  async function handleMFAToggle(enabled: boolean): Promise<void> {
    if (!tenantId) return;
    mfaPolicyBusy = true;
    const ok = await SecurityFactorService.setMFAPolicy({
      tenant_id: tenantId,
      require_factor_count: enabled ? 2 : 1,
    });
    mfaPolicyBusy = false;
    if (ok) {
      requireMFA = enabled;
      addNotification(
        'success',
        enabled ? 'MFA required: users must present 2+ factors' : 'MFA optional'
      );
    } else {
      addNotification('error', 'Failed to update MFA policy');
    }
  }

  $: totalActive = $activeFactors.length;
  $: groups = [
    { type: 'mtls' as AuthFactorType, factors: $factorsByType.mtls },
    { type: 'fido2' as AuthFactorType, factors: $factorsByType.fido2 },
    { type: 'piv' as AuthFactorType, factors: $factorsByType.piv },
  ].filter((g) => g.factors.length > 0);
</script>

<!-- Page header -->
<GradientHeader
  title="Security"
  subtitle="Manage authentication factors for your account"
/>

<!-- Add factor button -->
<div class="page-toolbar">
  <Button variant="primary" on:click={handleAddFactor} aria-label="Add authentication factor">
    <Icon path={mdiPlus} size={18} />
    Add factor
  </Button>
</div>

<!-- Factor list -->
<div class="security-content">
  {#if $factorState.loading}
    <div class="loading-center" aria-busy="true" aria-label="Loading factors">
      <LoadingSpinner size={32} />
    </div>
  {:else if $factorState.error}
    <Card variant="outlined" padding="md">
      <div class="error-row">
        <Icon path={mdiAlert} size={18} color="var(--error)" />
        <span class="text-body-medium">{$factorState.error}</span>
        <Button variant="text" on:click={() => loadFactors(userId)}>Retry</Button>
      </div>
    </Card>
  {:else if groups.length === 0}
    <Card variant="outlined" padding="lg">
      <div class="empty-state">
        <Icon path={mdiShieldCheckOutline} size={48} color="var(--on-surface-variant)" />
        <p class="text-body-large">No authentication factors registered.</p>
        <p class="text-body-medium">Add a factor to secure your account.</p>
      </div>
    </Card>
  {:else}
    {#each groups as group (group.type)}
      <Card variant="elevated" padding="md">
        <div class="group-header">
          <Icon path={typeIcon(group.type)} size={18} color={typeColor(group.type)} />
          <span class="text-title-small">{typeLabel(group.type)}</span>
          <span class="factor-count">{group.factors.length}</span>
        </div>

        <div class="factor-list">
          {#each group.factors as factor (factor.id)}
            <div class="factor-row">
              <div class="factor-identity">
                <!-- Inline label editor -->
                {#if relabelTarget?.id === factor.id}
                  <div class="relabel-row">
                    <Input
                      value={relabelDraft}
                      on:input={handleRelabelInput}
                    />
                    <button class="icon-action" on:click={commitRelabel} aria-label="Save label">
                      <Icon path={mdiCheck} size={16} color="var(--primary)" />
                    </button>
                    <button class="icon-action" on:click={cancelRelabel} aria-label="Cancel">
                      <Icon path={mdiClose} size={16} />
                    </button>
                  </div>
                {:else}
                  <div class="label-row">
                    <span class="text-body-medium factor-label">{factor.label}</span>
                    <button
                      class="icon-action muted"
                      on:click={() => startRelabel(factor)}
                      aria-label="Edit label"
                    >
                      <Icon path={mdiPencil} size={14} />
                    </button>
                  </div>
                {/if}

                <div class="factor-meta">
                  <span class="text-body-small">
                    Registered {relativeTime(factor.registered_at)}
                  </span>
                  <span class="meta-sep">·</span>
                  <span class="text-body-small">
                    Last used {relativeTime(factor.last_used_at)}
                  </span>
                </div>
              </div>

              <!-- Vendor badge -->
              <div class="vendor-badge">
                <StatusBadge
                  text={resolveVendorBadge(factor).name}
                  variant="neutral"
                />
              </div>

              <!-- Actions -->
              <div class="factor-actions">
                <Button
                  variant="outline"
                  size="sm"
                  on:click={() => startRotate(factor)}
                  aria-label="Rotate {factor.label}"
                >
                  <Icon path={mdiRefresh} size={14} />
                  Rotate
                </Button>
                <Button
                  variant={totalActive === 1 ? 'outline' : 'danger'}
                  size="sm"
                  disabled={totalActive === 1}
                  title={totalActive === 1 ? 'Cannot remove the last factor' : undefined}
                  on:click={() => startRemove(factor)}
                  aria-label="Remove {factor.label}"
                >
                  <Icon path={mdiDelete} size={14} />
                  Remove
                </Button>
              </div>
            </div>
          {/each}
        </div>
      </Card>
    {/each}
  {/if}

  <!-- Tenant admin MFA policy -->
  {#if isTenantAdmin}
    <Card variant="elevated" padding="md">
      <div class="group-header">
        <Icon path={mdiShieldCheckOutline} size={18} />
        <span class="text-title-small">Session policy</span>
      </div>
      <div class="mfa-row">
        <div class="mfa-label">
          <span class="text-body-medium">Require 2 or more factors per session</span>
          <span class="text-body-small muted-text">
            Users must authenticate with at least 2 factors before a session is issued.
          </span>
        </div>
        {#if mfaPolicyBusy}
          <LoadingSpinner size={20} />
        {:else}
          <Toggle
            checked={requireMFA}
            on:change={handleMFAChange}
            aria-label="Require 2 factors per session"
          />
        {/if}
      </div>
    </Card>
  {/if}
</div>

<!-- Remove confirmation modal -->
<Modal
  open={showRemoveModal}
  title="Remove authentication factor"
  on:close={() => { showRemoveModal = false; removeTarget = null; }}
>
  <p class="text-body-medium">
    Are you sure you want to remove <strong>{removeTarget?.label}</strong>?
    You will no longer be able to sign in with this factor.
  </p>
  <div slot="actions" class="modal-actions">
    <Button variant="text" on:click={() => { showRemoveModal = false; removeTarget = null; }}>
      Cancel
    </Button>
    <Button variant="danger" on:click={confirmRemove}>
      Remove
    </Button>
  </div>
</Modal>

<!-- Add / rotate factor wizard -->
<AddFactorWizard
  open={showWizard}
  {userId}
  rotateFactorId={rotateTarget?.id}
  rotateFactorType={rotateTarget?.type}
  on:close={() => { showWizard = false; rotateTarget = null; }}
  on:added={handleWizardAdded}
/>

<style>
  .page-toolbar {
    display: flex;
    justify-content: flex-end;
    padding: 12px 16px 0;
  }

  .security-content {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 16px;
  }

  .loading-center {
    display: flex;
    justify-content: center;
    padding: 48px;
  }

  .error-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 32px;
    text-align: center;
    color: var(--on-surface-variant);
  }

  .group-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 12px;
  }

  .factor-count {
    background: var(--surface-variant);
    color: var(--on-surface-variant);
    border-radius: 12px;
    padding: 2px 8px;
    font-size: 12px;
    font-weight: 600;
  }

  .factor-list {
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .factor-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 0;
    border-top: 1px solid var(--outline-variant);
  }

  .factor-row:first-child {
    border-top: none;
  }

  .factor-identity {
    flex: 1;
    min-width: 0;
  }

  .label-row {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .relabel-row {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .factor-label {
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .icon-action {
    background: none;
    border: none;
    cursor: pointer;
    padding: 2px;
    border-radius: 4px;
    display: flex;
    align-items: center;
    color: var(--on-surface);
  }

  .icon-action:hover {
    background: var(--surface-variant);
  }

  .icon-action.muted {
    opacity: 0.4;
  }

  .icon-action.muted:hover {
    opacity: 1;
  }

  .factor-meta {
    display: flex;
    align-items: center;
    gap: 4px;
    color: var(--on-surface-variant);
    font-size: 11px;
    margin-top: 2px;
  }

  .meta-sep {
    color: var(--outline);
  }

  .vendor-badge {
    display: none;
    flex-shrink: 0;
  }

  @media (min-width: 600px) {
    .vendor-badge {
      display: block;
    }
  }

  .factor-actions {
    display: flex;
    gap: 6px;
    flex-shrink: 0;
  }

  .mfa-row {
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .mfa-label {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .muted-text {
    color: var(--on-surface-variant);
  }

  .modal-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }
</style>
