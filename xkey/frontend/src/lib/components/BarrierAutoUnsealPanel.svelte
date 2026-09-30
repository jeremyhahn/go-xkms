<script lang="ts">
  /**
   * BarrierAutoUnsealPanel configures barrier auto-unseal through
   * BarrierAutoUnsealService: a named TPM policy carries the auto-unseal
   * mark, and the barrier password is sealed in the TPM under it. At startup
   * the TPM releases the password only while the PCRs hold the values the
   * policy approves; otherwise the barrier is unlocked by hand.
   */
  import { onMount } from 'svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Input from '$lib/components/Input.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import { mdiShieldLockOutline } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackend, callBackendVoidWithError } from '$lib/api/backend';
  import type { BarrierAutoUnsealStatus, TPMPolicyInfo } from '$lib/api/backend';
  import { policySummary } from '$lib/utils/tpmPolicy';

  let status: BarrierAutoUnsealStatus | null = null;
  let policies: TPMPolicyInfo[] = [];
  let loading = true;
  let selectedPolicy = '';
  let password = '';
  let enabling = false;
  let disabling = false;
  let error = '';

  export async function load(): Promise<void> {
    loading = true;
    const [loadedStatus, loadedPolicies] = await Promise.all([
      callBackend<BarrierAutoUnsealStatus>('BarrierAutoUnsealService', 'GetAutoUnsealStatus'),
      callBackend<TPMPolicyInfo[]>('TPMPolicyService', 'ListPolicies'),
    ]);
    status = loadedStatus;
    policies = (loadedPolicies ?? []).filter((p) => !p.builtin);
    selectedPolicy = status?.policy_name || policies[0]?.name || '';
    loading = false;
  }

  async function enable(): Promise<void> {
    error = '';
    if (!selectedPolicy) {
      error = 'Select a TPM policy.';
      return;
    }
    if (!password) {
      error = 'Enter the barrier password to seal under the policy.';
      return;
    }
    enabling = true;
    const result = await callBackendVoidWithError('BarrierAutoUnsealService', 'EnableAutoUnseal', selectedPolicy, password);
    enabling = false;
    password = '';
    if (!result.ok) {
      error = result.error || 'Failed to enable barrier auto-unseal.';
      return;
    }
    addNotification('success', `Barrier auto-unseal now uses TPM policy "${selectedPolicy}"`);
    await load();
  }

  async function disable(): Promise<void> {
    error = '';
    disabling = true;
    const result = await callBackendVoidWithError('BarrierAutoUnsealService', 'DisableAutoUnseal');
    disabling = false;
    if (!result.ok) {
      error = result.error || 'Failed to disable barrier auto-unseal.';
      return;
    }
    addNotification('success', 'Barrier auto-unseal disabled');
    await load();
  }

  onMount(load);
</script>

<div class="auto-unseal-panel" data-testid="barrier-auto-unseal-panel">
  {#if loading}
    <div class="loading-row">
      <LoadingSpinner size={32} />
      <span class="text-body-medium">Loading barrier auto-unseal status...</span>
    </div>
  {:else if !status}
    <p class="text-body-medium">Unable to load barrier auto-unseal status.</p>
    <Button variant="outline" on:click={load}>Retry</Button>
  {:else if !status.available}
    <div class="info" role="status">
      <Icon path={mdiShieldLockOutline} size={20} color="var(--color-on-surface-variant)" />
      <span class="text-body-small">Barrier auto-unseal is unavailable{status.reason ? `: ${status.reason}` : '.'}</span>
    </div>
  {:else}
    {#if status.policy_configured}
      <div class="setting-row">
        <div class="setting-info">
          <span class="text-title-small">Auto-unseal policy</span>
          <span class="text-body-small font-mono setting-desc" data-testid="auto-unseal-policy">{status.policy_name}</span>
        </div>
        <StatusBadge status={status.credential_sealed ? 'verified' : 'warning'}
          label={status.credential_sealed ? 'Password sealed' : 'Password not sealed'} />
      </div>
      <div class="setting-row">
        <div class="setting-info">
          <span class="text-title-small">Platform state</span>
          <span class="text-body-small setting-desc">
            {status.pcrs_match
              ? 'The live PCRs satisfy the policy: the barrier will unseal at startup.'
              : 'The live PCRs do not satisfy the policy: the barrier will need a manual unlock. Update the policy after an intended change.'}
          </span>
        </div>
        <StatusBadge status={status.pcrs_match ? 'verified' : 'warning'} />
      </div>
    {:else}
      <p class="text-body-small setting-desc">No TPM policy is the barrier auto-unseal policy.</p>
    {/if}

    {#if policies.length === 0}
      <div class="info" role="status">
        <Icon path={mdiShieldLockOutline} size={20} color="var(--color-on-surface-variant)" />
        <span class="text-body-small">Create a named TPM policy in the TPM view first; the built-in platform policy cannot carry auto-unseal.</span>
      </div>
    {:else}
      <div class="enable-row">
        <label class="text-label-medium" for="barrier-auto-unseal-policy">TPM policy</label>
        <select id="barrier-auto-unseal-policy" class="form-select" bind:value={selectedPolicy}>
          {#each policies as policy (policy.name)}
            <option value={policy.name}>{policy.name}: {policySummary(policy)}</option>
          {/each}
        </select>
        <Input id="barrier-auto-unseal-password" type="password" label="Barrier password" bind:value={password} />
        <div class="actions">
          <Button variant="primary" icon={mdiShieldLockOutline} loading={enabling} on:click={enable}>
            {status.policy_configured ? 'Apply' : 'Enable'}
          </Button>
          {#if status.policy_configured}
            <Button variant="danger" loading={disabling} on:click={disable}>Disable</Button>
          {/if}
        </div>
      </div>
    {/if}
    {#if error}<p class="text-body-small error-text" role="alert">{error}</p>{/if}
  {/if}
</div>

<style>
  .auto-unseal-panel {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .loading-row,
  .info {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .setting-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .setting-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .setting-desc {
    color: var(--color-on-surface-variant);
  }

  .enable-row {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .form-select {
    padding: 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-outline);
    background-color: var(--color-surface);
    color: var(--color-on-surface);
  }

  .actions {
    display: flex;
    gap: 8px;
  }

  .error-text {
    color: var(--color-error);
  }
</style>
