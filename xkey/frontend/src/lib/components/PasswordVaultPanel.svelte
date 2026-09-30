<script lang="ts">
  /**
   * PasswordVaultPanel manages the caller's personal password vault on the
   * connected xkmsd server through StaticPasswordService: first-run
   * enrollment, unlocking with a passphrase, the enrolled factors (rotate,
   * remove, add), and recovery with the one-time recovery code.
   *
   * The recovery code the server returns on the first enrollment and on every
   * recovery is shown exactly once; the panel keeps it on screen until the
   * user confirms they have stored it, then forgets it.
   */
  import { onMount } from 'svelte';
  import Button from '$lib/components/Button.svelte';
  import CopyIconButton from '$lib/components/CopyIconButton.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Input from '$lib/components/Input.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import { mdiDelete, mdiLockOpenOutline, mdiLockOutline, mdiLockReset, mdiPlus, mdiShieldLockOutline } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackendWithError, callBackendVoidWithError } from '$lib/api/backend';
  import type { PasswordVaultEnrollResult, PasswordVaultFactor, PasswordVaultStatus } from '$lib/api/backend';

  const SERVICE = 'StaticPasswordService';

  let status: PasswordVaultStatus | null = null;
  let loading = true;
  let busy = false;
  let error = '';
  let loadError = '';

  // Form fields. Secrets are cleared after every submission.
  let passphrase = '';
  let confirmPassphrase = '';
  let label = '';
  let recoveryCodeInput = '';

  // Sub-views of the locked and unlocked states.
  let recovering = false;
  let adding = false;
  let rotating: PasswordVaultFactor | null = null;

  // A recovery code the server just issued, shown until acknowledged.
  let issuedRecoveryCode = '';
  let storedAcknowledged = false;

  /**
   * holdsRecoveryCode is true while a just-issued recovery code is on screen,
   * so a hosting dialog can refuse a stray backdrop click or Escape that
   * would discard the only copy.
   */
  export let holdsRecoveryCode = false;
  $: holdsRecoveryCode = issuedRecoveryCode !== '';

  export async function load(): Promise<void> {
    loading = true;
    const { result, error: err } = await callBackendWithError<PasswordVaultStatus>(SERVICE, 'VaultStatus');
    status = result;
    loadError = err ?? '';
    loading = false;
  }

  function resetForm(): void {
    passphrase = '';
    confirmPassphrase = '';
    label = '';
    recoveryCodeInput = '';
    error = '';
  }

  /** newPassphraseError validates a passphrase being set, or returns ''. */
  function newPassphraseError(): string {
    if (!passphrase) return 'Enter a passphrase.';
    if (passphrase !== confirmPassphrase) return 'The passphrases do not match.';
    return '';
  }

  function showRecoveryCode(result: PasswordVaultEnrollResult | null): void {
    if (result?.recovery_code) {
      issuedRecoveryCode = result.recovery_code;
      storedAcknowledged = false;
    }
  }

  async function finishWithResult(
    call: Promise<{ result: PasswordVaultEnrollResult | null; error?: string }>,
    success: string,
  ): Promise<void> {
    busy = true;
    const { result, error: err } = await call;
    busy = false;
    passphrase = '';
    confirmPassphrase = '';
    recoveryCodeInput = '';
    if (err) {
      error = err;
      return;
    }
    resetForm();
    recovering = false;
    adding = false;
    rotating = null;
    showRecoveryCode(result);
    addNotification('success', success);
    await load();
  }

  async function enroll(): Promise<void> {
    error = newPassphraseError();
    if (error) return;
    await finishWithResult(
      callBackendWithError<PasswordVaultEnrollResult>(SERVICE, 'EnrollPassphrase', passphrase, label),
      'Passphrase enrolled',
    );
  }

  async function rotate(): Promise<void> {
    if (!rotating) return;
    error = newPassphraseError();
    if (error) return;
    await finishWithResult(
      callBackendWithError<PasswordVaultEnrollResult>(SERVICE, 'RotatePassphrase', rotating.id, passphrase, rotating.label),
      'Passphrase rotated',
    );
  }

  async function recover(): Promise<void> {
    error = '';
    if (!recoveryCodeInput) {
      error = 'Enter your recovery code.';
      return;
    }
    error = newPassphraseError();
    if (error) return;
    await finishWithResult(
      callBackendWithError<PasswordVaultEnrollResult>(SERVICE, 'RecoverWithPassphrase', recoveryCodeInput, passphrase, label),
      'Vault recovered',
    );
  }

  async function unlock(): Promise<void> {
    error = '';
    if (!passphrase) {
      error = 'Enter your vault passphrase.';
      return;
    }
    busy = true;
    const res = await callBackendVoidWithError(SERVICE, 'Unlock', passphrase);
    busy = false;
    passphrase = '';
    if (!res.ok) {
      error = res.error || 'Failed to unlock the vault.';
      return;
    }
    addNotification('success', 'Vault unlocked');
    await load();
  }

  async function lock(): Promise<void> {
    error = '';
    busy = true;
    const res = await callBackendVoidWithError(SERVICE, 'Lock');
    busy = false;
    if (!res.ok) {
      error = res.error || 'Failed to lock the vault.';
      return;
    }
    addNotification('success', 'Vault locked');
    await load();
  }

  async function remove(factor: PasswordVaultFactor): Promise<void> {
    error = '';
    busy = true;
    const res = await callBackendVoidWithError(SERVICE, 'RemoveVaultFactor', factor.id);
    busy = false;
    if (!res.ok) {
      error = res.error || 'Failed to remove the factor.';
      return;
    }
    addNotification('success', `Removed ${factor.label || factor.factor}`);
    await load();
  }

  function startRotate(factor: PasswordVaultFactor): void {
    resetForm();
    adding = false;
    rotating = factor;
  }

  function startAdd(): void {
    resetForm();
    rotating = null;
    adding = true;
  }

  function cancelSubview(): void {
    resetForm();
    recovering = false;
    adding = false;
    rotating = null;
  }

  function acknowledgeRecoveryCode(): void {
    issuedRecoveryCode = '';
    storedAcknowledged = false;
  }

  onMount(load);
</script>

<div class="vault-panel" data-testid="password-vault-panel">
  {#if loading}
    <div class="row">
      <LoadingSpinner size={32} />
      <span class="text-body-medium">Loading your vault...</span>
    </div>
  {:else if issuedRecoveryCode}
    <div class="recovery" role="region" aria-label="Recovery code">
      <span class="text-title-small">Your recovery code</span>
      <div class="code-row">
        <code class="recovery-code" data-testid="vault-recovery-code">{issuedRecoveryCode}</code>
        <CopyIconButton text={issuedRecoveryCode} tooltip="Copy recovery code" />
      </div>
      <p class="text-body-small warning-text">
        Store this now; it will not be shown again. It is the only way back into your
        personal vault if you lose every passphrase and passkey.
      </p>
      <label class="check-row text-body-medium">
        <input type="checkbox" bind:checked={storedAcknowledged} />
        I have stored my recovery code
      </label>
      <div class="actions">
        <Button variant="primary" disabled={!storedAcknowledged} on:click={acknowledgeRecoveryCode}>Done</Button>
      </div>
    </div>
  {:else if !status}
    <div class="row" role="status">
      <Icon path={mdiShieldLockOutline} size={20} color="var(--color-on-surface-variant)" />
      <span class="text-body-small">
        Your personal vault lives on an xkmsd server; connect to one to use it{loadError ? ` (${loadError})` : '.'}
      </span>
    </div>
    <div class="actions"><Button variant="outline" on:click={load}>Retry</Button></div>
  {:else if !status.initialized}
    <p class="text-body-small muted">
      Create your personal vault by choosing a passphrase. Your personal entries are sealed with a
      key only your own factors unlock.
    </p>
    <Input id="vault-new-passphrase" type="password" label="Passphrase" bind:value={passphrase} />
    <Input id="vault-confirm-passphrase" type="password" label="Confirm passphrase" bind:value={confirmPassphrase} />
    <Input id="vault-label" label="Label (optional)" placeholder="e.g. laptop" bind:value={label} />
    <div class="actions">
      <Button variant="primary" icon={mdiShieldLockOutline} loading={busy} on:click={enroll}>Create vault</Button>
    </div>
  {:else if !status.unlocked}
    {#if recovering}
      <p class="text-body-small muted">
        Your recovery code enrolls a new passphrase and opens your vault. You will receive a new
        recovery code; the old one stops working.
      </p>
      <Input id="vault-recovery-code" type="password" label="Recovery code" monospace bind:value={recoveryCodeInput} />
      <Input id="vault-new-passphrase" type="password" label="New passphrase" bind:value={passphrase} />
      <Input id="vault-confirm-passphrase" type="password" label="Confirm passphrase" bind:value={confirmPassphrase} />
      <Input id="vault-label" label="Label (optional)" bind:value={label} />
      <div class="actions">
        <Button variant="text" on:click={cancelSubview}>Cancel</Button>
        <Button variant="primary" icon={mdiLockReset} loading={busy} on:click={recover}>Recover</Button>
      </div>
    {:else}
      <div class="row">
        <StatusBadge status="warning" label="Locked" />
      </div>
      <Input id="vault-passphrase" type="password" label="Vault passphrase" bind:value={passphrase} />
      <div class="actions">
        <Button variant="text" on:click={() => { resetForm(); recovering = true; }}>Use recovery code</Button>
        <Button variant="primary" icon={mdiLockOpenOutline} loading={busy} on:click={unlock}>Unlock</Button>
      </div>
    {/if}
  {:else}
    <div class="row spread">
      <StatusBadge status="verified" label="Unlocked" />
      <Button variant="outline" size="sm" icon={mdiLockOutline} loading={busy} on:click={lock}>Lock</Button>
    </div>
    <ul class="factor-list" aria-label="Vault factors">
      {#each status.factors as factor (factor.id)}
        <li class="factor-row">
          <div class="factor-info">
            <span class="text-title-small">{factor.label || factor.factor}</span>
            <span class="text-body-small muted">{factor.factor} · added {factor.created_at}</span>
          </div>
          <div class="actions">
            {#if factor.factor === 'passphrase'}
              <Button variant="text" size="sm" icon={mdiLockReset} on:click={() => startRotate(factor)}>Rotate</Button>
            {/if}
            <Button variant="text" size="sm" icon={mdiDelete} on:click={() => remove(factor)}>Remove</Button>
          </div>
        </li>
      {/each}
    </ul>
    {#if rotating || adding}
      <div class="subform">
        <span class="text-title-small">
          {rotating ? `New passphrase for ${rotating.label || rotating.factor}` : 'Add a passphrase'}
        </span>
        <Input id="vault-new-passphrase" type="password" label="New passphrase" bind:value={passphrase} />
        <Input id="vault-confirm-passphrase" type="password" label="Confirm passphrase" bind:value={confirmPassphrase} />
        {#if adding}
          <Input id="vault-label" label="Label (optional)" bind:value={label} />
        {/if}
        <div class="actions">
          <Button variant="text" on:click={cancelSubview}>Cancel</Button>
          <Button variant="primary" loading={busy} on:click={rotating ? rotate : enroll}>
            {rotating ? 'Rotate' : 'Add'}
          </Button>
        </div>
      </div>
    {:else}
      <div class="actions">
        <Button variant="outline" size="sm" icon={mdiPlus} on:click={startAdd}>Add passphrase</Button>
      </div>
    {/if}
  {/if}
  {#if error}<p class="text-body-small error-text" role="alert">{error}</p>{/if}
</div>

<style>
  .vault-panel {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .spread {
    justify-content: space-between;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }

  .muted {
    color: var(--color-on-surface-variant);
  }

  .factor-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .factor-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
  }

  .factor-info,
  .subform,
  .recovery {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .code-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .recovery-code {
    font-family: var(--font-mono, monospace);
    font-size: 1.1rem;
    padding: 8px 12px;
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-variant);
    user-select: all;
  }

  .check-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .warning-text {
    color: var(--color-warning, var(--color-error));
  }

  .error-text {
    color: var(--color-error);
  }
</style>
