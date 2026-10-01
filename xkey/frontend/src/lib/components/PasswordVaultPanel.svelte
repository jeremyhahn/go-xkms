<script lang="ts">
  /**
   * PasswordVaultPanel manages the caller's personal password vault on the
   * connected xkmsd server through StaticPasswordService: first-run
   * enrollment, unlocking, the enrolled factors (rotate, remove, add), and
   * recovery with the one-time recovery code. Each of create, unlock, add and
   * recover takes either a passphrase or -- "Use security key" -- a passkey on
   * a FIDO2 security key, verified with the key's PIN. While a passkey call
   * is pending the panel asks the user to touch the key. "Use a key" takes a
   * key factor instead: the slot 9d key of a PIV backend, a certificate's
   * key, or a TPM key under a named policy, held in one of xKey's backends.
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
  import {
    mdiDelete,
    mdiFingerprint,
    mdiLockOpenOutline,
    mdiLockOutline,
    mdiLockReset,
    mdiPlus,
    mdiShieldKeyOutline,
    mdiShieldLockOutline,
  } from '$lib/utils/icons';
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
  let pin = '';

  // usePasskey switches the current form from a passphrase to a passkey on
  // a security key; touching is true while a passkey call waits for a touch.
  let usePasskey = false;
  let touching = false;

  // useKey switches the current form to a key factor (PIV, certificate,
  // TPM) held in one of xKey's key backends.
  let useKey = false;
  let keyFactor: 'piv' | 'certificate' | 'tpm' = 'piv';
  let keyBackend = '';
  let keyID = '';
  let keyPolicy = '';

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
    if (status?.initialized && !status.unlocked && !recovering) {
      usePasskey = onlyPasskeys(status.factors);
    }
  }

  /** onlyPasskeys is true when every unlockable factor is a passkey. */
  function onlyPasskeys(factors: PasswordVaultFactor[]): boolean {
    const unlockable = factors.filter((f) => f.factor === 'passkey' || f.factor === 'passphrase');
    return unlockable.length > 0 && unlockable.every((f) => f.factor === 'passkey');
  }

  function clearSecrets(): void {
    passphrase = '';
    confirmPassphrase = '';
    recoveryCodeInput = '';
    pin = '';
  }

  function resetForm(): void {
    clearSecrets();
    label = '';
    error = '';
    usePasskey = false;
    useKey = false;
    keyBackend = '';
    keyID = '';
    keyPolicy = '';
  }

  /** hasKeyFactor is true when the vault lists a PIV, certificate or TPM factor. */
  function hasKeyFactor(factors: PasswordVaultFactor[]): boolean {
    return factors.some((f) => f.factor === 'piv' || f.factor === 'certificate' || f.factor === 'tpm');
  }

  function setUseKey(value: boolean): void {
    clearSecrets();
    error = '';
    usePasskey = false;
    useKey = value;
  }

  /** keyFactorError validates the key factor being set, or returns ''. */
  function keyFactorError(): string {
    if (!keyBackend) return 'Name the xKey backend that holds the key.';
    if (keyFactor !== 'piv' && !keyID) return 'Name the key.';
    return '';
  }

  /** keyArgs are EnrollKeyFactor's key arguments: factor, backend, key, policy. */
  function keyArgs(): [string, string, string, string] {
    return [keyFactor, keyBackend, keyID, keyFactor === 'tpm' ? keyPolicy : ''];
  }

  function setUsePasskey(value: boolean): void {
    clearSecrets();
    error = '';
    usePasskey = value;
  }

  /** newPassphraseError validates a passphrase being set, or returns ''. */
  function newPassphraseError(): string {
    if (!passphrase) return 'Enter a passphrase.';
    if (passphrase !== confirmPassphrase) return 'The passphrases do not match.';
    return '';
  }

  /** newFactorError validates the factor being set, or returns ''. */
  function newFactorError(): string {
    if (usePasskey) return pin ? '' : 'Enter your security key PIN.';
    return newPassphraseError();
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
    touching = usePasskey;
    const { result, error: err } = await call;
    busy = false;
    touching = false;
    clearSecrets();
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
    if (useKey) {
      error = keyFactorError();
      if (error) return;
      await finishWithResult(
        callBackendWithError<PasswordVaultEnrollResult>(SERVICE, 'EnrollKeyFactor', ...keyArgs(), label),
        'Key enrolled',
      );
      return;
    }
    error = newFactorError();
    if (error) return;
    if (usePasskey) {
      await finishWithResult(
        callBackendWithError<PasswordVaultEnrollResult>(SERVICE, 'EnrollPasskey', label, pin),
        'Security key enrolled',
      );
      return;
    }
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
    if (useKey) {
      error = keyFactorError();
      if (error) return;
      await finishWithResult(
        callBackendWithError<PasswordVaultEnrollResult>(SERVICE, 'RecoverWithKeyFactor', recoveryCodeInput, ...keyArgs(), label),
        'Vault recovered',
      );
      return;
    }
    error = newFactorError();
    if (error) return;
    if (usePasskey) {
      await finishWithResult(
        callBackendWithError<PasswordVaultEnrollResult>(SERVICE, 'RecoverWithPasskey', recoveryCodeInput, label, pin),
        'Vault recovered',
      );
      return;
    }
    await finishWithResult(
      callBackendWithError<PasswordVaultEnrollResult>(SERVICE, 'RecoverWithPassphrase', recoveryCodeInput, passphrase, label),
      'Vault recovered',
    );
  }

  async function unlock(): Promise<void> {
    error = '';
    if (usePasskey ? !pin : !passphrase) {
      error = usePasskey ? 'Enter your security key PIN.' : 'Enter your vault passphrase.';
      return;
    }
    busy = true;
    touching = usePasskey;
    const res = usePasskey
      ? await callBackendVoidWithError(SERVICE, 'UnlockWithPasskey', pin)
      : await callBackendVoidWithError(SERVICE, 'Unlock', passphrase);
    busy = false;
    touching = false;
    clearSecrets();
    if (!res.ok) {
      error = res.error || 'Failed to unlock the vault.';
      return;
    }
    addNotification('success', 'Vault unlocked');
    await load();
  }

  async function unlockWithKey(): Promise<void> {
    error = '';
    busy = true;
    const res = await callBackendVoidWithError(SERVICE, 'UnlockWithKeyFactor');
    busy = false;
    if (!res.ok) {
      error = res.error || 'Failed to unlock the vault with a key.';
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

  function startAdd(kind: 'passphrase' | 'passkey' | 'key'): void {
    resetForm();
    rotating = null;
    adding = true;
    usePasskey = kind === 'passkey';
    useKey = kind === 'key';
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
      {#if usePasskey}
        Create your personal vault with a passkey on your security key. Your personal entries are
        sealed with a key only your own factors unlock.
      {:else}
        Create your personal vault by choosing a passphrase. Your personal entries are sealed with a
        key only your own factors unlock.
      {/if}
    </p>
    {#if useKey}
      <label class="text-body-medium" for="vault-key-factor">Key</label>
      <select id="vault-key-factor" bind:value={keyFactor}>
        <option value="piv">PIV card (slot 9d)</option>
        <option value="certificate">Certificate key</option>
        <option value="tpm">TPM key</option>
      </select>
      <Input id="vault-key-backend" label="xKey backend" placeholder="e.g. pkcs11, tpm2, software" bind:value={keyBackend} />
      {#if keyFactor !== 'piv'}
        <Input id="vault-key-id" label="Key ID" bind:value={keyID} />
      {/if}
      {#if keyFactor === 'tpm'}
        <Input id="vault-key-policy" label="TPM policy" placeholder="e.g. platform" bind:value={keyPolicy} />
      {/if}
    {:else if usePasskey}
      <Input id="vault-pin" type="password" label="Security key PIN" bind:value={pin} />
    {:else}
      <Input id="vault-new-passphrase" type="password" label="Passphrase" bind:value={passphrase} />
      <Input id="vault-confirm-passphrase" type="password" label="Confirm passphrase" bind:value={confirmPassphrase} />
    {/if}
    <Input id="vault-label" label="Label (optional)" placeholder={usePasskey ? 'e.g. yubikey' : 'e.g. laptop'} bind:value={label} />
    <div class="actions">
      <Button variant="text" icon={mdiShieldKeyOutline} on:click={() => setUseKey(!useKey)}>
        {useKey ? 'Use a passphrase' : 'Use a key'}
      </Button>
      <Button variant="text" icon={usePasskey ? mdiShieldLockOutline : mdiFingerprint} on:click={() => setUsePasskey(!usePasskey)}>
        {usePasskey ? 'Use a passphrase' : 'Use security key'}
      </Button>
      <Button variant="primary" icon={mdiShieldLockOutline} loading={busy} on:click={enroll}>Create vault</Button>
    </div>
  {:else if !status.unlocked}
    {#if recovering}
      <p class="text-body-small muted">
        Your recovery code enrolls a new {usePasskey ? 'security key' : 'passphrase'} and opens your
        vault. You will receive a new recovery code; the old one stops working.
      </p>
      <Input id="vault-recovery-code" type="password" label="Recovery code" monospace bind:value={recoveryCodeInput} />
      {#if useKey}
      <label class="text-body-medium" for="vault-key-factor">Key</label>
      <select id="vault-key-factor" bind:value={keyFactor}>
        <option value="piv">PIV card (slot 9d)</option>
        <option value="certificate">Certificate key</option>
        <option value="tpm">TPM key</option>
      </select>
      <Input id="vault-key-backend" label="xKey backend" placeholder="e.g. pkcs11, tpm2, software" bind:value={keyBackend} />
      {#if keyFactor !== 'piv'}
        <Input id="vault-key-id" label="Key ID" bind:value={keyID} />
      {/if}
      {#if keyFactor === 'tpm'}
        <Input id="vault-key-policy" label="TPM policy" placeholder="e.g. platform" bind:value={keyPolicy} />
      {/if}
      {:else if usePasskey}
        <Input id="vault-pin" type="password" label="Security key PIN" bind:value={pin} />
      {:else}
        <Input id="vault-new-passphrase" type="password" label="New passphrase" bind:value={passphrase} />
        <Input id="vault-confirm-passphrase" type="password" label="Confirm passphrase" bind:value={confirmPassphrase} />
      {/if}
      <Input id="vault-label" label="Label (optional)" bind:value={label} />
      <div class="actions">
        <Button variant="text" icon={usePasskey ? mdiShieldLockOutline : mdiFingerprint} on:click={() => setUsePasskey(!usePasskey)}>
          {usePasskey ? 'Use a passphrase' : 'Use security key'}
        </Button>
        <Button variant="text" icon={mdiShieldKeyOutline} on:click={() => setUseKey(!useKey)}>
          {useKey ? 'Use a passphrase' : 'Use a key'}
        </Button>
        <Button variant="text" on:click={cancelSubview}>Cancel</Button>
        <Button variant="primary" icon={mdiLockReset} loading={busy} on:click={recover}>Recover</Button>
      </div>
    {:else}
      <div class="row">
        <StatusBadge status="warning" label="Locked" />
      </div>
      {#if usePasskey}
        <Input id="vault-pin" type="password" label="Security key PIN" bind:value={pin} />
      {:else}
        <Input id="vault-passphrase" type="password" label="Vault passphrase" bind:value={passphrase} />
      {/if}
      <div class="actions">
        <Button variant="text" icon={usePasskey ? mdiShieldLockOutline : mdiFingerprint} on:click={() => setUsePasskey(!usePasskey)}>
          {usePasskey ? 'Use a passphrase' : 'Use security key'}
        </Button>
        <Button variant="text" on:click={() => { resetForm(); recovering = true; }}>Use recovery code</Button>
        {#if hasKeyFactor(status.factors)}
          <Button variant="outline" icon={mdiShieldKeyOutline} loading={busy} on:click={unlockWithKey}>Unlock with key</Button>
        {/if}
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
            <span class="text-body-small muted">
              {factor.factor}{factor.key_backend ? ` · ${factor.key_backend}${factor.key_id ? `/${factor.key_id}` : ''}` : ''}{factor.tpm_policy ? ` · policy ${factor.tpm_policy}` : ''} · added {factor.created_at}
            </span>
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
          {#if rotating}
            New passphrase for {rotating.label || rotating.factor}
          {:else if useKey}
            Add a key
          {:else if usePasskey}
            Add a security key
          {:else}
            Add a passphrase
          {/if}
        </span>
        {#if useKey}
      <label class="text-body-medium" for="vault-key-factor">Key</label>
      <select id="vault-key-factor" bind:value={keyFactor}>
        <option value="piv">PIV card (slot 9d)</option>
        <option value="certificate">Certificate key</option>
        <option value="tpm">TPM key</option>
      </select>
      <Input id="vault-key-backend" label="xKey backend" placeholder="e.g. pkcs11, tpm2, software" bind:value={keyBackend} />
      {#if keyFactor !== 'piv'}
        <Input id="vault-key-id" label="Key ID" bind:value={keyID} />
      {/if}
      {#if keyFactor === 'tpm'}
        <Input id="vault-key-policy" label="TPM policy" placeholder="e.g. platform" bind:value={keyPolicy} />
      {/if}
        {:else if usePasskey}
          <Input id="vault-pin" type="password" label="Security key PIN" bind:value={pin} />
        {:else}
          <Input id="vault-new-passphrase" type="password" label="New passphrase" bind:value={passphrase} />
          <Input id="vault-confirm-passphrase" type="password" label="Confirm passphrase" bind:value={confirmPassphrase} />
        {/if}
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
        <Button variant="outline" size="sm" icon={mdiPlus} on:click={() => startAdd('passphrase')}>Add passphrase</Button>
        <Button variant="outline" size="sm" icon={mdiShieldKeyOutline} on:click={() => startAdd('passkey')}>Add security key</Button>
        <Button variant="outline" size="sm" icon={mdiShieldKeyOutline} on:click={() => startAdd('key')}>Add key</Button>
      </div>
    {/if}
  {/if}
  {#if touching}
    <div class="row touch-prompt" role="status" data-testid="vault-touch-prompt">
      <Icon path={mdiFingerprint} size={20} color="var(--color-primary)" />
      <span class="text-body-medium">Touch your security key...</span>
    </div>
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
