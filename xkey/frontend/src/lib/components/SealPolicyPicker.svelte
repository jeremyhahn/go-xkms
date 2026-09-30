<script lang="ts">
  /**
   * SealPolicyPicker chooses how sealed data is protected: on the tpm2 backend
   * a TPM policy -- none, the built-in "platform" policy (the default), or a
   * named policy from TPMPolicyService -- plus, on any backend, an optional
   * password. With a policy, the password is the policy's password branch:
   * it still unseals after the PCRs change.
   */
  import { onMount } from 'svelte';
  import Input from '$lib/components/Input.svelte';
  import Toggle from '$lib/components/Toggle.svelte';
  import { callBackend } from '$lib/api/backend';
  import type { TPMPolicyInfo } from '$lib/api/backend';
  import { policySummary } from '$lib/utils/tpmPolicy';

  /** Effective sealing backend ("tpm2", "software", ...). */
  export let backend = '';
  /** Selected TPM policy: "platform", a named policy, or "" for none. */
  export let tpmPolicy = 'platform';
  export let requirePassword = false;
  export let password = '';
  export let passwordConfirm = '';

  let namedPolicies: TPMPolicyInfo[] = [];

  $: isTPM = backend === 'tpm2';
  // Only the tpm2 backend can bind to a TPM policy.
  $: if (!isTPM && tpmPolicy !== '') {
    tpmPolicy = '';
  }
  $: if (!requirePassword) {
    password = '';
    passwordConfirm = '';
  }

  onMount(async () => {
    const policies = await callBackend<TPMPolicyInfo[]>('TPMPolicyService', 'ListPolicies');
    namedPolicies = (policies ?? []).filter((p) => !p.builtin);
  });
</script>

<div class="policy-picker" data-testid="seal-policy-picker">
  {#if isTPM}
    <div class="form-field">
      <label class="text-label-medium" for="seal-tpm-policy">TPM policy</label>
      <select id="seal-tpm-policy" class="form-select" bind:value={tpmPolicy}>
        <option value="platform">Platform (built-in): platform PCR or password</option>
        {#each namedPolicies as policy (policy.name)}
          <option value={policy.name}>{policy.name}: {policySummary(policy)}</option>
        {/each}
        <option value="">None</option>
      </select>
      <span class="text-body-small hint">
        {tpmPolicy === ''
          ? 'The TPM unseals the data without checking the platform state.'
          : 'The TPM unseals the data only while the policy is satisfied.'}
      </span>
    </div>
  {/if}

  <Toggle bind:checked={requirePassword} label="Also require a password" />
  {#if requirePassword}
    <Input label="Password" type="password" placeholder="Password for the sealed data" bind:value={password} />
    <Input label="Confirm Password" type="password" placeholder="Re-enter password" bind:value={passwordConfirm} />
    {#if password && passwordConfirm && password !== passwordConfirm}
      <span class="text-body-small mismatch" role="alert">Passwords do not match</span>
    {/if}
    {#if isTPM && tpmPolicy !== ''}
      <span class="text-body-small hint">The password also unseals the data after the platform state changes.</span>
    {/if}
  {/if}
</div>

<style>
  .policy-picker {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .form-select {
    padding: 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-outline);
    background-color: var(--color-surface);
    color: var(--color-on-surface);
  }

  .hint {
    color: var(--color-on-surface-variant);
  }

  .mismatch {
    color: var(--color-error);
  }
</style>
