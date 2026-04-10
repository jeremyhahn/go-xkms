<script lang="ts">
  import { onMount, createEventDispatcher } from 'svelte';
  import GradientHeader from './GradientHeader.svelte';
  import Icon from './Icon.svelte';
  import Input from './Input.svelte';
  import Button from './Button.svelte';
  import { mdiShieldKeyOutline } from '$lib/utils/icons';
  import { isWailsAvailable, callBackend, callBackendVoidWithError } from '$lib/api/backend';

  export let configKey: string;
  export let title: string;
  export let subtitle: string = '';
  export let description: string = '';
  export let icon: string = mdiShieldKeyOutline;

  let pinRequired = false;
  let pinVerified = false;
  let pinInput = '';
  let pinVerifying = false;
  let pinError = '';
  let checking = true;

  const dispatch = createEventDispatcher<{ verified: void }>();

  async function checkConfig(): Promise<void> {
    if (!isWailsAvailable()) {
      checking = false;
      dispatch('verified');
      return;
    }
    const config = await callBackend<Record<string, any>>('AppService', 'GetConfig');
    if (config?.[configKey]) {
      pinRequired = true;
    } else {
      dispatch('verified');
    }
    checking = false;
  }

  async function handleVerify(): Promise<void> {
    if (!pinInput) return;
    pinVerifying = true;
    pinError = '';
    const { ok, error } = await callBackendVoidWithError('PINService', 'VerifyUserPIN', pinInput);
    if (ok) {
      pinVerified = true;
      pinInput = '';
      dispatch('verified');
    } else {
      pinError = error || 'Incorrect PIN. Please try again.';
    }
    pinVerifying = false;
  }

  onMount(checkConfig);
</script>

{#if checking}
  <!-- Config check in progress -->
{:else if pinRequired && !pinVerified}
  <GradientHeader {title} {subtitle} />
  <div class="pin-gate-area">
    <div class="lock-overlay">
      <div class="lock-card">
        <Icon path={icon} size={48} color="var(--color-primary)" />
        <h2 class="text-headline-small">PIN Required</h2>
        <p class="text-body-medium">{description}</p>
        <div class="unlock-form-inline">
          <Input
            type="password"
            placeholder="Enter PIN"
            bind:value={pinInput}
            disabled={pinVerifying}
            on:keydown={(e) => { if (e.key === 'Enter') handleVerify(); }}
          />
          <Button variant="primary" loading={pinVerifying} on:click={handleVerify} disabled={!pinInput}>
            Verify PIN
          </Button>
        </div>
        {#if pinError}
          <p class="pin-error text-body-small">{pinError}</p>
        {/if}
      </div>
    </div>
  </div>
{:else}
  <slot />
{/if}

<style>
  .pin-gate-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .lock-overlay {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 48px;
  }

  .lock-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    text-align: center;
    color: var(--color-on-surface-variant);
    max-width: 400px;
  }

  .lock-card h2 {
    color: var(--color-on-surface);
    margin: 0;
  }

  .lock-card p {
    margin: 0;
  }

  .unlock-form-inline {
    display: flex;
    gap: 12px;
    width: 100%;
    align-items: flex-end;
  }

  .unlock-form-inline :global(.input-wrapper) {
    flex: 1;
  }

  .pin-error {
    color: var(--color-error);
    text-align: center;
  }
</style>
