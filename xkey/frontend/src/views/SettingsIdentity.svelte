<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '$lib/components/Card.svelte';
  import Input from '$lib/components/Input.svelte';
  import Button from '$lib/components/Button.svelte';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend, callBackendVoidWithError } from '$lib/api/backend';
  import type { IdentityConfig } from '$lib/api/backend';

  let loading = false;
  let saving = false;

  let identity: IdentityConfig = {
    common_name: '',
    organization: '',
    organizational_unit: '',
    country: '',
    province: '',
    locality: '',
  };

  onMount(async () => {
    if (!isWailsAvailable()) return;
    loading = true;
    const result = await callBackend<IdentityConfig>('AppService', 'GetIdentity');
    if (result) {
      identity = result;
    }
    loading = false;
  });

  async function handleSave(): Promise<void> {
    saving = true;
    const result = await callBackendVoidWithError('AppService', 'UpdateIdentity', identity);
    saving = false;
    if (result.ok) {
      addNotification('success', 'Identity saved');
    } else {
      addNotification('error', result.error || 'Failed to save identity');
    }
  }
</script>

<Card variant="elevated">
  <div class="settings-section" data-testid="settings-identity-section">
    <h2 class="text-title-medium section-heading">Identity</h2>
    <p class="text-body-small setting-desc identity-desc">
      Default X.509 subject fields used when generating certificates.
    </p>

    {#if loading}
      <p class="text-body-small setting-desc">Loading...</p>
    {:else}
      <div class="identity-form" data-testid="identity-form">
        <div class="identity-field">
          <Input
            label="Common Name"
            placeholder="e.g. John Smith"
            bind:value={identity.common_name}
          />
        </div>
        <div class="identity-field">
          <Input
            label="Organization"
            placeholder="e.g. Acme Corp"
            bind:value={identity.organization}
          />
        </div>
        <div class="identity-field">
          <Input
            label="Organizational Unit"
            placeholder="e.g. Engineering"
            bind:value={identity.organizational_unit}
          />
        </div>
        <div class="identity-field">
          <Input
            label="Country (ISO 3166-1 alpha-2)"
            placeholder="e.g. US"
            bind:value={identity.country}
          />
        </div>
        <div class="identity-field">
          <Input
            label="State / Province"
            placeholder="e.g. California"
            bind:value={identity.province}
          />
        </div>
        <div class="identity-field">
          <Input
            label="Locality / City"
            placeholder="e.g. San Francisco"
            bind:value={identity.locality}
          />
        </div>
      </div>

      <div class="identity-actions">
        <Button variant="primary" loading={saving} on:click={handleSave}>
          Save
        </Button>
      </div>
    {/if}
  </div>
</Card>

<style>
  .identity-desc {
    margin-top: 4px;
    color: var(--color-on-surface-variant);
  }

  .identity-form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .identity-field {
    display: flex;
    flex-direction: column;
  }

  .identity-actions {
    display: flex;
    justify-content: flex-end;
    padding-top: 8px;
    border-top: 1px solid var(--color-outline-variant);
  }
</style>
