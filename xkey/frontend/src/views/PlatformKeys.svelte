<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import IdentityKeys from './IdentityKeys.svelte';
  import {
    mdiChevronUp, mdiChevronDown, mdiShieldCheckOutline, mdiKey,
    mdiDatabaseOutline
  } from '$lib/utils/icons';
  import { isWailsAvailable, callBackend } from '$lib/api/backend';
  import type { BackendSharedSRKInfo, BackendPlatformSRKInfo } from '$lib/api/backend';

  let loading = true;
  let sharedSrkInfo: BackendSharedSRKInfo | null = null;
  let platformSrkInfo: BackendPlatformSRKInfo | null = null;

  // Collapsible section state
  let srkExpanded = true;
  let keystoreExpanded = true;
  let identityExpanded = true;

  onMount(async () => {
    if (!isWailsAvailable()) {
      loading = false;
      return;
    }
    try {
      sharedSrkInfo = await callBackend<BackendSharedSRKInfo>('TPMService', 'GetSharedSRKInfo');
      platformSrkInfo = await callBackend<BackendPlatformSRKInfo>('TPMService', 'GetPlatformSRKInfo');
    } catch (err) {
      console.error('Failed to load SRK info:', err);
    }
    loading = false;
  });
</script>

<div class="platform-keys-view">
  <GradientHeader title="Platform Keys" subtitle="TPM platform key hierarchy" />

  {#if loading}
    <div class="loading-container">
      <LoadingSpinner size={48} />
      <p class="text-body-medium loading-text">Loading platform key data...</p>
    </div>
  {:else}
    <div class="view-content">

      <!-- TCG Shared SRK Section -->
      <Card variant="elevated">
        <div class="section">
          <button class="section-toggle" on:click={() => (srkExpanded = !srkExpanded)}>
            <h2 class="text-title-medium section-heading">
              <Icon path={mdiShieldCheckOutline} size={20} />
              TCG Shared SRK
            </h2>
            <Icon path={srkExpanded ? mdiChevronUp : mdiChevronDown} size={20} />
          </button>

          {#if srkExpanded}
            <div class="section-body">
              {#if sharedSrkInfo?.present}
                <div class="details-grid">
                  <div class="detail-item">
                    <span class="text-label-small field-label">Handle</span>
                    <span class="text-body-medium font-mono">{sharedSrkInfo.handle || 'N/A'}</span>
                  </div>
                  <div class="detail-item">
                    <span class="text-label-small field-label">Algorithm</span>
                    <span class="text-body-medium">{sharedSrkInfo.algorithm}</span>
                  </div>
                  <div class="detail-item">
                    <span class="text-label-small field-label">Status</span>
                    <span class="text-body-medium" style="color: var(--color-primary);">Provisioned</span>
                  </div>
                </div>
              {:else}
                <p class="text-body-medium empty-text">TCG Shared SRK is not provisioned.</p>
              {/if}
            </div>
          {/if}
        </div>
      </Card>

      <!-- Platform SRK Section -->
      <Card variant="elevated">
        <div class="section">
          <button class="section-toggle" on:click={() => (keystoreExpanded = !keystoreExpanded)}>
            <h2 class="text-title-medium section-heading">
              <Icon path={mdiDatabaseOutline} size={20} />
              Platform SRK
            </h2>
            <Icon path={keystoreExpanded ? mdiChevronUp : mdiChevronDown} size={20} />
          </button>

          {#if keystoreExpanded}
            <div class="section-body">
              {#if platformSrkInfo?.present}
                <div class="details-grid">
                  <div class="detail-item">
                    <span class="text-label-small field-label">Handle</span>
                    <span class="text-body-medium font-mono">
                      {platformSrkInfo?.handle || 'N/A'}
                    </span>
                  </div>
                  <div class="detail-item">
                    <span class="text-label-small field-label">Algorithm</span>
                    <span class="text-body-medium">
                      {platformSrkInfo?.algorithm || 'N/A'}
                    </span>
                  </div>
                  <div class="detail-item">
                    <span class="text-label-small field-label">Status</span>
                    <span class="text-body-medium" style="color: var(--color-primary);">Provisioned</span>
                  </div>
                  <div class="detail-item">
                    <span class="text-label-small field-label">Policy</span>
                    <span class="text-body-medium">
                      {platformSrkInfo?.policy_enabled ? platformSrkInfo.policy_name : 'None'}
                    </span>
                  </div>
                </div>
              {:else}
                <p class="text-body-medium empty-text">Platform SRK is not provisioned.</p>
              {/if}
            </div>
          {/if}
        </div>
      </Card>

      <!-- Identity Keys Section -->
      <Card variant="elevated">
        <div class="section">
          <button class="section-toggle" on:click={() => (identityExpanded = !identityExpanded)}>
            <h2 class="text-title-medium section-heading">
              <Icon path={mdiKey} size={20} />
              Identity Keys
            </h2>
            <Icon path={identityExpanded ? mdiChevronUp : mdiChevronDown} size={20} />
          </button>

          {#if identityExpanded}
            <div class="section-body">
              <IdentityKeys />
            </div>
          {/if}
        </div>
      </Card>

    </div>
  {/if}
</div>

<style>
  .platform-keys-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .view-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    max-width: 700px;
  }

  .loading-container {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    padding: 48px;
  }

  .loading-text {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .section {
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .section-toggle {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    background: none;
    border: none;
    padding: 0;
    cursor: pointer;
    color: var(--color-on-surface);
    border-bottom: 1px solid var(--color-outline-variant);
    padding-bottom: 8px;
  }

  .section-toggle:hover {
    opacity: 0.8;
  }

  .section-heading {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
    color: var(--color-on-surface);
  }

  .section-body {
    padding-top: 16px;
  }

  .details-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
  }

  .detail-item {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .empty-text {
    color: var(--color-on-surface-variant);
    margin: 0;
  }
</style>
