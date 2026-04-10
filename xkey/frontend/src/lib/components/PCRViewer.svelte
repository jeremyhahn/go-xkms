<script lang="ts">
  import Card from './Card.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import { mdiExport } from '$lib/utils/icons';

  export let pcrs: Array<{ index: number; value: string; description: string }> = [];
  export let bank: string = 'sha256';
  export let onBankChange: ((bank: string) => void) | null = null;
  export let onExport: (() => void) | null = null;

  // Internal values use lowercase to match the backend's validPCRBanks map.
  // Display labels use the conventional uppercase format for the UI.
  const banks: Array<{ value: string; label: string }> = [
    { value: 'sha1', label: 'SHA-1' },
    { value: 'sha256', label: 'SHA-256' },
    { value: 'sha384', label: 'SHA-384' },
    { value: 'sha512', label: 'SHA-512' },
  ];

  $: displayBank = banks.find((b) => b.value === bank)?.label ?? bank.toUpperCase();
</script>

<Card variant="outlined">
  <div class="pcr-viewer">
    <div class="pcr-header">
      <h3 class="text-title-medium pcr-title">PCR Values ({displayBank})</h3>
      <div class="pcr-controls">
        <select class="bank-select text-label-medium" bind:value={bank} on:change={() => onBankChange?.(bank)}>
          {#each banks as b}
            <option value={b.value}>{b.label}</option>
          {/each}
        </select>
        <Button variant="outline" size="sm" icon={mdiExport} on:click={() => onExport?.()}>Export</Button>
      </div>
    </div>

    <div class="pcr-table">
      <div class="pcr-table-header">
        <span class="pcr-col-index text-label-small">PCR</span>
        <span class="pcr-col-value text-label-small">Value</span>
        <span class="pcr-col-desc text-label-small">Description</span>
      </div>
      {#each pcrs as pcr}
        <div class="pcr-row">
          <span class="pcr-col-index text-body-small font-mono">{pcr.index}</span>
          <span class="pcr-col-value text-body-small font-mono" title={pcr.value}>
            {pcr.value}
          </span>
          <span class="pcr-col-desc text-body-small">{pcr.description}</span>
        </div>
      {/each}
    </div>

    {#if pcrs.length === 0}
      <p class="text-body-medium pcr-empty">No PCR values available for this bank.</p>
    {/if}
  </div>
</Card>

<style>
  .pcr-viewer {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .pcr-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .pcr-title {
    margin: 0;
    color: var(--color-on-surface);
  }

  .pcr-controls {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .bank-select {
    height: 36px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    outline: none;
    cursor: pointer;
  }

  .pcr-table {
    display: flex;
    flex-direction: column;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    max-height: 600px;
    overflow-y: auto;
  }

  .pcr-table-header {
    display: flex;
    padding: 8px 12px;
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
    gap: 12px;
    position: sticky;
    top: 0;
    z-index: 1;
  }

  .pcr-row {
    display: flex;
    padding: 8px 12px;
    gap: 12px;
    border-top: 1px solid var(--color-outline-variant);
    transition: background-color var(--transition-fast);
  }

  .pcr-row:hover {
    background-color: var(--color-surface-container-low);
  }

  .pcr-col-index {
    width: 48px;
    flex-shrink: 0;
    text-align: center;
  }

  .pcr-col-value {
    flex: 1;
    min-width: 0;
    word-break: break-all;
    font-size: 12px;
    line-height: 1.4;
  }

  .pcr-col-desc {
    width: 200px;
    flex-shrink: 0;
    color: var(--color-on-surface-variant);
  }

  .pcr-empty {
    color: var(--color-on-surface-variant);
    text-align: center;
    padding: 24px;
    margin: 0;
  }
</style>
