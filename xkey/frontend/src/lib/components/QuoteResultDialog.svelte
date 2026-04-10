<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import { mdiContentCopy, mdiShieldCheckOutline } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import type { BackendQuote } from '$lib/api/backend';
  import { truncateMiddle } from '$lib/utils/format';

  export let open: boolean = false;
  export let quote: BackendQuote | null = null;
  export let onClose: () => void = () => {};

  interface QuoteField {
    label: string;
    value: string;
    key: string;
  }

  $: fields = quote ? [
    { label: 'Quote Data', value: quote.quote_data, key: 'quote_data' },
    { label: 'Signature', value: quote.signature, key: 'signature' },
    { label: 'PCR Digest', value: quote.pcr_digest, key: 'pcr_digest' },
    { label: 'Nonce', value: quote.nonce, key: 'nonce' },
    { label: 'Created At', value: quote.created_at, key: 'created_at' },
  ] as QuoteField[] : [];

  async function copyField(field: QuoteField): Promise<void> {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      await navigator.clipboard.writeText(field.value);
      addNotification('success', `${field.label} copied to clipboard`);
    }
  }

  async function copyAllFields(): Promise<void> {
    if (!quote || typeof navigator === 'undefined' || !navigator.clipboard) return;
    const text = fields
      .map((f) => `${f.label}: ${f.value}`)
      .join('\n\n');
    await navigator.clipboard.writeText(text);
    addNotification('success', 'All quote data copied to clipboard');
  }
</script>

<Modal bind:open title="TPM Quote Result" maxWidth="560px">
  <div class="quote-result">
    <div class="quote-header">
      <Icon path={mdiShieldCheckOutline} size={24} />
      <span class="text-title-small">Attestation Quote</span>
    </div>

    {#if quote}
      <div class="quote-fields">
        {#each fields as field}
          <div class="quote-field">
            <div class="field-header">
              <span class="text-label-medium field-label">{field.label}</span>
              <button
                class="copy-btn"
                on:click={() => copyField(field)}
                title="Copy {field.label} to clipboard"
                aria-label="Copy {field.label} to clipboard"
              >
                <Icon path={mdiContentCopy} size={14} />
              </button>
            </div>
            <div class="field-value-container">
              {#if field.key === 'created_at'}
                <span class="text-body-medium field-value">{field.value}</span>
              {:else}
                <span
                  class="text-body-small field-value font-mono"
                  title={field.value}
                >
                  {truncateMiddle(field.value, 80)}
                </span>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {:else}
      <p class="text-body-medium no-quote">No quote data available.</p>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    {#if quote}
      <Button variant="outline" icon={mdiContentCopy} on:click={copyAllFields}>Copy All</Button>
    {/if}
    <Button variant="text" on:click={() => { open = false; onClose(); }}>Close</Button>
  </svelte:fragment>
</Modal>

<style>
  .quote-result {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .quote-header {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-security-verified);
    padding-bottom: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .quote-fields {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .quote-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .field-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 11px;
  }

  .copy-btn {
    width: 24px;
    height: 24px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background-color var(--transition-fast);
    flex-shrink: 0;
  }

  .copy-btn:hover {
    background-color: var(--color-surface-variant);
  }

  .field-value-container {
    padding: 8px 12px;
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    border: 1px solid var(--color-outline-variant);
  }

  .field-value {
    color: var(--color-on-surface);
    word-break: break-all;
    line-height: 1.4;
  }

  .no-quote {
    color: var(--color-on-surface-variant);
    text-align: center;
    padding: 24px;
    margin: 0;
  }
</style>
