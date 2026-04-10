<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';

  export let open: boolean = false;
  export let onClose: () => void = () => {};
  export let onGenerate: ((data: { pcrSelection: number[]; bank: string; nonce: string }) => void) | null = null;

  // Internal values use lowercase to match the backend's validPCRBanks map.
  const bankOptions: Array<{ value: string; label: string }> = [
    { value: 'sha1', label: 'SHA-1' },
    { value: 'sha256', label: 'SHA-256' },
    { value: 'sha384', label: 'SHA-384' },
    { value: 'sha512', label: 'SHA-512' },
  ];

  let bank = 'sha256';
  let nonce = '';
  let pcrInput = '0,1,2,3,4,5,6,7';

  $: if (open) {
    bank = 'sha256';
    nonce = '';
    pcrInput = '0,1,2,3,4,5,6,7';
  }

  function handleGenerate(): void {
    const selection = pcrInput
      .split(',')
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => !isNaN(n));
    onGenerate?.({ pcrSelection: selection, bank, nonce });
    open = false;
    onClose();
  }
</script>

<Modal bind:open title="Generate TPM Quote" maxWidth="440px">
  <div class="quote-form">
    <Input
      label="PCR Selection"
      placeholder="e.g., 0,1,2,3,4,5,6,7"
      bind:value={pcrInput}
      helperText="Comma-separated PCR indices to include in the quote"
    />
    <div class="form-field">
      <label class="text-label-medium form-label" for="quote-hash-algo">Hash Algorithm</label>
      <select id="quote-hash-algo" class="form-select" bind:value={bank}>
        {#each bankOptions as opt}
          <option value={opt.value}>{opt.label}</option>
        {/each}
      </select>
    </div>
    <Input
      label="Nonce (optional)"
      placeholder="Hex-encoded nonce (leave empty to auto-generate)"
      bind:value={nonce}
      helperText="Random hex nonce for freshness. If empty, one will be generated."
      monospace
    />
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => { open = false; onClose(); }}>Cancel</Button>
    <Button variant="primary" on:click={handleGenerate}>Generate Quote</Button>
  </svelte:fragment>
</Modal>

<style>
  .quote-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .form-label {
    color: var(--color-on-surface-variant);
    padding-left: 4px;
  }

  .form-select {
    height: 48px;
    padding: 0 16px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    cursor: pointer;
    transition: border-color var(--transition-fast);
  }

  .form-select:focus {
    border-color: var(--color-primary);
    box-shadow: 0 0 0 1px var(--color-primary);
  }
</style>
