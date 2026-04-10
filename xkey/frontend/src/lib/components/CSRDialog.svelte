<script context="module" lang="ts">
  export interface CSRDialogData {
    commonName: string;
    organization: string;
    organizationalUnit: string;
    country: string;
    state: string;
    locality: string;
    algorithm: string;
  }
</script>

<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';

  export let open: boolean = false;
  export let onClose: () => void = () => {};
  export let onGenerate: ((data: CSRDialogData) => void) | null = null;

  let commonName = '';
  let organization = '';
  let organizationalUnit = '';
  let country = '';
  let state = '';
  let locality = '';
  let algorithm = 'ECDSA P-256';
  let errors: Record<string, string> = {};

  $: if (open) {
    commonName = '';
    organization = '';
    organizationalUnit = '';
    country = '';
    state = '';
    locality = '';
    algorithm = 'ECDSA P-256';
    errors = {};
  }

  function validate(): boolean {
    errors = {};
    if (!commonName.trim()) errors['cn'] = 'Common Name is required';
    return Object.keys(errors).length === 0;
  }

  function handleGenerate(): void {
    if (!validate()) return;
    onGenerate?.({ commonName, organization, organizationalUnit, country, state, locality, algorithm });
    open = false;
    onClose();
  }
</script>

<Modal bind:open title="Generate CSR" maxWidth="480px">
  <div class="csr-form">
    <slot />
    <Input
      label="Common Name (CN)"
      placeholder="e.g., John Doe"
      bind:value={commonName}
      error={errors['cn'] || ''}
    />
    <Input
      label="Organization (O)"
      placeholder="e.g., Acme Corp"
      bind:value={organization}
    />
    <Input
      label="Organizational Unit (OU)"
      placeholder="e.g., Engineering"
      bind:value={organizationalUnit}
    />
    <Input
      label="Country (C)"
      placeholder="e.g., US"
      bind:value={country}
    />
    <Input
      label="State / Province (ST)"
      placeholder="e.g., California"
      bind:value={state}
    />
    <Input
      label="Locality / City (L)"
      placeholder="e.g., San Francisco"
      bind:value={locality}
    />
    <div class="form-field">
      <label class="text-label-medium form-label" for="csr-algorithm">Algorithm</label>
      <select id="csr-algorithm" class="form-select" bind:value={algorithm}>
        <option>ECDSA P-256</option>
        <option>ECDSA P-384</option>
        <option>RSA 2048</option>
        <option>RSA 4096</option>
      </select>
    </div>
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => { open = false; onClose(); }}>Cancel</Button>
    <Button variant="primary" on:click={handleGenerate}>Generate CSR</Button>
  </svelte:fragment>
</Modal>

<style>
  .csr-form {
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
