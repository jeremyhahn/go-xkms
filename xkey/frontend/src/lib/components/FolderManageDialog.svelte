<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';

  export let open: boolean = false;
  export let mode: 'create' | 'rename' = 'create';
  export let currentName: string = '';
  export let initialValue: string = '';
  export let onClose: () => void = () => {};
  export let onSubmit: (name: string) => void = () => {};

  let folderName = '';

  $: if (open) {
    folderName = mode === 'rename' ? currentName : initialValue;
  }

  function handleSubmit(): void {
    if (!folderName.trim()) return;
    onSubmit(folderName.trim());
    open = false;
  }

  function handleClose(): void {
    open = false;
    onClose();
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter' && folderName.trim()) {
      handleSubmit();
    }
  }
</script>

<Modal bind:open title={mode === 'create' ? 'New Folder' : 'Rename Folder'} maxWidth="400px">
  <div class="folder-form">
    <label class="form-field">
      <span class="form-label">{mode === 'create' ? 'Folder Name' : 'New Name'}</span>
      <input
        type="text"
        class="form-input"
        bind:value={folderName}
        placeholder={mode === 'create' ? 'e.g. Work/Email' : 'Enter new name'}
        on:keydown={handleKeydown}
      />
      {#if mode === 'create'}
        <span class="form-hint">Use "/" to create nested folders (e.g. Work/Email)</span>
      {/if}
    </label>
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={handleClose}>Cancel</Button>
    <Button variant="primary" on:click={handleSubmit} disabled={!folderName.trim()}>
      {mode === 'create' ? 'Create' : 'Rename'}
    </Button>
  </svelte:fragment>
</Modal>

<style>
  .folder-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-label {
    font-size: 13px;
    font-weight: 500;
    color: var(--color-on-surface-variant);
  }

  .form-input {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    transition: border-color var(--transition-fast);
    width: 100%;
    box-sizing: border-box;
  }

  .form-input:focus {
    border-color: var(--color-primary);
  }

  .form-hint {
    font-size: 12px;
    color: var(--color-on-surface-variant);
    opacity: 0.7;
  }
</style>
