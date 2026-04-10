<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import CollapsibleSection from './CollapsibleSection.svelte';
  import { mdiRefresh, mdiEye, mdiEyeOff } from '$lib/utils/icons';
  import { callBackend } from '$lib/api/backend';
  import type { StaticPasswordEntry, AddPasswordParams, UpdatePasswordParams } from '$lib/api/backend';

  export let open: boolean = false;
  export let mode: 'add' | 'edit' = 'add';
  export let entry: StaticPasswordEntry | null = null;
  export let folders: string[] = [];
  export let onClose: () => void = () => {};
  export let onSave: (params: AddPasswordParams | UpdatePasswordParams) => void = () => {};

  let name = '';
  let username = '';
  let password = '';
  let url = '';
  let matchPatternsText = '';
  let notes = '';
  let folderPath = '';
  let expiresAt = '';
  let genLength = 32;
  let genCharset = 'all';
  let showPassword = false;
  let showNewFolder = false;
  let newFolderName = '';

  $: if (open) {
    resetFields();
  }

  function resetFields(): void {
    if (mode === 'edit' && entry) {
      name = entry.title || entry.name || '';
      username = entry.username || '';
      password = entry.password || '';
      url = entry.url || '';
      matchPatternsText = (entry.match_patterns || []).join('\n');
      notes = entry.notes || '';
      folderPath = entry.folder_path || '';
      expiresAt = entry.expires_at ? formatDateForInput(entry.expires_at) : '';
    } else {
      name = '';
      username = '';
      password = '';
      url = '';
      matchPatternsText = '';
      notes = '';
      folderPath = '';
      expiresAt = '';
    }
    genLength = 32;
    genCharset = 'all';
    showPassword = false;
    showNewFolder = false;
    newFolderName = '';
  }

  function formatDateForInput(dateStr: string): string {
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr);
      return d.toISOString().slice(0, 16);
    } catch {
      return '';
    }
  }

  async function generatePassword(): Promise<void> {
    const result = await callBackend<string>('StaticPasswordService', 'GeneratePassword', genLength, genCharset);
    if (result) {
      password = result;
    }
  }

  function handleFolderChange(value: string): void {
    if (value === '__new__') {
      showNewFolder = true;
      folderPath = '';
    } else {
      showNewFolder = false;
      folderPath = value;
    }
  }

  function parseMatchPatterns(text: string): string[] | undefined {
    const patterns = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    return patterns.length > 0 ? patterns : undefined;
  }

  function handleSave(): void {
    const resolvedFolder = showNewFolder ? newFolderName : folderPath;
    const resolvedExpiry = expiresAt ? new Date(expiresAt).toISOString() : '';
    const patterns = parseMatchPatterns(matchPatternsText);

    if (mode === 'edit' && entry) {
      const params: UpdatePasswordParams = {
        id: entry.id,
        name,
        title: name,
        username,
        password,
        url,
        match_patterns: patterns,
        notes,
        folder_path: resolvedFolder,
        expires_at: resolvedExpiry,
      };
      onSave(params);
    } else {
      const params: AddPasswordParams = {
        name,
        title: name,
        username,
        password,
        url,
        match_patterns: patterns,
        notes,
        folder_path: resolvedFolder,
        expires_at: resolvedExpiry,
      };
      onSave(params);
    }
  }

  function handleClose(): void {
    open = false;
    onClose();
  }
</script>

<Modal bind:open title={mode === 'add' ? 'Add Password' : 'Edit Password'} maxWidth="520px">
  <div class="form-container">
    <label class="form-field">
      <span class="form-label">Name <span class="required">*</span></span>
      <input type="text" class="form-input" bind:value={name} placeholder="e.g. GitHub Account" />
    </label>

    <label class="form-field">
      <span class="form-label">Username</span>
      <input type="text" class="form-input" bind:value={username} placeholder="e.g. user@example.com" />
    </label>

    <div class="form-field">
      <span class="form-label">Password</span>
      <div class="password-row">
        <div class="password-input-wrapper">
          {#if showPassword}
            <input type="text" class="form-input font-mono" bind:value={password} placeholder="Enter or generate" />
          {:else}
            <input type="password" class="form-input font-mono" bind:value={password} placeholder="Enter or generate" />
          {/if}
          <button class="input-action-btn" on:click={() => (showPassword = !showPassword)} title={showPassword ? 'Hide' : 'Reveal'}>
            <Icon path={showPassword ? mdiEyeOff : mdiEye} size={18} />
          </button>
        </div>
        <button class="generate-btn" on:click={generatePassword} title="Generate password">
          <Icon path={mdiRefresh} size={18} />
        </button>
      </div>
      <div class="generate-options">
        <label class="option-field">
          <span class="option-label">Length</span>
          <input type="range" min="8" max="128" bind:value={genLength} class="option-slider" />
          <span class="option-value">{genLength}</span>
        </label>
        <label class="option-field">
          <span class="option-label">Charset</span>
          <select bind:value={genCharset} class="form-select">
            <option value="all">All characters</option>
            <option value="alphanumeric">Alphanumeric</option>
          </select>
        </label>
      </div>
    </div>

    <label class="form-field">
      <span class="form-label">URL</span>
      <input type="text" class="form-input" bind:value={url} placeholder="e.g. https://github.com" />
    </label>

    <label class="form-field">
      <span class="form-label">Notes</span>
      <textarea class="form-input form-textarea" bind:value={notes} placeholder="Optional notes..." rows="3"></textarea>
    </label>

    <div class="form-field">
      <span class="form-label">Folder</span>
      {#if !showNewFolder}
        <select
          class="form-select"
          value={folderPath}
          on:change={(e) => handleFolderChange(e.currentTarget.value)}
        >
          <option value="">No folder</option>
          {#each folders as f}
            <option value={f}>{f}</option>
          {/each}
          <option value="__new__">New folder...</option>
        </select>
      {:else}
        <div class="new-folder-row">
          <input type="text" class="form-input" bind:value={newFolderName} placeholder="e.g. Work/Email" />
          <button class="cancel-new-btn" on:click={() => { showNewFolder = false; folderPath = ''; }}>Cancel</button>
        </div>
      {/if}
    </div>

    <CollapsibleSection title="Advanced" defaultOpen={false}>
      <label class="form-field">
        <span class="form-label">URL Match Patterns</span>
        <textarea
          class="form-input form-textarea match-patterns-input"
          bind:value={matchPatternsText}
          placeholder="*.signin.aws.amazon.com&#10;login.example.com"
          rows="2"
        ></textarea>
        <span class="form-hint">One pattern per line. Use *.domain.com to match all subdomains.</span>
      </label>

      <label class="form-field">
        <span class="form-label">Expires At</span>
        <input type="datetime-local" class="form-input" bind:value={expiresAt} />
      </label>
    </CollapsibleSection>
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={handleClose}>Cancel</Button>
    <Button variant="primary" on:click={handleSave} disabled={!name.trim() || !password}>
      {mode === 'add' ? 'Add' : 'Save'}
    </Button>
  </svelte:fragment>
</Modal>

<style>
  .form-container {
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

  .required {
    color: var(--color-error);
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

  .form-input.font-mono {
    font-family: var(--font-mono, monospace);
  }

  .form-textarea {
    resize: vertical;
    min-height: 60px;
  }

  .match-patterns-input {
    font-family: var(--font-mono, monospace);
    font-size: 13px;
    min-height: 44px;
  }

  .form-hint {
    font-size: 11px;
    color: var(--color-on-surface-variant);
    opacity: 0.7;
  }

  .form-select {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    transition: border-color var(--transition-fast);
    cursor: pointer;
    width: 100%;
    box-sizing: border-box;
  }

  .form-select:focus {
    border-color: var(--color-primary);
  }

  .password-row {
    display: flex;
    gap: 8px;
  }

  .password-input-wrapper {
    flex: 1;
    position: relative;
  }

  .password-input-wrapper .form-input {
    padding-right: 40px;
  }

  .input-action-btn {
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    width: 28px;
    height: 28px;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0;
  }

  .input-action-btn:hover {
    background-color: var(--color-surface-variant);
  }

  .generate-btn {
    width: 42px;
    height: 42px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface-variant);
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background-color var(--transition-fast);
    padding: 0;
  }

  .generate-btn:hover {
    background: var(--color-surface-container);
  }

  .generate-options {
    display: flex;
    gap: 16px;
    margin-top: 8px;
  }

  .option-field {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
  }

  .option-label {
    font-size: 12px;
    color: var(--color-on-surface-variant);
    flex-shrink: 0;
  }

  .option-slider {
    flex: 1;
    min-width: 60px;
    accent-color: var(--color-primary);
  }

  .option-value {
    font-size: 12px;
    font-weight: 500;
    color: var(--color-on-surface);
    min-width: 28px;
    text-align: right;
  }

  .new-folder-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .new-folder-row .form-input {
    flex: 1;
  }

  .cancel-new-btn {
    padding: 8px 12px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-primary);
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 500;
    white-space: nowrap;
    transition: background-color var(--transition-fast);
  }

  .cancel-new-btn:hover {
    background-color: var(--color-primary-95, var(--color-surface-container));
  }
</style>
