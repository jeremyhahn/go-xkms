<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import Icon from './Icon.svelte';
  import { mdiFileDocumentOutline, mdiFolder } from '$lib/utils/icons';
  import { callBackend } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';
  import type { ImportParams, ImportResult, ImportPreviewResult } from '$lib/api/backend';

  export let open = false;
  export let onClose: () => void = () => {};
  export let onImported: () => void = () => {};

  let filePath = '';
  let format = '';  // Auto-detect
  let password = '';
  let targetFolder = '';
  let skipDuplicates = true;
  let overwriteDuplicates = false;
  let importTOTP = true;

  let preview: ImportPreviewResult | null = null;
  let previewing = false;
  let importing = false;
  let step: 'select' | 'preview' | 'result' = 'select';
  let result: ImportResult | null = null;

  $: needsPassword = filePath.toLowerCase().endsWith('.kdbx');
  $: detectedFormat = detectFormat(filePath);

  function detectFormat(path: string): string {
    if (!path) return '';
    const lower = path.toLowerCase();
    if (lower.endsWith('.kdbx')) return 'KeePass Database (KDBX)';
    if (lower.endsWith('.xml')) return 'KeePass XML Export';
    if (lower.endsWith('.csv')) return 'CSV Export';
    return 'Unknown';
  }

  function resetForm(): void {
    filePath = '';
    format = '';
    password = '';
    targetFolder = '';
    skipDuplicates = true;
    overwriteDuplicates = false;
    importTOTP = true;
    preview = null;
    result = null;
    step = 'select';
    previewing = false;
    importing = false;
  }

  async function handleBrowse(): Promise<void> {
    const path = await callBackend<string>('StaticPasswordService', 'OpenImportFileDialog');
    if (path) {
      filePath = path;
      preview = null;
      step = 'select';
    }
  }

  async function handlePreview(): Promise<void> {
    if (!filePath) {
      addNotification('error', 'Please select a file to import');
      return;
    }
    if (needsPassword && !password) {
      addNotification('error', 'Password is required for KDBX files');
      return;
    }

    previewing = true;
    const params: ImportParams = {
      file_path: filePath,
      format: format,
      password: password,
      target_folder: targetFolder,
      skip_duplicates: skipDuplicates,
      overwrite_duplicates: overwriteDuplicates,
      import_totp: importTOTP,
    };

    const previewResult = await callBackend<ImportPreviewResult>('StaticPasswordService', 'PreviewImport', params);
    previewing = false;

    if (previewResult) {
      preview = previewResult;
      step = 'preview';
    } else {
      addNotification('error', 'Failed to parse import file. Check file format and password.');
    }
  }

  async function handleImport(): Promise<void> {
    if (!filePath) return;

    importing = true;
    const params: ImportParams = {
      file_path: filePath,
      format: format,
      password: password,
      target_folder: targetFolder,
      skip_duplicates: skipDuplicates,
      overwrite_duplicates: overwriteDuplicates,
      import_totp: importTOTP,
    };

    const importResult = await callBackend<ImportResult>('StaticPasswordService', 'ImportPasswords', params);
    importing = false;

    if (importResult) {
      result = importResult;
      step = 'result';
      if (importResult.imported > 0) {
        addNotification('success', `Imported ${importResult.imported} password${importResult.imported !== 1 ? 's' : ''}`);
        onImported();
      }
    } else {
      addNotification('error', 'Import failed');
    }
  }

  function handleClose(): void {
    resetForm();
    open = false;
    onClose();
  }

  function handleBack(): void {
    step = 'select';
  }
</script>

<Modal title="Import Passwords" bind:open persistent={false} maxWidth="560px">
  <!-- Step 1: Select file -->
  {#if step === 'select'}
    <div class="import-body">
      <p class="text-body-medium import-description">
        Import passwords from KeePass (KDBX, XML) or CSV exports.
      </p>

      <div class="file-select">
        <div class="file-input-row">
          <Input
            label="File"
            placeholder="Select a password file..."
            bind:value={filePath}
            readonly
          />
          <Button variant="secondary" on:click={handleBrowse}>Browse</Button>
        </div>
        {#if detectedFormat}
          <span class="format-hint">Format: {detectedFormat}</span>
        {/if}
      </div>

      {#if needsPassword}
        <Input
          type="password"
          label="Database Password"
          placeholder="Enter KDBX master password"
          bind:value={password}
        />
      {/if}

      <Input
        label="Target Folder (optional)"
        placeholder="e.g. Imported/KeePass"
        bind:value={targetFolder}
      />

      <div class="import-options">
        <label class="import-toggle">
          <input type="checkbox" bind:checked={skipDuplicates} />
          <span>Skip duplicate entries</span>
        </label>
        <label class="import-toggle">
          <input type="checkbox" bind:checked={importTOTP} />
          <span>Import TOTP/OTP secrets</span>
        </label>
      </div>
    </div>

  <!-- Step 2: Preview -->
  {:else if step === 'preview'}
    <div class="import-body">
      <p class="text-body-medium import-description">
        Found <strong>{preview?.total || 0}</strong> passwords to import.
      </p>

      <div class="preview-list">
        {#if preview && preview.entries.length > 0}
          <div class="preview-header">
            <span class="preview-col-title">Title</span>
            <span class="preview-col-user">Username</span>
            <span class="preview-col-folder">Folder</span>
          </div>
          <div class="preview-items">
            {#each preview.entries.slice(0, 50) as entry}
              <div class="preview-item">
                <span class="preview-col-title" title={entry.title}>
                  <Icon path={mdiFileDocumentOutline} size={14} />
                  {entry.title || '(untitled)'}
                  {#if entry.has_totp}
                    <span class="totp-badge">TOTP</span>
                  {/if}
                </span>
                <span class="preview-col-user" title={entry.username}>{entry.username || '-'}</span>
                <span class="preview-col-folder" title={entry.folder_path}>
                  {#if entry.folder_path}
                    <Icon path={mdiFolder} size={14} />
                    {entry.folder_path}
                  {:else}
                    -
                  {/if}
                </span>
              </div>
            {/each}
            {#if preview.entries.length > 50}
              <div class="preview-more">
                ... and {preview.entries.length - 50} more entries
              </div>
            {/if}
          </div>
        {:else}
          <p class="text-body-small">No entries found in the file.</p>
        {/if}
      </div>
    </div>

  <!-- Step 3: Result -->
  {:else if step === 'result'}
    <div class="import-body">
      <div class="result-summary">
        <div class="result-stat result-success">
          <span class="result-value">{result?.imported || 0}</span>
          <span class="result-label">Imported</span>
        </div>
        <div class="result-stat result-skipped">
          <span class="result-value">{result?.skipped || 0}</span>
          <span class="result-label">Skipped</span>
        </div>
        <div class="result-stat result-failed">
          <span class="result-value">{result?.failed || 0}</span>
          <span class="result-label">Failed</span>
        </div>
        {#if result?.totp_imported}
          <div class="result-stat result-totp">
            <span class="result-value">{result.totp_imported}</span>
            <span class="result-label">TOTP</span>
          </div>
        {/if}
      </div>

      {#if result?.errors && result.errors.length > 0}
        <div class="result-errors">
          <h4 class="text-title-small">Errors</h4>
          <ul class="error-list">
            {#each result.errors.slice(0, 10) as err}
              <li><strong>{err.entry_name}</strong>: {err.error}</li>
            {/each}
            {#if result.errors.length > 10}
              <li>... and {result.errors.length - 10} more errors</li>
            {/if}
          </ul>
        </div>
      {/if}
    </div>
  {/if}

  <!-- Actions slot - outside of conditionals, with internal conditionals -->
  <svelte:fragment slot="actions">
    {#if step === 'select'}
      <Button variant="text" on:click={handleClose}>Cancel</Button>
      <Button variant="primary" on:click={handlePreview} disabled={!filePath || previewing} loading={previewing}>
        {previewing ? 'Loading...' : 'Preview'}
      </Button>
    {:else if step === 'preview'}
      <Button variant="text" on:click={handleBack}>Back</Button>
      <Button variant="primary" on:click={handleImport} disabled={!preview?.total || importing} loading={importing}>
        {importing ? 'Importing...' : `Import ${preview?.total || 0} Passwords`}
      </Button>
    {:else if step === 'result'}
      <Button variant="primary" on:click={handleClose}>Done</Button>
    {/if}
  </svelte:fragment>
</Modal>

<style>
  .import-body {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .import-description {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .file-select {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .file-input-row {
    display: flex;
    gap: 8px;
    align-items: flex-end;
  }

  .file-input-row :global(.input-wrapper) {
    flex: 1;
  }

  .format-hint {
    font-size: 12px;
    color: var(--color-on-surface-variant);
    margin-left: 2px;
  }

  .import-options {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .import-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    font-size: 14px;
    color: var(--color-on-surface);
  }

  .import-toggle input[type="checkbox"] {
    width: 18px;
    height: 18px;
    accent-color: var(--color-primary);
  }

  .preview-list {
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    max-height: 300px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .preview-header {
    display: flex;
    padding: 8px 12px;
    background: var(--color-surface-container);
    border-bottom: 1px solid var(--color-outline-variant);
    font-size: 12px;
    font-weight: 500;
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
  }

  .preview-items {
    overflow-y: auto;
    flex: 1;
  }

  .preview-item {
    display: flex;
    padding: 8px 12px;
    border-bottom: 1px solid var(--color-outline-variant);
    font-size: 13px;
  }

  .preview-item:last-child {
    border-bottom: none;
  }

  .preview-col-title {
    flex: 2;
    display: flex;
    align-items: center;
    gap: 6px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .preview-col-user {
    flex: 1.5;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--color-on-surface-variant);
  }

  .preview-col-folder {
    flex: 1.5;
    display: flex;
    align-items: center;
    gap: 4px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--color-on-surface-variant);
    font-size: 12px;
  }

  .totp-badge {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: var(--radius-xs);
    background: var(--color-tertiary-container);
    color: var(--color-on-tertiary-container);
    font-weight: 500;
  }

  .preview-more {
    padding: 12px;
    text-align: center;
    font-size: 12px;
    color: var(--color-on-surface-variant);
    background: var(--color-surface-container);
  }

  .result-summary {
    display: flex;
    gap: 16px;
    justify-content: center;
    padding: 16px 0;
  }

  .result-stat {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 12px 20px;
    border-radius: var(--radius-md);
    min-width: 80px;
  }

  .result-value {
    font-size: 28px;
    font-weight: 600;
  }

  .result-label {
    font-size: 12px;
    text-transform: uppercase;
    opacity: 0.8;
  }

  .result-success {
    background: var(--color-success-container, #d4edda);
    color: var(--color-on-success-container, #155724);
  }

  .result-skipped {
    background: var(--color-surface-container);
    color: var(--color-on-surface-variant);
  }

  .result-failed {
    background: var(--color-error-container, #f8d7da);
    color: var(--color-on-error-container, #721c24);
  }

  .result-totp {
    background: var(--color-tertiary-container);
    color: var(--color-on-tertiary-container);
  }

  .result-errors {
    border: 1px solid var(--color-error-container);
    border-radius: var(--radius-sm);
    padding: 12px;
  }

  .result-errors h4 {
    margin: 0 0 8px;
    color: var(--color-error);
  }

  .error-list {
    margin: 0;
    padding-left: 20px;
    font-size: 13px;
    color: var(--color-on-surface-variant);
  }

  .error-list li {
    margin-bottom: 4px;
  }
</style>
