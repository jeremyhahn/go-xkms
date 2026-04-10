<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import {
    mdiPlay, mdiCheckCircle, mdiAlertCircle, mdiChevronDown, mdiChevronUp,
    mdiConsoleLine, mdiFolderOpen, mdiDelete, mdiContentSaveOutline
  } from '$lib/utils/icons';
  import { callBackend, callBackendVoid } from '$lib/api/backend';
  import type { OIDCProviderEntry, OIDCExecResult, OIDCSavedScript } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let providers: OIDCProviderEntry[] = [];
  export let onExecute: (providerName: string, script: string) => Promise<OIDCExecResult | null> = async () => null;

  type SourceMode = 'paste' | 'file';

  let selectedProvider = '';
  let script = '';
  let scriptName = '';
  let sourceMode: SourceMode = 'paste';
  let selectedFilePath = '';
  let executing = false;
  let saving = false;
  let result: OIDCExecResult | null = null;
  let showEnvRef = false;
  let savedScripts: OIDCSavedScript[] = [];
  let loadingScripts = false;

  $: if (open) {
    if (!selectedProvider && providers.length > 0) {
      selectedProvider = providers[0].name;
    }
    result = null;
    loadSavedScripts();
  }

  $: canExecute = selectedProvider && (
    (sourceMode === 'paste' && script.trim()) ||
    (sourceMode === 'file' && selectedFilePath)
  );

  async function loadSavedScripts(): Promise<void> {
    loadingScripts = true;
    const scripts = await callBackend<OIDCSavedScript[]>('OIDCService', 'ListScripts');
    savedScripts = scripts ?? [];
    loadingScripts = false;
  }

  async function handleExecute(): Promise<void> {
    if (!selectedProvider) return;
    executing = true;
    result = null;

    if (sourceMode === 'paste') {
      if (!script.trim()) return;
      result = await onExecute(selectedProvider, script.trim());
    } else if (sourceMode === 'file' && selectedFilePath) {
      result = await callBackend<OIDCExecResult>(
        'OIDCService', 'ExecuteScriptFile', selectedProvider, selectedFilePath
      );
    }

    executing = false;
  }

  async function handleBrowse(): Promise<void> {
    const path = await callBackend<string>('OIDCService', 'BrowseScriptFile');
    if (path) {
      selectedFilePath = path;
    }
  }

  async function handleSaveScript(): Promise<void> {
    const name = scriptName.trim() || 'untitled';
    if (!script.trim()) {
      addNotification('error', 'Script content is empty');
      return;
    }
    saving = true;
    const saved = await callBackend<OIDCSavedScript>('OIDCService', 'SaveScript', name, script.trim());
    saving = false;
    if (saved) {
      addNotification('success', `Script "${saved.name}" saved`);
      scriptName = '';
      await loadSavedScripts();
    } else {
      addNotification('error', 'Failed to save script');
    }
  }

  async function handleLoadSaved(s: OIDCSavedScript): Promise<void> {
    const content = await callBackend<string>('OIDCService', 'GetScriptContent', s.file_name);
    if (content !== null && content !== undefined) {
      script = content;
      scriptName = s.name;
      sourceMode = 'paste';
      addNotification('info', `Loaded "${s.name}"`);
    } else {
      addNotification('error', 'Failed to load script');
    }
  }

  async function handleDeleteSaved(s: OIDCSavedScript): Promise<void> {
    const ok = await callBackendVoid('OIDCService', 'DeleteScript', s.file_name);
    if (ok) {
      addNotification('info', `Deleted "${s.name}"`);
      await loadSavedScripts();
    } else {
      addNotification('error', 'Failed to delete script');
    }
  }

  async function handleRunSaved(s: OIDCSavedScript): Promise<void> {
    if (!selectedProvider) return;
    executing = true;
    result = null;
    const path = await callBackend<string>('OIDCService', 'GetSavedScriptPath', s.file_name);
    if (path) {
      result = await callBackend<OIDCExecResult>(
        'OIDCService', 'ExecuteScriptFile', selectedProvider, path
      );
    }
    executing = false;
  }
</script>

<Modal bind:open title="Script Runner" maxWidth="680px">
  <div class="script-dialog">
    <div class="form-field">
      <label class="text-label-medium form-label" for="script-provider">Provider</label>
      <select id="script-provider" class="form-select" bind:value={selectedProvider}>
        {#each providers as p}
          <option value={p.name}>{p.name} ({p.type})</option>
        {/each}
      </select>
    </div>

    <!-- Source mode toggle -->
    <div class="mode-toggle">
      <button
        class="mode-btn"
        class:active={sourceMode === 'paste'}
        on:click={() => (sourceMode = 'paste')}
      >
        <Icon path={mdiConsoleLine} size={16} />
        <span>Paste Script</span>
      </button>
      <button
        class="mode-btn"
        class:active={sourceMode === 'file'}
        on:click={() => (sourceMode = 'file')}
      >
        <Icon path={mdiFolderOpen} size={16} />
        <span>Browse File</span>
      </button>
    </div>

    {#if sourceMode === 'paste'}
      <div class="form-field">
        <label class="text-label-medium form-label" for="script-input">Script</label>
        <textarea
          id="script-input"
          class="script-textarea font-mono"
          rows="8"
          placeholder="#!/bin/bash&#10;echo $OIDC_ACCESS_TOKEN"
          bind:value={script}
        ></textarea>
      </div>

      <!-- Save controls -->
      <div class="save-row">
        <input
          type="text"
          class="save-name-input"
          placeholder="Script name (optional)"
          bind:value={scriptName}
        />
        <Button
          variant="outline"
          size="sm"
          icon={mdiContentSaveOutline}
          loading={saving}
          disabled={!script.trim()}
          on:click={handleSaveScript}
        >
          Save
        </Button>
      </div>
    {:else}
      <div class="file-browse">
        <div class="file-path-row">
          <input
            type="text"
            class="file-path-input font-mono"
            placeholder="No file selected"
            readonly
            value={selectedFilePath}
          />
          <Button variant="outline" size="sm" icon={mdiFolderOpen} on:click={handleBrowse}>
            Browse
          </Button>
        </div>
      </div>
    {/if}

    <!-- Saved scripts list -->
    {#if savedScripts.length > 0}
      <div class="saved-section">
        <span class="text-label-medium form-label">Saved Scripts</span>
        <div class="saved-list">
          {#each savedScripts as s (s.file_name)}
            <div class="saved-item">
              <span class="saved-name text-body-small font-mono">{s.name}</span>
              <div class="saved-actions">
                <button class="icon-btn" title="Load into editor" on:click={() => handleLoadSaved(s)}>
                  <Icon path={mdiConsoleLine} size={16} />
                </button>
                <button
                  class="icon-btn"
                  title="Run"
                  disabled={!selectedProvider || executing}
                  on:click={() => handleRunSaved(s)}
                >
                  <Icon path={mdiPlay} size={16} />
                </button>
                <button class="icon-btn icon-btn-danger" title="Delete" on:click={() => handleDeleteSaved(s)}>
                  <Icon path={mdiDelete} size={16} />
                </button>
              </div>
            </div>
          {/each}
        </div>
      </div>
    {/if}

    {#if result}
      <div class="result-section">
        <div class="result-header">
          {#if result.success}
            <Icon path={mdiCheckCircle} size={18} color="var(--color-security-verified)" />
            <span class="text-title-small" style="color: var(--color-security-verified);">Success (exit {result.exit_code})</span>
          {:else}
            <Icon path={mdiAlertCircle} size={18} color="var(--color-error)" />
            <span class="text-title-small" style="color: var(--color-error);">
              Failed (exit {result.exit_code}){result.error ? `: ${result.error}` : ''}
            </span>
          {/if}
        </div>

        {#if result.stdout}
          <div class="output-block">
            <span class="text-label-small output-label">stdout</span>
            <pre class="output-content font-mono">{result.stdout}</pre>
          </div>
        {/if}

        {#if result.stderr}
          <div class="output-block output-stderr">
            <span class="text-label-small output-label">stderr</span>
            <pre class="output-content font-mono">{result.stderr}</pre>
          </div>
        {/if}
      </div>
    {/if}

    <button class="env-ref-toggle" on:click={() => (showEnvRef = !showEnvRef)}>
      <Icon path={showEnvRef ? mdiChevronUp : mdiChevronDown} size={18} />
      <span class="text-label-medium">Environment Variables Reference</span>
    </button>

    {#if showEnvRef}
      <div class="env-ref">
        <div class="env-row"><code>OIDC_PROVIDER</code><span>Provider name</span></div>
        <div class="env-row"><code>OIDC_ISSUER</code><span>Issuer URL</span></div>
        <div class="env-row"><code>OIDC_CLIENT_ID</code><span>Client ID</span></div>
        <div class="env-row"><code>OIDC_ACCESS_TOKEN</code><span>Access token</span></div>
        <div class="env-row"><code>OIDC_REFRESH_TOKEN</code><span>Refresh token</span></div>
        <div class="env-row"><code>OIDC_ID_TOKEN</code><span>ID token</span></div>
        <div class="env-row"><code>OIDC_EXPIRES_AT</code><span>Expiry timestamp</span></div>
        <div class="env-row"><code>OIDC_SUBJECT</code><span>Token subject</span></div>
        <div class="env-row"><code>OIDC_EMAIL</code><span>User email</span></div>
      </div>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => (open = false)} disabled={executing}>Close</Button>
    <Button
      variant="primary"
      icon={mdiPlay}
      loading={executing}
      disabled={!canExecute}
      on:click={handleExecute}
    >
      Execute
    </Button>
  </svelte:fragment>
</Modal>

<style>
  .script-dialog {
    display: flex;
    flex-direction: column;
    gap: 12px;
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
  }

  .form-select:focus {
    border-color: var(--color-primary);
  }

  /* Mode toggle */
  .mode-toggle {
    display: flex;
    gap: 0;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .mode-btn {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 10px 16px;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: background-color 0.15s, color 0.15s;
  }

  .mode-btn:not(:last-child) {
    border-right: 1px solid var(--color-outline-variant);
  }

  .mode-btn:hover {
    background-color: var(--color-surface-container);
  }

  .mode-btn.active {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .script-textarea {
    width: 100%;
    min-height: 160px;
    padding: 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-size: 13px;
    line-height: 1.5;
    resize: vertical;
    outline: none;
    box-sizing: border-box;
  }

  .script-textarea:focus {
    border-color: var(--color-primary);
  }

  /* Save row */
  .save-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .save-name-input {
    flex: 1;
    height: 36px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 13px;
    outline: none;
  }

  .save-name-input:focus {
    border-color: var(--color-primary);
  }

  /* File browse */
  .file-browse {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .file-path-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .file-path-input {
    flex: 1;
    height: 40px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface-variant);
    font-size: 12px;
    outline: none;
  }

  /* Saved scripts */
  .saved-section {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .saved-list {
    display: flex;
    flex-direction: column;
    gap: 2px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .saved-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 12px;
    background-color: var(--color-surface-container-lowest);
  }

  .saved-item:not(:last-child) {
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .saved-name {
    color: var(--color-on-surface);
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .saved-actions {
    display: flex;
    gap: 4px;
    flex-shrink: 0;
  }

  .icon-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color 0.15s;
  }

  .icon-btn:hover {
    background-color: var(--color-surface-container);
  }

  .icon-btn:disabled {
    opacity: 0.4;
    cursor: default;
  }

  .icon-btn-danger:hover {
    background-color: var(--color-error-container, #fbe9e7);
    color: var(--color-error);
  }

  /* Result */
  .result-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-md);
  }

  .result-header {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .output-block {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .output-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .output-content {
    margin: 0;
    padding: 8px 12px;
    background-color: var(--color-surface-container-lowest);
    border-radius: var(--radius-sm);
    font-size: 12px;
    line-height: 1.5;
    max-height: 200px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--color-on-surface);
  }

  .output-stderr .output-content {
    color: var(--color-error);
  }

  .env-ref-toggle {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 0;
    border: none;
    background: transparent;
    color: var(--color-primary);
    cursor: pointer;
    font-family: var(--font-sans);
  }

  .env-ref {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px 12px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
  }

  .env-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 4px 0;
    font-size: 13px;
  }

  .env-row code {
    font-family: var(--font-mono);
    color: var(--color-primary);
    font-size: 12px;
  }

  .env-row span {
    color: var(--color-on-surface-variant);
    font-size: 12px;
  }
</style>
