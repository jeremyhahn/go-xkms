<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import SSHKeySelect from './SSHKeySelect.svelte';
  import { isWailsAvailable, SSHProfileService, SSHConnectService, SSHConsoleService } from '$lib/api/backend';
  import type { SSHConnectParams } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';
  import { sshDefaultConsoleMode, type ConsoleMode } from '$lib/stores/ssh';

  export let open: boolean = false;
  export let folders: string[] = [];
  export let onClose: () => void = () => {};
  export let onProfileSaved: () => void = () => {};
  /**
   * Called with the WebSocket URL, the connection params, and whether the
   * user opted into session persistence when connecting in embedded mode.
   * SSH.svelte uses this to open a console tab (the params are its
   * reconnect origin; persist records it in the session store).
   */
  export let onConsoleReady:
    | ((url: string, params: SSHConnectParams, persist: boolean) => void)
    | undefined = undefined;

  let host = '';
  let port = 22;
  let user = '';
  let keyName = '';
  let keySource: '' | 'local' = '';
  let localIdentity = '';
  let saveAsProfile = false;
  let profileName = '';
  let profileFolder = '';
  let consoleMode: ConsoleMode = $sshDefaultConsoleMode;
  let persistSession = false;
  let connecting = false;

  $: if (open) {
    resetForm();
  }

  function resetForm(): void {
    host = '';
    port = 22;
    user = '';
    keyName = '';
    keySource = '';
    localIdentity = '';
    saveAsProfile = false;
    profileName = '';
    profileFolder = '';
    consoleMode = $sshDefaultConsoleMode;
    persistSession = false;
  }

  async function handleConnect(): Promise<void> {
    if (!host.trim()) {
      addNotification('error', 'Host is required');
      return;
    }
    if (!user.trim()) {
      addNotification('error', 'Username is required');
      return;
    }

    connecting = true;

    if (saveAsProfile && profileName.trim()) {
      const saved = await SSHProfileService.addProfile({
        name: profileName.trim(),
        folder_path: profileFolder.trim(),
        host: host.trim(),
        port,
        user: user.trim(),
        key_scope: 'user',
        key_owner: 'local',
        key_name: keyName,
        key_source: keySource,
        local_identity: localIdentity,
        persist_session: persistSession,
        notes: '',
        console_mode: '',
      });
      if (saved) {
        onProfileSaved();
      }
    }

    const params: SSHConnectParams = {
      host: host.trim(),
      port,
      user: user.trim(),
      key_scope: 'user',
      key_owner: 'local',
      key_name: keyName,
      key_source: keySource,
      local_identity: localIdentity,
    };

    const effectiveMode = consoleMode || $sshDefaultConsoleMode || 'system';

    if (effectiveMode === 'embedded') {
      const { result: info, error } = await SSHConsoleService.openConsoleWithError(params);
      connecting = false;
      // With a real backend, a missing URL is a failure to surface; without
      // one (Vite standalone), the panel opens as a demo placeholder.
      if (!info?.url && isWailsAvailable()) {
        addNotification('error', error ? `Failed to open console: ${error}` : `Failed to open console to ${host}`);
        return;
      }
      open = false;
      onConsoleReady?.(info?.url ?? '', params, persistSession);
      return;
    }

    const { ok, error } = await SSHConnectService.connectOneTimeWithError(params);
    connecting = false;

    if (ok) {
      addNotification('success', `Connecting to ${user}@${host}:${port}`);
      open = false;
    } else {
      addNotification('error', error ? `Failed to connect: ${error}` : `Failed to connect to ${host}`);
    }
  }

  function handleClose(): void {
    open = false;
    onClose();
  }
</script>

<Modal bind:open title="New SSH Connection" maxWidth="480px">
  <div class="form-fields">
    <div class="form-row">
      <div class="form-field form-field--grow">
        <label class="field-label text-label-medium" for="ssh-connect-host">Host</label>
        <input
          id="ssh-connect-host"
          class="text-input"
          type="text"
          placeholder="hostname or IP"
          bind:value={host}
        />
      </div>
      <div class="form-field form-field--port">
        <label class="field-label text-label-medium" for="ssh-connect-port">Port</label>
        <input
          id="ssh-connect-port"
          class="text-input"
          type="number"
          min="1"
          max="65535"
          bind:value={port}
        />
      </div>
    </div>

    <div class="form-field">
      <label class="field-label text-label-medium" for="ssh-connect-user">Username</label>
      <input
        id="ssh-connect-user"
        class="text-input"
        type="text"
        placeholder="e.g. ubuntu, root"
        bind:value={user}
      />
    </div>

    <div class="form-field">
      <label class="field-label text-label-medium" for="ssh-connect-key">SSH Key</label>
      <SSHKeySelect id="ssh-connect-key" bind:keyName bind:keySource bind:localIdentity />
    </div>

    <div class="form-field">
      <label class="field-label text-label-medium" for="ssh-connect-console-mode">Open in</label>
      <select
        id="ssh-connect-console-mode"
        class="text-input select-input"
        bind:value={consoleMode}
        data-testid="ssh-connect-console-mode"
      >
        <option value="">Use default</option>
        <option value="system">System terminal</option>
        <option value="embedded">Embedded console</option>
      </select>
    </div>

    {#if (consoleMode || $sshDefaultConsoleMode || 'system') === 'embedded'}
      <label class="save-toggle" data-testid="ssh-connect-persist-toggle">
        <input type="checkbox" bind:checked={persistSession} data-testid="ssh-connect-persist-checkbox" />
        <span class="text-body-medium">Persistent session (restore tab after restart)</span>
      </label>
    {/if}

    <label class="save-toggle">
      <input type="checkbox" bind:checked={saveAsProfile} />
      <span class="text-body-medium">Save as profile</span>
    </label>

    {#if saveAsProfile}
      <div class="save-profile-fields">
        <div class="form-field">
          <label class="field-label text-label-medium" for="ssh-connect-profile-name">Profile Name</label>
          <input
            id="ssh-connect-profile-name"
            class="text-input"
            type="text"
            placeholder="e.g. My Server"
            bind:value={profileName}
          />
        </div>
        <div class="form-field">
          <label class="field-label text-label-medium" for="ssh-connect-folder">Folder (optional)</label>
          <input
            id="ssh-connect-folder"
            class="text-input"
            type="text"
            placeholder="e.g. Work/Dev"
            list="ssh-connect-folder-list"
            bind:value={profileFolder}
          />
          <datalist id="ssh-connect-folder-list">
            {#each folders as f (f)}
              <option value={f}></option>
            {/each}
          </datalist>
        </div>
      </div>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    <Button variant="outline" on:click={handleClose}>Cancel</Button>
    <Button variant="primary" loading={connecting} on:click={handleConnect}>Connect</Button>
  </svelte:fragment>
</Modal>

<style>
  .form-fields {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .form-row {
    display: flex;
    gap: 12px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
    flex: 1;
  }

  .form-field--grow {
    flex: 1;
  }

  .form-field--port {
    flex: 0 0 90px;
  }

  .field-label {
    color: var(--color-on-surface-variant);
  }

  .text-input {
    height: 40px;
    padding: 0 12px;
    border: 1px solid var(--color-outline);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    width: 100%;
    box-sizing: border-box;
  }

  .text-input:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .select-input {
    cursor: pointer;
  }

  .save-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    color: var(--color-on-surface);
  }

  .save-toggle input[type="checkbox"] {
    width: 16px;
    height: 16px;
    accent-color: var(--color-primary);
    cursor: pointer;
  }

  .save-profile-fields {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-left: 24px;
    border-left: 2px solid var(--color-outline-variant);
  }
</style>
