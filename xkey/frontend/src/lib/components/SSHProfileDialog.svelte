<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import SSHKeySelect from './SSHKeySelect.svelte';
  import { SSHProfileService } from '$lib/api/backend';
  import type { SSHProfileEntry, SSHProfileParams } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let mode: 'add' | 'edit' = 'add';
  export let profile: SSHProfileEntry | null = null;
  export let folders: string[] = [];
  export let onClose: () => void = () => {};
  export let onSave: () => void = () => {};

  let name = '';
  let folderPath = '';
  let host = '';
  let port = 22;
  let user = '';
  let keyName = '';
  let keySource: '' | 'local' = '';
  let localIdentity = '';
  let persistSession = false;
  let notes = '';
  let consoleMode: 'system' | 'embedded' | '' = '';
  let saving = false;

  $: if (open) {
    resetForm();
  }

  function resetForm(): void {
    if (mode === 'edit' && profile) {
      name = profile.name;
      folderPath = profile.folder_path;
      host = profile.host;
      port = profile.port || 22;
      user = profile.user;
      keyName = profile.key_name;
      keySource = profile.key_source === 'local' ? 'local' : '';
      localIdentity = profile.local_identity ?? '';
      persistSession = profile.persist_session ?? false;
      notes = profile.notes || '';
      consoleMode = profile.console_mode ?? '';
    } else {
      name = '';
      folderPath = '';
      host = '';
      port = 22;
      user = '';
      keyName = '';
      keySource = '';
      localIdentity = '';
      persistSession = false;
      notes = '';
      consoleMode = '';
    }
  }

  async function handleSubmit(): Promise<void> {
    if (!name.trim()) {
      addNotification('error', 'Profile name is required');
      return;
    }
    if (!host.trim()) {
      addNotification('error', 'Host is required');
      return;
    }
    if (!user.trim()) {
      addNotification('error', 'Username is required');
      return;
    }

    saving = true;
    const params: SSHProfileParams = {
      id: mode === 'edit' && profile ? profile.id : undefined,
      name: name.trim(),
      folder_path: folderPath.trim(),
      host: host.trim(),
      port,
      user: user.trim(),
      key_scope: 'user',
      key_owner: 'local',
      key_name: keyName,
      key_source: keySource,
      local_identity: localIdentity,
      persist_session: persistSession,
      notes: notes.trim(),
      console_mode: consoleMode,
    };

    let ok = false;
    if (mode === 'edit') {
      ok = await SSHProfileService.updateProfile(params);
    } else {
      const result = await SSHProfileService.addProfile(params);
      ok = result !== null;
    }
    saving = false;

    if (ok) {
      addNotification('success', mode === 'edit' ? `Profile "${name}" updated` : `Profile "${name}" created`);
      open = false;
      onSave();
    } else {
      addNotification('error', mode === 'edit' ? 'Failed to update profile' : 'Failed to create profile');
    }
  }

  function handleClose(): void {
    open = false;
    onClose();
  }
</script>

<Modal
  bind:open
  title={mode === 'edit' ? 'Edit SSH Profile' : 'New SSH Profile'}
  maxWidth="520px"
>
  <div class="form-fields">
    <div class="form-row">
      <div class="form-field">
        <label class="field-label text-label-medium" for="ssh-profile-name">Profile Name</label>
        <input
          id="ssh-profile-name"
          class="text-input"
          type="text"
          placeholder="e.g. Production Server"
          bind:value={name}
        />
      </div>
      <div class="form-field form-field--sm">
        <label class="field-label text-label-medium" for="ssh-profile-folder">Folder</label>
        <input
          id="ssh-profile-folder"
          class="text-input"
          type="text"
          placeholder="e.g. Work/Dev"
          list="ssh-profile-folder-list"
          bind:value={folderPath}
        />
        <datalist id="ssh-profile-folder-list">
          {#each folders as f (f)}
            <option value={f}></option>
          {/each}
        </datalist>
      </div>
    </div>

    <div class="form-row">
      <div class="form-field form-field--grow">
        <label class="field-label text-label-medium" for="ssh-profile-host">Host</label>
        <input
          id="ssh-profile-host"
          class="text-input"
          type="text"
          placeholder="hostname or IP"
          bind:value={host}
        />
      </div>
      <div class="form-field form-field--port">
        <label class="field-label text-label-medium" for="ssh-profile-port">Port</label>
        <input
          id="ssh-profile-port"
          class="text-input"
          type="number"
          min="1"
          max="65535"
          bind:value={port}
        />
      </div>
    </div>

    <div class="form-field">
      <label class="field-label text-label-medium" for="ssh-profile-user">Username</label>
      <input
        id="ssh-profile-user"
        class="text-input"
        type="text"
        placeholder="e.g. ubuntu, ec2-user"
        bind:value={user}
      />
    </div>

    <div class="form-field">
      <label class="field-label text-label-medium" for="ssh-profile-key">SSH Key</label>
      <SSHKeySelect id="ssh-profile-key" bind:keyName bind:keySource bind:localIdentity />
    </div>

    <div class="form-field">
      <label class="field-label text-label-medium" for="ssh-profile-console-mode">Open in</label>
      <select
        id="ssh-profile-console-mode"
        class="text-input select-input"
        bind:value={consoleMode}
        data-testid="ssh-profile-console-mode"
      >
        <option value="">Use default</option>
        <option value="system">System terminal</option>
        <option value="embedded">Embedded console</option>
      </select>
    </div>

    <label class="persist-toggle" data-testid="ssh-profile-persist-toggle">
      <input type="checkbox" bind:checked={persistSession} data-testid="ssh-profile-persist-checkbox" />
      <span class="text-body-medium">Persistent console session (restore tab after restart)</span>
    </label>

    <div class="form-field">
      <label class="field-label text-label-medium" for="ssh-profile-notes">Notes (optional)</label>
      <textarea
        id="ssh-profile-notes"
        class="text-input textarea-input"
        placeholder="Any notes about this connection..."
        rows="3"
        bind:value={notes}
      ></textarea>
    </div>
  </div>

  <svelte:fragment slot="actions">
    <Button variant="outline" on:click={handleClose}>Cancel</Button>
    <Button variant="primary" loading={saving} on:click={handleSubmit}>
      {mode === 'edit' ? 'Save' : 'Create'}
    </Button>
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

  .form-field--sm {
    flex: 0 0 160px;
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

  .textarea-input {
    height: auto;
    padding: 10px 12px;
    resize: vertical;
    line-height: 1.5;
  }

  .persist-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    color: var(--color-on-surface);
  }

  .persist-toggle input[type='checkbox'] {
    width: 16px;
    height: 16px;
    accent-color: var(--color-primary);
    cursor: pointer;
  }
</style>
