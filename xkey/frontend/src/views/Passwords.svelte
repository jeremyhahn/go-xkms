<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Button from '$lib/components/Button.svelte';
  import SearchBar from '$lib/components/SearchBar.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Input from '$lib/components/Input.svelte';
  import PasswordFolderTree from '$lib/components/PasswordFolderTree.svelte';
  import PasswordListItem from '$lib/components/PasswordListItem.svelte';
  import PasswordDetailPanel from '$lib/components/PasswordDetailPanel.svelte';
  import PasswordAddEditDialog from '$lib/components/PasswordAddEditDialog.svelte';
  import PasswordImportDialog from '$lib/components/PasswordImportDialog.svelte';
  import FolderManageDialog from '$lib/components/FolderManageDialog.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import TeamManageDialog from '$lib/components/TeamManageDialog.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { mdiPlus, mdiLockOutline, mdiDownload, mdiUpload, mdiImport, mdiAccountGroup, mdiPencil, mdiDelete } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend, callBackendVoid, TeamService } from '$lib/api/backend';
  import type {
    StaticPasswordEntry,
    AddPasswordParams,
    UpdatePasswordParams,
    TeamInfo,
  } from '$lib/api/backend';

  let passwords: StaticPasswordEntry[] = [];
  let folders: string[] = [];
  let selectedFolder: string | null = null;
  let selectedEntry: StaticPasswordEntry | null = null;
  let searchQuery = '';

  let showAddDialog = false;
  let showEditDialog = false;
  let showFolderDialog = false;
  let folderDialogMode: 'create' | 'rename' = 'create';
  let folderToRename = '';

  let deleteConfirmEntry: StaticPasswordEntry | null = null;
  let deleteFolderPath: string | null = null;

  // Backup dialog state
  let showBackupDialog = false;
  let backupEncrypt = false;
  let backupAlgorithm: 'aes-128' | 'aes-192' | 'aes-256' = 'aes-256';
  let backupPassword = '';
  let backupPasswordConfirm = '';
  let backupBusy = false;

  // Restore dialog state
  let showRestoreDialog = false;
  let restoreFilePath = '';
  let restoreEncrypted = false;
  let restoreAlgorithm: 'aes-128' | 'aes-192' | 'aes-256' = 'aes-256';
  let restorePassword = '';
  let restoreBusy = false;

  // Import dialog state (KeePass, CSV, XML)
  let showImportDialog = false;

  // Team state
  let teams: TeamInfo[] = [];
  let selectedTeam: TeamInfo | null = null;
  let showTeamDialog = false;
  let teamDialogMode: 'create' | 'edit' = 'create';
  let teamToManage: TeamInfo | null = null;
  let deleteConfirmTeam: TeamInfo | null = null;

  onMount(() => {
    loadPasswords();
    loadTeams();
  });

  $: filteredPasswords = computeFiltered(passwords, selectedFolder, selectedTeam, searchQuery);

  $: passwordCounts = computeCounts(passwords);

  function computeFiltered(
    all: StaticPasswordEntry[],
    folder: string | null,
    team: TeamInfo | null,
    query: string,
  ): StaticPasswordEntry[] {
    let result = all;

    if (folder !== null) {
      result = result.filter(p =>
        p.folder_path === folder || p.folder_path.startsWith(folder + '/'),
      );
    }

    if (team !== null) {
      result = result.filter(p => p.backend_id === team.owner_id);
    }

    if (query) {
      const lower = query.toLowerCase();
      result = result.filter(p =>
        (p.title || '').toLowerCase().includes(lower) ||
        p.name.toLowerCase().includes(lower) ||
        (p.username || '').toLowerCase().includes(lower) ||
        (p.url || '').toLowerCase().includes(lower) ||
        (p.notes || '').toLowerCase().includes(lower),
      );
    }

    return result;
  }

  function computeCounts(all: StaticPasswordEntry[]): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const p of all) {
      if (p.folder_path) {
        counts[p.folder_path] = (counts[p.folder_path] || 0) + 1;
      }
    }
    return counts;
  }

  async function loadPasswords(): Promise<void> {
    if (!isWailsAvailable()) return;

    const result = await callBackend<StaticPasswordEntry[]>('StaticPasswordService', 'ListPasswords');
    if (result) {
      passwords = result;
    }

    const folderResult = await callBackend<string[]>('StaticPasswordService', 'ListFolders');
    if (folderResult) {
      // Merge backend folders with any locally created empty folders
      const merged = new Set([...folderResult, ...folders]);
      folders = Array.from(merged).sort();
    }
  }

  async function loadTeams(): Promise<void> {
    if (!isWailsAvailable()) return;
    const result = await TeamService.listTeams();
    if (result) {
      teams = result;
    }
  }

  function handleTeamSelect(team: TeamInfo): void {
    if (selectedTeam?.id === team.id) {
      selectedTeam = null;
    } else {
      selectedTeam = team;
      selectedFolder = null;
      selectedEntry = null;
    }
  }

  function handleCreateTeam(): void {
    teamDialogMode = 'create';
    teamToManage = null;
    showTeamDialog = true;
  }

  function handleManageTeam(team: TeamInfo): void {
    teamDialogMode = 'edit';
    teamToManage = team;
    showTeamDialog = true;
  }

  function handleDeleteTeamRequest(team: TeamInfo): void {
    deleteConfirmTeam = team;
  }

  async function confirmDeleteTeam(): Promise<void> {
    if (!deleteConfirmTeam) return;
    const team = deleteConfirmTeam;
    const ok = await TeamService.deleteTeam(team.name);
    deleteConfirmTeam = null;
    if (ok) {
      addNotification('info', `Team "${team.name}" deleted`);
      if (selectedTeam?.id === team.id) {
        selectedTeam = null;
      }
      await loadTeams();
    } else {
      addNotification('error', `Failed to delete team "${team.name}"`);
    }
  }

  function cancelDeleteTeam(): void {
    deleteConfirmTeam = null;
  }

  async function handleTeamSave(e: CustomEvent<{ name: string; members: string[] }>): Promise<void> {
    const { name, members } = e.detail;
    showTeamDialog = false;

    if (teamDialogMode === 'create') {
      const created = await TeamService.createTeam(name);
      if (!created) {
        addNotification('error', `Failed to create team "${name}"`);
        return;
      }
      // Add members to newly created team.
      for (const userID of members) {
        await TeamService.addMember(created.name, userID);
      }
      addNotification('success', `Team "${name}" created`);
      await loadTeams();
    } else if (teamToManage) {
      const current = teamToManage.members ?? [];
      const toAdd = members.filter(m => !current.includes(m));
      const toRemove = current.filter(m => !members.includes(m));
      for (const userID of toAdd) {
        await TeamService.addMember(teamToManage.name, userID);
      }
      for (const userID of toRemove) {
        await TeamService.removeMember(teamToManage.name, userID);
      }
      addNotification('success', `Team "${teamToManage.name}" updated`);
      await loadTeams();
      // Re-sync the selected team if it was the one we just edited.
      if (selectedTeam?.id === teamToManage.id) {
        selectedTeam = teams.find(t => t.id === teamToManage!.id) ?? null;
      }
    }
  }

  function handleFolderSelect(e: CustomEvent<string | null>): void {
    selectedFolder = e.detail;
    selectedTeam = null;
    selectedEntry = null;
  }

  function handleEntrySelect(e: CustomEvent<StaticPasswordEntry>): void {
    selectedEntry = e.detail;
  }

  function handleCopyPassword(e: CustomEvent<StaticPasswordEntry>): void {
    const entry = e.detail;
    navigator.clipboard.writeText(entry.password).then(() => {
      addNotification('success', `Password for "${entry.title || entry.name}" copied`);
    }).catch(() => {
      addNotification('error', 'Failed to copy password');
    });
  }

  function handleSearchChange(value: string): void {
    searchQuery = value;
  }

  async function handleAddSave(params: AddPasswordParams | UpdatePasswordParams): Promise<void> {
    const result = await callBackend<StaticPasswordEntry>(
      'StaticPasswordService',
      'AddPasswordV2',
      params,
    );
    if (result !== null) {
      addNotification('success', `Password "${(params as AddPasswordParams).name}" added`);
      showAddDialog = false;
      await loadPasswords();
      // Auto-select the newly added entry and ensure it's visible.
      const addParams = params as AddPasswordParams;
      const newEntry = passwords.find(p => p.name === addParams.name);
      if (newEntry) {
        // Switch to the new entry's folder so it's visible in the filtered list.
        if (selectedFolder !== null && newEntry.folder_path !== selectedFolder &&
            !newEntry.folder_path.startsWith(selectedFolder + '/')) {
          selectedFolder = newEntry.folder_path || null;
        }
        selectedEntry = newEntry;
      }
    } else {
      addNotification('error', `Failed to add password "${(params as AddPasswordParams).name}"`);
    }
  }

  async function handleEditSave(params: AddPasswordParams | UpdatePasswordParams): Promise<void> {
    const ok = await callBackendVoid(
      'StaticPasswordService',
      'UpdatePasswordV2',
      params,
    );
    if (ok) {
      addNotification('success', `Password "${(params as UpdatePasswordParams).name}" updated`);
      showEditDialog = false;
      await loadPasswords();
      // Re-select the updated entry from the refreshed list.
      const updated = passwords.find(p => p.id === (params as UpdatePasswordParams).id);
      if (updated) {
        selectedEntry = updated;
      } else {
        selectedEntry = null;
      }
    } else {
      addNotification('error', `Failed to update password "${(params as UpdatePasswordParams).name}"`);
    }
  }

  function requestDelete(e: CustomEvent<StaticPasswordEntry>): void {
    deleteConfirmEntry = e.detail;
  }

  async function confirmDelete(): Promise<void> {
    if (!deleteConfirmEntry) return;
    const entry = deleteConfirmEntry;
    const ok = await callBackendVoid('StaticPasswordService', 'DeletePassword', entry.id);
    deleteConfirmEntry = null;
    if (ok) {
      addNotification('info', `Password "${entry.title || entry.name}" deleted`);
      if (selectedEntry?.id === entry.id) {
        selectedEntry = null;
      }
      await loadPasswords();
    } else {
      addNotification('error', `Failed to delete password "${entry.title || entry.name}"`);
    }
  }

  function cancelDelete(): void {
    deleteConfirmEntry = null;
  }

  let folderInitialValue = '';

  function handleCreateFolder(): void {
    folderDialogMode = 'create';
    folderToRename = '';
    folderInitialValue = '';
    showFolderDialog = true;
  }

  function handleCreateSubfolder(e: CustomEvent<string>): void {
    folderDialogMode = 'create';
    folderToRename = '';
    folderInitialValue = e.detail + '/';
    showFolderDialog = true;
  }

  function handleRenameFolder(e: CustomEvent<string>): void {
    folderDialogMode = 'rename';
    folderToRename = e.detail;
    showFolderDialog = true;
  }

  function handleDeleteFolderRequest(e: CustomEvent<string>): void {
    deleteFolderPath = e.detail;
  }

  async function confirmDeleteFolder(): Promise<void> {
    if (!deleteFolderPath) return;
    const path = deleteFolderPath;
    const ok = await callBackendVoid('StaticPasswordService', 'DeleteFolder', path);
    deleteFolderPath = null;
    if (ok) {
      addNotification('info', `Folder "${path}" deleted`);
      if (selectedFolder === path) {
        selectedFolder = null;
      }
      await loadPasswords();
    } else {
      addNotification('error', `Failed to delete folder "${path}"`);
    }
  }

  function cancelDeleteFolder(): void {
    deleteFolderPath = null;
  }

  async function handleFolderSubmit(name: string): Promise<void> {
    if (folderDialogMode === 'rename' && folderToRename) {
      const ok = await callBackendVoid('StaticPasswordService', 'RenameFolder', folderToRename, name);
      if (ok) {
        addNotification('success', `Folder renamed to "${name}"`);
        if (selectedFolder === folderToRename) {
          selectedFolder = name;
        }
      } else {
        addNotification('error', `Failed to rename folder`);
      }
      showFolderDialog = false;
      await loadPasswords();
    } else {
      // Persist the folder on the backend so it survives across restarts.
      const ok = await callBackendVoid('StaticPasswordService', 'CreateFolder', name);
      if (ok) {
        if (!folders.includes(name)) {
          folders = [...folders, name];
        }
        addNotification('success', `Folder "${name}" created`);
      } else {
        addNotification('error', `Failed to create folder "${name}"`);
      }
      showFolderDialog = false;
    }
  }

  function openEditDialog(e: CustomEvent<StaticPasswordEntry>): void {
    selectedEntry = e.detail;
    showEditDialog = true;
  }

  function openRestoreDialog(): void {
    restoreFilePath = '';
    restoreEncrypted = false;
    restoreAlgorithm = 'aes-256';
    restorePassword = '';
    showRestoreDialog = true;
  }

  function closeRestoreDialog(): void {
    showRestoreDialog = false;
  }

  async function handleBrowseRestoreFile(): Promise<void> {
    const path = await callBackend<string>('StaticPasswordService', 'OpenBackupFileDialog');
    if (path) {
      restoreFilePath = path;
      // Auto-detect encrypted files by extension.
      restoreEncrypted = path.endsWith('.enc');
    }
  }

  async function handleRestore(): Promise<void> {
    if (!restoreFilePath) {
      addNotification('error', 'Please select a backup file');
      return;
    }
    if (restoreEncrypted && !restorePassword) {
      addNotification('error', 'Password is required for encrypted backups');
      return;
    }

    restoreBusy = true;
    const count = await callBackend<number>(
      'StaticPasswordService',
      'RestorePasswords',
      restoreFilePath,
      restoreEncrypted,
      restoreEncrypted ? restoreAlgorithm : '',
      restoreEncrypted ? restorePassword : '',
    );
    restoreBusy = false;

    if (count !== null) {
      addNotification('success', `Imported ${count} password${count !== 1 ? 's' : ''}`);
      showRestoreDialog = false;
      await loadPasswords();
    } else {
      addNotification('error', 'Failed to restore passwords (wrong password or invalid file)');
    }
  }

  function openBackupDialog(): void {
    backupEncrypt = false;
    backupAlgorithm = 'aes-256';
    backupPassword = '';
    backupPasswordConfirm = '';
    showBackupDialog = true;
  }

  function closeBackupDialog(): void {
    showBackupDialog = false;
  }

  async function handleBackup(): Promise<void> {
    if (backupEncrypt) {
      if (!backupPassword) {
        addNotification('error', 'Password is required for encrypted backup');
        return;
      }
      if (backupPassword !== backupPasswordConfirm) {
        addNotification('error', 'Passwords do not match');
        return;
      }
    }

    backupBusy = true;
    const filePath = await callBackend<string>('StaticPasswordService', 'SaveBackupFileAs');
    if (!filePath) {
      backupBusy = false;
      return;
    }

    const ok = await callBackendVoid(
      'StaticPasswordService',
      'BackupPasswords',
      filePath,
      backupEncrypt,
      backupEncrypt ? backupAlgorithm : '',
      backupEncrypt ? backupPassword : '',
    );
    backupBusy = false;

    if (ok) {
      addNotification('success', `Passwords exported to ${filePath}`);
      showBackupDialog = false;
    } else {
      addNotification('error', 'Failed to export passwords');
    }
  }

</script>

<div class="passwords-view">
  <GradientHeader title="Passwords" subtitle="Static password management" />

  <ViewToolbar>
    <Button icon={mdiImport} variant="outline" on:click={() => { showImportDialog = true; }}>Import</Button>
    <Button icon={mdiUpload} variant="outline" on:click={openRestoreDialog}>Restore</Button>
    <Button icon={mdiDownload} variant="outline" on:click={openBackupDialog}>Backup</Button>
    <div class="toolbar-spacer" />
    <Button icon={mdiPlus} variant="primary" on:click={() => { showAddDialog = true; }}>Add Password</Button>
  </ViewToolbar>

  <div class="content">
    <div class="three-panel">
        <aside class="panel-left">
          <PasswordFolderTree
            {folders}
            {selectedFolder}
            {passwordCounts}
            on:select={handleFolderSelect}
            on:createFolder={handleCreateFolder}
            on:createSubfolder={handleCreateSubfolder}
            on:renameFolder={handleRenameFolder}
            on:deleteFolder={handleDeleteFolderRequest}
          />

          <div class="teams-section">
            <div class="teams-header">
              <span class="teams-heading">
                <Icon path={mdiAccountGroup} size={16} />
                Teams
              </span>
              <button
                class="teams-add-btn"
                type="button"
                title="Create team"
                aria-label="Create team"
                on:click={handleCreateTeam}
              >
                <Icon path={mdiPlus} size={16} />
              </button>
            </div>

            {#if teams.length === 0}
              <p class="teams-empty">No teams yet.</p>
            {:else}
              <ul class="teams-list" aria-label="Teams">
                {#each teams as team (team.id)}
                  <!-- svelte-ignore a11y-no-noninteractive-element-interactions a11y-no-noninteractive-tabindex -->
                  <li
                    class="teams-item"
                    class:teams-item--selected={selectedTeam?.id === team.id}
                    tabindex="0"
                    on:click={() => handleTeamSelect(team)}
                    on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleTeamSelect(team); } }}
                  >
                    <span class="teams-item-name">{team.name}</span>
                    <span class="teams-item-count">{team.members?.length ?? 0}</span>

                    {#if selectedTeam?.id === team.id}
                      <div class="teams-item-actions">
                        <button
                          class="teams-action-btn"
                          type="button"
                          title="Manage team"
                          aria-label="Manage {team.name}"
                          on:click|stopPropagation={() => handleManageTeam(team)}
                        >
                          <Icon path={mdiPencil} size={14} />
                        </button>
                        <button
                          class="teams-action-btn teams-action-btn--danger"
                          type="button"
                          title="Delete team"
                          aria-label="Delete {team.name}"
                          on:click|stopPropagation={() => handleDeleteTeamRequest(team)}
                        >
                          <Icon path={mdiDelete} size={14} />
                        </button>
                      </div>
                    {/if}
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        </aside>

        <div class="panel-center">
          <div class="list-toolbar">
            <SearchBar
              bind:value={searchQuery}
              placeholder="Search passwords..."
              onChange={handleSearchChange}
            />
          </div>
          <div class="list-content">
            {#if passwords.length === 0}
              <EmptyState
                icon={mdiLockOutline}
                title="No passwords stored"
                description="Add static passwords for quick access and autofill."
              />
            {:else if filteredPasswords.length === 0}
              <EmptyState
                icon={mdiLockOutline}
                title="No matching passwords"
                description="Try a different search term or folder."
              />
            {:else}
              {#each filteredPasswords as entry (entry.id)}
                <PasswordListItem
                  {entry}
                  selected={selectedEntry?.id === entry.id}
                  on:select={handleEntrySelect}
                  on:copyPassword={handleCopyPassword}
                  on:delete={requestDelete}
                />
              {/each}
            {/if}
          </div>
        </div>

        <aside class="panel-right">
          <PasswordDetailPanel
            entry={selectedEntry}
            on:edit={openEditDialog}
            on:delete={requestDelete}
          />
        </aside>
      </div>
  </div>

  <PasswordAddEditDialog
    bind:open={showAddDialog}
    mode="add"
    {folders}
    onClose={() => { showAddDialog = false; }}
    onSave={handleAddSave}
  />

  <PasswordAddEditDialog
    bind:open={showEditDialog}
    mode="edit"
    entry={selectedEntry}
    {folders}
    onClose={() => { showEditDialog = false; }}
    onSave={handleEditSave}
  />

  <FolderManageDialog
    bind:open={showFolderDialog}
    mode={folderDialogMode}
    currentName={folderToRename}
    initialValue={folderInitialValue}
    onClose={() => { showFolderDialog = false; }}
    onSubmit={handleFolderSubmit}
  />

  <PasswordImportDialog
    bind:open={showImportDialog}
    onClose={() => { showImportDialog = false; }}
    onImported={loadPasswords}
  />

  <Modal title="Backup Passwords" bind:open={showBackupDialog} persistent={false}>
    <div class="backup-body">
      <p class="text-body-medium backup-description">
        Export all {passwords.length} password{passwords.length !== 1 ? 's' : ''} to a file. Optionally encrypt the backup with AES.
      </p>

      <label class="backup-toggle">
        <input type="checkbox" bind:checked={backupEncrypt} />
        <span>Encrypt backup</span>
      </label>

      {#if backupEncrypt}
        <div class="backup-encrypt-options">
          <div class="backup-algorithm">
            <span class="field-label">Algorithm</span>
            <div class="backup-chips">
              <button class="chip" class:chip-active={backupAlgorithm === 'aes-128'} on:click={() => backupAlgorithm = 'aes-128'}>AES-128</button>
              <button class="chip" class:chip-active={backupAlgorithm === 'aes-192'} on:click={() => backupAlgorithm = 'aes-192'}>AES-192</button>
              <button class="chip" class:chip-active={backupAlgorithm === 'aes-256'} on:click={() => backupAlgorithm = 'aes-256'}>AES-256</button>
            </div>
          </div>
          <Input type="password" label="Password" placeholder="Encryption password" bind:value={backupPassword} />
          <Input type="password" label="Confirm Password" placeholder="Confirm password" bind:value={backupPasswordConfirm} />
        </div>
      {/if}
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={closeBackupDialog}>Cancel</Button>
      <Button variant="primary" icon={mdiDownload} loading={backupBusy} on:click={handleBackup}>Export</Button>
    </svelte:fragment>
  </Modal>

  <Modal title="Restore Passwords" bind:open={showRestoreDialog} persistent={false}>
    <div class="backup-body">
      <p class="text-body-medium backup-description">
        Import passwords from a backup file. Existing passwords with the same name will be skipped.
      </p>

      <div class="restore-file-picker">
        <Input
          label="Backup file"
          placeholder="Select a backup file..."
          bind:value={restoreFilePath}
          readonly
        />
        <Button variant="secondary" size="sm" on:click={handleBrowseRestoreFile}>Browse</Button>
      </div>

      <label class="backup-toggle">
        <input type="checkbox" bind:checked={restoreEncrypted} />
        <span>File is encrypted</span>
      </label>

      {#if restoreEncrypted}
        <div class="backup-encrypt-options">
          <div class="backup-algorithm">
            <span class="field-label">Algorithm</span>
            <div class="backup-chips">
              <button class="chip" class:chip-active={restoreAlgorithm === 'aes-128'} on:click={() => restoreAlgorithm = 'aes-128'}>AES-128</button>
              <button class="chip" class:chip-active={restoreAlgorithm === 'aes-192'} on:click={() => restoreAlgorithm = 'aes-192'}>AES-192</button>
              <button class="chip" class:chip-active={restoreAlgorithm === 'aes-256'} on:click={() => restoreAlgorithm = 'aes-256'}>AES-256</button>
            </div>
          </div>
          <Input type="password" label="Password" placeholder="Decryption password" bind:value={restorePassword} />
        </div>
      {/if}
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={closeRestoreDialog}>Cancel</Button>
      <Button variant="primary" icon={mdiUpload} loading={restoreBusy} on:click={handleRestore} disabled={!restoreFilePath}>Import</Button>
    </svelte:fragment>
  </Modal>

  {#if deleteConfirmEntry}
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div class="confirm-overlay" on:click|self={cancelDelete} on:keydown={(e) => e.key === 'Escape' && cancelDelete()} role="dialog" aria-modal="true" tabindex="-1">
      <div class="confirm-dialog">
        <h3 class="text-title-medium confirm-title">Delete Password</h3>
        <p class="text-body-medium confirm-message">
          Are you sure you want to delete "{deleteConfirmEntry.title || deleteConfirmEntry.name}"? This action cannot be undone.
        </p>
        <div class="confirm-actions">
          <Button variant="text" on:click={cancelDelete}>Cancel</Button>
          <Button variant="danger" on:click={confirmDelete}>Delete</Button>
        </div>
      </div>
    </div>
  {/if}

  {#if deleteFolderPath}
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div class="confirm-overlay" on:click|self={cancelDeleteFolder} on:keydown={(e) => e.key === 'Escape' && cancelDeleteFolder()} role="dialog" aria-modal="true" tabindex="-1">
      <div class="confirm-dialog">
        <h3 class="text-title-medium confirm-title">Delete Folder</h3>
        <p class="text-body-medium confirm-message">
          Are you sure you want to delete the folder "{deleteFolderPath}"? Passwords in this folder will become unorganized.
        </p>
        <div class="confirm-actions">
          <Button variant="text" on:click={cancelDeleteFolder}>Cancel</Button>
          <Button variant="danger" on:click={confirmDeleteFolder}>Delete</Button>
        </div>
      </div>
    </div>
  {/if}

  <TeamManageDialog
    bind:open={showTeamDialog}
    mode={teamDialogMode}
    team={teamToManage}
    on:save={handleTeamSave}
  />

  {#if deleteConfirmTeam}
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div class="confirm-overlay" on:click|self={cancelDeleteTeam} on:keydown={(e) => e.key === 'Escape' && cancelDeleteTeam()} role="dialog" aria-modal="true" tabindex="-1">
      <div class="confirm-dialog">
        <h3 class="text-title-medium confirm-title">Delete Team</h3>
        <p class="text-body-medium confirm-message">
          Are you sure you want to delete the team "{deleteConfirmTeam.name}"? This cannot be undone.
        </p>
        <div class="confirm-actions">
          <Button variant="text" on:click={cancelDeleteTeam}>Cancel</Button>
          <Button variant="danger" on:click={confirmDeleteTeam}>Delete</Button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .passwords-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .content {
    flex: 1;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  /* Three-panel layout */
  .three-panel {
    flex: 1;
    display: grid;
    grid-template-columns: 220px 1fr 320px;
    overflow: hidden;
  }

  .panel-left {
    border-right: 1px solid var(--color-outline-variant);
    overflow-y: auto;
    background-color: var(--color-surface-container-lowest);
  }

  .panel-center {
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .list-toolbar {
    padding: 12px 16px;
    border-bottom: 1px solid var(--color-outline-variant);
    flex-shrink: 0;
  }

  .list-content {
    flex: 1;
    overflow-y: auto;
  }

  .panel-right {
    border-left: 1px solid var(--color-outline-variant);
    overflow: hidden;
    background-color: var(--color-surface-container-lowest);
  }

  /* Delete confirmation dialog */
  .confirm-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .confirm-dialog {
    background: var(--color-surface-container-high);
    border-radius: var(--radius-xl);
    padding: 24px;
    width: 400px;
    max-width: 90vw;
    box-shadow: var(--shadow-xl);
  }

  .confirm-title {
    color: var(--color-on-surface);
    margin: 0 0 12px;
  }

  .confirm-message {
    color: var(--color-on-surface-variant);
    margin: 0 0 20px;
    line-height: 1.5;
  }

  .confirm-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }

  /* Backup dialog */
  .backup-body {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .backup-description {
    color: var(--color-on-surface-variant);
    margin: 0;
    line-height: 1.5;
  }

  .backup-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    font-size: 14px;
    color: var(--color-on-surface);
  }

  .backup-toggle input[type="checkbox"] {
    width: 18px;
    height: 18px;
    accent-color: var(--color-primary);
    cursor: pointer;
  }

  .backup-encrypt-options {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-left: 26px;
  }

  .backup-algorithm {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .field-label {
    font-size: 11px;
    font-weight: 500;
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .backup-chips {
    display: flex;
    gap: 6px;
  }

  .chip {
    padding: 6px 14px;
    border-radius: 16px;
    font-size: 13px;
    font-weight: 500;
    border: 1px solid var(--color-outline-variant);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .chip:hover {
    background-color: var(--color-surface-container);
  }

  .chip-active {
    background-color: var(--color-primary);
    color: var(--color-on-primary);
    border-color: var(--color-primary);
  }

  .chip-active:hover {
    background-color: var(--color-primary);
    opacity: 0.9;
  }

  .restore-file-picker {
    display: flex;
    gap: 8px;
    align-items: flex-end;
  }

  .restore-file-picker :global(.input-wrapper) {
    flex: 1;
  }

  /* Teams sidebar section */
  .teams-section {
    border-top: 1px solid var(--color-outline-variant);
    padding: 8px 0 12px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .teams-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 4px 12px 4px 8px;
    margin-bottom: 2px;
  }

  .teams-heading {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--color-on-surface-variant);
  }

  .teams-add-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--color-primary);
    cursor: pointer;
    transition: background-color var(--transition-fast);
    flex-shrink: 0;
  }

  .teams-add-btn:hover {
    background: var(--color-surface-container);
  }

  .teams-empty {
    font-size: 12px;
    color: var(--color-on-surface-variant);
    opacity: 0.6;
    margin: 0;
    padding: 4px 12px;
  }

  .teams-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
  }

  .teams-item {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 8px;
    margin: 0 4px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color 120ms ease, color 120ms ease;
    min-height: 32px;
    user-select: none;
    position: relative;
  }

  .teams-item:hover {
    background: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .teams-item:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: -2px;
  }

  .teams-item--selected {
    background: var(--color-primary-container, var(--color-surface-variant));
    color: var(--color-on-primary-container, var(--color-primary));
    font-weight: 500;
  }

  .teams-item-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .teams-item-count {
    font-size: 11px;
    font-weight: 500;
    padding: 0 5px;
    min-width: 18px;
    height: 18px;
    line-height: 18px;
    text-align: center;
    border-radius: var(--radius-full);
    background: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    flex-shrink: 0;
  }

  .teams-item--selected .teams-item-count {
    background: var(--color-primary);
    color: var(--color-on-primary);
  }

  .teams-item-actions {
    display: flex;
    align-items: center;
    gap: 2px;
    flex-shrink: 0;
  }

  .teams-action-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color var(--transition-fast), color var(--transition-fast);
  }

  .teams-action-btn:hover {
    background: var(--color-surface-container-high);
    color: var(--color-on-surface);
  }

  .teams-action-btn--danger:hover {
    background: var(--color-error-container);
    color: var(--color-error);
  }

</style>
