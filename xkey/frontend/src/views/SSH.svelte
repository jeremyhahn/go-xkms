<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Button from '$lib/components/Button.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import BackendSelector from '$lib/components/BackendSelector.svelte';
  import BackendBadge from '$lib/components/BackendBadge.svelte';
  import FolderTree from '$lib/components/FolderTree.svelte';
  import FolderManageDialog from '$lib/components/FolderManageDialog.svelte';
  import SSHProfileDialog from '$lib/components/SSHProfileDialog.svelte';
  import SSHConnectDialog from '$lib/components/SSHConnectDialog.svelte';
  import GenerateSSHKeyDialog from '$lib/components/GenerateSSHKeyDialog.svelte';
  import SourceBadge from '$lib/components/SourceBadge.svelte';
  import {
    mdiSsh,
    mdiPlus,
    mdiDelete,
    mdiExport,
    mdiContentCopy,
    mdiPencil,
    mdiConnection,
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import {
    isWailsAvailable,
    callBackend,
    callBackendVoid,
    SSHProfileService,
    SSHConnectService,
    SSHConsoleService,
    SSHLocalService,
  } from '$lib/api/backend';
  import type {
    SSHKeyInfo,
    SSHProfileEntry,
    SSHLocalKeyInfo,
    SSHConfigHostEntry,
    SSHConnectParams,
    SSHConsoleSessionRecord,
  } from '$lib/api/backend';
  import SSHConsole from '$lib/components/SSHConsole.svelte';
  import { sshDefaultConsoleMode } from '$lib/stores/ssh';

  // ── Tab state ────────────────────────────────────────────────────────────────

  type SSHTab = 'keys' | 'profiles';
  // The SSH application is primarily a connection manager, so it opens on the
  // Profiles tab; the Keys tab is a filtered view of the SSH key store.
  let activeTab: SSHTab = 'profiles';

  // ── Keys tab state ───────────────────────────────────────────────────────────

  let keys: SSHKeyInfo[] = [];
  let loading = false;

  /** Backend filter chip selection ('all' or a backend id). */
  let keyFilterBackend = 'all';

  $: filteredKeys = keyFilterBackend === 'all'
    ? keys
    : keys.filter(k => k.backend === keyFilterBackend);

  // Generate dialog state (the form itself lives in the shared
  // GenerateSSHKeyDialog component — the single SSH-key generation path).
  let showGenerateDialog = false;

  // Export public key dialog state
  let showExportDialog = false;
  let exportedPublicKey = '';
  let exportingKeyName = '';

  // Delete confirm dialog state
  let showDeleteConfirm = false;
  let deleteTargetName = '';
  let deleting = false;

  async function loadKeys(): Promise<void> {
    if (!isWailsAvailable()) {
      keys = [];
      return;
    }
    loading = true;
    const result = await callBackend<SSHKeyInfo[]>('SSHService', 'ListKeys');
    keys = result ?? [];
    loading = false;
  }

  /** Source of the Keys tab table: the xkey key store, or the local ssh-agent / ~/.ssh discovery. */
  type SSHKeySource = 'xkey' | 'local';
  let keySource: SSHKeySource = 'xkey';

  let localKeys: SSHLocalKeyInfo[] = [];
  let localKeysLoading = false;
  let localKeysLoaded = false;

  async function loadLocalKeys(): Promise<void> {
    if (!isWailsAvailable()) {
      localKeys = [];
      localKeysLoaded = true;
      return;
    }
    localKeysLoading = true;
    const result = await SSHLocalService.listLocalKeys();
    localKeys = result ?? [];
    localKeysLoading = false;
    localKeysLoaded = true;
  }

  // Loads once when the Local source is first selected, mirroring the
  // guarded-reactive pattern used elsewhere in this view (e.g. loadProfiles).
  $: if (activeTab === 'keys' && keySource === 'local' && !localKeysLoaded && !localKeysLoading) {
    loadLocalKeys();
  }

  /** Backend id of the SSH key a profile references (for the profile-row badge). */
  function keyBackendFor(name: string): string {
    return keys.find((k) => k.name === name)?.backend ?? '';
  }

  async function handleExport(name: string): Promise<void> {
    if (!isWailsAvailable()) return;
    const result = await callBackend<string>('SSHService', 'ExportPublic', name);
    if (result) {
      exportedPublicKey = result;
      exportingKeyName = name;
      showExportDialog = true;
    } else {
      addNotification('error', `Failed to export public key for "${name}"`);
    }
  }

  async function copyPublicKey(): Promise<void> {
    try {
      await navigator.clipboard.writeText(exportedPublicKey);
      addNotification('success', 'Public key copied to clipboard');
    } catch {
      addNotification('error', 'Failed to copy to clipboard');
    }
  }

  function openDeleteConfirm(name: string): void {
    deleteTargetName = name;
    showDeleteConfirm = true;
  }

  async function handleDelete(): Promise<void> {
    if (!isWailsAvailable()) return;
    deleting = true;
    const ok = await callBackendVoid('SSHService', 'DeleteKey', deleteTargetName);
    deleting = false;
    showDeleteConfirm = false;
    if (ok) {
      addNotification('success', `SSH key "${deleteTargetName}" deleted`);
      deleteTargetName = '';
      await loadKeys();
    } else {
      addNotification('error', `Failed to delete SSH key "${deleteTargetName}"`);
      deleteTargetName = '';
    }
  }

  // ── Connections tab state ────────────────────────────────────────────────────

  let profiles: SSHProfileEntry[] = [];
  let folders: string[] = [];
  let selectedFolder: string | null = null;
  let profilesLoading = false;
  /**
   * True once a profile load has been attempted for the current tab visit.
   * Without this latch the auto-load reactive statement re-fires forever when
   * the profile list is legitimately empty: loadProfiles() clears
   * profilesLoading on completion, which re-satisfies the guard, which loads
   * again. That loop also prevents the "No Profiles" empty state from ever
   * settling, leaving the tab blank.
   */
  let profilesLoadAttempted = false;

  $: profileCounts = computeProfileCounts(profiles);
  $: displayedProfiles = selectedFolder === null
    ? profiles
    : profiles.filter(p =>
        p.folder_path === selectedFolder ||
        p.folder_path.startsWith(selectedFolder + '/')
      );

  function computeProfileCounts(all: SSHProfileEntry[]): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const p of all) {
      if (p.folder_path) {
        counts[p.folder_path] = (counts[p.folder_path] || 0) + 1;
      }
    }
    return counts;
  }

  /** Hosts parsed from ~/.ssh/config, shown in a dedicated section below the profiles list. */
  let configHosts: SSHConfigHostEntry[] = [];

  async function loadProfiles(): Promise<void> {
    if (!isWailsAvailable()) return;
    profilesLoading = true;
    const [profileList, folderList, configHostList] = await Promise.all([
      SSHProfileService.listProfiles(),
      SSHProfileService.listFolders(),
      SSHLocalService.listConfigHosts(),
    ]);
    profiles = profileList ?? [];
    const merged = new Set([...(folderList ?? []), ...folders]);
    folders = Array.from(merged).sort();
    configHosts = configHostList ?? [];
    profilesLoading = false;
  }

  // Profile dialog state
  let showProfileDialog = false;
  let profileDialogMode: 'add' | 'edit' = 'add';
  let editingProfile: SSHProfileEntry | null = null;

  function openAddProfile(): void {
    profileDialogMode = 'add';
    editingProfile = null;
    showProfileDialog = true;
  }

  function openEditProfile(profile: SSHProfileEntry): void {
    profileDialogMode = 'edit';
    editingProfile = profile;
    showProfileDialog = true;
  }

  async function handleProfileSaved(): Promise<void> {
    await loadProfiles();
  }

  // Delete profile confirm state
  let showDeleteProfileConfirm = false;
  let deleteProfileTarget: SSHProfileEntry | null = null;
  let deletingProfile = false;

  function openDeleteProfile(profile: SSHProfileEntry): void {
    deleteProfileTarget = profile;
    showDeleteProfileConfirm = true;
  }

  async function handleDeleteProfile(): Promise<void> {
    if (!deleteProfileTarget) return;
    deletingProfile = true;
    const ok = await SSHProfileService.deleteProfile(deleteProfileTarget.id);
    deletingProfile = false;
    showDeleteProfileConfirm = false;
    if (ok) {
      addNotification('success', `Profile "${deleteProfileTarget.name}" deleted`);
      deleteProfileTarget = null;
      await loadProfiles();
    } else {
      addNotification('error', `Failed to delete profile "${deleteProfileTarget?.name}"`);
    }
  }

  // One-time connection dialog
  let showConnectDialog = false;

  // ── Embedded console panel state: multiple tabbed sessions ──
  // Each tab owns a live SSHConsole (WebSocket + xterm). Inactive tabs stay
  // MOUNTED and are hidden with CSS — unmounting would dispose the terminal
  // and close the socket. `origin` remembers how the session was opened so
  // an ended tab can reconnect (console tokens are one-time).
  interface ConsoleTabOrigin {
    params?: SSHConnectParams;
    profileId?: string;
    alias?: string;
  }
  interface ConsoleTab {
    id: number;
    title: string;
    url: string;
    status: 'live' | 'ended';
    origin: ConsoleTabOrigin;
    /** Session started with persistence enabled (opt-in; default memory-only). */
    persist: boolean;
    /** Persistent-session record ID ('' for memory-only sessions). */
    recordId: string;
  }
  let consoleTabs: ConsoleTab[] = [];
  let activeConsoleTabId = 0;
  let consoleTabSeq = 0;

  /** Builds the persisted-session record for a tab's title + origin. */
  function sessionRecordForTab(tab: Pick<ConsoleTab, 'title' | 'origin' | 'recordId'>): SSHConsoleSessionRecord {
    const record: SSHConsoleSessionRecord = { title: tab.title };
    if (tab.recordId) record.id = tab.recordId;
    if (tab.origin.profileId) {
      record.profile_id = tab.origin.profileId;
    } else if (tab.origin.alias) {
      record.alias = tab.origin.alias;
    } else if (tab.origin.params) {
      const p = tab.origin.params;
      record.host = p.host;
      record.port = p.port;
      record.user = p.user;
      record.key_scope = p.key_scope;
      record.key_owner = p.key_owner;
      record.key_name = p.key_name;
      record.key_source = p.key_source ?? '';
      record.local_identity = p.local_identity ?? '';
    }
    return record;
  }

  /** Reconstructs a tab's reconnect origin from a persisted record. */
  function originFromSessionRecord(record: SSHConsoleSessionRecord): ConsoleTabOrigin {
    if (record.profile_id) return { profileId: record.profile_id };
    if (record.alias) return { alias: record.alias };
    return {
      params: {
        host: record.host ?? '',
        port: record.port ?? 22,
        user: record.user ?? '',
        key_scope: record.key_scope ?? 'user',
        key_owner: record.key_owner ?? 'local',
        key_name: record.key_name ?? '',
        key_source: (record.key_source === 'local' ? 'local' : '') as '' | 'local',
        local_identity: record.local_identity ?? '',
      },
    };
  }

  /**
   * Restores persisted sessions as disconnected tabs (reconnect on demand —
   * never auto-dialing SSH). Runs once per view mount; memory-only sessions
   * are, by design, gone after a reload/restart/navigation.
   */
  async function restorePersistedSessions(): Promise<void> {
    if (!isWailsAvailable() || consoleTabs.length > 0) return;
    const records = (await SSHConsoleService.listSessions()) ?? [];
    if (records.length === 0) return;
    const restored: ConsoleTab[] = records
      .filter((record) => record.id)
      .map((record) => {
        consoleTabSeq += 1;
        return {
          id: consoleTabSeq,
          title: record.title,
          url: '',
          status: 'ended' as const,
          origin: originFromSessionRecord(record),
          persist: true,
          recordId: record.id ?? '',
        };
      });
    if (restored.length === 0) return;
    consoleTabs = [...consoleTabs, ...restored];
    activeConsoleTabId = restored[0].id;
  }

  $: showConsolePanel = consoleTabs.length > 0;
  $: activeConsoleTab = consoleTabs.find((tab) => tab.id === activeConsoleTabId) ?? null;

  /** Resolves the effective console mode from an optional per-connection override,
   *  falling back to the global default. Config hosts have no per-host override,
   *  so they call this with no argument to resolve the global default directly. */
  function effectiveConsoleMode(overrideMode: string = ''): 'system' | 'embedded' {
    const mode = overrideMode || $sshDefaultConsoleMode || 'system';
    return mode === 'embedded' ? 'embedded' : 'system';
  }

  function openConsolePanel(url: string, title: string, origin: ConsoleTabOrigin = {}, persist = false): void {
    consoleTabSeq += 1;
    const tab: ConsoleTab = { id: consoleTabSeq, title, url, status: 'live', origin, persist, recordId: '' };
    consoleTabs = [...consoleTabs, tab];
    activeConsoleTabId = tab.id;

    // Opt-in persistence: record the session so its tab is restored after a
    // reload/restart. Memory-only sessions (the default) skip this entirely.
    if (persist && isWailsAvailable()) {
      void SSHConsoleService.saveSession(sessionRecordForTab(tab)).then((saved) => {
        if (!saved?.id) {
          addNotification('error', `Failed to persist session "${title}" — it will be memory-only`);
          consoleTabs = consoleTabs.map((entry) =>
            entry.id === tab.id ? { ...entry, persist: false } : entry
          );
          return;
        }
        consoleTabs = consoleTabs.map((entry) =>
          entry.id === tab.id ? { ...entry, recordId: saved.id ?? '' } : entry
        );
      });
    }
  }

  function activateConsoleTab(id: number): void {
    activeConsoleTabId = id;
  }

  function closeConsoleTab(id: number): void {
    const closing = consoleTabs.find((tab) => tab.id === id);
    const idx = consoleTabs.findIndex((tab) => tab.id === id);
    consoleTabs = consoleTabs.filter((tab) => tab.id !== id);
    if (activeConsoleTabId === id && consoleTabs.length > 0) {
      // Activate the neighbor that took the closed tab's place.
      const next = consoleTabs[Math.min(Math.max(idx, 0), consoleTabs.length - 1)];
      activeConsoleTabId = next.id;
    }
    // Closing a tab ends the session for good — its persisted record goes too.
    if (closing?.recordId && isWailsAvailable()) {
      void SSHConsoleService.deleteSession(closing.recordId);
    }
  }

  function closeConsolePanel(): void {
    if (isWailsAvailable()) {
      for (const tab of consoleTabs) {
        if (tab.recordId) void SSHConsoleService.deleteSession(tab.recordId);
      }
    }
    consoleTabs = [];
    activeConsoleTabId = 0;
  }

  function markConsoleTabEnded(id: number): void {
    consoleTabs = consoleTabs.map((tab) => (tab.id === id ? { ...tab, status: 'ended' as const } : tab));
  }

  /** Reopens an ended tab's session in place (tokens are one-time, so this
   *  mints a fresh ticket from the tab's remembered origin). */
  async function reconnectConsoleTab(id: number): Promise<void> {
    const tab = consoleTabs.find((entry) => entry.id === id);
    if (!tab || !isWailsAvailable()) return;

    let result: { url: string } | null = null;
    let error: string | undefined;
    if (tab.origin.profileId) {
      ({ result, error } = await SSHConsoleService.openProfileConsoleWithError(tab.origin.profileId));
    } else if (tab.origin.alias) {
      ({ result, error } = await SSHConsoleService.openConfigHostConsoleWithError(tab.origin.alias));
    } else if (tab.origin.params) {
      ({ result, error } = await SSHConsoleService.openConsoleWithError(tab.origin.params));
    } else {
      addNotification('error', 'This session cannot be reconnected');
      return;
    }
    if (!result?.url) {
      addNotification('error', error ? `Failed to reconnect: ${error}` : `Failed to reconnect "${tab.title}"`);
      return;
    }
    // A new url remounts the SSHConsole via the keyed each-block.
    consoleTabs = consoleTabs.map((entry) =>
      entry.id === id ? { ...entry, url: result.url, status: 'live' as const } : entry
    );
    activeConsoleTabId = id;

    // Touch the persisted record's last-connected timestamp.
    if (tab.recordId && isWailsAvailable()) {
      void SSHConsoleService.saveSession(sessionRecordForTab(tab));
    }
  }

  // Connect to a saved profile
  async function handleConnectProfile(profile: SSHProfileEntry): Promise<void> {
    if (!isWailsAvailable()) {
      // In Vite-only mode, show the embedded panel with a placeholder if mode is embedded.
      if (effectiveConsoleMode(profile.console_mode) === 'embedded') {
        openConsolePanel('', `${profile.user}@${profile.host}`, { profileId: profile.id });
      } else {
        addNotification('error', 'Backend connection required');
      }
      return;
    }
    if (effectiveConsoleMode(profile.console_mode) === 'embedded') {
      const { result: info, error } = await SSHConsoleService.openProfileConsoleWithError(profile.id);
      if (!info?.url) {
        addNotification('error', error ? `Failed to open console: ${error}` : `Failed to open console to "${profile.name}"`);
        return;
      }
      openConsolePanel(info.url, `${profile.user}@${profile.host}`, { profileId: profile.id }, profile.persist_session ?? false);
      return;
    }
    const ok = await SSHConnectService.connectProfile(profile.id);
    if (ok) {
      addNotification('success', `Connecting to ${profile.user}@${profile.host}`);
    } else {
      addNotification('error', `Failed to launch connection to "${profile.name}"`);
    }
  }

  /** Target label for a config host, e.g. "admin@build-server:2222" or "build-server". */
  function configHostTarget(host: SSHConfigHostEntry): string {
    const userPart = host.user ? `${host.user}@` : '';
    const portPart = host.port ? `:${host.port}` : '';
    return `${userPart}${host.hostname}${portPart}`;
  }

  // Connect to a host discovered from ~/.ssh/config. These have no per-host
  // console-mode override, so the effective mode resolves from the global default.
  async function handleConnectConfigHost(host: SSHConfigHostEntry): Promise<void> {
    const target = configHostTarget(host);
    if (!isWailsAvailable()) {
      if (effectiveConsoleMode() === 'embedded') {
        openConsolePanel('', target, { alias: host.alias });
      } else {
        addNotification('error', 'Backend connection required');
      }
      return;
    }
    if (effectiveConsoleMode() === 'embedded') {
      const { result: info, error } = await SSHConsoleService.openConfigHostConsoleWithError(host.alias);
      if (!info?.url) {
        addNotification('error', error ? `Failed to open console: ${error}` : `Failed to open console to "${host.alias}"`);
        return;
      }
      openConsolePanel(info.url, target, { alias: host.alias });
      return;
    }
    const ok = await SSHConnectService.connectConfigHost(host.alias);
    if (ok) {
      addNotification('success', `Connecting to ${target}`);
    } else {
      addNotification('error', `Failed to launch connection to "${host.alias}"`);
    }
  }

  // Folder management
  let showFolderDialog = false;
  let folderDialogMode: 'create' | 'rename' = 'create';
  let folderToRename = '';
  let folderInitialValue = '';
  let deleteFolderPath: string | null = null;

  function handleFolderSelect(e: CustomEvent<string | null>): void {
    selectedFolder = e.detail;
  }

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
    const ok = await SSHProfileService.deleteFolder(path);
    deleteFolderPath = null;
    if (ok) {
      addNotification('info', `Folder "${path}" deleted`);
      if (selectedFolder === path) selectedFolder = null;
      await loadProfiles();
    } else {
      addNotification('error', `Failed to delete folder "${path}"`);
    }
  }

  async function handleFolderSubmit(name: string): Promise<void> {
    if (folderDialogMode === 'rename' && folderToRename) {
      const ok = await SSHProfileService.renameFolder(folderToRename, name);
      if (ok) {
        addNotification('success', `Folder renamed to "${name}"`);
        if (selectedFolder === folderToRename) selectedFolder = name;
      } else {
        addNotification('error', 'Failed to rename folder');
      }
    } else {
      const ok = await SSHProfileService.createFolder(name);
      if (ok) {
        if (!folders.includes(name)) {
          folders = [...folders, name];
        }
        addNotification('success', `Folder "${name}" created`);
      } else {
        addNotification('error', `Failed to create folder "${name}"`);
      }
    }
    await loadProfiles();
  }

  // ── Lifecycle ────────────────────────────────────────────────────────────────

  onMount(async () => {
    await loadKeys();
    await restorePersistedSessions();
  });

  // Reset the latch when leaving the tab so re-entering refreshes the list
  // once (explicit create/delete handlers call loadProfiles directly).
  $: if (activeTab !== 'profiles' && profilesLoadAttempted) {
    profilesLoadAttempted = false;
  }

  $: if (activeTab === 'profiles' && !profilesLoadAttempted && !profilesLoading) {
    profilesLoadAttempted = true;
    loadProfiles();
  }
</script>

<div class="ssh-view" data-testid="ssh-view">
  <GradientHeader title="SSH" subtitle="Connection profiles and keys" />

  <!-- Tab bar -->
  <div class="ssh-tabs" role="tablist">
    <button
      class="ssh-tab text-label-large"
      class:ssh-tab--active={activeTab === 'keys'}
      role="tab"
      aria-selected={activeTab === 'keys'}
      data-testid="ssh-tab-keys"
      on:click={() => (activeTab = 'keys')}
    >
      Keys
      {#if activeTab === 'keys'}
        <span class="ssh-tab-indicator"></span>
      {/if}
    </button>
    <button
      class="ssh-tab text-label-large"
      class:ssh-tab--active={activeTab === 'profiles'}
      role="tab"
      aria-selected={activeTab === 'profiles'}
      data-testid="ssh-tab-profiles"
      on:click={() => (activeTab = 'profiles')}
    >
      Profiles
      {#if activeTab === 'profiles'}
        <span class="ssh-tab-indicator"></span>
      {/if}
    </button>
  </div>

  <!-- ── KEYS TAB ── -->
  {#if activeTab === 'keys'}
    <div class="ssh-content">
      <ViewToolbar>
        <div class="key-source-toggle" role="group" aria-label="Key source" data-testid="ssh-key-source-toggle">
          <button
            class="key-source-btn text-label-medium"
            class:key-source-btn--active={keySource === 'xkey'}
            data-testid="ssh-key-source-xkey"
            on:click={() => (keySource = 'xkey')}
          >
            xkey
          </button>
          <button
            class="key-source-btn text-label-medium"
            class:key-source-btn--active={keySource === 'local'}
            data-testid="ssh-key-source-local"
            on:click={() => (keySource = 'local')}
          >
            Local
          </button>
        </div>
        {#if keySource === 'xkey'}
          <BackendSelector
            capability="signing"
            bind:selected={keyFilterBackend}
            showAll={true}
            on:change={(e) => { keyFilterBackend = e.detail; }}
          />
        {/if}
        <div class="toolbar-spacer" />
        {#if keySource === 'xkey'}
          <Button
            variant="primary"
            size="sm"
            icon={mdiPlus}
            data-testid="ssh-generate-button"
            on:click={() => (showGenerateDialog = true)}
          >
            Generate Key
          </Button>
        {/if}
      </ViewToolbar>

      {#if keySource === 'xkey'}
        {#if filteredKeys.length > 0}
          <div class="ssh-key-table">
            <table>
              <thead>
                <tr>
                  <th class="text-label-medium">Name</th>
                  <th class="text-label-medium">Algorithm</th>
                  <th class="text-label-medium">Fingerprint</th>
                  <th class="text-label-medium">Backend</th>
                  <th class="text-label-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {#each filteredKeys as key (key.name)}
                  <tr class="ssh-key-row" data-testid="ssh-key-row">
                    <td class="key-name text-body-medium">{key.name}</td>
                    <td>
                      <span class="algo-badge">{key.algorithm}</span>
                    </td>
                    <td class="fingerprint text-body-small">{key.fingerprint || '—'}</td>
                    <td>
                      {#if key.backend}
                        <BackendBadge backend={key.backend} compact />
                      {:else}
                        <span class="muted text-body-small">—</span>
                      {/if}
                    </td>
                    <td class="actions-cell">
                      <Button
                        variant="outline"
                        size="sm"
                        icon={mdiExport}
                        on:click={() => handleExport(key.name)}
                      >
                        Export
                      </Button>
                      <Button
                        variant="text"
                        size="sm"
                        icon={mdiDelete}
                        on:click={() => openDeleteConfirm(key.name)}
                      >
                        Delete
                      </Button>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {:else if !loading}
          <EmptyState
            data-testid="ssh-empty-state"
            icon={mdiSsh}
            title="No SSH Keys"
            description="Generate your first SSH key to use with remote servers, Git hosting, and other SSH-based services."
            actionLabel="Generate Key"
            onAction={() => (showGenerateDialog = true)}
          />
        {/if}
      {:else if localKeys.length > 0}
        <div class="ssh-key-table">
          <table>
            <thead>
              <tr>
                <th class="text-label-medium">Source</th>
                <th class="text-label-medium">Type</th>
                <th class="text-label-medium">Fingerprint</th>
                <th class="text-label-medium">Comment</th>
              </tr>
            </thead>
            <tbody>
              {#each localKeys as localKey (localKey.source + localKey.path + localKey.fingerprint)}
                <tr class="ssh-key-row" data-testid="ssh-local-key-row">
                  <td>
                    <SourceBadge
                      label={localKey.source === 'agent' ? 'Agent' : 'File'}
                      variant={localKey.source}
                      title={localKey.source === 'file' ? localKey.path : ''}
                      data-testid="ssh-local-key-badge"
                    />
                  </td>
                  <td class="text-body-medium">{localKey.key_type}</td>
                  <td class="fingerprint text-body-small">{localKey.fingerprint || '—'}</td>
                  <td class="text-body-medium">{localKey.comment || '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else if !localKeysLoading}
        <EmptyState
          data-testid="ssh-empty-state"
          icon={mdiSsh}
          title="No Local Keys"
          description="No SSH keys found in your ssh-agent or ~/.ssh directory."
        />
      {/if}
    </div>
  {/if}

  <!-- ── CONNECTIONS TAB ── -->
  {#if activeTab === 'profiles'}
    <div class="ssh-connections" data-testid="ssh-profiles">
      <aside class="connections-sidebar">
        <FolderTree
          {folders}
          {selectedFolder}
          counts={profileCounts}
          allLabel="All Profiles"
          on:select={handleFolderSelect}
          on:createFolder={handleCreateFolder}
          on:createSubfolder={handleCreateSubfolder}
          on:renameFolder={handleRenameFolder}
          on:deleteFolder={handleDeleteFolderRequest}
        />
      </aside>

      <div class="connections-main">
        <ViewToolbar>
          <div class="toolbar-spacer" />
          <Button
            variant="outline"
            size="sm"
            icon={mdiConnection}
            data-testid="ssh-new-connection"
            on:click={() => (showConnectDialog = true)}
          >
            New Connection
          </Button>
          <Button
            variant="primary"
            size="sm"
            icon={mdiPlus}
            data-testid="ssh-new-profile"
            on:click={openAddProfile}
          >
            New Profile
          </Button>
        </ViewToolbar>

        {#if displayedProfiles.length > 0}
          <div class="profiles-list">
            {#each displayedProfiles as profile (profile.id)}
              <div class="profile-row" data-testid="ssh-profile-row">
                <div class="profile-info">
                  <span class="profile-name text-body-medium">{profile.name}</span>
                  <span class="profile-target text-body-small">
                    {profile.user}@{profile.host}:{profile.port}
                  </span>
                  <span class="profile-key text-body-small">
                    {#if profile.key_name}
                      <span class="profile-key-name">Key: {profile.key_name}</span>
                      {#if keyBackendFor(profile.key_name)}
                        <BackendBadge backend={keyBackendFor(profile.key_name)} compact />
                      {/if}
                    {:else}
                      <span class="profile-key-none">No key (password auth)</span>
                    {/if}
                  </span>
                  {#if profile.notes}
                    <span class="profile-notes text-body-small">{profile.notes}</span>
                  {/if}
                </div>
                <div class="profile-actions">
                  <Button
                    variant="primary"
                    size="sm"
                    icon={mdiConnection}
                    data-testid="ssh-connect-button"
                    on:click={() => handleConnectProfile(profile)}
                  >
                    Connect
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    icon={mdiPencil}
                    on:click={() => openEditProfile(profile)}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="text"
                    size="sm"
                    icon={mdiDelete}
                    on:click={() => openDeleteProfile(profile)}
                  >
                    Delete
                  </Button>
                </div>
              </div>
            {/each}
          </div>
        {:else if !profilesLoading}
          <EmptyState
            icon={mdiSsh}
            title="No Profiles"
            description="Create a profile to quickly connect to SSH servers."
            actionLabel="New Profile"
            onAction={openAddProfile}
          />
        {/if}

        <!-- ~/.ssh/config hosts: not folder-filtered — always shown when present. -->
        {#if configHosts.length > 0}
          <div class="config-hosts-section" data-testid="ssh-config-hosts-section">
            <h3 class="config-hosts-heading text-label-large">From ~/.ssh/config</h3>
            <div class="config-hosts-list">
              {#each configHosts as host (host.alias)}
                <div class="config-host-row" data-testid="ssh-config-host-row">
                  <div class="config-host-info">
                    <span class="config-host-alias text-body-medium">{host.alias}</span>
                    <span class="config-host-target text-body-small">{configHostTarget(host)}</span>
                    {#if host.identity_files && host.identity_files.length > 0}
                      <span class="config-host-identity text-body-small">
                        Identity: {host.identity_files.join(', ')}
                      </span>
                    {/if}
                    <SourceBadge label="ssh_config" variant="config" />
                  </div>
                  <div class="config-host-actions">
                    <Button
                      variant="primary"
                      size="sm"
                      icon={mdiConnection}
                      data-testid="ssh-config-host-connect"
                      on:click={() => handleConnectConfigHost(host)}
                    >
                      Connect
                    </Button>
                  </div>
                </div>
              {/each}
            </div>
          </div>
        {/if}
      </div>
    </div>
  {/if}

  <!-- ── EMBEDDED CONSOLE PANEL (tabbed sessions) ── -->
  {#if showConsolePanel}
    <div class="console-panel-overlay" data-testid="ssh-console-panel">
      <div class="console-panel-header">
        <div class="console-tab-strip" role="tablist" aria-label="SSH sessions" data-testid="ssh-console-tabs">
          {#each consoleTabs as tab (tab.id)}
            <div
              class="console-tab"
              class:console-tab--active={tab.id === activeConsoleTabId}
              class:console-tab--ended={tab.status === 'ended'}
              role="tab"
              aria-selected={tab.id === activeConsoleTabId}
              tabindex="0"
              data-testid="ssh-console-tab"
              on:click={() => activateConsoleTab(tab.id)}
              on:keydown={(e) => e.key === 'Enter' && activateConsoleTab(tab.id)}
            >
              <span
                class="console-tab-status"
                class:console-tab-status--ended={tab.status === 'ended'}
                aria-hidden="true"
              ></span>
              <span class="console-tab-title" title={tab.title}>{tab.title || 'SSH Console'}</span>
              <button
                class="console-tab-close"
                aria-label="Close session {tab.title}"
                data-testid="ssh-console-tab-close"
                on:click|stopPropagation={() => closeConsoleTab(tab.id)}
              >
                &#10005;
              </button>
            </div>
          {/each}
          <button
            class="console-tab-add"
            aria-label="New SSH session"
            title="New SSH session"
            data-testid="ssh-console-tab-add"
            on:click={() => (showConnectDialog = true)}
          >
            +
          </button>
        </div>
        <div class="console-panel-actions">
          {#if activeConsoleTab?.status === 'ended'}
            <Button
              variant="outline"
              size="sm"
              data-testid="ssh-console-tab-reconnect"
              on:click={() => activeConsoleTab && reconnectConsoleTab(activeConsoleTab.id)}
            >
              Reconnect
            </Button>
          {/if}
          <button
            class="console-close-btn"
            aria-label="Close console"
            data-testid="ssh-console-close"
            on:click={closeConsolePanel}
          >
            &#10005;
          </button>
        </div>
      </div>
      <div class="console-panel-body">
        {#each consoleTabs as tab (tab.id)}
          <!-- Inactive tabs stay mounted (hidden) so their sessions live on;
               re-keying on url remounts a tab after reconnect. -->
          <div class="console-tab-pane" class:console-tab-pane--hidden={tab.id !== activeConsoleTabId}>
            {#key tab.url}
              <SSHConsole
                url={tab.url}
                title={tab.title}
                placeholder={tab.persist ? 'Session not connected — press Reconnect' : ''}
                onEnded={() => markConsoleTabEnded(tab.id)}
              />
            {/key}
          </div>
        {/each}
      </div>
    </div>
  {/if}

  <!-- ── KEYS TAB DIALOGS ── -->

  <!-- Generate Key Dialog -->
  <GenerateSSHKeyDialog bind:open={showGenerateDialog} onGenerated={loadKeys} />

  <!-- Export Public Key Dialog -->
  <Modal bind:open={showExportDialog} title="Export Public Key" maxWidth="600px">
    <p class="export-hint text-body-small">
      Public key for <strong>{exportingKeyName}</strong>. Add it to
      <code>~/.ssh/authorized_keys</code> on the target server.
    </p>
    <div class="export-key-block">
      <code class="key-text">{exportedPublicKey}</code>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="outline" on:click={() => (showExportDialog = false)}>Close</Button>
      <Button variant="primary" icon={mdiContentCopy} on:click={copyPublicKey}>Copy</Button>
    </svelte:fragment>
  </Modal>

  <!-- Delete Key Confirmation Dialog -->
  <Modal bind:open={showDeleteConfirm} title="Delete SSH Key" maxWidth="400px">
    <p class="confirm-message text-body-medium">
      Are you sure you want to delete <strong>{deleteTargetName}</strong>?
      This action cannot be undone.
    </p>
    <svelte:fragment slot="actions">
      <Button variant="outline" on:click={() => (showDeleteConfirm = false)}>Cancel</Button>
      <Button variant="danger" loading={deleting} on:click={handleDelete}>Delete</Button>
    </svelte:fragment>
  </Modal>

  <!-- ── CONNECTIONS TAB DIALOGS ── -->

  <SSHProfileDialog
    bind:open={showProfileDialog}
    mode={profileDialogMode}
    profile={editingProfile}
    {folders}
    onClose={() => { showProfileDialog = false; }}
    onSave={handleProfileSaved}
  />

  <SSHConnectDialog
    bind:open={showConnectDialog}
    {folders}
    onClose={() => { showConnectDialog = false; }}
    onProfileSaved={handleProfileSaved}
    onConsoleReady={(url, params, persist) =>
      openConsolePanel(url, params.user && params.host ? `${params.user}@${params.host}` : 'SSH Console', { params }, persist)}
  />

  <!-- Delete Profile Confirmation -->
  <Modal bind:open={showDeleteProfileConfirm} title="Delete Profile" maxWidth="400px">
    <p class="confirm-message text-body-medium">
      Are you sure you want to delete profile <strong>{deleteProfileTarget?.name}</strong>?
      This action cannot be undone.
    </p>
    <svelte:fragment slot="actions">
      <Button variant="outline" on:click={() => (showDeleteProfileConfirm = false)}>Cancel</Button>
      <Button variant="danger" loading={deletingProfile} on:click={handleDeleteProfile}>Delete</Button>
    </svelte:fragment>
  </Modal>

  <!-- Delete Folder Confirmation -->
  {#if deleteFolderPath}
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div
      class="confirm-overlay"
      on:click|self={() => { deleteFolderPath = null; }}
      on:keydown={(e) => { if (e.key === 'Escape') deleteFolderPath = null; }}
      role="dialog"
      aria-modal="true"
      tabindex="-1"
    >
      <div class="confirm-dialog">
        <h3 class="text-title-medium confirm-title">Delete Folder</h3>
        <p class="text-body-medium confirm-message-inner">
          Delete folder <strong>{deleteFolderPath}</strong> and all its profiles?
          This action cannot be undone.
        </p>
        <div class="confirm-actions">
          <Button variant="outline" on:click={() => { deleteFolderPath = null; }}>Cancel</Button>
          <Button variant="danger" on:click={confirmDeleteFolder}>Delete</Button>
        </div>
      </div>
    </div>
  {/if}

  <FolderManageDialog
    bind:open={showFolderDialog}
    mode={folderDialogMode}
    currentName={folderToRename}
    initialValue={folderInitialValue}
    onClose={() => { showFolderDialog = false; }}
    onSubmit={handleFolderSubmit}
  />
</div>

<style>
  .ssh-view {
    height: 100%;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    position: relative;
  }

  /* ── Tab bar ── */
  .ssh-tabs {
    display: flex;
    border-bottom: 1px solid var(--color-outline-variant);
    flex-shrink: 0;
    overflow-x: auto;
  }

  .ssh-tab {
    position: relative;
    padding: 12px 24px;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    white-space: nowrap;
    transition: color var(--transition-fast), background-color var(--transition-fast);
    font-family: var(--font-sans);
  }

  .ssh-tab:hover {
    color: var(--color-on-surface);
    background-color: var(--color-surface-container);
  }

  .ssh-tab--active {
    color: var(--color-primary);
  }

  .ssh-tab-indicator {
    position: absolute;
    bottom: 0;
    left: 8px;
    right: 8px;
    height: 3px;
    background-color: var(--color-primary);
    border-radius: 3px 3px 0 0;
    animation: scale-in 200ms ease;
  }

  @keyframes scale-in {
    from { transform: scaleX(0); }
    to { transform: scaleX(1); }
  }

  /* ── Keys tab ── */
  .ssh-content {
    flex: 1;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
  }

  .ssh-key-table {
    padding: 16px 24px;
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  thead th {
    text-align: left;
    padding: 8px 12px;
    color: var(--color-on-surface-variant);
    border-bottom: 1px solid var(--color-outline-variant);
    white-space: nowrap;
  }

  .ssh-key-row {
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .ssh-key-row:last-child {
    border-bottom: none;
  }

  .ssh-key-row:hover {
    background-color: var(--color-surface-container-low);
  }

  tbody td {
    padding: 12px;
    vertical-align: middle;
  }

  .key-name {
    font-weight: 500;
    color: var(--color-on-surface);
  }

  .fingerprint {
    font-family: var(--font-mono, monospace);
    color: var(--color-on-surface-variant);
    max-width: 240px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .algo-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    font-size: 12px;
    font-weight: 500;
    white-space: nowrap;
  }

  :global([data-theme="dark"]) .algo-badge {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .muted {
    color: var(--color-on-surface-variant);
    opacity: 0.5;
  }

  .actions-cell {
    display: flex;
    gap: 4px;
    align-items: center;
    white-space: nowrap;
  }

  /* ── Key source toggle ── */
  .key-source-toggle {
    display: inline-flex;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-full);
    overflow: hidden;
    flex-shrink: 0;
  }

  .key-source-btn {
    padding: 6px 16px;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color var(--transition-fast), color var(--transition-fast);
  }

  .key-source-btn:not(:last-child) {
    border-right: 1px solid var(--color-outline-variant);
  }

  .key-source-btn:hover {
    background-color: var(--color-surface-container);
  }

  .key-source-btn--active {
    background-color: var(--color-primary);
    color: var(--color-on-primary);
  }

  /* ── Connections tab ── */
  .ssh-connections {
    flex: 1;
    display: flex;
    overflow: hidden;
  }

  .connections-sidebar {
    width: 220px;
    flex-shrink: 0;
    border-right: 1px solid var(--color-outline-variant);
    overflow-y: auto;
    background-color: var(--color-surface-container-lowest);
  }

  .connections-main {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .profiles-list {
    flex: 1;
    overflow-y: auto;
    padding: 8px 0;
  }

  .profile-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 20px;
    border-bottom: 1px solid var(--color-outline-variant);
    transition: background-color 120ms ease;
  }

  .profile-row:last-child {
    border-bottom: none;
  }

  .profile-row:hover {
    background-color: var(--color-surface-container-low);
  }

  .profile-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .profile-name {
    font-weight: 500;
    color: var(--color-on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .profile-target {
    font-family: var(--font-mono, monospace);
    color: var(--color-on-surface-variant);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .profile-key {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--color-on-surface-variant);
    margin-top: 2px;
  }

  .profile-key-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .profile-key-none {
    font-style: italic;
    opacity: 0.8;
  }

  .profile-notes {
    color: var(--color-on-surface-variant);
    opacity: 0.7;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .profile-actions {
    display: flex;
    gap: 4px;
    align-items: center;
    flex-shrink: 0;
  }

  /* ── Config hosts section (~/.ssh/config) ── */
  .config-hosts-section {
    border-top: 1px solid var(--color-outline-variant);
    flex-shrink: 0;
  }

  .config-hosts-heading {
    padding: 12px 20px 4px;
    color: var(--color-on-surface-variant);
  }

  .config-hosts-list {
    display: flex;
    flex-direction: column;
    max-height: 240px;
    overflow-y: auto;
  }

  .config-host-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 20px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .config-host-row:last-child {
    border-bottom: none;
  }

  .config-host-row:hover {
    background-color: var(--color-surface-container-low);
  }

  .config-host-info {
    flex: 1;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    min-width: 0;
  }

  .config-host-alias {
    font-weight: 500;
    color: var(--color-on-surface);
  }

  .config-host-target {
    font-family: var(--font-mono, monospace);
    color: var(--color-on-surface-variant);
  }

  .config-host-identity {
    color: var(--color-on-surface-variant);
    opacity: 0.8;
  }

  .config-host-actions {
    flex-shrink: 0;
  }

  /* ── Embedded console panel ── */
  .console-panel-overlay {
    position: absolute;
    inset: 0;
    z-index: 100;
    display: flex;
    flex-direction: column;
    background-color: var(--color-surface);
  }

  .console-panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 6px 12px;
    flex-shrink: 0;
    background-color: var(--color-surface-container-high);
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .console-tab-strip {
    display: flex;
    align-items: center;
    gap: 4px;
    flex: 1;
    min-width: 0;
    overflow-x: auto;
  }

  .console-tab {
    display: flex;
    align-items: center;
    gap: 6px;
    max-width: 220px;
    padding: 5px 8px 5px 10px;
    border-radius: var(--radius-sm) var(--radius-sm) 0 0;
    border: 1px solid transparent;
    border-bottom: none;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
  }

  .console-tab--active {
    background-color: var(--color-surface);
    border-color: var(--color-outline-variant);
    color: var(--color-on-surface);
  }

  .console-tab--ended {
    opacity: 0.65;
  }

  .console-tab-status {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background-color: var(--color-primary);
    flex-shrink: 0;
  }

  .console-tab-status--ended {
    background-color: var(--color-outline);
  }

  .console-tab-title {
    overflow: hidden;
    text-overflow: ellipsis;
    font-family: var(--font-mono, monospace);
    font-size: 12px;
  }

  .console-tab-close {
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-size: 12px;
    padding: 1px 4px;
    border-radius: var(--radius-sm);
    line-height: 1;
    flex-shrink: 0;
  }

  .console-tab-close:hover {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .console-tab-add {
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-size: 16px;
    padding: 2px 8px;
    border-radius: var(--radius-sm);
    line-height: 1;
    flex-shrink: 0;
  }

  .console-tab-add:hover {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .console-panel-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  .console-close-btn {
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-size: 18px;
    padding: 4px 8px;
    border-radius: var(--radius-sm);
    line-height: 1;
  }

  .console-close-btn:hover {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .console-panel-body {
    flex: 1;
    min-height: 0;
    padding: 8px;
    position: relative;
  }

  .console-tab-pane {
    width: 100%;
    height: 100%;
  }

  .console-tab-pane--hidden {
    display: none;
  }

  /* ── Export dialog ── */
  .export-hint {
    color: var(--color-on-surface-variant);
    margin: 0 0 12px 0;
  }

  .export-key-block {
    background-color: var(--color-surface-container);
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    padding: 12px;
    overflow-x: auto;
    max-height: 200px;
    overflow-y: auto;
  }

  .key-text {
    font-family: var(--font-mono, monospace);
    color: var(--color-on-surface);
    word-break: break-all;
    white-space: pre-wrap;
    font-size: 12px;
    display: block;
  }

  /* ── Confirm dialogs ── */
  .confirm-message {
    color: var(--color-on-surface);
    margin: 0;
  }

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

  .confirm-message-inner {
    color: var(--color-on-surface-variant);
    margin: 0 0 20px;
    line-height: 1.5;
  }

  .confirm-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
</style>
