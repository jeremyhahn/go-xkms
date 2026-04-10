<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Button from '$lib/components/Button.svelte';
  import SearchBar from '$lib/components/SearchBar.svelte';
  import DataTable from '$lib/components/DataTable.svelte';
  import type { Column } from '$lib/components/DataTable.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import PairChooserDialog from '$lib/components/PairChooserDialog.svelte';
  import PairBLEDialog from '$lib/components/PairBLEDialog.svelte';
  import PairAgentDialog from '$lib/components/PairAgentDialog.svelte';
  import { mdiPlus, mdiLanConnect, mdiCellphone, mdiPuzzleOutline, mdiDotsVertical } from '$lib/utils/icons';
  import { navigateTo, appState } from '$lib/stores/app';
  import { pairedDevices, setDevices, updateDeviceConnection, updateDeviceAttestation, updateDeviceBackend, removeDevice } from '$lib/stores/pairing';
  import type { PairedDevice, DeviceAttestation, PairedDeviceType } from '$lib/stores/pairing';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend, callBackendVoid } from '$lib/api/backend';
  import type { BackendPairedDevice } from '$lib/api/backend';
  import { formatRelativeTime } from '$lib/utils/format';

  let showChooserDialog = false;
  let showBLEDialog = false;
  let showAgentDialog = false;
  let searchQuery = '';
  let loading = false;
  let sortColumn = 'name';
  let sortDirection: 'asc' | 'desc' = 'asc';

  // Context menu state
  let openMenuAddress: string | null = null;

  const columns: Column[] = [
    { key: 'name', label: 'Name', sortable: true },
    { key: 'type', label: 'Type', width: '120px', sortable: true },
    { key: 'status', label: 'Status', width: '120px', sortable: true },
    { key: 'last_seen', label: 'Last Seen', width: '160px', sortable: true },
  ];

  const typeIcons: Record<string, string> = {
    phone: mdiCellphone,
    extension: mdiPuzzleOutline,
    agent: mdiLanConnect,
  };

  const typeLabels: Record<string, string> = {
    phone: 'Phone',
    extension: 'Extension',
    agent: 'Agent',
  };

  function getTypeIcon(value: unknown): string {
    return typeIcons[String(value)] || mdiLanConnect;
  }

  function getTypeLabel(value: unknown): string {
    return typeLabels[String(value)] || String(value);
  }

  // Map device data to table rows
  $: tableRows = $pairedDevices
    .filter((d) => {
      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return d.name.toLowerCase().includes(q) || d.address.toLowerCase().includes(q) || typeLabels[d.type].toLowerCase().includes(q);
    })
    .map((d) => ({
      id: d.address,
      name: d.name,
      type: d.type,
      status: d.attestationStatus,
      last_seen: d.lastAttestation,
      _device: d,
    }))
    .sort((a, b) => {
      const key = sortColumn as keyof typeof a;
      const aVal = String(a[key] ?? '');
      const bVal = String(b[key] ?? '');
      const cmp = aVal.localeCompare(bVal);
      return sortDirection === 'asc' ? cmp : -cmp;
    });

  onMount(async () => {
    if (isWailsAvailable()) {
      loading = true;
      const devices = await callBackend<BackendPairedDevice[]>('PhoneService', 'ListDevices');
      if (devices && devices.length > 0) {
        setDevices(devices.map(d => ({
          name: d.name,
          address: d.address,
          paired: d.paired_at,
          securityLevel: d.security_level,
          attestationStatus: d.connected ? 'connected' : 'disconnected',
          lastAttestation: d.last_seen,
          isDefault: false,
          isBackend: d.is_backend || false,
          attestation: null,
          policy: null,
          type: d.type || 'phone',
        })));
      }
      loading = false;
    }
  });

  function handleSort(e: CustomEvent<{ column: string; direction: string }>): void {
    sortColumn = e.detail.column;
    sortDirection = e.detail.direction as 'asc' | 'desc';
  }

  function handleRowClick(e: CustomEvent<{ row: any }>): void {
    const row = e.detail.row;
    appState.update((s) => ({
      ...s,
      currentView: 'pairing-detail',
      modalProps: { deviceAddress: row.id },
    }));
  }

  function toggleMenu(address: string, event: MouseEvent): void {
    event.stopPropagation();
    openMenuAddress = openMenuAddress === address ? null : address;
  }

  function closeMenu(): void {
    openMenuAddress = null;
  }

  async function handleConnect(device: PairedDevice): Promise<void> {
    closeMenu();
    addNotification('info', `Connecting to ${device.name}...`);
    const ok = await callBackendVoid('PhoneService', 'Connect', device.name);
    if (ok) {
      updateDeviceConnection(device.name, true);
      addNotification('success', `Connected to ${device.name}`);
    } else {
      addNotification('error', `Failed to connect to ${device.name}`);
    }
  }

  async function handleDisconnect(device: PairedDevice): Promise<void> {
    closeMenu();
    const ok = await callBackendVoid('PhoneService', 'Disconnect', device.name);
    if (ok) {
      updateDeviceConnection(device.name, false);
      addNotification('info', `Disconnected from ${device.name}`);
    } else {
      addNotification('error', `Failed to disconnect from ${device.name}`);
    }
  }

  async function handleAttest(device: PairedDevice): Promise<void> {
    closeMenu();
    addNotification('info', `Requesting attestation from ${device.name}...`);
    try {
      const result = await callBackend<DeviceAttestation>('PhoneService', 'AttestDevice', device.name);
      if (result) {
        updateDeviceAttestation(device.address, result);
        if (result.verified) {
          addNotification('success', `Attestation verified for ${device.name}`);
        } else {
          addNotification('warning', `Attestation completed but unverified: ${result.error_message || 'chain verification failed'}`);
        }
      } else {
        addNotification('error', `Attestation failed for ${device.name}`);
      }
    } catch (err) {
      addNotification('error', `Attestation failed: ${err}`);
    }
  }

  function handleDetails(device: PairedDevice): void {
    closeMenu();
    appState.update((s) => ({
      ...s,
      currentView: 'pairing-detail',
      modalProps: { deviceAddress: device.address },
    }));
  }

  async function handleUnpair(device: PairedDevice): Promise<void> {
    closeMenu();
    const ok = await callBackendVoid('PhoneService', 'Unpair', device.name);
    if (ok) {
      removeDevice(device.address);
      addNotification('info', `${device.name} unpaired`);
    } else {
      addNotification('error', `Failed to unpair ${device.name}`);
    }
  }

  // Chooser dialog handlers
  function openChooser(): void {
    showChooserDialog = true;
  }

  function handleChooseBLE(): void {
    showChooserDialog = false;
    showBLEDialog = true;
  }

  function handleChooseAgent(): void {
    showChooserDialog = false;
    showAgentDialog = true;
  }

  async function handleBLEPair(_address: string): Promise<void> {
    showBLEDialog = false;
    addNotification('success', 'Device paired successfully');
    if (isWailsAvailable()) {
      const devices = await callBackend<BackendPairedDevice[]>('PhoneService', 'ListDevices');
      if (devices && devices.length > 0) {
        setDevices(devices.map(d => ({
          name: d.name,
          address: d.address,
          paired: d.paired_at,
          securityLevel: d.security_level,
          attestationStatus: d.connected ? 'connected' : 'disconnected',
          lastAttestation: d.last_seen,
          isDefault: false,
          isBackend: d.is_backend || false,
          attestation: null,
          policy: null,
          type: d.type || 'phone',
        })));
      }
    }
  }

  async function handleAgentPair(_address: string): Promise<void> {
    showAgentDialog = false;
    addNotification('success', 'Agent paired successfully');
    if (isWailsAvailable()) {
      const devices = await callBackend<BackendPairedDevice[]>('PhoneService', 'ListDevices');
      if (devices && devices.length > 0) {
        setDevices(devices.map(d => ({
          name: d.name,
          address: d.address,
          paired: d.paired_at,
          securityLevel: d.security_level,
          attestationStatus: d.connected ? 'connected' : 'disconnected',
          lastAttestation: d.last_seen,
          isDefault: false,
          isBackend: d.is_backend || false,
          attestation: null,
          policy: null,
          type: d.type || 'phone',
        })));
      }
    }
  }
</script>

<svelte:window on:click={closeMenu} />

<div class="pairing-view">
  <GradientHeader title="Pairing" subtitle="Manage paired devices, extensions, and remote agents" />

  <ViewToolbar>
    <SearchBar
      placeholder="Search paired devices..."
      bind:value={searchQuery}
      onChange={(v) => (searchQuery = v)}
    />
    <span class="text-body-small device-count">{tableRows.length} paired</span>
    <div class="toolbar-spacer" />
    <Button variant="primary" size="sm" icon={mdiPlus} on:click={openChooser}>
      Pair
    </Button>
  </ViewToolbar>

  <div class="pairing-content">
    <DataTable
      {columns}
      rows={tableRows}
      rowKey="id"
      {sortColumn}
      {sortDirection}
      {loading}
      emptyIcon={mdiLanConnect}
      emptyTitle="No Paired Devices"
      emptyDescription="Pair a BLE phone, browser extension, or remote xKey agent to get started."
      on:sort={handleSort}
      on:rowclick={handleRowClick}
    >
      <svelte:fragment slot="cell" let:row let:column let:value>
        {#if column.key === 'type'}
          <span class="type-badge type-{value}">
            <Icon path={getTypeIcon(value)} size={14} />
            {getTypeLabel(value)}
          </span>
        {:else if column.key === 'status'}
          <StatusBadge
            status={value === 'connected' ? 'connected' : value === 'verified' ? 'verified' : value === 'unverified' ? 'unverified' : 'disconnected'}
          />
        {:else if column.key === 'last_seen'}
          <span class="text-body-small last-seen">
            {value ? formatRelativeTime(value) : 'Never'}
          </span>
        {:else}
          {value ?? ''}
        {/if}
      </svelte:fragment>

      <svelte:fragment slot="actions" let:row>
        <div class="row-actions">
          <button class="kebab-btn" on:click|stopPropagation={(e) => toggleMenu(row.id, e)} aria-label="Actions">
            <Icon path={mdiDotsVertical} size={18} />
          </button>
          {#if openMenuAddress === row.id}
            <div class="context-menu" on:click|stopPropagation on:keydown|stopPropagation role="menu" tabindex="0">
              {#if row.status !== 'connected'}
                <button class="menu-item" on:click={() => handleConnect(row._device)}>Connect</button>
              {:else}
                <button class="menu-item" on:click={() => handleDisconnect(row._device)}>Disconnect</button>
              {/if}
              <button class="menu-item" on:click={() => handleAttest(row._device)}>Attest</button>
              <button class="menu-item" on:click={() => handleDetails(row._device)}>Details</button>
              <div class="menu-divider"></div>
              <button class="menu-item menu-danger" on:click={() => handleUnpair(row._device)}>Unpair</button>
            </div>
          {/if}
        </div>
      </svelte:fragment>
    </DataTable>
  </div>

  <PairChooserDialog
    bind:open={showChooserDialog}
    onClose={() => (showChooserDialog = false)}
    onChooseBLE={handleChooseBLE}
    onChooseAgent={handleChooseAgent}
  />

  <PairBLEDialog
    bind:open={showBLEDialog}
    onClose={() => (showBLEDialog = false)}
    onPair={handleBLEPair}
  />

  <PairAgentDialog
    bind:open={showAgentDialog}
    onClose={() => (showAgentDialog = false)}
    onPair={handleAgentPair}
  />
</div>

<style>
  .pairing-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .pairing-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
  }

  .device-count {
    color: var(--color-on-surface-variant);
    white-space: nowrap;
    flex-shrink: 0;
  }

  /* Type badges */
  .type-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: var(--radius-full);
    font-size: 0.8rem;
    font-weight: 500;
    white-space: nowrap;
  }

  .type-phone {
    background-color: var(--color-primary-95);
    color: var(--color-primary);
  }
  :global([data-theme="dark"]) .type-phone {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .type-extension {
    background-color: var(--color-secondary-container);
    color: var(--color-on-secondary-container);
  }

  .type-agent {
    background-color: var(--color-tertiary-container);
    color: var(--color-on-tertiary-container);
  }

  .last-seen {
    color: var(--color-on-surface-variant);
  }

  /* Context menu */
  .row-actions {
    position: relative;
    display: inline-flex;
  }

  .kebab-btn {
    width: 32px;
    height: 32px;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background-color var(--transition-fast);
  }

  .kebab-btn:hover {
    background-color: var(--color-surface-container);
  }

  .context-menu {
    position: absolute;
    right: 0;
    top: 100%;
    z-index: 100;
    min-width: 160px;
    background: var(--color-surface-container-lowest);
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    box-shadow: var(--elevation-2);
    padding: 4px 0;
  }

  .menu-item {
    display: block;
    width: 100%;
    padding: 8px 16px;
    border: none;
    background: transparent;
    color: var(--color-on-surface);
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 0.875rem;
    text-align: left;
    transition: background-color var(--transition-fast);
  }

  .menu-item:hover {
    background-color: var(--color-surface-container);
  }

  .menu-danger {
    color: var(--color-error);
  }

  .menu-divider {
    height: 1px;
    background: var(--color-outline-variant);
    margin: 4px 0;
  }
</style>
