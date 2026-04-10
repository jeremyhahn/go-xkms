<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Button from '$lib/components/Button.svelte';
  import SearchBar from '$lib/components/SearchBar.svelte';
  import AuditEntry from '$lib/components/AuditEntry.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Pagination from '$lib/components/Pagination.svelte';
  import {
    mdiExport, mdiClipboardTextOutline
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend } from '$lib/api/backend';

  /** Shape returned by AuditService.GetEntries on the backend. */
  interface BackendAuditEntry {
    timestamp: string;
    operation: string;
    backend: string;
    key_id: string;
    device_id: string;
    device_name: string;
    success: boolean;
    error?: string;
    duration_ms: number;
    details?: Record<string, unknown>;
  }

  interface AuditEntryData {
    id: string;
    timestamp: string;
    operation: string;
    device: string;
    backend: string;
    keyId: string;
    success: boolean;
    details: string;
    ipAddress: string;
  }

  let entries: AuditEntryData[] = [];
  let filteredEntries: AuditEntryData[] = [];
  let searchQuery = '';
  let filterOperation = 'all';
  let filterDevice = 'all';
  let filterStatus = 'all';
  let showExportModal = false;
  let exportFormat = 'json';
  let currentPage = 1;
  const pageSize = 20;
  let loading = false;

  $: {
    let result = entries;

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (e) =>
          e.operation.toLowerCase().includes(q) ||
          e.details.toLowerCase().includes(q) ||
          e.device.toLowerCase().includes(q) ||
          e.keyId.toLowerCase().includes(q)
      );
    }

    if (filterOperation !== 'all') {
      result = result.filter((e) => e.operation.toLowerCase() === filterOperation);
    }

    if (filterDevice !== 'all') {
      result = result.filter((e) => e.device === filterDevice);
    }

    if (filterStatus !== 'all') {
      result = result.filter((e) => (filterStatus === 'success' ? e.success : !e.success));
    }

    filteredEntries = result;
  }

  $: totalPages = Math.max(1, Math.ceil(filteredEntries.length / pageSize));
  $: pagedEntries = filteredEntries.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  /** Unique device names derived from loaded entries for the filter dropdown. */
  $: deviceNames = [...new Set(entries.map(e => e.device).filter(Boolean))];

  /** Unique operations derived from loaded entries for the filter dropdown. */
  $: operationNames = [...new Set(entries.map(e => e.operation.toLowerCase()).filter(Boolean))];

  async function loadEntries(): Promise<void> {
    if (!isWailsAvailable()) return;
    loading = true;
    const result = await callBackend<BackendAuditEntry[]>('AuditService', 'GetEntries', {});
    loading = false;
    if (result && result.length > 0) {
      entries = result.map((e, i) => ({
        id: `audit-${i}`,
        timestamp: e.timestamp,
        operation: e.operation,
        device: e.device_name || e.device_id || '',
        backend: e.backend,
        keyId: e.key_id || '',
        success: e.success,
        details: e.error || `${e.operation} operation`,
        ipAddress: '',
      })).sort((a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );
    } else {
      entries = [];
    }
  }

  onMount(loadEntries);

  async function handleExport(): Promise<void> {
    if (isWailsAvailable()) {
      const data = await callBackend<Uint8Array>('AuditService', 'ExportEntries', exportFormat, {});
      if (data !== null) {
        addNotification('success', `Audit log exported as ${exportFormat.toUpperCase()}`);
      } else {
        addNotification('error', 'Failed to export audit log');
      }
    } else {
      addNotification('info', 'Export not available outside desktop application');
    }
    showExportModal = false;
  }
</script>

<div class="audit-view">
  <GradientHeader title="Audit Log" subtitle="Security event history" />

  <ViewToolbar>
    <SearchBar
      placeholder="Search events..."
      bind:value={searchQuery}
      onChange={(v) => (searchQuery = v)}
    />
    <div class="audit-filters">
      <select class="filter-select text-label-medium" bind:value={filterOperation}>
        <option value="all">All operations</option>
        {#each operationNames as op}
          <option value={op}>{op.charAt(0).toUpperCase() + op.slice(1)}</option>
        {/each}
      </select>
      <select class="filter-select text-label-medium" bind:value={filterDevice}>
        <option value="all">All devices</option>
        {#each deviceNames as dev}
          <option value={dev}>{dev}</option>
        {/each}
      </select>
      <select class="filter-select text-label-medium" bind:value={filterStatus}>
        <option value="all">All statuses</option>
        <option value="success">Success</option>
        <option value="failure">Failure</option>
      </select>
    </div>
    <div class="toolbar-spacer" />
    <Button variant="outline" size="sm" icon={mdiExport} on:click={() => (showExportModal = true)}>
      Export
    </Button>
  </ViewToolbar>

  <div class="audit-content">

    <!-- Result count -->
    <div class="result-count">
      <span class="text-body-small">{filteredEntries.length} event(s) found</span>
    </div>

    <!-- Entry list -->
    {#if pagedEntries.length > 0}
      <div class="audit-list">
        {#each pagedEntries as entry (entry.id)}
          <AuditEntry {entry} />
        {/each}
      </div>

      <!-- Pagination -->
      {#if totalPages > 1}
        <Pagination
          {currentPage}
          {totalPages}
          totalItems={filteredEntries.length}
          {pageSize}
          on:pagechange={(e) => (currentPage = e.detail)}
        />
      {/if}
    {:else if entries.length === 0}
      <EmptyState
        icon={mdiClipboardTextOutline}
        title="No audit log entries"
        description="Audit events will appear here as security operations are performed."
      />
    {:else}
      <EmptyState
        icon={mdiClipboardTextOutline}
        title="No events found"
        description="No audit events match your current filters. Try adjusting your search criteria."
      />
    {/if}
  </div>

  <Modal bind:open={showExportModal} title="Export Audit Log" maxWidth="400px">
    <div class="export-form">
      <div class="form-field">
        <label class="text-label-medium form-label" for="audit-export-format">Export format</label>
        <select id="audit-export-format" class="form-select" bind:value={exportFormat}>
          <option value="json">JSON</option>
          <option value="csv">CSV</option>
        </select>
      </div>
      <p class="text-body-small export-info">
        Exporting {filteredEntries.length} event(s) matching your current filters.
      </p>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showExportModal = false)}>Cancel</Button>
      <Button variant="primary" on:click={handleExport}>Export</Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .audit-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .audit-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .audit-filters {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }

  .filter-select {
    height: 36px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    outline: none;
    cursor: pointer;
  }

  .filter-select:focus {
    border-color: var(--color-primary);
  }

  .result-count {
    color: var(--color-on-surface-variant);
  }

  .audit-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .export-form {
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
  }

  .export-info {
    color: var(--color-on-surface-variant);
    margin: 0;
  }
</style>
