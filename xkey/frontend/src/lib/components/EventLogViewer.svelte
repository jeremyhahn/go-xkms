<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import { mdiExport, mdiFilter, mdiShieldCheck } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import type { BackendEventLogEntry, EventLogReplayResult } from '$lib/api/backend';

  export let open: boolean = false;
  export let entries: BackendEventLogEntry[] = [];
  export let loading: boolean = false;
  export let onClose: () => void = () => {};
  export let onReplay: (() => Promise<EventLogReplayResult | null>) | undefined = undefined;

  let filterPCRIndex = -1;
  let filterEventType = '';
  let replayResult: EventLogReplayResult | null = null;
  let replayLoading = false;

  $: filteredEntries = entries.filter((e) => {
    if (filterPCRIndex >= 0 && e.pcr_index !== filterPCRIndex) return false;
    if (filterEventType && e.event_type !== filterEventType) return false;
    return true;
  });

  $: uniquePCRIndices = [...new Set(entries.map((e) => e.pcr_index))].sort((a, b) => a - b);
  $: uniqueEventTypes = [...new Set(entries.map((e) => e.event_type))].sort();

  function handleFilterChange(event: Event): void {
    const target = event.target as HTMLSelectElement;
    filterPCRIndex = parseInt(target.value, 10);
  }

  function handleEventTypeChange(event: Event): void {
    const target = event.target as HTMLSelectElement;
    filterEventType = target.value;
  }

  async function handleExportJSON(): Promise<void> {
    const exportData = filteredEntries.map((e) => ({
      pcr_index: e.pcr_index,
      event_type: e.event_type,
      digest_hex: e.digest_hex,
      event_data: e.event_data,
    }));
    const json = JSON.stringify(exportData, null, 2);
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      await navigator.clipboard.writeText(json);
      addNotification('success', `Event log (${filteredEntries.length} entries) copied to clipboard as JSON`);
    }
  }

  async function handleReplay(): Promise<void> {
    if (!onReplay) return;
    replayLoading = true;
    try {
      replayResult = await onReplay();
    } catch {
      addNotification('error', 'Event log replay failed');
      replayResult = null;
    } finally {
      replayLoading = false;
    }
  }

  $: if (open) {
    filterPCRIndex = -1;
    filterEventType = '';
    replayResult = null;
  }
</script>

<Modal bind:open title="TPM Event Log" maxWidth="900px">
  <div class="event-log-viewer">
    {#if loading}
      <div class="loading-container">
        <LoadingSpinner size={40} />
        <p class="text-body-medium loading-text">Loading event log...</p>
      </div>
    {:else if entries.length === 0}
      <p class="text-body-medium empty-text">No event log entries available.</p>
    {:else}
      <div class="event-log-controls">
        <div class="filter-groups">
          <div class="filter-group">
            <Icon path={mdiFilter} size={16} />
            <label class="text-label-medium filter-label" for="pcr-filter">Filter by PCR:</label>
            <select id="pcr-filter" class="filter-select text-label-medium" on:change={handleFilterChange}>
              <option value="-1">All PCRs</option>
              {#each uniquePCRIndices as idx}
                <option value={idx}>PCR {idx}</option>
              {/each}
            </select>
          </div>
          <div class="filter-group">
            <label class="text-label-medium filter-label" for="type-filter">Event Type:</label>
            <select id="type-filter" class="filter-select text-label-medium" on:change={handleEventTypeChange}>
              <option value="">All Types</option>
              {#each uniqueEventTypes as evType}
                <option value={evType}>{evType}</option>
              {/each}
            </select>
          </div>
        </div>
        <span class="text-body-small entry-count">
          {filteredEntries.length} of {entries.length} entries
        </span>
      </div>

      <div class="event-log-table-wrapper">
        <table class="event-log-table" aria-label="TPM Event Log">
          <thead>
            <tr>
              <th class="text-label-small col-pcr" scope="col">PCR</th>
              <th class="text-label-small col-type" scope="col">Event Type</th>
              <th class="text-label-small col-digest" scope="col">Digest</th>
              <th class="text-label-small col-data" scope="col">Event Data</th>
            </tr>
          </thead>
          <tbody>
            {#each filteredEntries as entry}
              <tr>
                <td class="text-body-small font-mono col-pcr">{entry.pcr_index}</td>
                <td class="text-body-small col-type">{entry.event_type}</td>
                <td class="text-body-small font-mono col-digest" title={entry.digest_hex}>
                  {entry.digest_hex}
                </td>
                <td class="text-body-small col-data" title={entry.event_data}>
                  {entry.event_data}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      {#if replayResult}
        <div class="replay-results">
          <div class="replay-summary" class:replay-success={replayResult.success} class:replay-failure={!replayResult.success}>
            <span class="text-title-small">
              {replayResult.success ? 'Replay Verified' : 'Replay Mismatch'}
            </span>
            <div class="replay-stats">
              <span class="text-body-small">Total: {replayResult.total_pcrs}</span>
              <span class="text-body-small replay-match">Match: {replayResult.match_count}</span>
              {#if replayResult.mismatch_count > 0}
                <span class="text-body-small replay-mismatch">Mismatch: {replayResult.mismatch_count}</span>
              {/if}
              <span class="text-body-small">Banks: {replayResult.banks.join(', ')}</span>
            </div>
          </div>

          {#if replayResult.entries.length > 0}
            <div class="replay-table-wrapper">
              <table class="event-log-table" aria-label="PCR Replay Results">
                <thead>
                  <tr>
                    <th class="text-label-small" scope="col">Bank</th>
                    <th class="text-label-small" scope="col">PCR</th>
                    <th class="text-label-small" scope="col">Expected</th>
                    <th class="text-label-small" scope="col">Actual</th>
                    <th class="text-label-small" scope="col">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {#each replayResult.entries as rEntry}
                    <tr>
                      <td class="text-body-small">{rEntry.bank}</td>
                      <td class="text-body-small font-mono">{rEntry.pcr_index}</td>
                      <td class="text-body-small font-mono replay-digest" title={rEntry.expected}>
                        {rEntry.expected}
                      </td>
                      <td class="text-body-small font-mono replay-digest" title={rEntry.actual}>
                        {rEntry.actual}
                      </td>
                      <td class="text-body-small">
                        <span class="replay-badge" class:badge-match={rEntry.match} class:badge-mismatch={!rEntry.match}>
                          {rEntry.match ? 'Match' : 'Mismatch'}
                        </span>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </div>
      {/if}
    {/if}
  </div>

  <svelte:fragment slot="actions">
    {#if entries.length > 0 && onReplay}
      <Button variant="outline" size="sm" icon={mdiShieldCheck} loading={replayLoading} on:click={handleReplay}>
        Verify Event Log
      </Button>
    {/if}
    {#if entries.length > 0}
      <Button variant="outline" size="sm" icon={mdiExport} on:click={handleExportJSON}>
        Export JSON
      </Button>
    {/if}
    <Button variant="text" on:click={() => { open = false; onClose(); }}>Close</Button>
  </svelte:fragment>
</Modal>

<style>
  .event-log-viewer {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .loading-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    padding: 32px;
  }

  .loading-text {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .empty-text {
    color: var(--color-on-surface-variant);
    text-align: center;
    padding: 32px;
    margin: 0;
  }

  .event-log-controls {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .filter-groups {
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
  }

  .filter-group {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--color-on-surface-variant);
  }

  .filter-label {
    color: var(--color-on-surface-variant);
    white-space: nowrap;
  }

  .filter-select {
    height: 32px;
    padding: 0 10px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 12px;
    outline: none;
    cursor: pointer;
  }

  .filter-select:focus {
    border-color: var(--color-primary);
  }

  .entry-count {
    color: var(--color-on-surface-variant);
    white-space: nowrap;
  }

  .event-log-table-wrapper {
    max-height: 400px;
    overflow: auto;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
  }

  .event-log-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  .event-log-table thead {
    position: sticky;
    top: 0;
    z-index: 1;
  }

  .event-log-table th {
    padding: 8px 10px;
    text-align: left;
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
    border-bottom: 1px solid var(--color-outline-variant);
    white-space: nowrap;
  }

  .event-log-table td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--color-outline-variant);
    color: var(--color-on-surface);
  }

  .event-log-table tbody tr:hover {
    background-color: var(--color-surface-container-low);
  }

  .event-log-table tbody tr:last-child td {
    border-bottom: none;
  }

  .col-pcr {
    width: 50px;
    text-align: center;
    flex-shrink: 0;
  }

  .col-type {
    width: 160px;
  }

  .col-digest {
    width: 280px;
    min-width: 0;
    word-break: break-all;
    font-size: 12px;
    line-height: 1.4;
  }

  .col-data {
    min-width: 0;
    word-break: break-all;
    font-size: 12px;
    line-height: 1.4;
  }

  .replay-results {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 4px;
  }

  .replay-summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    border-radius: var(--radius-sm);
    gap: 12px;
  }

  .replay-success {
    background-color: var(--color-success-container, rgba(76, 175, 80, 0.12));
    color: var(--color-on-success-container, #2e7d32);
  }

  .replay-failure {
    background-color: var(--color-error-container, rgba(244, 67, 54, 0.12));
    color: var(--color-on-error-container, #c62828);
  }

  .replay-stats {
    display: flex;
    gap: 16px;
    align-items: center;
  }

  .replay-match {
    color: var(--color-success, #4caf50);
  }

  .replay-mismatch {
    color: var(--color-error, #f44336);
  }

  .replay-table-wrapper {
    max-height: 200px;
    overflow: auto;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
  }

  .replay-digest {
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 12px;
  }

  .replay-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 500;
  }

  .badge-match {
    background-color: var(--color-success-container, rgba(76, 175, 80, 0.12));
    color: var(--color-success, #4caf50);
  }

  .badge-mismatch {
    background-color: var(--color-error-container, rgba(244, 67, 54, 0.12));
    color: var(--color-error, #f44336);
  }
</style>
