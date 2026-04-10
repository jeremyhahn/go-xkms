<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import PCRViewer from '$lib/components/PCRViewer.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import { mdiArrowLeft, mdiChip, mdiAlertCircle } from '$lib/utils/icons';
  import { navigateTo } from '$lib/stores/app';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend } from '$lib/api/backend';
  import type { BackendTPMInfo, BackendPCRValue } from '$lib/api/backend';

  let loading = true;
  let tpmInfo: BackendTPMInfo | null = null;
  let pcrValues: Array<{ index: number; value: string; description: string }> = [];
  let selectedPCRBank = 'sha256';
  let pcrLoading = false;

  const pcrDescriptions: Record<number, string> = {
    0: 'SRTM/BIOS/Host Platform Extensions',
    1: 'Host Platform Configuration',
    2: 'Option ROM Code',
    3: 'Option ROM Configuration and Data',
    4: 'IPL Code (Boot Loader)',
    5: 'IPL Configuration and Data',
    6: 'State Transition',
    7: 'Secure Boot State',
    8: 'OS/Kernel (Linux IMA)',
    9: 'OS/Kernel (Linux IMA)',
    10: 'OS/Kernel (Linux IMA)',
    11: 'Application Specific',
    12: 'Application Specific',
    13: 'Application Specific',
    14: 'Application Specific',
    15: 'Debug',
    16: 'Debug',
    17: 'DRTM (TXT)',
    18: 'DRTM (TXT)',
    19: 'DRTM (TXT)',
    20: 'DRTM (TXT)',
    21: 'DRTM (TXT)',
    22: 'DRTM (TXT)',
    23: 'Application Support',
  };

  function pcrDescription(index: number): string {
    return pcrDescriptions[index] || `PCR ${index}`;
  }

  async function loadPCRs(bank: string): Promise<void> {
    if (!isWailsAvailable()) return;
    pcrLoading = true;
    const result = await callBackend<BackendPCRValue[]>('TPMService', 'GetPCRs', bank);
    if (result && result.length > 0) {
      pcrValues = result.map((pcr) => ({
        index: pcr.index,
        value: pcr.digest,
        description: pcrDescription(pcr.index),
      }));
    } else {
      pcrValues = [];
    }
    pcrLoading = false;
  }

  onMount(async () => {
    if (!isWailsAvailable()) {
      loading = false;
      return;
    }
    const info = await callBackend<BackendTPMInfo>('TPMService', 'GetInfo');
    tpmInfo = info;

    if (info?.pcr_banks && info.pcr_banks.length > 0) {
      selectedPCRBank = info.pcr_banks.includes('sha256')
        ? 'sha256'
        : info.pcr_banks[0];
    }

    await loadPCRs(selectedPCRBank);
    loading = false;
  });

  function handleBankChange(bank: string): void {
    selectedPCRBank = bank;
    loadPCRs(bank);
  }

  function handleExportPCR(): void {
    const exportData = pcrValues.map((pcr) => ({
      index: pcr.index,
      bank: selectedPCRBank,
      digest: pcr.value,
      description: pcr.description,
    }));
    const json = JSON.stringify(exportData, null, 2);
    const displayBank = selectedPCRBank.toUpperCase();
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(json).then(() => {
        addNotification('success', `PCR values (${displayBank}) copied to clipboard`);
      });
    } else {
      addNotification('success', `PCR values (${displayBank}) exported`);
    }
  }

  $: hardwareDetails = tpmInfo ? [
    { label: 'Manufacturer', value: tpmInfo.manufacturer || 'Unknown' },
    { label: 'Vendor ID', value: tpmInfo.vendor_id || 'Unknown' },
    { label: 'Model', value: tpmInfo.model || 'Unknown' },
    { label: 'Firmware Version', value: tpmInfo.firmware_version || 'Unknown' },
    { label: 'Specification', value: tpmInfo.family ? `TPM ${tpmInfo.family} rev ${tpmInfo.revision}` : 'Unknown' },
    { label: 'Level', value: tpmInfo.level ? String(tpmInfo.level) : 'Unknown' },
    { label: 'Max RSA Key Size', value: tpmInfo.max_rsa_key_size ? `${tpmInfo.max_rsa_key_size} bits` : 'N/A' },
    { label: 'Max ECC Key Size', value: tpmInfo.max_ecc_key_size ? `${tpmInfo.max_ecc_key_size} bits` : 'N/A' },
    { label: 'Max NV Buffer', value: tpmInfo.max_nv_buffer_size ? `${tpmInfo.max_nv_buffer_size} bytes` : 'N/A' },
    { label: 'FIPS 140-2 Mode', value: tpmInfo.fips_mode ? 'Enabled' : 'Disabled' },
    { label: 'Lockout Counter', value: tpmInfo.lockout_counter != null ? String(tpmInfo.lockout_counter) : 'N/A' },
    { label: 'Max Auth Failures', value: tpmInfo.max_auth_fail ? String(tpmInfo.max_auth_fail) : 'N/A' },
    { label: 'Active Sessions (Max)', value: tpmInfo.active_sessions_max ? String(tpmInfo.active_sessions_max) : 'N/A' },
    { label: 'Auth Sessions (Loaded)', value: tpmInfo.auth_sessions_loaded != null ? String(tpmInfo.auth_sessions_loaded) : 'N/A' },
    { label: 'Auth Sessions (Active)', value: tpmInfo.auth_sessions_active != null ? String(tpmInfo.auth_sessions_active) : 'N/A' },
    { label: 'Persistent Keys (Loaded)', value: tpmInfo.persistent_loaded != null ? String(tpmInfo.persistent_loaded) : 'N/A' },
    { label: 'Persistent Keys (Available)', value: tpmInfo.persistent_avail != null ? String(tpmInfo.persistent_avail) : 'N/A' },
    { label: 'Transient Objects (Available)', value: tpmInfo.transient_avail != null ? String(tpmInfo.transient_avail) : 'N/A' },
    { label: 'NV Indexes (Defined)', value: tpmInfo.nv_indexes_defined != null ? String(tpmInfo.nv_indexes_defined) : 'N/A' },
    { label: 'NV Indexes (Max)', value: tpmInfo.nv_indexes_max != null ? String(tpmInfo.nv_indexes_max) : 'N/A' },
  ] : [];

  $: capabilities = tpmInfo?.capabilities ?? [];
  $: algorithms = tpmInfo?.algorithms ?? [];
</script>

<div class="tpm-info-view">
  <div class="detail-header">
    <button class="back-btn" on:click={() => navigateTo('tpm')}>
      <Icon path={mdiArrowLeft} size={20} />
      <span class="text-label-large">TPM 2.0</span>
    </button>
    <h1 class="text-headline-small detail-title">TPM Hardware Details</h1>
  </div>

  {#if loading}
    <div class="loading-container">
      <LoadingSpinner size={48} />
      <p class="text-body-medium loading-text">Loading TPM information...</p>
    </div>
  {:else if !tpmInfo}
    <div class="empty-container">
      <Icon path={mdiAlertCircle} size={48} />
      <h3 class="text-title-large empty-title">TPM Not Available</h3>
      <p class="text-body-medium empty-desc">
        Unable to retrieve TPM hardware information. The TPM may not be present or accessible on this system.
      </p>
    </div>
  {:else}
    <div class="detail-content">
      <!-- Hardware Details -->
      <Card variant="elevated">
        <div class="section">
          <h2 class="text-title-medium section-heading">
            <Icon path={mdiChip} size={20} />
            Hardware Details
          </h2>
          <div class="info-table">
            {#each hardwareDetails as item}
              <div class="info-row">
                <span class="text-label-medium info-label">{item.label}</span>
                <span class="text-body-medium info-value">{item.value}</span>
              </div>
            {/each}
          </div>
        </div>
      </Card>

      <!-- Capabilities -->
      {#if capabilities.length > 0}
        <Card variant="outlined">
          <div class="section">
            <h2 class="text-title-medium section-heading">Capabilities</h2>
            <div class="capabilities-grid">
              {#each capabilities as cap}
                <div class="capability-chip">
                  <span class="capability-check">&#10003;</span>
                  <span class="text-label-medium">{cap}</span>
                </div>
              {/each}
            </div>
          </div>
        </Card>
      {/if}

      <!-- Supported Algorithms -->
      {#if algorithms.length > 0}
        <Card variant="outlined">
          <div class="section">
            <h2 class="text-title-medium section-heading">Supported Algorithms</h2>
            <div class="algorithms-grid">
              {#each algorithms as algo}
                <div class="algorithm-chip">
                  <span class="text-label-medium">{algo}</span>
                </div>
              {/each}
            </div>
          </div>
        </Card>
      {/if}

      <!-- PCR Values -->
      {#if pcrLoading}
        <Card variant="outlined">
          <div class="pcr-loading-container">
            <LoadingSpinner size={32} />
            <p class="text-body-medium loading-text">Loading PCR values...</p>
          </div>
        </Card>
      {:else}
        <PCRViewer
          pcrs={pcrValues}
          bank={selectedPCRBank}
          onBankChange={handleBankChange}
          onExport={handleExportPCR}
        />
      {/if}
    </div>
  {/if}
</div>

<style>
  .tpm-info-view {
    min-height: 100%;
    display: flex;
    flex-direction: column;
  }

  .detail-header {
    padding: 16px 24px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
    flex-shrink: 0;
  }

  .back-btn {
    display: inline-flex; align-items: center; gap: 6px;
    border: none; background: transparent; color: var(--color-primary);
    cursor: pointer; font-family: var(--font-sans); padding: 4px 0;
    align-self: flex-start; transition: opacity var(--transition-fast);
  }
  .back-btn:hover { opacity: 0.8; }

  .detail-title { margin: 0; color: var(--color-on-surface); }

  .detail-content {
    flex: 1; padding: 24px;
    display: flex; flex-direction: column; gap: 20px; max-width: 900px;
  }

  .loading-container {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    padding: 48px;
  }

  .loading-text {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .empty-container {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 12px;
    padding: 48px;
    color: var(--color-on-surface-variant);
  }

  .empty-title {
    color: var(--color-on-surface);
    margin: 0;
  }

  .empty-desc {
    color: var(--color-on-surface-variant);
    margin: 0;
    max-width: 400px;
    text-align: center;
    line-height: 1.5;
  }

  .pcr-loading-container {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 12px;
    padding: 32px;
  }

  .section { display: flex; flex-direction: column; gap: 16px; }

  .section-heading {
    display: flex; align-items: center; gap: 8px;
    margin: 0; color: var(--color-on-surface);
  }

  .info-table { display: flex; flex-direction: column; }

  .info-row {
    display: flex; align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .info-row:last-child { border-bottom: none; }

  .info-label {
    width: 200px; flex-shrink: 0;
    color: var(--color-on-surface-variant);
  }

  .info-value { color: var(--color-on-surface); }

  .capabilities-grid {
    display: flex; flex-wrap: wrap; gap: 8px;
  }

  .capability-chip {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 6px 12px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .capability-check {
    color: var(--color-security-verified);
    font-weight: 600;
    font-size: 12px;
  }

  .algorithms-grid {
    display: flex; flex-wrap: wrap; gap: 8px;
  }

  .algorithm-chip {
    display: inline-flex; align-items: center;
    padding: 6px 14px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
    border: 1px solid var(--color-outline-variant);
  }
</style>
