<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Input from '$lib/components/Input.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import Toggle from '$lib/components/Toggle.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import PCRViewer from '$lib/components/PCRViewer.svelte';
  import QuoteDialog from '$lib/components/QuoteDialog.svelte';
  import QuoteResultDialog from '$lib/components/QuoteResultDialog.svelte';
  import CertificateViewerDialog from '$lib/components/CertificateViewerDialog.svelte';
  import TPMProvisionDialog from '$lib/components/TPMProvisionDialog.svelte';
  import TPMInstallDialog from '$lib/components/TPMInstallDialog.svelte';
  import TPMFactoryResetDialog from '$lib/components/TPMFactoryResetDialog.svelte';
  import TPMProvisionKeyDialog from '$lib/components/TPMProvisionKeyDialog.svelte';
  import EventLogViewer from '$lib/components/EventLogViewer.svelte';
  import TPMPolicyPanel from '$lib/components/TPMPolicyPanel.svelte';
  import DataTable from '$lib/components/DataTable.svelte';
  import type { Column } from '$lib/components/DataTable.svelte';
  import PlatformKeys from './PlatformKeys.svelte';
  import {
    mdiChip, mdiKey, mdiShieldCheckOutline, mdiCertificate, mdiImport,
    mdiShieldKey, mdiGauge, mdiMemory, mdiDatabaseOutline, mdiTune,
    mdiLockOutline, mdiAccount, mdiShieldOutline, mdiFormatListBulleted,
    mdiPlus, mdiDelete, mdiRefresh, mdiPencil, mdiAlert, mdiDeleteSweep,
    mdiConsoleLine, mdiChartBellCurveCumulative, mdiCog, mdiUpload
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend, callBackendVoid, callBackendWithError } from '$lib/api/backend';
  import type {
    BackendTPMStatus, BackendTPMInfo, BackendEKInfo, BackendEKECCInfo,
    BackendIAKInfo, BackendIDevIDInfo, BackendSharedSRKInfo, BackendPCRValue,
    BackendQuote, BackendEventLogEntry, HandleInfo, LockoutInfo,
    NVSummary, VerificationStatus, KeyViewData, BackendCertifyKeyResult,
    EventLogReplayResult,
  } from '$lib/api/backend';

  type TPMCategory = 'overview' | 'platform' | 'measurements' | 'key-handles'
    | 'nv-storage' | 'policies' | 'attestation' | 'lockout' | 'authorization' | 'verification';

  const tpmCategories: Array<{ id: TPMCategory; label: string; icon: string }> = [
    { id: 'overview', label: 'Overview', icon: mdiGauge },
    { id: 'platform', label: 'Platform Keys', icon: mdiShieldCheckOutline },
    { id: 'measurements', label: 'Measurements', icon: mdiMemory },
    { id: 'key-handles', label: 'Key Handles', icon: mdiFormatListBulleted },
    { id: 'nv-storage', label: 'NV Storage', icon: mdiDatabaseOutline },
    { id: 'policies', label: 'Policies', icon: mdiTune },
    { id: 'attestation', label: 'Attestation', icon: mdiShieldCheckOutline },
    { id: 'lockout', label: 'Lockout', icon: mdiLockOutline },
    { id: 'authorization', label: 'Authorization', icon: mdiAccount },
    { id: 'verification', label: 'Verification', icon: mdiShieldOutline },
  ];

  let activeCategory: TPMCategory = 'overview';
  let loading = true;

  // Dialog state
  let showQuoteDialog = false;
  let showQuoteResult = false;
  let showCertViewer = false;
  let showProvisionDialog = false;
  let showInstallDialog = false;
  let showFactoryResetDialog = false;
  let showProvisionKeyDialog = false;
  let provisionKeyType: 'IAK' | 'IDevID' = 'IAK';
  let showEventLog = false;

  let quoteResult: BackendQuote | null = null;
  let certViewerPEM = '';
  let certViewerTitle = '';
  let eventLogEntries: BackendEventLogEntry[] = [];
  let eventLogLoading = false;

  // TPM data
  let tpmStatus: BackendTPMStatus | null = null;
  let tpmInfo: BackendTPMInfo | null = null;
  let ekInfo: BackendEKInfo | null = null;
  let ekECCInfo: BackendEKECCInfo | null = null;
  let iakInfo: BackendIAKInfo | null = null;
  let idevidInfo: BackendIDevIDInfo | null = null;
  let sharedSrkInfo: BackendSharedSRKInfo | null = null;

  // Measurements state
  let pcrValues: Array<{ index: number; value: string; description: string }> = [];
  let selectedPCRBank = 'sha256';
  let pcrLoading = false;
  let pcrLoadAttempted = false;

  // Key handles state
  let persistentHandles: HandleInfo[] = [];
  let transientHandles: HandleInfo[] = [];
  let handlesLoading = false;
  let handleTab: 'persistent' | 'transient' = 'persistent';
  let editingHandle: string | null = null;
  let editDescription = '';

  // NV Storage state
  let nvSummary: NVSummary | null = null;
  let nvLoading = false;
  let showNVCreateDialog = false;
  let nvCreateType = 'ordinary';
  let nvCreateHandle = '';
  let nvCreateSize = 32;
  let nvCreateAuthRead = true;
  let nvCreateAuthWrite = true;
  let nvCreating = false;
  let nvReadData = '';
  let showNVReadDialog = false;
  let nvReadHandle = '';
  let nvWriteData = '';
  let showNVWriteDialog = false;
  let nvWriteHandle = '';

  // Lockout state
  let lockoutInfo: LockoutInfo | null = null;
  let lockoutLoading = false;
  let lockoutResetAuth = '';
  let lockoutResetting = false;
  let showForceResetLockoutConfirm = false;
  let forceResetLockoutConfirmed = false;
  let forceResetLockoutAuth = '';
  let forceResettingLockout = false;

  // Key View dialog state
  let showKeyViewDialog = false;
  let keyViewData: KeyViewData | null = null;
  let keyViewLoading = false;

  // Certify Key dialog state
  let showCertifyDialog = false;
  let certifyResult: BackendCertifyKeyResult | null = null;
  let certifyKeyHandle = '';

  // Commands filter state
  let commandsFilter = '';

  // Properties filter state
  let fixedPropsFilter = '';
  let varPropsFilter = '';
  let showFixedProps = false;
  let showVariableProps = false;

  // CSR generation state
  let csrData = '';
  let showCSRDialog = false;
  let csrGenerating = false;

  // Authorization state
  let ownerOldAuth = '';
  let ownerNewAuth = '';
  let ownerConfirmAuth = '';
  let endorsementOldAuth = '';
  let endorsementNewAuth = '';
  let endorsementConfirmAuth = '';
  let lockoutOldAuth = '';
  let lockoutNewAuth = '';
  let lockoutConfirmAuth = '';
  let authChanging = false;

  // Verification state
  let verificationStatus: VerificationStatus | null = null;
  let verificationLoading = false;
  let caPEM = '';
  let caImporting = false;
  let caFileInput: HTMLInputElement;

  // Provision mode
  let showProvisionModeDialog = false;
  let provisionMode: 'install' | 'provision' = 'provision';
  let installOwnerAuth = '';
  let provisionOwnerAuth = '';
  let provisionLockoutAuth = '';
  let provisionEKCertPEM = '';

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

  $: tpmDisplay = {
    available: tpmStatus?.available ?? false,
    deviceExists: tpmStatus?.device_exists ?? false,
    manufacturer: (tpmStatus?.manufacturer || tpmInfo?.manufacturer || '').trim(),
    model: (tpmInfo?.model || tpmInfo?.vendor_id || '').trim(),
    firmwareVersion: (tpmStatus?.firmware_version || tpmInfo?.firmware_version || '').trim(),
    specVersion: tpmInfo?.family ? `TPM ${tpmInfo.family.trim()}` : '',
    provisioned: tpmStatus?.provisioned ?? false,
    devicePath: tpmStatus?.device_path || '',
  };

  $: statusLevel = tpmStatus?.status_level || 'none';

  $: provisioningBadgeStatus = (() => {
    switch (statusLevel) {
      case 'device_identity': return 'verified' as const;
      case 'owner': return 'connected' as const;
      case 'manufacturer': return 'warning' as const;
      default: return 'neutral' as const;
    }
  })();

  $: provisioningLabel = (() => {
    switch (statusLevel) {
      case 'device_identity': return 'Device Identity';
      case 'owner': return 'Owner Provisioned';
      case 'manufacturer': return 'Manufacturer Default';
      default: return 'Not Provisioned';
    }
  })();

  $: identityKeys = [
    {
      name: 'Endorsement Key (EK-RSA)',
      provisioned: ekInfo?.present ?? false,
      type: ekInfo?.present
        ? ekInfo.key_size > 0
          ? `${ekInfo.algorithm} ${ekInfo.key_size}`
          : ekInfo.algorithm
        : 'N/A',
      hasCert: !!(ekInfo?.certificate),
      certExportMethod: 'ExportEKCert' as const,
      certImportMethod: 'ImportEKCert' as const,
    },
    {
      name: 'Endorsement Key (EK-ECC)',
      provisioned: ekECCInfo?.present ?? false,
      type: ekECCInfo?.present
        ? ekECCInfo.key_size > 0
          ? `${ekECCInfo.algorithm} ${ekECCInfo.key_size}`
          : ekECCInfo.algorithm
        : 'N/A',
      hasCert: !!(ekECCInfo?.certificate),
      certExportMethod: 'ExportEKECCCert' as const,
      certImportMethod: 'ImportEKECCCert' as const,
    },
    {
      name: 'Initial Attestation Key (IAK)',
      provisioned: iakInfo?.present ?? false,
      type: iakInfo?.present
        ? iakInfo.key_size > 0
          ? `${iakInfo.algorithm} ${iakInfo.key_size}`
          : iakInfo.algorithm
        : 'N/A',
      hasCert: !!(iakInfo?.certificate),
      certExportMethod: 'ExportIAKCert' as const,
      certImportMethod: 'ImportIAKCert' as const,
    },
    {
      name: 'Initial Device ID (IDevID)',
      provisioned: idevidInfo?.present ?? false,
      type: idevidInfo?.present
        ? idevidInfo.key_size > 0
          ? `${idevidInfo.algorithm} ${idevidInfo.key_size}`
          : idevidInfo.algorithm
        : 'N/A',
      hasCert: !!(idevidInfo?.certificate),
      certExportMethod: 'ExportIDevIDCert' as const,
      certImportMethod: 'ImportIDevIDCert' as const,
    },
  ];

  $: srkDisplay = sharedSrkInfo
    ? { present: sharedSrkInfo.present, algorithm: sharedSrkInfo.algorithm }
    : { present: false, algorithm: 'N/A' };

  $: isFullyProvisioned = (sharedSrkInfo?.present ?? false) && (iakInfo?.present ?? false) && (idevidInfo?.present ?? false);

  $: filteredCommands = (tpmInfo?.commands ?? []).filter((cmd: { code: string; name: string; description: string }) => {
    if (!commandsFilter) return true;
    const q = commandsFilter.toLowerCase();
    return cmd.code.toLowerCase().includes(q) ||
           cmd.name.toLowerCase().includes(q) ||
           cmd.description.toLowerCase().includes(q);
  });

  $: filteredFixedProps = (tpmInfo?.fixed_properties ?? []).filter((p: { name: string; raw: string; value: string }) => {
    if (!fixedPropsFilter) return true;
    const q = fixedPropsFilter.toLowerCase();
    return p.name.toLowerCase().includes(q) || p.raw.toLowerCase().includes(q) || p.value.toLowerCase().includes(q);
  });

  $: filteredVarProps = (tpmInfo?.variable_properties ?? []).filter((p: { name: string; raw: string; value: string }) => {
    if (!varPropsFilter) return true;
    const q = varPropsFilter.toLowerCase();
    return p.name.toLowerCase().includes(q) || p.raw.toLowerCase().includes(q) || p.value.toLowerCase().includes(q);
  });

  // Lazy-load data per category
  $: if (activeCategory === 'measurements' && isWailsAvailable() && pcrValues.length === 0 && !pcrLoading && !pcrLoadAttempted) {
    loadPCRs(selectedPCRBank);
  }

  $: if (activeCategory === 'key-handles' && isWailsAvailable() && persistentHandles.length === 0 && !handlesLoading) {
    loadHandles();
  }

  $: if (activeCategory === 'nv-storage' && isWailsAvailable() && !nvSummary && !nvLoading) {
    loadNVSummary();
  }

  $: if (activeCategory === 'lockout' && isWailsAvailable() && !lockoutInfo && !lockoutLoading) {
    loadLockoutInfo();
  }

  $: if (activeCategory === 'verification' && isWailsAvailable() && !verificationStatus && !verificationLoading) {
    // Verification is loaded on-demand via button
  }

  onMount(async () => {
    if (!isWailsAvailable()) {
      loading = false;
      return;
    }

    try {
      const results = await Promise.allSettled([
        callBackend<BackendTPMStatus>('TPMService', 'GetStatus'),
        callBackend<BackendTPMInfo>('TPMService', 'GetInfo'),
        callBackend<BackendEKInfo>('TPMService', 'GetEKInfo'),
        callBackend<BackendEKECCInfo>('TPMService', 'GetEKECCInfo'),
        callBackend<BackendIAKInfo>('TPMService', 'GetIAKInfo'),
        callBackend<BackendIDevIDInfo>('TPMService', 'GetIDevIDInfo'),
        callBackend<BackendSharedSRKInfo>('TPMService', 'GetSharedSRKInfo'),
      ]);

      tpmStatus = results[0].status === 'fulfilled' ? results[0].value : null;
      tpmInfo = results[1].status === 'fulfilled' ? results[1].value : null;
      ekInfo = results[2].status === 'fulfilled' ? results[2].value : null;
      ekECCInfo = results[3].status === 'fulfilled' ? results[3].value : null;
      iakInfo = results[4].status === 'fulfilled' ? results[4].value : null;
      idevidInfo = results[5].status === 'fulfilled' ? results[5].value : null;
      sharedSrkInfo = results[6].status === 'fulfilled' ? results[6].value : null;

      if (tpmInfo?.pcr_banks && tpmInfo.pcr_banks.length > 0) {
        selectedPCRBank = tpmInfo.pcr_banks.includes('sha256')
          ? 'sha256'
          : tpmInfo.pcr_banks[0];
      }
    } catch (err) {
      console.error('Failed to load TPM data:', err);
      addNotification('error', 'Failed to load TPM information');
    }

    loading = false;
  });

  // --- PCR / Measurements ---
  function pcrDescription(index: number): string {
    return pcrDescriptions[index] || `PCR ${index}`;
  }

  async function loadPCRs(bank: string): Promise<void> {
    if (!isWailsAvailable()) return;
    pcrLoading = true;
    pcrLoadAttempted = true;
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

  function handleBankChange(bank: string): void {
    selectedPCRBank = bank;
    pcrLoadAttempted = false;
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
    }
  }

  // --- Identity Keys ---
  function handleViewCert(keyName: string): void {
    let certPEM = '';
    if (keyName.includes('EK-ECC')) {
      certPEM = ekECCInfo?.certificate ?? '';
    } else if (keyName.includes('EK')) {
      certPEM = ekInfo?.certificate ?? '';
    } else if (keyName.includes('IAK')) {
      certPEM = iakInfo?.certificate ?? '';
    } else if (keyName.includes('IDevID')) {
      certPEM = idevidInfo?.certificate ?? '';
    }
    if (certPEM) {
      certViewerPEM = certPEM;
      certViewerTitle = `${keyName} Certificate`;
      showCertViewer = true;
    } else {
      addNotification('warning', `No certificate available for ${keyName}`);
    }
  }

  async function handleViewKey(keyName: string): Promise<void> {
    keyViewLoading = true;
    keyViewData = await callBackend<KeyViewData>('TPMService', 'ViewKey', keyName);
    keyViewLoading = false;
    if (keyViewData) {
      showKeyViewDialog = true;
    } else {
      addNotification('error', `Failed to load ${keyName} details`);
    }
  }

  async function copyToClipboard(text: string, label: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      addNotification('success', `${label} copied to clipboard`);
    } catch {
      addNotification('error', 'Failed to copy to clipboard');
    }
  }

  async function handleExportCert(method: string, keyName: string): Promise<void> {
    const result = await callBackend<string>('TPMService', method, 'PEM');
    if (result) {
      if (typeof navigator !== 'undefined' && navigator.clipboard) {
        await navigator.clipboard.writeText(result);
        addNotification('success', `${keyName} certificate copied to clipboard`);
      }
    } else {
      addNotification('error', `Failed to export ${keyName} certificate`);
    }
  }

  async function handleImportCert(method: string, keyName: string): Promise<void> {
    if (typeof navigator === 'undefined' || !navigator.clipboard) {
      addNotification('error', 'Clipboard API not available');
      return;
    }
    try {
      const certPEM = await navigator.clipboard.readText();
      if (!certPEM.includes('BEGIN CERTIFICATE')) {
        addNotification('error', 'Clipboard does not contain a valid PEM certificate');
        return;
      }
      const ok = await callBackendVoid('TPMService', method, certPEM);
      if (ok) {
        addNotification('success', `${keyName} certificate imported successfully`);
        if (method === 'ImportEKCert') {
          ekInfo = await callBackend<BackendEKInfo>('TPMService', 'GetEKInfo');
        } else if (method === 'ImportEKECCCert') {
          ekECCInfo = await callBackend<BackendEKECCInfo>('TPMService', 'GetEKECCInfo');
        } else if (method === 'ImportIAKCert') {
          iakInfo = await callBackend<BackendIAKInfo>('TPMService', 'GetIAKInfo');
        } else if (method === 'ImportIDevIDCert') {
          idevidInfo = await callBackend<BackendIDevIDInfo>('TPMService', 'GetIDevIDInfo');
        }
      } else {
        addNotification('error', `Failed to import ${keyName} certificate`);
      }
    } catch {
      addNotification('error', 'Failed to read from clipboard');
    }
  }

  // --- Attestation ---
  async function handleGenerateQuote(data: { pcrSelection: number[]; bank: string; nonce: string }): Promise<void> {
    const result = await callBackend<BackendQuote>(
      'TPMService', 'GenerateQuote', data.nonce, data.pcrSelection, data.bank
    );
    if (result) {
      quoteResult = result;
      showQuoteResult = true;
      addNotification('success', `Quote generated for PCRs [${data.pcrSelection.join(',')}] using ${data.bank}`);
    } else {
      addNotification('error', 'Failed to generate TPM quote');
    }
  }

  async function handleReplayEventLog(): Promise<EventLogReplayResult | null> {
    return callBackend<EventLogReplayResult>('TPMService', 'ReplayEventLog');
  }

  async function handleViewEventLog(): Promise<void> {
    eventLogLoading = true;
    showEventLog = true;
    const result = await callBackend<BackendEventLogEntry[]>('TPMService', 'GetEventLog');
    eventLogEntries = result ?? [];
    eventLogLoading = false;
  }

  async function handleCertifyKey(): Promise<void> {
    if (!certifyKeyHandle) {
      addNotification('error', 'Please enter a key handle to certify');
      return;
    }
    const result = await callBackend<BackendCertifyKeyResult>('TPMService', 'CertifyKey', certifyKeyHandle);
    if (result) {
      certifyResult = result;
      showCertifyDialog = true;
    } else {
      addNotification('error', 'Failed to certify key');
    }
  }

  async function handleGenerateCSR(): Promise<void> {
    // Precondition checks
    if (!ekInfo?.certificate) {
      addNotification('error', 'EK certificate is required to generate an IDevID CSR');
      return;
    }
    if (!iakInfo?.present) {
      addNotification('error', 'IAK must be provisioned before generating an IDevID CSR');
      return;
    }
    if (!idevidInfo?.present) {
      addNotification('error', 'IDevID must be provisioned before generating a CSR');
      return;
    }

    csrGenerating = true;
    const { result, error } = await callBackendWithError<string>('TPMService', 'GenerateIDevIDCSR');
    csrGenerating = false;
    if (result) {
      csrData = result;
      showCSRDialog = true;
    } else {
      addNotification('error', error || 'Failed to generate IDevID CSR');
    }
  }

  // --- Key Handles ---
  async function loadHandles(): Promise<void> {
    handlesLoading = true;
    const [persistent, transient] = await Promise.all([
      callBackend<HandleInfo[]>('TPMService', 'ListPersistentHandles'),
      callBackend<HandleInfo[]>('TPMService', 'ListTransientHandles'),
    ]);
    persistentHandles = persistent ?? [];
    transientHandles = transient ?? [];
    handlesLoading = false;
  }

  function startEditDescription(handle: string, currentDesc: string): void {
    editingHandle = handle;
    editDescription = currentDesc;
  }

  async function saveDescription(handle: string): Promise<void> {
    await callBackend('TPMService', 'SetHandleDescription', handle, editDescription);
    editingHandle = null;
    addNotification('success', 'Handle description updated');
    loadHandles();
  }

  function cancelEdit(): void {
    editingHandle = null;
    editDescription = '';
  }

  // --- NV Storage ---
  async function loadNVSummary(): Promise<void> {
    nvLoading = true;
    const result = await callBackend<NVSummary>('TPMService', 'GetNVSummary');
    nvSummary = result;
    nvLoading = false;
  }

  async function handleNVCreate(): Promise<void> {
    nvCreating = true;
    const handle = parseInt(nvCreateHandle, 16) || parseInt(nvCreateHandle, 10) || 0;
    let ok = false;
    if (nvCreateType === 'counter') {
      ok = await callBackendVoid('TPMService', 'DefineNVCounter', handle, '');
    } else if (nvCreateType === 'extend') {
      ok = await callBackendVoid('TPMService', 'DefineNVExtend', handle, '');
    } else {
      ok = await callBackendVoid('TPMService', 'DefineNVOrdinary', handle, nvCreateSize, '');
    }
    nvCreating = false;
    if (ok) {
      addNotification('success', 'NV index created');
      showNVCreateDialog = false;
      nvSummary = null;
      loadNVSummary();
    } else {
      addNotification('error', 'Failed to create NV index');
    }
  }

  async function handleNVRead(handle: string, nvType: string, size: number = 0): Promise<void> {
    nvReadHandle = handle;
    const h = parseInt(handle, 16) || parseInt(handle, 10) || 0;

    if (nvType === 'counter') {
      const { result, error } = await callBackendWithError<number>('TPMService', 'ReadNVCounter', h, '');
      if (error) {
        addNotification('error', `Failed to read NV counter: ${error}`);
        return;
      }
      nvReadData = result !== null ? String(result) : '0';
    } else if (nvType === 'extend') {
      const { result, error } = await callBackendWithError<string>('TPMService', 'ReadNVExtend', h, '');
      if (error) {
        addNotification('error', `Failed to read NV extend digest: ${error}`);
        return;
      }
      nvReadData = result ?? '';
    } else {
      const { result, error } = await callBackendWithError<string>('TPMService', 'ReadNVData', h, size, '');
      if (error) {
        addNotification('error', `Failed to read NV data: ${error}`);
        return;
      }
      nvReadData = result ?? '';
    }
    showNVReadDialog = true;
  }

  function openNVWrite(handle: string): void {
    nvWriteHandle = handle;
    nvWriteData = '';
    showNVWriteDialog = true;
  }

  async function handleNVWrite(): Promise<void> {
    const h = parseInt(nvWriteHandle, 16) || parseInt(nvWriteHandle, 10) || 0;
    const ok = await callBackendVoid('TPMService', 'WriteNVData', h, nvWriteData, '');
    if (ok) {
      addNotification('success', `NV index ${nvWriteHandle} written`);
      showNVWriteDialog = false;
    } else {
      addNotification('error', 'Failed to write NV index');
    }
  }

  async function handleNVIncrement(handle: string): Promise<void> {
    const h = parseInt(handle, 16) || parseInt(handle, 10) || 0;
    const ok = await callBackendVoid('TPMService', 'IncrementNVCounter', h, '');
    if (ok) {
      addNotification('success', `NV counter ${handle} incremented`);
      nvSummary = null;
      loadNVSummary();
    } else {
      addNotification('error', 'Failed to increment NV counter');
    }
  }

  async function handleNVExtend(handle: string): Promise<void> {
    const h = parseInt(handle, 16) || parseInt(handle, 10) || 0;
    const ok = await callBackendVoid('TPMService', 'ExtendNV', h, '', '');
    if (ok) {
      addNotification('success', `NV index ${handle} extended`);
    } else {
      addNotification('error', 'Failed to extend NV index');
    }
  }

  async function handleNVDelete(handle: string): Promise<void> {
    const h = parseInt(handle, 16) || parseInt(handle, 10) || 0;
    const ok = await callBackendVoid('TPMService', 'DeleteNVIndex', h, '');
    if (ok) {
      addNotification('success', `NV index ${handle} deleted`);
      nvSummary = null;
      loadNVSummary();
    } else {
      addNotification('error', 'Failed to delete NV index');
    }
  }

  // --- Lockout ---
  async function loadLockoutInfo(): Promise<void> {
    lockoutLoading = true;
    const result = await callBackend<LockoutInfo>('TPMService', 'GetLockoutInfo');
    lockoutInfo = result;
    lockoutLoading = false;
  }

  async function handleResetLockout(): Promise<void> {
    lockoutResetting = true;
    const ok = await callBackendVoid('TPMService', 'ResetLockout', lockoutResetAuth);
    lockoutResetting = false;
    if (ok) {
      addNotification('success', 'Lockout counter reset');
      lockoutResetAuth = '';
      lockoutInfo = null;
      loadLockoutInfo();
    } else {
      addNotification('error', 'Failed to reset lockout');
    }
  }

  async function handleForceResetLockout(): Promise<void> {
    forceResettingLockout = true;
    const ok = await callBackendVoid('TPMService', 'ForceResetLockout', forceResetLockoutAuth);
    forceResettingLockout = false;
    showForceResetLockoutConfirm = false;
    forceResetLockoutConfirmed = false;
    forceResetLockoutAuth = '';
    if (ok) {
      addNotification('success', 'Lockout counter reset successfully');
      lockoutInfo = null;
      loadLockoutInfo();
    } else {
      addNotification('error', 'Failed to reset lockout counter');
    }
  }

  // --- Authorization ---
  async function handleChangeOwnerAuth(): Promise<void> {
    if (ownerNewAuth !== ownerConfirmAuth) {
      addNotification('error', 'New passwords do not match');
      return;
    }
    authChanging = true;
    const ok = await callBackendVoid('TPMService', 'ChangeOwnerAuth', ownerOldAuth, ownerNewAuth);
    authChanging = false;
    if (ok) {
      addNotification('success', 'Owner authorization changed');
      ownerOldAuth = '';
      ownerNewAuth = '';
      ownerConfirmAuth = '';
    } else {
      addNotification('error', 'Failed to change owner authorization');
    }
  }

  async function handleChangeEndorsementAuth(): Promise<void> {
    if (endorsementNewAuth !== endorsementConfirmAuth) {
      addNotification('error', 'New passwords do not match');
      return;
    }
    authChanging = true;
    const ok = await callBackendVoid('TPMService', 'ChangeEndorsementAuth', endorsementOldAuth, endorsementNewAuth);
    authChanging = false;
    if (ok) {
      addNotification('success', 'Endorsement authorization changed');
      endorsementOldAuth = '';
      endorsementNewAuth = '';
      endorsementConfirmAuth = '';
    } else {
      addNotification('error', 'Failed to change endorsement authorization');
    }
  }

  async function handleChangeLockoutAuth(): Promise<void> {
    if (lockoutNewAuth !== lockoutConfirmAuth) {
      addNotification('error', 'New passwords do not match');
      return;
    }
    authChanging = true;
    const ok = await callBackendVoid('TPMService', 'ChangeLockoutAuth', lockoutOldAuth, lockoutNewAuth);
    authChanging = false;
    if (ok) {
      addNotification('success', 'Lockout authorization changed');
      lockoutOldAuth = '';
      lockoutNewAuth = '';
      lockoutConfirmAuth = '';
    } else {
      addNotification('error', 'Failed to change lockout authorization');
    }
  }

  // --- Verification ---
  async function handleCACertFileSelect(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    try {
      const lowerName = file.name.toLowerCase();
      if (lowerName.endsWith('.der') || (lowerName.endsWith('.cer') && !lowerName.endsWith('.pem'))) {
        // DER binary format - read as ArrayBuffer, base64 encode, and wrap as PEM
        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);
        // Check if it looks like PEM text (starts with '-----')
        const firstBytes = String.fromCharCode(...bytes.slice(0, 10));
        if (firstBytes.startsWith('-----')) {
          // Actually PEM text despite .cer/.der extension
          const decoder = new TextDecoder();
          caPEM = decoder.decode(bytes);
          addNotification('info', `Loaded PEM certificate from ${file.name}`);
        } else {
          let binary = '';
          for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
          }
          const base64 = btoa(binary);
          // Format as PEM with 64-char line wrapping
          const lines = base64.match(/.{1,64}/g) || [];
          caPEM = '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----\n';
          addNotification('info', `Loaded DER certificate from ${file.name}`);
        }
      } else {
        // PEM text format - read as text
        const text = await file.text();
        caPEM = text;
        addNotification('info', `Loaded PEM certificate from ${file.name}`);
      }
    } catch (err) {
      addNotification('error', `Failed to read certificate file: ${err}`);
    }
    // Reset file input so same file can be re-selected
    input.value = '';
  }

  async function handleImportCA(): Promise<void> {
    if (!caPEM.trim()) {
      addNotification('error', 'PEM certificate data is required');
      return;
    }
    caImporting = true;
    const ok = await callBackendVoid('TPMService', 'ImportManufacturerCA', caPEM);
    caImporting = false;
    if (ok) {
      addNotification('success', 'CA certificate imported');
      caPEM = '';
    } else {
      addNotification('error', 'Failed to import CA certificate');
    }
  }

  async function handleVerifyTPM(): Promise<void> {
    verificationLoading = true;
    const result = await callBackend<VerificationStatus>('TPMService', 'VerifyTPM');
    verificationStatus = result;
    verificationLoading = false;
    if (result) {
      if (result.status === 'verified') {
        addNotification('success', 'TPM verification passed');
      } else {
        addNotification('error', result.error || 'TPM verification failed');
      }
    }
  }

  // --- Provisioning ---
  function handleProvisionComplete(): void {
    showProvisionDialog = false;
    if (isWailsAvailable()) {
      Promise.allSettled([
        callBackend<BackendTPMStatus>('TPMService', 'GetStatus'),
        callBackend<BackendEKInfo>('TPMService', 'GetEKInfo'),
        callBackend<BackendEKECCInfo>('TPMService', 'GetEKECCInfo'),
        callBackend<BackendIAKInfo>('TPMService', 'GetIAKInfo'),
        callBackend<BackendIDevIDInfo>('TPMService', 'GetIDevIDInfo'),
        callBackend<BackendSharedSRKInfo>('TPMService', 'GetSharedSRKInfo'),
      ]).then((results) => {
        tpmStatus = results[0].status === 'fulfilled' ? results[0].value : tpmStatus;
        ekInfo = results[1].status === 'fulfilled' ? results[1].value : ekInfo;
        ekECCInfo = results[2].status === 'fulfilled' ? results[2].value : ekECCInfo;
        iakInfo = results[3].status === 'fulfilled' ? results[3].value : iakInfo;
        idevidInfo = results[4].status === 'fulfilled' ? results[4].value : idevidInfo;
        sharedSrkInfo = results[5].status === 'fulfilled' ? results[5].value : sharedSrkInfo;
      });
    }
  }
</script>

<div class="tpm-view">
  <GradientHeader title="TPM 2.0" subtitle="Trusted Platform Module management" />

  {#if loading}
    <div class="loading-container">
      <LoadingSpinner size={48} />
      <p class="text-body-medium loading-text">Loading TPM status...</p>
    </div>
  {:else}
    <div class="tpm-layout">
      <!-- Category Sidebar -->
      <nav class="tpm-nav">
        {#each tpmCategories as cat}
          <button
            class="tpm-nav-item"
            class:nav-active={activeCategory === cat.id}
            on:click={() => (activeCategory = cat.id)}
          >
            <Icon path={cat.icon} size={20} />
            <span class="text-label-large">{cat.label}</span>
          </button>
        {/each}
      </nav>

      <!-- Content Panel -->
      <div class="tpm-panel">

        {#if activeCategory === 'overview'}
          <!-- TPM Hardware Overview -->
          <Card variant="security">
            <div class="section">
              <div class="tpm-hardware-header">
                <div class="tpm-icon">
                  <Icon path={mdiChip} size={32} color="#FFFFFF" />
                </div>
                <div class="tpm-hw-info">
                  <h2 class="text-title-large">TPM Hardware</h2>
                  <StatusBadge status={tpmDisplay.available ? 'connected' : 'error'} />
                </div>
              </div>

              <!-- Hardware Identification -->
              <h3 class="text-title-small overview-subheading">Hardware Identification</h3>
              <div class="tpm-details-grid">
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Manufacturer</span>
                  <span class="text-body-medium">{tpmDisplay.manufacturer || 'Unknown'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Model</span>
                  <span class="text-body-medium">{tpmDisplay.model || 'Unknown'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Vendor ID</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.vendor_id || 'Unknown'}</span>
                </div>
                {#if tpmInfo?.manufacturer}
                  <div class="tpm-detail">
                    <span class="text-label-small field-label">Manufacturer ID</span>
                    <span class="text-body-medium font-mono">{tpmInfo.manufacturer}</span>
                  </div>
                {/if}
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Firmware Version</span>
                  <span class="text-body-medium font-mono">{tpmDisplay.firmwareVersion || 'Unknown'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Specification Family</span>
                  <span class="text-body-medium">{tpmDisplay.specVersion || 'Unknown'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Specification Level</span>
                  <span class="text-body-medium">{tpmInfo?.level ?? 'N/A'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Specification Revision</span>
                  <span class="text-body-medium">{tpmInfo?.revision ?? 'N/A'}</span>
                </div>
                {#if tpmInfo?.firmware_version}
                  <div class="tpm-detail">
                    <span class="text-label-small field-label">TPM Version</span>
                    <span class="text-body-medium font-mono">{tpmInfo.firmware_version}</span>
                  </div>
                {/if}
                {#if tpmDisplay.devicePath}
                  <div class="tpm-detail">
                    <span class="text-label-small field-label">Device Path</span>
                    <span class="text-body-medium font-mono">{tpmDisplay.devicePath}</span>
                  </div>
                {/if}
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Provisioning Status</span>
                  <span class="text-body-medium">{provisioningLabel}</span>
                </div>
              </div>

              <!-- Cryptographic Capabilities -->
              <h3 class="text-title-small overview-subheading">Cryptographic Capabilities</h3>
              <div class="tpm-details-grid">
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Max RSA Key Size</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.max_rsa_key_size ? `${tpmInfo.max_rsa_key_size.toLocaleString()} bits` : 'N/A'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Max ECC Key Size</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.max_ecc_key_size ? `${tpmInfo.max_ecc_key_size.toLocaleString()} bits` : 'N/A'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">FIPS 140-2 Mode</span>
                  <StatusBadge status={tpmInfo?.fips_mode ? 'verified' : 'neutral'} />
                </div>
              </div>

              <!-- Resource Utilization -->
              <h3 class="text-title-small overview-subheading">Resource Utilization</h3>
              <div class="tpm-details-grid">
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Max NV Buffer Size</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.max_nv_buffer_size ? `${tpmInfo.max_nv_buffer_size.toLocaleString()} bytes` : 'N/A'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">NV Indexes</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.nv_indexes_defined ?? 'N/A'} / {tpmInfo?.nv_indexes_max ?? 'N/A'} defined</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Persistent Keys</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.persistent_loaded ?? 'N/A'} loaded, {tpmInfo?.persistent_avail ?? 'N/A'} available</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Transient Keys Available</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.transient_avail ?? 'N/A'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Max Active Sessions</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.active_sessions_max ?? 'N/A'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Auth Sessions</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.auth_sessions_loaded ?? 'N/A'} loaded, {tpmInfo?.auth_sessions_active ?? 'N/A'} active</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Input Buffer Max</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.input_buffer_max ?? 'N/A'} bytes</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Max Digest Size</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.max_digest_size ?? 'N/A'} bytes</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Max Object Context</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.max_object_context ?? 'N/A'} bytes</span>
                </div>
              </div>

              <!-- Security State -->
              <h3 class="text-title-small overview-subheading">Security State</h3>
              <div class="tpm-details-grid">
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Lockout Counter</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.lockout_counter ?? 'N/A'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Max Auth Failures</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.max_auth_fail ?? 'N/A'}</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Lockout Interval</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.lockout_interval ?? 'N/A'}s</span>
                </div>
                <div class="tpm-detail">
                  <span class="text-label-small field-label">Lockout Recovery</span>
                  <span class="text-body-medium font-mono">{tpmInfo?.lockout_recovery ?? 'N/A'}s</span>
                </div>
              </div>
            </div>
          </Card>

          <!-- Supported Algorithms -->
          {#if tpmInfo?.algorithms && tpmInfo.algorithms.length > 0}
            <Card variant="outlined">
              <div class="section">
                <h2 class="text-title-medium section-heading">
                  <Icon path={mdiShieldCheckOutline} size={20} />
                  Supported Algorithms
                </h2>
                <div class="overview-chips-grid">
                  {#each tpmInfo.algorithms as algo}
                    <div class="algorithm-chip">
                      <span class="text-label-medium">{algo}</span>
                    </div>
                  {/each}
                </div>
              </div>
            </Card>
          {/if}

          <!-- Capabilities -->
          {#if tpmInfo?.capabilities && tpmInfo.capabilities.length > 0}
            <Card variant="outlined">
              <div class="section">
                <h2 class="text-title-medium section-heading">
                  <Icon path={mdiTune} size={20} />
                  Capabilities
                </h2>
                <div class="overview-chips-grid">
                  {#each tpmInfo.capabilities as cap}
                    <div class="capability-chip">
                      <span class="capability-check">&#10003;</span>
                      <span class="text-label-medium">{cap}</span>
                    </div>
                  {/each}
                </div>
              </div>
            </Card>
          {/if}

          <!-- PCR Banks -->
          {#if tpmInfo?.pcr_banks && tpmInfo.pcr_banks.length > 0}
            <Card variant="outlined">
              <div class="section">
                <h2 class="text-title-medium section-heading">
                  <Icon path={mdiMemory} size={20} />
                  PCR Banks
                </h2>
                <div class="overview-chips-grid">
                  {#each tpmInfo.pcr_banks as bank}
                    <div class="pcr-bank-chip">
                      <span class="text-label-medium font-mono">{bank}</span>
                    </div>
                  {/each}
                </div>
              </div>
            </Card>
          {/if}

          <!-- Supported Commands -->
          {#if tpmInfo?.commands && tpmInfo.commands.length > 0}
            <Card variant="outlined">
              <div class="section">
                <h2 class="text-title-medium section-heading">
                  <Icon path={mdiConsoleLine} size={20} />
                  Supported Commands ({tpmInfo.commands.length})
                </h2>
                <div style="margin-bottom: 12px;">
                  <Input
                    placeholder="Filter commands..."
                    bind:value={commandsFilter}
                  />
                  {#if commandsFilter}
                    <div style="margin-top: 6px; font-size: 0.75rem; color: var(--md-sys-color-on-surface-variant, #49454f);">
                      Showing {filteredCommands.length} of {tpmInfo.commands.length} commands
                    </div>
                  {/if}
                </div>
                <div class="commands-table-container" style="max-height: 600px; overflow-y: auto;">
                  <table class="commands-table" style="width: 100%; border-collapse: collapse;">
                    <thead style="position: sticky; top: 0; z-index: 1;">
                      <tr style="background: var(--md-sys-color-surface-container-highest, #e6e0e9);">
                        <th style="width: 72px; padding: 8px 12px; text-align: left; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;">Code</th>
                        <th style="width: 200px; padding: 8px 12px; text-align: left; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;">Command</th>
                        <th style="padding: 8px 12px; text-align: left; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;">Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each filteredCommands as cmd}
                        <tr style="border-bottom: 1px solid var(--md-sys-color-outline-variant, #cac4d0);">
                          <td style="padding: 6px 12px; font-family: monospace; font-size: 0.8125rem; color: var(--md-sys-color-primary, #6750a4);">{cmd.code}</td>
                          <td style="padding: 6px 12px; font-family: monospace; font-size: 0.8125rem;">{cmd.name}</td>
                          <td style="padding: 6px 12px; font-size: 0.8125rem; color: var(--md-sys-color-on-surface-variant, #49454f);">{cmd.description}</td>
                        </tr>
                      {/each}
                      {#if filteredCommands.length === 0 && commandsFilter}
                        <tr><td colspan="3" style="text-align: center; padding: 16px; color: var(--md-sys-color-on-surface-variant, #49454f);">No commands match "{commandsFilter}"</td></tr>
                      {/if}
                    </tbody>
                  </table>
                </div>
              </div>
            </Card>
          {/if}

          <!-- ECC Curves -->
          {#if tpmInfo?.ecc_curves && tpmInfo.ecc_curves.length > 0}
            <Card variant="outlined">
              <div class="section">
                <h2 class="text-title-medium section-heading">
                  <Icon path={mdiChartBellCurveCumulative} size={20} />
                  ECC Curves
                </h2>
                <div class="overview-chips-grid">
                  {#each tpmInfo.ecc_curves as curve}
                    <div class="pcr-bank-chip">
                      <span class="text-label-medium">{curve}</span>
                    </div>
                  {/each}
                </div>
              </div>
            </Card>
          {/if}

          <!-- Fixed Properties -->
          {#if tpmInfo?.fixed_properties && tpmInfo.fixed_properties.length > 0}
            <Card variant="outlined">
              <div class="section">
                <h2 class="text-title-medium section-heading">
                  <Icon path={mdiCog} size={20} />
                  Fixed Properties ({tpmInfo.fixed_properties.length})
                </h2>
                <div style="margin-bottom: 12px;">
                  <Input
                    placeholder="Filter properties..."
                    bind:value={fixedPropsFilter}
                  />
                  {#if fixedPropsFilter}
                    <div style="margin-top: 6px; font-size: 0.75rem; color: var(--md-sys-color-on-surface-variant, #49454f);">
                      Showing {filteredFixedProps.length} of {tpmInfo.fixed_properties.length} properties
                    </div>
                  {/if}
                </div>
                <div class="commands-table-container" style="max-height: 600px; overflow-y: auto;">
                  <table class="commands-table" style="width: 100%; border-collapse: collapse;">
                    <thead style="position: sticky; top: 0; z-index: 1;">
                      <tr style="background: var(--md-sys-color-surface-container-highest, #e6e0e9);">
                        <th style="width: 220px; padding: 8px 12px; text-align: left; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;">Property</th>
                        <th style="width: 120px; padding: 8px 12px; text-align: left; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;">Raw</th>
                        <th style="padding: 8px 12px; text-align: left; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;">Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each filteredFixedProps as prop}
                        <tr style="border-bottom: 1px solid var(--md-sys-color-outline-variant, #cac4d0);">
                          <td style="padding: 6px 12px; font-family: monospace; font-size: 0.8125rem; color: var(--md-sys-color-primary, #6750a4);">{prop.name}</td>
                          <td style="padding: 6px 12px; font-family: monospace; font-size: 0.8125rem;">{prop.raw}</td>
                          <td style="padding: 6px 12px; font-size: 0.8125rem; color: var(--md-sys-color-on-surface-variant, #49454f);">{prop.value}</td>
                        </tr>
                      {/each}
                      {#if filteredFixedProps.length === 0 && fixedPropsFilter}
                        <tr><td colspan="3" style="text-align: center; padding: 16px; color: var(--md-sys-color-on-surface-variant, #49454f);">No properties match "{fixedPropsFilter}"</td></tr>
                      {/if}
                    </tbody>
                  </table>
                </div>
              </div>
            </Card>
          {/if}

          <!-- Variable Properties -->
          {#if tpmInfo?.variable_properties && tpmInfo.variable_properties.length > 0}
            <Card variant="outlined">
              <div class="section">
                <h2 class="text-title-medium section-heading">
                  <Icon path={mdiTune} size={20} />
                  Variable Properties ({tpmInfo.variable_properties.length})
                </h2>
                <div style="margin-bottom: 12px;">
                  <Input
                    placeholder="Filter properties..."
                    bind:value={varPropsFilter}
                  />
                  {#if varPropsFilter}
                    <div style="margin-top: 6px; font-size: 0.75rem; color: var(--md-sys-color-on-surface-variant, #49454f);">
                      Showing {filteredVarProps.length} of {tpmInfo.variable_properties.length} properties
                    </div>
                  {/if}
                </div>
                <div class="commands-table-container" style="max-height: 600px; overflow-y: auto;">
                  <table class="commands-table" style="width: 100%; border-collapse: collapse;">
                    <thead style="position: sticky; top: 0; z-index: 1;">
                      <tr style="background: var(--md-sys-color-surface-container-highest, #e6e0e9);">
                        <th style="width: 220px; padding: 8px 12px; text-align: left; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;">Property</th>
                        <th style="width: 120px; padding: 8px 12px; text-align: left; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;">Raw</th>
                        <th style="padding: 8px 12px; text-align: left; font-size: 0.75rem; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;">Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each filteredVarProps as prop}
                        <tr style="border-bottom: 1px solid var(--md-sys-color-outline-variant, #cac4d0);">
                          <td style="padding: 6px 12px; font-family: monospace; font-size: 0.8125rem; color: var(--md-sys-color-primary, #6750a4);">{prop.name}</td>
                          <td style="padding: 6px 12px; font-family: monospace; font-size: 0.8125rem;">{prop.raw}</td>
                          <td style="padding: 6px 12px; font-size: 0.8125rem; color: var(--md-sys-color-on-surface-variant, #49454f);">{prop.value}</td>
                        </tr>
                      {/each}
                      {#if filteredVarProps.length === 0 && varPropsFilter}
                        <tr><td colspan="3" style="text-align: center; padding: 16px; color: var(--md-sys-color-on-surface-variant, #49454f);">No properties match "{varPropsFilter}"</td></tr>
                      {/if}
                    </tbody>
                  </table>
                </div>
              </div>
            </Card>
          {/if}

          <!-- Actions -->
          <Card variant="outlined">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiShieldKey} size={20} />
                Actions
              </h2>
              <div class="actions-list">
                <div class="action-row">
                  <div class="action-info">
                    <span class="text-title-small">Install</span>
                    <span class="text-body-small action-description">
                      Provisions the TCG Shared SRK, IAK, and IDevID. Will not overwrite existing keys.
                    </span>
                  </div>
                  <Button
                    variant="secondary"
                    icon={mdiShieldKey}
                    disabled={isFullyProvisioned}
                    on:click={() => (showInstallDialog = true)}
                  >
                    Install
                  </Button>
                </div>
                <div class="action-row">
                  <div class="action-info">
                    <span class="text-title-small danger-label">Factory Reset</span>
                    <span class="text-body-small action-description">
                      Resets TPM to manufacturer state. Only the EK will remain.
                    </span>
                  </div>
                  <Button
                    variant="text"
                    icon={mdiDeleteSweep}
                    on:click={() => (showFactoryResetDialog = true)}
                  >
                    Factory Reset
                  </Button>
                </div>
              </div>
            </div>
          </Card>

        {:else if activeCategory === 'platform'}
          <PlatformKeys />

        {:else if activeCategory === 'measurements'}
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

        {:else if activeCategory === 'key-handles'}
          <Card variant="elevated">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiFormatListBulleted} size={20} />
                Key Handles
              </h2>

              <div class="handle-tabs">
                <button
                  class="handle-tab"
                  class:handle-tab-active={handleTab === 'persistent'}
                  on:click={() => (handleTab = 'persistent')}
                >
                  Persistent
                </button>
                <button
                  class="handle-tab"
                  class:handle-tab-active={handleTab === 'transient'}
                  on:click={() => (handleTab = 'transient')}
                >
                  Transient
                </button>
              </div>

              {#if handlesLoading}
                <div class="pcr-loading-container">
                  <LoadingSpinner size={32} />
                  <p class="text-body-medium loading-text">Loading handles...</p>
                </div>
              {:else}
                {@const handles = handleTab === 'persistent' ? persistentHandles : transientHandles}
                {#if handles.length > 0}
                  <div class="handles-table">
                    <div class="handles-header">
                      <span class="text-label-small col-handle">Handle</span>
                      <span class="text-label-small col-algo">Algorithm</span>
                      <span class="text-label-small col-type">Type</span>
                      <span class="text-label-small col-desc">Description</span>
                      <span class="text-label-small col-actions"></span>
                    </div>
                    {#each handles as h}
                      <div class="handles-row">
                        <span class="text-body-small font-mono col-handle">{h.handle}</span>
                        <span class="text-body-small col-algo">{h.algorithm}</span>
                        <span class="text-body-small col-type">{h.type}</span>
                        <span class="text-body-small col-desc">
                          {#if editingHandle === h.handle}
                            <div class="inline-edit">
                              <input
                                class="inline-edit-input text-body-small"
                                bind:value={editDescription}
                                on:keydown={(e) => { if (e.key === 'Enter') saveDescription(h.handle); if (e.key === 'Escape') cancelEdit(); }}
                              />
                              <button class="inline-edit-btn save" on:click={() => saveDescription(h.handle)}>Save</button>
                              <button class="inline-edit-btn cancel" on:click={cancelEdit}>Cancel</button>
                            </div>
                          {:else}
                            {h.description || '--'}
                          {/if}
                        </span>
                        <span class="col-actions">
                          {#if editingHandle !== h.handle}
                            <Button variant="text" size="sm" icon={mdiPencil} on:click={() => startEditDescription(h.handle, h.description)}>
                              Edit
                            </Button>
                          {/if}
                        </span>
                      </div>
                    {/each}
                  </div>
                {:else}
                  <p class="text-body-medium empty-text">No {handleTab} handles found.</p>
                {/if}
              {/if}
            </div>
          </Card>

        {:else if activeCategory === 'nv-storage'}
          <Card variant="elevated">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiDatabaseOutline} size={20} />
                NV Storage
              </h2>

              {#if nvLoading}
                <div class="pcr-loading-container">
                  <LoadingSpinner size={32} />
                  <p class="text-body-medium loading-text">Loading NV storage...</p>
                </div>
              {:else if nvSummary}
                <!-- Summary -->
                <div class="nv-summary-card">
                  <div class="nv-summary-counts">
                    <span class="text-body-medium">{nvSummary.indexes_defined} / {nvSummary.indexes_max} indexes defined</span>
                  </div>
                  {#if nvSummary.indexes_max > 0}
                    <div class="nv-usage-bar">
                      <div
                        class="nv-usage-fill"
                        style="width: {Math.min((nvSummary.indexes_defined / nvSummary.indexes_max) * 100, 100)}%"
                      ></div>
                    </div>
                  {/if}
                </div>

                <!-- NV Index Table -->
                {#if nvSummary.indexes && nvSummary.indexes.length > 0}
                  <div class="handles-table">
                    <div class="handles-header">
                      <span class="text-label-small col-handle">Handle</span>
                      <span class="text-label-small col-type">Type</span>
                      <span class="text-label-small col-algo">Size</span>
                      <span class="text-label-small col-desc">Auth</span>
                      <span class="text-label-small col-actions">Actions</span>
                    </div>
                    {#each nvSummary.indexes as nv}
                      <div class="handles-row">
                        <span class="text-body-small font-mono col-handle">{nv.handle}</span>
                        <span class="text-body-small col-type">{nv.type}</span>
                        <span class="text-body-small col-algo">{nv.size} B</span>
                        <span class="text-body-small col-desc">
                          {nv.auth_read ? 'R' : ''}{nv.auth_write ? 'W' : ''}
                        </span>
                        <span class="col-actions nv-actions">
                          <Button variant="text" size="sm" on:click={() => handleNVRead(nv.handle, nv.type, nv.size)}>Read</Button>
                          {#if nv.type === 'ordinary'}
                            <Button variant="text" size="sm" on:click={() => openNVWrite(nv.handle)}>Write</Button>
                          {:else if nv.type === 'counter'}
                            <Button variant="text" size="sm" on:click={() => handleNVIncrement(nv.handle)}>Increment</Button>
                          {:else if nv.type === 'extend'}
                            <Button variant="text" size="sm" on:click={() => handleNVExtend(nv.handle)}>Extend</Button>
                          {/if}
                          <Button variant="text" size="sm" icon={mdiDelete} on:click={() => handleNVDelete(nv.handle)}>Delete</Button>
                        </span>
                      </div>
                    {/each}
                  </div>
                {:else}
                  <p class="text-body-medium empty-text">No NV indexes defined.</p>
                {/if}

                <div class="tpm-actions">
                  <Button variant="primary" icon={mdiPlus} on:click={() => (showNVCreateDialog = true)}>
                    Create NV Index
                  </Button>
                </div>
              {:else}
                <p class="text-body-medium empty-text">Unable to load NV storage information.</p>
                <Button variant="outline" on:click={loadNVSummary}>Retry</Button>
              {/if}
            </div>
          </Card>

        {:else if activeCategory === 'policies'}
          <TPMPolicyPanel />

        {:else if activeCategory === 'attestation'}
          <Card variant="elevated">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiShieldCheckOutline} size={20} />
                Attestation
              </h2>
              <div class="attestation-actions">
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Generate Quote</span>
                    <span class="text-body-small setting-desc">Create a TPM quote over selected PCR registers</span>
                  </div>
                  <Button variant="primary" icon={mdiShieldCheckOutline} on:click={() => (showQuoteDialog = true)}>
                    Generate Quote
                  </Button>
                </div>
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Event Log</span>
                    <span class="text-body-small setting-desc">View the TPM event log entries</span>
                  </div>
                  <Button variant="outline" icon={mdiCertificate} on:click={handleViewEventLog}>
                    View Event Log
                  </Button>
                </div>
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Certify Key</span>
                    <span class="text-body-small setting-desc">Certify a persistent key using the IAK as the signing handle</span>
                  </div>
                  <div style="display: flex; gap: 8px; align-items: center;">
                    <input
                      type="text"
                      class="text-input"
                      placeholder="0x81020000"
                      bind:value={certifyKeyHandle}
                      style="width: 140px;"
                    />
                    <Button variant="outline" on:click={handleCertifyKey}>
                      Certify
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </Card>

        {:else if activeCategory === 'lockout'}
          <Card variant="elevated">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiLockOutline} size={20} />
                Lockout
              </h2>

              {#if lockoutLoading}
                <div class="pcr-loading-container">
                  <LoadingSpinner size={32} />
                  <p class="text-body-medium loading-text">Loading lockout info...</p>
                </div>
              {:else if lockoutInfo}
                <div class="tpm-details-grid">
                  <div class="tpm-detail">
                    <span class="text-label-small field-label">Counter</span>
                    <span class="text-body-medium">{lockoutInfo.counter}</span>
                  </div>
                  <div class="tpm-detail">
                    <span class="text-label-small field-label">Max Failures</span>
                    <span class="text-body-medium">{lockoutInfo.max_fail}</span>
                  </div>
                  <div class="tpm-detail">
                    <span class="text-label-small field-label">Interval</span>
                    <span class="text-body-medium">{lockoutInfo.interval}s</span>
                  </div>
                  <div class="tpm-detail">
                    <span class="text-label-small field-label">Recovery</span>
                    <span class="text-body-medium">{lockoutInfo.recovery}s</span>
                  </div>
                  <div class="tpm-detail">
                    <span class="text-label-small field-label">Status</span>
                    <StatusBadge status={lockoutInfo.is_locked ? 'error' : 'verified'} />
                  </div>
                </div>

                <!-- Reset Lockout -->
                <Card variant="outlined">
                  <div class="section">
                    <h3 class="text-title-small">Reset Lockout Counter</h3>
                    <div class="auth-form-row">
                      <Input
                        label="Lockout Authorization"
                        type="password"
                        placeholder="Enter lockout auth"
                        bind:value={lockoutResetAuth}
                        disabled={lockoutResetting}
                      />
                      <Button
                        variant="primary"
                        icon={mdiRefresh}
                        loading={lockoutResetting}
                        on:click={handleResetLockout}
                        disabled={!lockoutResetAuth}
                      >
                        Reset
                      </Button>
                    </div>
                  </div>
                </Card>

                <!-- Force Reset Lockout -->
                <Card variant="outlined">
                  <div class="section">
                    <h3 class="text-title-small">Force Reset Lockout</h3>
                    <div class="force-clear-warning" role="alert">
                      <Icon path={mdiAlert} size={20} />
                      <p class="text-body-small">
                        Force Reset Lockout resets the dictionary attack counter so authentication can resume.
                        This does NOT erase any TPM keys or data.
                      </p>
                    </div>
                    <div class="auth-form-row">
                      <Input
                        label="Lockout Authorization"
                        type="password"
                        placeholder="Enter lockout auth"
                        bind:value={forceResetLockoutAuth}
                        disabled={forceResettingLockout}
                      />
                    </div>
                    <div class="force-clear-actions">
                      <label class="force-clear-confirm-label">
                        <input type="checkbox" bind:checked={forceResetLockoutConfirmed} />
                        <span class="text-body-small">I understand this will reset the lockout counter</span>
                      </label>
                      <Button
                        variant="danger"
                        on:click={() => (showForceResetLockoutConfirm = true)}
                        disabled={!forceResetLockoutConfirmed}
                      >
                        Reset Lockout
                      </Button>
                    </div>
                  </div>
                </Card>
              {:else}
                <p class="text-body-medium empty-text">Unable to load lockout information.</p>
                <Button variant="outline" on:click={loadLockoutInfo}>Retry</Button>
              {/if}
            </div>
          </Card>

        {:else if activeCategory === 'authorization'}
          <!-- Owner Auth -->
          <Card variant="elevated">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiAccount} size={20} />
                Owner Authorization
              </h2>
              <div class="auth-form">
                <Input label="Current Password" type="password" placeholder="Current owner auth" bind:value={ownerOldAuth} disabled={authChanging} />
                <Input label="New Password" type="password" placeholder="New owner auth" bind:value={ownerNewAuth} disabled={authChanging} />
                <Input label="Confirm Password" type="password" placeholder="Confirm new auth" bind:value={ownerConfirmAuth} disabled={authChanging} />
                {#if ownerNewAuth && ownerConfirmAuth && ownerNewAuth !== ownerConfirmAuth}
                  <p class="text-body-small auth-mismatch">Passwords do not match</p>
                {/if}
                <Button
                  variant="primary"
                  loading={authChanging}
                  on:click={handleChangeOwnerAuth}
                  disabled={!ownerOldAuth || !ownerNewAuth || ownerNewAuth !== ownerConfirmAuth}
                >
                  Change Owner Auth
                </Button>
              </div>
            </div>
          </Card>

          <!-- Endorsement Auth -->
          <Card variant="outlined">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiKey} size={20} />
                Endorsement Authorization
              </h2>
              <div class="auth-form">
                <Input label="Current Password" type="password" placeholder="Current endorsement auth" bind:value={endorsementOldAuth} disabled={authChanging} />
                <Input label="New Password" type="password" placeholder="New endorsement auth" bind:value={endorsementNewAuth} disabled={authChanging} />
                <Input label="Confirm Password" type="password" placeholder="Confirm new auth" bind:value={endorsementConfirmAuth} disabled={authChanging} />
                {#if endorsementNewAuth && endorsementConfirmAuth && endorsementNewAuth !== endorsementConfirmAuth}
                  <p class="text-body-small auth-mismatch">Passwords do not match</p>
                {/if}
                <Button
                  variant="primary"
                  loading={authChanging}
                  on:click={handleChangeEndorsementAuth}
                  disabled={!endorsementOldAuth || !endorsementNewAuth || endorsementNewAuth !== endorsementConfirmAuth}
                >
                  Change Endorsement Auth
                </Button>
              </div>
            </div>
          </Card>

          <!-- Lockout Auth -->
          <Card variant="outlined">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiLockOutline} size={20} />
                Lockout Authorization
              </h2>
              <div class="auth-form">
                <Input label="Current Password" type="password" placeholder="Current lockout auth" bind:value={lockoutOldAuth} disabled={authChanging} />
                <Input label="New Password" type="password" placeholder="New lockout auth" bind:value={lockoutNewAuth} disabled={authChanging} />
                <Input label="Confirm Password" type="password" placeholder="Confirm new auth" bind:value={lockoutConfirmAuth} disabled={authChanging} />
                {#if lockoutNewAuth && lockoutConfirmAuth && lockoutNewAuth !== lockoutConfirmAuth}
                  <p class="text-body-small auth-mismatch">Passwords do not match</p>
                {/if}
                <Button
                  variant="primary"
                  loading={authChanging}
                  on:click={handleChangeLockoutAuth}
                  disabled={!lockoutOldAuth || !lockoutNewAuth || lockoutNewAuth !== lockoutConfirmAuth}
                >
                  Change Lockout Auth
                </Button>
              </div>
            </div>
          </Card>

        {:else if activeCategory === 'verification'}
          <!-- CA Import -->
          <Card variant="elevated">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiCertificate} size={20} />
                CA Certificate Import
              </h2>
              <p class="text-body-small setting-desc">
                Import a CA certificate to verify the TPM endorsement key certificate chain.
              </p>
              <div class="ca-import-controls" style="display: flex; gap: 8px; margin-bottom: 12px;">
                <Button variant="outline" icon={mdiUpload} on:click={() => caFileInput.click()}>
                  Browse Certificate File
                </Button>
                <span class="text-body-small" style="color: var(--md-sys-color-on-surface-variant); align-self: center;">
                  Supports PEM (.pem, .crt) and DER (.der, .cer) formats
                </span>
              </div>
              <input
                type="file"
                accept=".pem,.crt,.der,.cer"
                style="display: none;"
                bind:this={caFileInput}
                on:change={handleCACertFileSelect}
              />
              <p class="text-body-small setting-desc">
                Or paste a PEM-encoded certificate below:
              </p>
              <textarea
                class="pem-textarea"
                placeholder="Paste PEM-encoded CA certificate here..."
                bind:value={caPEM}
                rows="8"
              ></textarea>
              <Button variant="primary" icon={mdiImport} loading={caImporting} on:click={handleImportCA} disabled={!caPEM.trim()}>
                Import CA Certificate
              </Button>
            </div>
          </Card>

          <!-- Verification -->
          <Card variant="outlined">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiShieldOutline} size={20} />
                TPM Verification
              </h2>
              <div class="setting-row">
                <div class="setting-info">
                  <span class="text-title-small">Verify TPM</span>
                  <span class="text-body-small setting-desc">Verify the TPM endorsement key certificate chain against imported CA certificates</span>
                </div>
                <Button variant="primary" icon={mdiShieldCheckOutline} loading={verificationLoading} on:click={handleVerifyTPM}>
                  Verify
                </Button>
              </div>

              {#if verificationStatus}
                <div class="verification-result" class:verified={verificationStatus.status === 'verified'} class:failed={verificationStatus.status === 'failed'} class:unverified={verificationStatus.status !== 'verified' && verificationStatus.status !== 'failed'}>
                  <div class="verification-status-row">
                    <span class="verification-dot"></span>
                    <span class="text-title-small">
                      {#if verificationStatus.status === 'verified'}
                        Verified
                      {:else if verificationStatus.status === 'failed'}
                        Failed
                      {:else}
                        Unverified
                      {/if}
                    </span>
                  </div>
                  {#if verificationStatus.error}
                    <p class="text-body-small verification-error">{verificationStatus.error}</p>
                  {/if}
                  <div class="verification-details">
                    {#if verificationStatus.issuer}
                      <div class="tpm-detail">
                        <span class="text-label-small field-label">Issuer</span>
                        <span class="text-body-small">{verificationStatus.issuer}</span>
                      </div>
                    {/if}
                    {#if verificationStatus.subject}
                      <div class="tpm-detail">
                        <span class="text-label-small field-label">Subject</span>
                        <span class="text-body-small">{verificationStatus.subject}</span>
                      </div>
                    {/if}
                    {#if verificationStatus.not_before}
                      <div class="tpm-detail">
                        <span class="text-label-small field-label">Not Before</span>
                        <span class="text-body-small">{verificationStatus.not_before}</span>
                      </div>
                    {/if}
                    {#if verificationStatus.not_after}
                      <div class="tpm-detail">
                        <span class="text-label-small field-label">Not After</span>
                        <span class="text-body-small">{verificationStatus.not_after}</span>
                      </div>
                    {/if}
                  </div>
                </div>
              {/if}
            </div>
          </Card>
        {/if}
      </div>
    </div>
  {/if}

  <!-- Dialogs -->
  <QuoteDialog
    bind:open={showQuoteDialog}
    onClose={() => (showQuoteDialog = false)}
    onGenerate={handleGenerateQuote}
  />

  <QuoteResultDialog
    bind:open={showQuoteResult}
    quote={quoteResult}
    onClose={() => (showQuoteResult = false)}
  />

  <CertificateViewerDialog
    bind:open={showCertViewer}
    certPEM={certViewerPEM}
    title={certViewerTitle}
    onClose={() => (showCertViewer = false)}
  />

  <TPMProvisionDialog
    bind:open={showProvisionDialog}
    onClose={() => (showProvisionDialog = false)}
    onComplete={handleProvisionComplete}
  />

  <TPMInstallDialog
    bind:open={showInstallDialog}
    onClose={() => (showInstallDialog = false)}
    onComplete={handleProvisionComplete}
  />

  <TPMFactoryResetDialog
    bind:open={showFactoryResetDialog}
    onClose={() => (showFactoryResetDialog = false)}
    onComplete={handleProvisionComplete}
  />

  <TPMProvisionKeyDialog
    bind:open={showProvisionKeyDialog}
    keyType={provisionKeyType}
    onClose={() => (showProvisionKeyDialog = false)}
    onComplete={handleProvisionComplete}
  />

  {#if showEventLog}
    <EventLogViewer
      bind:open={showEventLog}
      entries={eventLogEntries}
      loading={eventLogLoading}
      onClose={() => (showEventLog = false)}
      onReplay={handleReplayEventLog}
    />
  {/if}

  <!-- NV Create Dialog -->
  <Modal bind:open={showNVCreateDialog} title="Create NV Index" maxWidth="440px">
    <div class="nv-create-form">
      <div class="form-field">
        <label class="text-label-medium" for="nv-type">Type</label>
        <select id="nv-type" class="form-select" bind:value={nvCreateType} disabled={nvCreating}>
          <option value="ordinary">Ordinary</option>
          <option value="counter">Counter</option>
          <option value="extend">Extend</option>
        </select>
      </div>
      <Input label="Handle" placeholder="0x01800001" bind:value={nvCreateHandle} monospace disabled={nvCreating} />
      <div class="form-field">
        <label class="text-label-medium" for="nv-size">Size (bytes)</label>
        <input id="nv-size" type="number" class="number-input" bind:value={nvCreateSize} min="1" max="2048" disabled={nvCreating} />
      </div>
      <div class="nv-auth-toggles">
        <Toggle bind:checked={nvCreateAuthRead} label="Require auth for read" />
        <Toggle bind:checked={nvCreateAuthWrite} label="Require auth for write" />
      </div>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showNVCreateDialog = false)} disabled={nvCreating}>Cancel</Button>
      <Button variant="primary" loading={nvCreating} on:click={handleNVCreate} disabled={!nvCreateHandle}>Create</Button>
    </svelte:fragment>
  </Modal>

  <!-- NV Read Dialog -->
  <Modal bind:open={showNVReadDialog} title="NV Index Data" maxWidth="480px">
    <div class="nv-read-content">
      <p class="text-label-medium">Handle: <span class="font-mono">{nvReadHandle}</span></p>
      <pre class="nv-data-display font-mono text-body-small">{nvReadData || '(empty)'}</pre>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="primary" on:click={() => (showNVReadDialog = false)}>Close</Button>
    </svelte:fragment>
  </Modal>

  <!-- NV Write Dialog -->
  <Modal bind:open={showNVWriteDialog} title="Write NV Index" maxWidth="440px">
    <div class="nv-create-form">
      <p class="text-label-medium">Handle: <span class="font-mono">{nvWriteHandle}</span></p>
      <textarea
        class="pem-textarea"
        placeholder="Enter data to write..."
        bind:value={nvWriteData}
        rows="6"
      ></textarea>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showNVWriteDialog = false)}>Cancel</Button>
      <Button variant="primary" on:click={handleNVWrite} disabled={!nvWriteData}>Write</Button>
    </svelte:fragment>
  </Modal>

  <!-- Force Reset Lockout Confirm -->
  <Modal bind:open={showForceResetLockoutConfirm} title="Confirm Reset Lockout" maxWidth="440px">
    <div class="force-clear-warning" role="alert">
      <Icon path={mdiAlert} size={20} />
      <p class="text-body-medium">
        This will reset the dictionary attack lockout counter so authentication can resume.
        No TPM keys or data will be erased.
      </p>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => { showForceResetLockoutConfirm = false; }} disabled={forceResettingLockout}>Cancel</Button>
      <Button variant="danger" loading={forceResettingLockout} on:click={handleForceResetLockout}>Reset Lockout Counter</Button>
    </svelte:fragment>
  </Modal>

  <!-- Key View Dialog -->
  <Modal bind:open={showKeyViewDialog} title={keyViewData?.name ?? 'Key Details'} maxWidth="600px">
    {#if keyViewData}
      <div class="key-view-content">
        <div class="tpm-details-grid">
          <div class="tpm-detail">
            <span class="text-label-small field-label">Algorithm</span>
            <span class="text-body-medium">{keyViewData.algorithm}</span>
          </div>
          {#if keyViewData.key_size > 0}
            <div class="tpm-detail">
              <span class="text-label-small field-label">Key Size</span>
              <span class="text-body-medium">{keyViewData.key_size} bits</span>
            </div>
          {/if}
          {#if keyViewData.handle}
            <div class="tpm-detail">
              <span class="text-label-small field-label">Handle</span>
              <span class="text-body-medium font-mono">{keyViewData.handle}</span>
            </div>
          {/if}
        </div>

        {#if keyViewData.public_key_pem}
          <div class="key-pem-section">
            <div class="pem-header">
              <span class="text-label-medium">Public Key</span>
              <Button variant="text" size="sm" on:click={() => keyViewData && copyToClipboard(keyViewData.public_key_pem, 'Public key')}>Copy</Button>
            </div>
            <pre class="pem-display font-mono text-body-small">{keyViewData.public_key_pem}</pre>
          </div>
        {/if}

        {#if keyViewData.certificate}
          <div class="key-pem-section">
            <div class="pem-header">
              <span class="text-label-medium">Certificate</span>
              <Button variant="text" size="sm" on:click={() => keyViewData && copyToClipboard(keyViewData.certificate, 'Certificate')}>Copy</Button>
            </div>
            <pre class="pem-display font-mono text-body-small">{keyViewData.certificate}</pre>
          </div>
        {/if}
      </div>
    {/if}
    <svelte:fragment slot="actions">
      <Button variant="primary" on:click={() => (showKeyViewDialog = false)}>Close</Button>
    </svelte:fragment>
  </Modal>

  <!-- Certify Key Result Dialog -->
  <Modal bind:open={showCertifyDialog} title="Certification Result" maxWidth="560px">
    {#if certifyResult}
      <div class="key-view-content">
        <div class="key-pem-section">
          <div class="pem-header">
            <span class="text-label-medium">Attested Data</span>
            <Button variant="text" size="sm" on:click={() => certifyResult && copyToClipboard(certifyResult.attested, 'Attested data')}>Copy</Button>
          </div>
          <pre class="pem-display font-mono text-body-small">{certifyResult.attested}</pre>
        </div>
        <div class="key-pem-section">
          <div class="pem-header">
            <span class="text-label-medium">Signature</span>
            <Button variant="text" size="sm" on:click={() => certifyResult && copyToClipboard(certifyResult.signature, 'Signature')}>Copy</Button>
          </div>
          <pre class="pem-display font-mono text-body-small">{certifyResult.signature}</pre>
        </div>
        <div class="key-pem-section">
          <div class="pem-header">
            <span class="text-label-medium">Nonce</span>
            <Button variant="text" size="sm" on:click={() => certifyResult && copyToClipboard(certifyResult.nonce, 'Nonce')}>Copy</Button>
          </div>
          <pre class="pem-display font-mono text-body-small">{certifyResult.nonce}</pre>
        </div>
      </div>
    {/if}
    <svelte:fragment slot="actions">
      <Button variant="primary" on:click={() => (showCertifyDialog = false)}>Close</Button>
    </svelte:fragment>
  </Modal>

  <!-- CSR Result Dialog -->
  <Modal bind:open={showCSRDialog} title="TCG-CSR-IDEVID" maxWidth="560px">
    <div class="key-view-content">
      <p class="text-body-small">
        Submit this CSR to your Certificate Authority for signing.
        After receiving the signed certificate, use the Import Cert button on the IDevID key to install it.
      </p>
      <div class="key-pem-section">
        <div class="pem-header">
          <span class="text-label-medium">CSR Data (hex)</span>
          <Button variant="text" size="sm" on:click={() => copyToClipboard(csrData, 'CSR data')}>Copy</Button>
        </div>
        <pre class="pem-display font-mono text-body-small">{csrData}</pre>
      </div>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showCSRDialog = false)}>Close</Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .tpm-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .tpm-layout {
    flex: 1;
    display: flex;
    overflow: hidden;
  }

  .tpm-nav {
    width: 220px;
    min-width: 220px;
    padding: 16px 12px;
    border-right: 1px solid var(--color-outline-variant);
    display: flex;
    flex-direction: column;
    gap: 4px;
    overflow-y: auto;
  }

  .tpm-nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
    border: none;
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-family: var(--font-sans);
    text-align: left;
    transition: background-color var(--transition-fast), color var(--transition-fast);
    width: 100%;
  }

  .tpm-nav-item:hover {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .tpm-nav-item.nav-active {
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    font-weight: 600;
  }

  :global([data-theme="dark"]) .tpm-nav-item.nav-active {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .tpm-panel {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    max-width: 700px;
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

  /* Sections & Cards */
  .section {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .section-heading {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
    color: var(--color-on-surface);
    padding-bottom: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .empty-text {
    color: var(--color-on-surface-variant);
    margin: 0;
    padding: 8px 0;
  }

  /* Overview */
  .tpm-hardware-header {
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .tpm-icon {
    width: 56px;
    height: 56px;
    border-radius: var(--radius-lg);
    background: var(--gradient-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .tpm-hw-info {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .tpm-hw-info h2 { margin: 0; color: var(--color-on-surface); }

  .tpm-details-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
  }

  .tpm-detail {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .overview-subheading {
    margin: 8px 0 0 0;
    padding-top: 16px;
    border-top: 1px solid var(--color-outline-variant);
    color: var(--color-on-surface);
  }

  .overview-chips-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .pcr-bank-chip {
    display: inline-flex;
    align-items: center;
    padding: 6px 14px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
    border: 1px solid var(--color-outline-variant);
  }

  .tpm-actions {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
  }

  /* Actions */
  .actions-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .action-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-low);
  }

  .action-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .action-description {
    color: var(--color-on-surface-variant);
  }

  .danger-label {
    color: var(--color-error);
  }

  /* Measurements / Info table */
  .pcr-loading-container {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 12px;
    padding: 32px;
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

  .algorithm-chip {
    display: inline-flex; align-items: center;
    padding: 6px 14px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
    border: 1px solid var(--color-outline-variant);
  }

  /* Key Handles */
  .handle-tabs {
    display: flex;
    gap: 0;
    border-bottom: 2px solid var(--color-outline-variant);
  }

  .handle-tab {
    padding: 10px 20px;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-family: var(--font-sans);
    font-weight: 500;
    font-size: 14px;
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    transition: color var(--transition-fast), border-color var(--transition-fast);
  }

  .handle-tab:hover {
    color: var(--color-on-surface);
  }

  .handle-tab-active {
    color: var(--color-primary);
    border-bottom-color: var(--color-primary);
  }

  .handles-table {
    display: flex;
    flex-direction: column;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    overflow: hidden;
  }

  .handles-header {
    display: flex;
    padding: 8px 12px;
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
    gap: 12px;
  }

  .handles-row {
    display: flex;
    padding: 8px 12px;
    gap: 12px;
    border-top: 1px solid var(--color-outline-variant);
    align-items: center;
    transition: background-color var(--transition-fast);
  }

  .handles-row:hover {
    background-color: var(--color-surface-container-low);
  }

  .col-handle { width: 120px; flex-shrink: 0; }
  .col-algo { width: 80px; flex-shrink: 0; }
  .col-type { width: 80px; flex-shrink: 0; }
  .col-desc { flex: 1; min-width: 0; }
  .col-actions { flex-shrink: 0; display: flex; gap: 4px; }

  .inline-edit {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .inline-edit-input {
    flex: 1;
    padding: 4px 8px;
    border: 1px solid var(--color-primary);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 13px;
    outline: none;
  }

  .inline-edit-btn {
    padding: 4px 8px;
    border: none;
    border-radius: var(--radius-sm);
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 12px;
    font-weight: 500;
  }

  .inline-edit-btn.save {
    background-color: var(--color-primary);
    color: var(--color-on-primary);
  }

  .inline-edit-btn.cancel {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
  }

  /* NV Storage */
  .nv-summary-card {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .nv-summary-counts {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-on-surface);
  }

  .nv-usage-bar {
    height: 8px;
    border-radius: 4px;
    background-color: var(--color-surface-container);
    overflow: hidden;
  }

  .nv-usage-fill {
    height: 100%;
    border-radius: 4px;
    background: var(--gradient-primary);
    transition: width var(--transition-normal);
  }

  .nv-actions {
    flex-wrap: wrap;
  }

  .nv-create-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-field label {
    color: var(--color-on-surface-variant);
  }

  .form-select {
    height: 40px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
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

  .number-input {
    width: 100%;
    height: 40px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
    font-size: 14px;
    outline: none;
  }

  .number-input:focus {
    border-color: var(--color-primary);
  }

  .nv-auth-toggles {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .nv-read-content {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .nv-data-display {
    padding: 12px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-outline-variant);
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 300px;
    overflow-y: auto;
    margin: 0;
    color: var(--color-on-surface);
  }

  /* Attestation */
  .attestation-actions {
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .setting-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    padding: 12px 0;
  }

  .setting-row + .setting-row {
    border-top: 1px solid var(--color-surface-variant);
  }

  .setting-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .setting-info span:first-child {
    color: var(--color-on-surface);
  }

  .setting-desc {
    color: var(--color-on-surface-variant);
  }

  /* Lockout */
  .auth-form-row {
    display: flex;
    align-items: flex-end;
    gap: 12px;
  }

  .auth-form-row :global(.input-wrapper) {
    flex: 1;
  }

  .force-clear-warning {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px 16px;
    background-color: var(--color-security-danger-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-security-danger-container);
  }

  .force-clear-warning p {
    margin: 0;
    line-height: 1.5;
  }

  .force-clear-actions {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .force-clear-confirm-label {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    color: var(--color-on-surface-variant);
  }

  .force-clear-confirm-label input[type="checkbox"] {
    accent-color: var(--color-error);
  }

  /* Authorization */
  .auth-form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .auth-mismatch {
    margin: 0;
    color: var(--color-error);
  }

  /* Verification */
  .pem-textarea {
    width: 100%;
    padding: 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
    font-size: 13px;
    resize: vertical;
    outline: none;
    box-sizing: border-box;
  }

  .pem-textarea:focus {
    border-color: var(--color-primary);
  }

  .verification-result {
    padding: 16px;
    border-radius: var(--radius-md);
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .verification-result.verified {
    background-color: var(--color-security-verified-container);
    color: var(--color-on-security-verified-container);
  }

  .verification-result.failed {
    background-color: var(--color-security-danger-container);
    color: var(--color-on-security-danger-container);
  }

  .verification-result.unverified {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
  }

  .verification-status-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .verification-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .verified .verification-dot {
    background-color: var(--color-security-verified);
  }

  .failed .verification-dot {
    background-color: var(--color-security-danger);
  }

  .unverified .verification-dot {
    background-color: var(--color-on-surface-variant);
    opacity: 0.5;
  }

  .verification-error {
    margin: 0;
  }

  .verification-details {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  /* Key View / Certify / CSR dialogs */
  .key-view-content {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .key-pem-section {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .pem-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .pem-display {
    background: var(--md-sys-color-surface-container);
    border-radius: 8px;
    padding: 12px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
    font-size: 11px;
    line-height: 1.4;
  }

  .text-input {
    height: 36px;
    padding: 0 10px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
    font-size: 13px;
    outline: none;
  }

  .text-input:focus {
    border-color: var(--color-primary);
  }
</style>
