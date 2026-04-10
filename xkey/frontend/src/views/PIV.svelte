<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import GeneratePIVKeyDialog from '$lib/components/GeneratePIVKeyDialog.svelte';
  import BackendSelector from '$lib/components/BackendSelector.svelte';
  import { mdiCreditCardOutline, mdiKey, mdiCertificate, mdiEye, mdiPlus } from '$lib/utils/icons';
  import { appState, pivBackend, setPIVBackend } from '$lib/stores/app';
  import type { PIVSlot } from '$lib/types';
  import { isHardwareBackend as sharedIsHardwareBackend } from '$lib/utils/backends';
  import { isWailsAvailable, callBackend } from '$lib/api/backend';
  import type { BackendPIVSlot } from '$lib/api/backend';

  let slots: PIVSlot[] = [];
  let showGenerateDialog = false;
  let generateSlotId = '';
  let generateSlotLabel = '';

  // Use stateful store — persists across navigation
  $: selectedBackend = $pivBackend;

  const defaultSlots: PIVSlot[] = [
    { slotId: '9A', label: 'PIV Authentication', purpose: 'General authentication, SSH, VPN', loaded: false, algorithm: null, subject: null, issuer: null, serialNumber: null, notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null, backend: null, backendDisplayName: null },
    { slotId: '9C', label: 'Digital Signature', purpose: 'Code signing, document signing', loaded: false, algorithm: null, subject: null, issuer: null, serialNumber: null, notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null, backend: null, backendDisplayName: null },
    { slotId: '9D', label: 'Key Management', purpose: 'Encryption, key exchange', loaded: false, algorithm: null, subject: null, issuer: null, serialNumber: null, notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null, backend: null, backendDisplayName: null },
    { slotId: '9E', label: 'Card Authentication', purpose: 'Physical access, card authentication', loaded: false, algorithm: null, subject: null, issuer: null, serialNumber: null, notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null, backend: null, backendDisplayName: null },
    { slotId: 'F9', label: 'Attestation', purpose: 'Device attestation certificate', loaded: false, algorithm: null, subject: null, issuer: null, serialNumber: null, notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null, backend: null, backendDisplayName: null },
  ];

  async function loadSlots(): Promise<void> {
    if (isWailsAvailable()) {
      const backendSlots = await callBackend<BackendPIVSlot[]>('PIVService', 'GetSlots');
      if (backendSlots && backendSlots.length > 0) {
        slots = backendSlots.map(s => ({
          slotId: s.slot.toUpperCase(),
          label: s.name,
          purpose: s.description,
          loaded: s.has_cert,
          algorithm: s.algorithm || null,
          subject: s.subject || null,
          issuer: s.issuer || null,
          serialNumber: null,
          notBefore: s.not_before || null,
          notAfter: s.not_after || null,
          keyUsage: [],
          fingerprint: s.fingerprint || null,
          daysRemaining: s.not_after ? Math.floor((new Date(s.not_after).getTime() - Date.now()) / 86400000) : null,
          backend: s.backend || null,
          backendDisplayName: s.backend_display_name || null,
        }));
        return;
      }
    }
    slots = defaultSlots;
  }

  onMount(async () => {
    // If we already have a stored backend from a previous visit, sync it
    // to the Go service before loading slots.
    if ($pivBackend && isWailsAvailable()) {
      await callBackend('PIVService', 'SetBackend', $pivBackend);
    }
    loadSlots();
  });

  async function handleBackendChange(e: CustomEvent<string>): Promise<void> {
    const backend = e.detail;
    setPIVBackend(backend);
    if (isWailsAvailable() && backend) {
      await callBackend('PIVService', 'SetBackend', backend);
      loadSlots();
    }
  }

  $: filteredSlots = (() => {
    const base = selectedBackend
      ? slots.filter(s => !s.backend || s.backend === selectedBackend)
      : slots;
    // Always show all 5 standard PIV slots, merging loaded data with empty defaults
    const slotIds = new Set(base.map(s => s.slotId));
    const missing = defaultSlots.filter(d => !slotIds.has(d.slotId));
    return [...base, ...missing].sort((a, b) => a.slotId.localeCompare(b.slotId));
  })();

  function viewSlot(slot: PIVSlot): void {
    appState.update((s) => ({
      ...s,
      currentView: 'piv-slot',
      modalProps: { slotId: slot.slotId },
    }));
  }

  function openGenerateDialog(slot: PIVSlot): void {
    generateSlotId = slot.slotId;
    generateSlotLabel = slot.label;
    showGenerateDialog = true;
  }

  function handleKeyGenerated(): void {
    showGenerateDialog = false;
    loadSlots();
  }

  function getCertStatus(slot: PIVSlot): 'connected' | 'warning' | 'error' | 'neutral' {
    if (slot.daysRemaining === null) return 'neutral';
    if (slot.daysRemaining <= 0) return 'error';
    if (slot.daysRemaining <= 30) return 'warning';
    return 'connected';
  }

  function getExpiryLabel(days: number | null): string {
    if (days === null) return 'N/A';
    if (days <= 0) return 'Expired';
    if (days <= 30) return 'Expiring';
    return 'Valid';
  }

  function isHardwareBacked(backend: string | null): boolean {
    return backend !== null && sharedIsHardwareBackend(backend);
  }
</script>

<div class="piv-view" data-testid="piv-view">
  <GradientHeader title="PIV Smart Card" subtitle="NIST SP 800-73 certificate slots" />

  <ViewToolbar>
    <BackendSelector
      capability="piv"
      selected={$pivBackend}
      showAll={false}
      connectedOnly={false}
      on:change={handleBackendChange}
    />
  </ViewToolbar>

  <div class="piv-content">
    <div class="piv-grid">
      {#each filteredSlots as slot}
        <Card variant={slot.loaded ? 'elevated' : 'outlined'} hoverable on:click={() => viewSlot(slot)}>
          <div class="slot-card" data-testid="piv-slot-card-{slot.slotId}">
            <div class="slot-header">
              <div class="slot-id-badge" class:slot-loaded={slot.loaded}>
                <span class="text-label-large">{slot.slotId}</span>
              </div>
              <div class="slot-info">
                <h3 class="text-title-small">{slot.label}</h3>
                <span class="text-body-small slot-purpose">{slot.purpose}</span>
                {#if slot.backend && !slot.loaded}
                  <span class="backend-chip" class:hardware={isHardwareBacked(slot.backend)}>{slot.backendDisplayName || slot.backend || ''}</span>
                {/if}
              </div>
            </div>

            {#if slot.loaded}
              <div class="slot-details" data-testid="piv-slot-details-{slot.slotId}">
                <div class="slot-detail-row">
                  <Icon path={mdiKey} size={16} />
                  <span class="text-body-small">{slot.algorithm}</span>
                  {#if slot.backend}
                    <span class="backend-chip" class:hardware={isHardwareBacked(slot.backend)}>{slot.backendDisplayName || slot.backend || ''}</span>
                  {/if}
                </div>
                <div class="slot-detail-row">
                  <Icon path={mdiCertificate} size={16} />
                  <span class="text-body-small">{slot.subject}</span>
                </div>
                <div class="slot-expiry-row">
                  <StatusBadge status={getCertStatus(slot)} />
                  <span class="text-body-small">
                    {getExpiryLabel(slot.daysRemaining)}
                    {#if slot.daysRemaining !== null && slot.daysRemaining > 0}
                      &mdash; {slot.daysRemaining} days remaining
                    {/if}
                  </span>
                </div>
              </div>
              <div class="slot-action">
                <Button variant="text" size="sm" icon={mdiEye}>View Certificate</Button>
              </div>
            {:else}
              <div class="slot-empty" data-testid="piv-slot-empty-{slot.slotId}">
                <span class="text-body-medium slot-empty-text">Empty slot</span>
                <!-- svelte-ignore a11y-click-events-have-key-events -->
                <div on:click|stopPropagation role="none">
                  {#if slot.slotId === 'F9'}
                    <Button variant="outline" size="sm" icon={mdiPlus} on:click={() => openGenerateDialog(slot)} data-testid="piv-slot-action-{slot.slotId}">Import Certificate</Button>
                  {:else}
                    <Button variant="outline" size="sm" icon={mdiPlus} on:click={() => openGenerateDialog(slot)} data-testid="piv-slot-action-{slot.slotId}">Generate Key</Button>
                  {/if}
                </div>
              </div>
            {/if}
          </div>
        </Card>
      {/each}
    </div>
  </div>

  <GeneratePIVKeyDialog
    bind:open={showGenerateDialog}
    slotId={generateSlotId}
    slotLabel={generateSlotLabel}
    backend={selectedBackend}
    onClose={() => (showGenerateDialog = false)}
    onGenerated={handleKeyGenerated}
  />
</div>

<style>
  .piv-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .piv-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
  }

  .piv-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 20px;
  }

  .slot-card {
    display: flex;
    flex-direction: column;
    gap: 16px;
    min-height: 180px;
  }

  .slot-header {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .slot-id-badge {
    width: 44px;
    height: 44px;
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    font-weight: 600;
  }

  .slot-id-badge.slot-loaded {
    background: var(--gradient-primary);
    color: #FFFFFF;
  }

  .slot-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .slot-info h3 {
    margin: 0;
    color: var(--color-on-surface);
  }

  .slot-purpose {
    color: var(--color-on-surface-variant);
  }

  .slot-details {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .slot-detail-row {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-on-surface-variant);
  }

  .slot-expiry-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .slot-expiry-row span {
    color: var(--color-on-surface-variant);
  }

  .slot-action {
    display: flex;
    justify-content: flex-end;
    margin-top: auto;
  }

  .slot-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    padding: 16px 0;
    flex: 1;
    justify-content: center;
  }

  .slot-empty-text {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  .backend-chip {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-sm, 4px);
    font-size: 11px;
    font-weight: 500;
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    line-height: 1.4;
  }

  .backend-chip.hardware {
    background-color: var(--color-primary-container, rgba(0, 120, 120, 0.12));
    color: var(--color-on-primary-container, #006a6a);
  }

  @media (max-width: 800px) {
    .piv-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
