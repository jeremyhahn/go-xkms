<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import UnsealDialog from '$lib/components/UnsealDialog.svelte';
  import {
    mdiShieldCheckOutline, mdiChip, mdiNumeric, mdiKey,
    mdiServerNetwork,
    mdiHarddisk, mdiShieldLockOutline, mdiFingerprint,
    mdiCertificate, mdiCloudOutline, mdiLockOutline,
    mdiLockOpen, mdiClose, mdiClipboardTextOutline
  } from '$lib/utils/icons';
  import { navigateTo } from '$lib/stores/app';
  import { formatRelativeTime } from '$lib/utils/format';
  import { isWailsAvailable, callBackend } from '$lib/api/backend';
  import type { AppStatus, BarrierSealInfo } from '$lib/api/backend';

  interface StatusCard {
    id: string;
    label: string;
    icon: string;
    status: string;
    statusType: 'connected' | 'disconnected' | 'verified' | 'warning' | 'error' | 'neutral';
    view: string;
  }

  interface ActivityEvent {
    id: string;
    type: string;
    title: string;
    description: string;
    timestamp: string;
    icon: string;
    success: boolean;
  }

  let statusCards: StatusCard[] = [];
  let recentActivity: ActivityEvent[] = [];
  let appStatus: AppStatus | null = null;
  let barrierInfo: BarrierSealInfo | null = null;
  let showUnsealDialog = false;

  /** Map audit operation types to icons. */
  const auditIconMap: Record<string, string> = {
    sign: mdiFingerprint,
    verify: mdiShieldCheckOutline,
    encrypt: mdiLockOutline,
    decrypt: mdiLockOpen,
    generate: mdiKey,
    import: mdiKey,
    export: mdiKey,
    delete: mdiClose,
    seal: mdiShieldLockOutline,
    unseal: mdiLockOpen,
    default: mdiClipboardTextOutline,
  };

  function auditIcon(operation: string): string {
    const op = operation.toLowerCase();
    for (const [key, icon] of Object.entries(auditIconMap)) {
      if (op.includes(key)) return icon;
    }
    return auditIconMap.default;
  }

  async function handleUnsealSuccess(): Promise<void> {
    showUnsealDialog = false;
    if (isWailsAvailable()) {
      appStatus = await callBackend<AppStatus>('AppService', 'GetStatus');
    }
  }

  onMount(async () => {
    if (isWailsAvailable()) {
      const [statusResult, barrierResult] = await Promise.all([
        callBackend<AppStatus>('AppService', 'GetStatus'),
        callBackend<BarrierSealInfo>('BarrierService', 'GetSealInfo'),
      ]);
      appStatus = statusResult;
      barrierInfo = barrierResult;
    }

    const mode = appStatus?.mode || 'standalone';
    const serverAddr = appStatus?.server_address || '';
    const tpmAvail = appStatus?.tpm_available || false;
    const tpmDeviceExists = appStatus?.tpm_device_exists || false;
    const tpmProv = appStatus?.tpm_provisioned || false;
    const storEncrypted = appStatus?.storage_encrypted || false;
    const storMounted = appStatus?.storage_mounted || false;

    // Mode card
    let modeStatus: string;
    let modeStatusType: StatusCard['statusType'];
    if (mode === 'xkmsd') {
      modeStatus = `Connected to ${serverAddr}`;
      modeStatusType = 'connected';
    } else {
      modeStatus = 'Standalone';
      modeStatusType = 'neutral';
    }

    // Storage card
    let storageStatus: string;
    let storageStatusType: StatusCard['statusType'];
    if (storEncrypted && storMounted) {
      storageStatus = 'Encrypted & Mounted';
      storageStatusType = 'verified';
    } else if (storEncrypted) {
      storageStatus = 'Encrypted (Locked)';
      storageStatusType = 'warning';
    } else {
      storageStatus = 'Not Encrypted';
      storageStatusType = 'disconnected';
    }

    statusCards = [
      {
        id: 'mode',
        label: 'Mode',
        icon: mode === 'xkmsd' ? mdiServerNetwork : mdiShieldLockOutline,
        status: modeStatus,
        statusType: modeStatusType,
        view: mode === 'xkmsd' ? 'keys' : 'settings',
      },
      {
        id: 'storage',
        label: 'Storage',
        icon: mdiHarddisk,
        status: storageStatus,
        statusType: storageStatusType,
        view: 'settings',
      },
    ];

    // Show TPM card when the device node exists, even if TPM init failed.
    if (tpmAvail || tpmDeviceExists) {
      let tpmStatus: string;
      let tpmStatusType: StatusCard['statusType'];
      if (tpmProv) {
        tpmStatus = 'Provisioned';
        tpmStatusType = 'verified';
      } else if (tpmAvail) {
        tpmStatus = 'Available';
        tpmStatusType = 'warning';
      } else {
        tpmStatus = 'Not Ready';
        tpmStatusType = 'error';
      }
      statusCards.push({
        id: 'tpm',
        label: 'TPM 2.0',
        icon: mdiChip,
        status: tpmStatus,
        statusType: tpmStatusType,
        view: 'tpm',
      });
    }

    // Barrier encryption status card.
    if (barrierInfo) {
      let barrierStatus: string;
      let barrierStatusType: StatusCard['statusType'];
      if (!barrierInfo.initialized) {
        barrierStatus = 'Not Configured';
        barrierStatusType = 'warning';
      } else if (barrierInfo.sealed) {
        barrierStatus = 'Sealed';
        barrierStatusType = 'disconnected';
      } else {
        barrierStatus = 'Unsealed';
        barrierStatusType = 'verified';
      }
      statusCards.push({
        id: 'barrier',
        label: 'Barrier',
        icon: mdiShieldLockOutline,
        status: barrierStatus,
        statusType: barrierStatusType,
        view: 'seal',
      });
    }

    // Load recent audit events.
    if (isWailsAvailable()) {
      const auditResult = await callBackend<Array<{
        timestamp: string;
        operation: string;
        backend: string;
        key_id: string;
        device_name: string;
        device_id: string;
        success: boolean;
        error?: string;
      }>>('AuditService', 'GetEntries', {});
      if (auditResult && auditResult.length > 0) {
        recentActivity = auditResult
          .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
          .slice(0, 5)
          .map((e, i) => ({
            id: `dash-audit-${i}`,
            type: e.operation,
            title: e.operation,
            description: e.error || `${e.operation} on ${e.backend || 'local'}`,
            timestamp: e.timestamp,
            icon: auditIcon(e.operation),
            success: e.success,
          }));
      }
    }
  });
</script>

<div class="dashboard">
  <GradientHeader title="xKey" subtitle="Virtual Security Key">
    <div class="header-badges">
      {#if appStatus}
        <span class="text-label-small version-badge">v{appStatus.version}</span>
        <StatusBadge status={appStatus.mode === 'xkmsd' ? 'connected' : 'neutral'} />
      {/if}
    </div>
  </GradientHeader>

  <div class="dashboard-content">
    <!-- Status Cards (3-column) -->
    <section class="status-grid">
      {#each statusCards as card}
        <Card variant="elevated" hoverable on:click={() => navigateTo(card.view)}>
          <div class="status-card-inner">
            <div class="status-card-icon">
              <Icon path={card.icon} size={24} />
            </div>
            <div class="status-card-info">
              <span class="text-label-large status-card-label">{card.label}</span>
              <span class="text-body-small status-card-status">{card.status}</span>
            </div>
            <StatusBadge status={card.statusType} />
          </div>
        </Card>
      {/each}
    </section>

    <!-- Barrier Detail (compact) -->
    {#if barrierInfo?.initialized}
      <section class="barrier-detail">
        <Card variant="outlined" hoverable on:click={() => navigateTo('seal')}>
          <div class="barrier-detail-inner">
            <div class="barrier-detail-icon">
              <Icon path={mdiShieldLockOutline} size={20} />
            </div>
            <div class="barrier-detail-info">
              <span class="text-label-large">Barrier Encryption</span>
              <span class="text-body-small barrier-detail-meta">
                {barrierInfo.strategy_label || barrierInfo.strategy || 'Unknown'}
              </span>
            </div>
            {#if barrierInfo.hardware_backed}
              <span class="barrier-hw-badge">
                <Icon path={mdiChip} size={12} />
                Hardware
              </span>
            {/if}
            <StatusBadge status={barrierInfo.sealed ? 'disconnected' : 'verified'} />
          </div>
        </Card>
      </section>
    {/if}

    <!-- Unseal Dialog -->
    <UnsealDialog
      bind:open={showUnsealDialog}
      strategy={appStatus?.seal_strategy || 'software'}
      on:close={() => (showUnsealDialog = false)}
      on:success={handleUnsealSuccess}
    />

    <!-- Key Inventory -->
    {#if appStatus}
      <section class="key-inventory-section">
        <Card variant="outlined">
          <div class="key-inventory">
            <h2 class="text-title-medium inventory-title">Key Inventory</h2>
            <div class="inventory-stats">
              <div class="inventory-stat" on:click={() => navigateTo('oath')} role="button" tabindex="0" on:keypress={() => navigateTo('oath')}>
                <Icon path={mdiNumeric} size={20} />
                <div class="stat-content">
                  <span class="text-headline-small stat-number">{appStatus.oath_account_count}</span>
                  <span class="text-label-small stat-label">OATH Accounts</span>
                </div>
              </div>
              <div class="inventory-divider"></div>
              <div class="inventory-stat" on:click={() => navigateTo('fido2')} role="button" tabindex="0" on:keypress={() => navigateTo('fido2')}>
                <Icon path={mdiFingerprint} size={20} />
                <div class="stat-content">
                  <span class="text-headline-small stat-number">{appStatus.fido2_cred_count}</span>
                  <span class="text-label-small stat-label">FIDO2 Credentials</span>
                </div>
              </div>
              <div class="inventory-divider"></div>
              <div class="inventory-stat" on:click={() => navigateTo('piv')} role="button" tabindex="0" on:keypress={() => navigateTo('piv')}>
                <Icon path={mdiCertificate} size={20} />
                <div class="stat-content">
                  <span class="text-headline-small stat-number">{appStatus.piv_cert_count}</span>
                  <span class="text-label-small stat-label">PIV Certificates</span>
                </div>
              </div>
              <div class="inventory-divider"></div>
              <div class="inventory-stat" on:click={() => navigateTo('keys')} role="button" tabindex="0" on:keypress={() => navigateTo('keys')}>
                <Icon path={mdiCloudOutline} size={20} />
                <div class="stat-content">
                  <span class="text-headline-small stat-number">{appStatus.remote_key_count}</span>
                  <span class="text-label-small stat-label">Remote Keys</span>
                </div>
              </div>
            </div>
          </div>
        </Card>
      </section>
    {/if}

    <!-- Recent Activity -->
    <section class="activity-section">
      <div class="activity-header">
        <h2 class="text-title-medium section-title">Recent Activity</h2>
        {#if recentActivity.length > 0}
          <button class="view-all-link text-label-medium" on:click={() => navigateTo('audit-log')}>View All</button>
        {/if}
      </div>
      <div class="activity-list">
        {#each recentActivity as event}
          <div class="activity-item" class:activity-success={event.success} class:activity-failure={!event.success}>
            <div class="activity-icon">
              <Icon path={event.icon} size={18} />
            </div>
            <div class="activity-info">
              <span class="text-title-small">{event.title}</span>
              <span class="text-body-small activity-desc">{event.description}</span>
            </div>
            <span class="text-body-small activity-time">{formatRelativeTime(event.timestamp)}</span>
          </div>
        {/each}
        {#if recentActivity.length === 0}
          <p class="text-body-medium activity-empty">No recent activity</p>
        {/if}
      </div>
    </section>

    <!-- System Info Footer -->
    {#if appStatus}
      <footer class="system-info">
        <span class="text-body-small info-item">v{appStatus.version}</span>
        <span class="text-body-small info-item">{appStatus.platform}</span>
        <span class="text-body-small info-item">{appStatus.go_version}</span>
        <span class="text-body-small info-item">Uptime: {appStatus.uptime}</span>
      </footer>
    {/if}
  </div>
</div>

<style>
  .dashboard {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .header-badges {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .version-badge {
    color: rgba(255, 255, 255, 0.8);
    background: rgba(255, 255, 255, 0.15);
    padding: 2px 8px;
    border-radius: var(--radius-full);
  }

  .dashboard-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  .status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
  }

  .status-card-inner {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .status-card-icon {
    width: 44px;
    height: 44px;
    border-radius: var(--radius-md);
    background: var(--gradient-primary);
    color: #FFFFFF;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .status-card-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .status-card-label {
    color: var(--color-on-surface);
  }

  .status-card-status {
    color: var(--color-on-surface-variant);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* Key Inventory */
  .key-inventory {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .inventory-title {
    margin: 0;
    color: var(--color-on-surface);
  }

  .inventory-stats {
    display: flex;
    align-items: center;
    gap: 0;
  }

  .inventory-stat {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-radius: var(--radius-md);
    cursor: pointer;
    transition: background-color var(--transition-fast);
    color: var(--color-on-surface-variant);
  }

  .inventory-stat:hover {
    background-color: var(--color-surface-container-low);
  }

  .stat-content {
    display: flex;
    flex-direction: column;
  }

  .stat-number {
    color: var(--color-on-surface);
    line-height: 1.2;
  }

  .stat-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .inventory-divider {
    width: 1px;
    height: 40px;
    background-color: var(--color-outline-variant);
    flex-shrink: 0;
  }

  .activity-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .view-all-link {
    background: none;
    border: none;
    color: var(--color-primary);
    cursor: pointer;
    padding: 4px 8px;
    border-radius: var(--radius-sm);
    transition: background-color var(--transition-fast);
    font-family: var(--font-sans);
  }

  .view-all-link:hover {
    background-color: var(--color-primary-95);
  }

  .section-title {
    margin: 0 0 16px 0;
    color: var(--color-on-surface);
  }

  .activity-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .activity-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 12px;
    border-radius: var(--radius-md);
    transition: background-color var(--transition-fast);
  }

  .activity-item:hover {
    background-color: var(--color-surface-container-low);
  }

  .activity-icon {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .activity-success .activity-icon {
    background-color: var(--color-security-verified-container);
    color: var(--color-security-verified);
  }

  .activity-failure .activity-icon {
    background-color: var(--color-security-danger-container);
    color: var(--color-security-danger);
  }

  .activity-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .activity-info span:first-child {
    color: var(--color-on-surface);
  }

  .activity-desc {
    color: var(--color-on-surface-variant);
  }

  .activity-time {
    color: var(--color-on-surface-variant);
    flex-shrink: 0;
  }

  .activity-empty {
    color: var(--color-on-surface-variant);
    text-align: center;
    padding: 24px;
    margin: 0;
  }

  /* System Info Footer */
  .system-info {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 12px 0;
    border-top: 1px solid var(--color-outline-variant);
  }

  .info-item {
    color: var(--color-on-surface-variant);
  }

  .info-item + .info-item::before {
    content: '';
    display: none;
  }

  /* Barrier Detail */
  .barrier-detail-inner {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .barrier-detail-icon {
    width: 36px;
    height: 36px;
    border-radius: var(--radius-md);
    background: var(--color-tertiary-container, #e8def8);
    color: var(--color-on-tertiary-container, #1d192b);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .barrier-detail-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .barrier-detail-info .text-label-large {
    color: var(--color-on-surface);
  }

  .barrier-detail-meta {
    color: var(--color-on-surface-variant);
  }

  .barrier-hw-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    background-color: var(--color-tertiary-container, #e8def8);
    color: var(--color-on-tertiary-container, #1d192b);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    flex-shrink: 0;
  }

  @media (max-width: 1000px) {
    .status-grid {
      grid-template-columns: 1fr;
    }

    .inventory-stats {
      flex-wrap: wrap;
    }

    .inventory-divider {
      display: none;
    }
  }
</style>
