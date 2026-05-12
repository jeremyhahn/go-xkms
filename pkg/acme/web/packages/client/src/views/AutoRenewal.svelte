<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import StatusBadge from '@trustedca/shared/components/StatusBadge.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import { renewalStatus, renewalConfig, acmeLoading, fetchRenewalStatus, fetchRenewalConfig } from '../lib/stores/acme';
  import { clientApi } from '../lib/api/client-api';

  let enabled = false;
  // checkInterval is displayed as-is from the Go duration string (e.g. "24h0m0s").
  // On save we send it back as a duration string.
  let checkInterval = '24h0m0s';
  let renewalThreshold = 0.33;
  let saving = false;

  async function handleSave() {
    saving = true;
    try {
      await clientApi.updateRenewalConfig({
        enabled,
        checkInterval,
        renewalThreshold,
      });
      notifySuccess('Renewal configuration saved');
      await fetchRenewalConfig();
    } catch (e) {
      notifyError(`Failed to save: ${(e as Error).message}`);
    } finally {
      saving = false;
    }
  }

  onMount(async () => {
    await Promise.all([fetchRenewalStatus(), fetchRenewalConfig()]);
    if ($renewalConfig) {
      enabled = $renewalConfig.enabled;
      checkInterval = $renewalConfig.checkInterval;
      renewalThreshold = $renewalConfig.renewalThreshold;
    }
  });
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Auto-Renewal
  </h1>

  {#if $acmeLoading}
    <div class="flex items-center justify-center py-20">
      <LoadingSpinner size="lg" />
    </div>
  {:else}
    <div class="max-w-2xl space-y-6">
      <Card title="Renewal Configuration">
        <form class="space-y-4" on:submit|preventDefault={handleSave}>
          <div class="flex items-center gap-3">
            <input
              id="auto-renew-enabled"
              type="checkbox"
              bind:checked={enabled}
              class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 dark:border-slate-600 dark:bg-slate-700"
            />
            <label for="auto-renew-enabled" class="text-sm font-medium text-slate-700 dark:text-slate-300">
              Enable automatic certificate renewal
            </label>
          </div>

          <FormField label="Check Interval" hint="Go duration string, e.g. 24h0m0s or 12h30m" id="check-interval">
            <input
              id="check-interval"
              class="input"
              type="text"
              bind:value={checkInterval}
              placeholder="24h0m0s"
            />
          </FormField>

          <FormField label="Renewal Threshold" hint="Fraction of lifetime remaining at which renewal triggers (e.g. 0.33 renews ~30 days before expiry on a 90-day cert)" id="renewal-threshold">
            <input
              id="renewal-threshold"
              class="input"
              type="number"
              min="0.01"
              max="0.99"
              step="0.01"
              bind:value={renewalThreshold}
            />
          </FormField>

          <Button type="submit" variant="primary" loading={saving}>
            Save Configuration
          </Button>
        </form>
      </Card>

      {#if $renewalStatus}
        <Card title="Renewal Status">
          <div class="space-y-3">
            <div class="flex items-center gap-2">
              <StatusBadge status={$renewalStatus.enabled ? 'active' : 'pending'} />
              <span class="text-sm text-slate-700 dark:text-slate-300">
                {$renewalStatus.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Check Interval</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {$renewalStatus.checkInterval}
              </p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Renewal Threshold</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {$renewalStatus.renewalThreshold}
              </p>
            </div>
          </div>
        </Card>
      {/if}
    </div>
  {/if}
</div>
