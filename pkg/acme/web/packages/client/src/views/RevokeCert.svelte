<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import { clientApi } from '../lib/api/client-api';

  let specName = '';
  let specs: string[] = [];
  let reason = 0;
  let loading = false;

  const revocationReasons = [
    { value: 0, label: 'Unspecified' },
    { value: 1, label: 'Key Compromise' },
    { value: 3, label: 'Affiliation Changed' },
    { value: 4, label: 'Superseded' },
    { value: 5, label: 'Cessation of Operation' },
  ];

  async function loadSpecs() {
    try {
      const data = await clientApi.listCertificates();
      specs = Object.keys(data).sort();
      if (!specName && specs.length > 0) specName = specs[0];
    } catch (e) {
      notifyError(`Failed to load certificate specs: ${(e as Error).message}`);
    }
  }

  async function handleRevoke() {
    if (!specName) return;

    loading = true;
    try {
      await clientApi.revokeCertificate({ name: specName, reason });
      notifySuccess(`Certificate "${specName}" revoked`);
    } catch (e) {
      notifyError(`Revocation failed: ${(e as Error).message}`);
    } finally {
      loading = false;
    }
  }

  onMount(loadSpecs);
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Revoke Certificate
  </h1>

  <div class="max-w-xl">
    <Card title="Certificate Revocation" subtitle="Permanently revoke a certificate">
      <form class="space-y-4" on:submit|preventDefault={handleRevoke}>
        <FormField label="Certificate Spec" required id="revoke-spec">
          {#if specs.length === 0}
            <input
              id="revoke-spec"
              class="input"
              type="text"
              bind:value={specName}
              placeholder="web-demo"
              required
            />
          {:else}
            <select id="revoke-spec" class="select" bind:value={specName} required>
              {#each specs as s}
                <option value={s}>{s}</option>
              {/each}
            </select>
          {/if}
        </FormField>

        <FormField label="Revocation Reason" id="revoke-reason">
          <select id="revoke-reason" class="select" bind:value={reason}>
            {#each revocationReasons as r}
              <option value={r.value}>{r.label}</option>
            {/each}
          </select>
        </FormField>

        <div class="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 dark:border-amber-700 dark:bg-amber-900/20">
          <p class="text-sm text-amber-800 dark:text-amber-200">
            Certificate revocation is permanent and cannot be undone.
          </p>
        </div>

        <Button type="submit" variant="danger" {loading} disabled={!specName}>
          Revoke Certificate
        </Button>
      </form>
    </Card>
  </div>
</div>
