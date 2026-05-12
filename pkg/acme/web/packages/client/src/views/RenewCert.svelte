<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import { clientApi } from '../lib/api/client-api';

  let specName = '';
  let specs: string[] = [];
  let loading = false;

  async function loadSpecs() {
    try {
      const data = await clientApi.listCertificates();
      specs = Object.keys(data).sort();
      if (!specName && specs.length > 0) specName = specs[0];
    } catch (e) {
      notifyError(`Failed to load certificate specs: ${(e as Error).message}`);
    }
  }

  async function handleRenew() {
    if (!specName) return;

    loading = true;
    try {
      const res = await clientApi.renewCertificate({ name: specName });
      notifySuccess(`Certificate renewed for "${res.subject || specName}"`);
    } catch (e) {
      notifyError(`Renewal failed: ${(e as Error).message}`);
    } finally {
      loading = false;
    }
  }

  onMount(loadSpecs);
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Renew Certificate
  </h1>

  <div class="max-w-xl">
    <Card title="Certificate Renewal" subtitle="Renew an existing managed certificate">
      <form class="space-y-4" on:submit|preventDefault={handleRenew}>
        <FormField
          label="Certificate Spec"
          required
          hint="Select the managed spec whose certificate should be renewed"
          id="renew-spec"
        >
          {#if specs.length === 0}
            <input
              id="renew-spec"
              class="input"
              type="text"
              bind:value={specName}
              placeholder="web-demo"
              required
            />
          {:else}
            <select id="renew-spec" class="select" bind:value={specName} required>
              {#each specs as s}
                <option value={s}>{s}</option>
              {/each}
            </select>
          {/if}
        </FormField>

        <Button type="submit" variant="primary" {loading} disabled={!specName}>
          Renew Certificate
        </Button>
      </form>
    </Card>
  </div>
</div>
