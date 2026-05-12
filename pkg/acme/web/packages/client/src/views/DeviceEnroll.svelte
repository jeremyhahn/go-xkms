<script lang="ts">
  import Card from '@trustedca/shared/components/Card.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import { clientApi } from '../lib/api/client-api';

  let ekCertPem = '';
  let akName = '';
  let deviceId = '';
  let manufacturer = '';
  let model = '';
  let loading = false;

  async function handleEnroll() {
    if (!ekCertPem || !akName) return;

    loading = true;
    try {
      const res = await clientApi.deviceEnroll({
        ek_cert_pem: ekCertPem,
        ak_name: akName,
        device_info: deviceId ? {
          device_id: deviceId,
          manufacturer: manufacturer || undefined,
          model: model || undefined,
        } : undefined,
      });
      notifySuccess(`Device enrolled. EAB KID: ${res.eab_kid}`);
    } catch (e) {
      notifyError(`Enrollment failed: ${(e as Error).message}`);
    } finally {
      loading = false;
    }
  }
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Device Enrollment
  </h1>

  <div class="max-w-xl">
    <Card title="TPM Device Enrollment" subtitle="Enroll a device using its TPM Endorsement Key certificate">
      <form class="space-y-4" on:submit|preventDefault={handleEnroll}>
        <FormField label="EK Certificate (PEM)" required id="ek-cert">
          <textarea
            id="ek-cert"
            class="input font-mono text-xs"
            rows="6"
            bind:value={ekCertPem}
            placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
            required
          ></textarea>
        </FormField>

        <FormField label="AK Name" required hint="Attestation Key name (hex encoded)" id="ak-name">
          <input
            id="ak-name"
            class="input font-mono"
            type="text"
            bind:value={akName}
            required
          />
        </FormField>

        <FormField label="Device ID" hint="Optional device identifier" id="device-id">
          <input
            id="device-id"
            class="input"
            type="text"
            bind:value={deviceId}
          />
        </FormField>

        <div class="grid grid-cols-2 gap-4">
          <FormField label="Manufacturer" id="manufacturer">
            <input
              id="manufacturer"
              class="input"
              type="text"
              bind:value={manufacturer}
            />
          </FormField>

          <FormField label="Model" id="model">
            <input
              id="model"
              class="input"
              type="text"
              bind:value={model}
            />
          </FormField>
        </div>

        <Button type="submit" variant="primary" {loading} disabled={!ekCertPem || !akName}>
          Enroll Device
        </Button>
      </form>
    </Card>
  </div>
</div>
