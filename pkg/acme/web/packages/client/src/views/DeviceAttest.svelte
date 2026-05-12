<script lang="ts">
  import Card from '@trustedca/shared/components/Card.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import { clientApi } from '../lib/api/client-api';

  let akName = '';
  let quote = '';
  let signature = '';
  let nonce = '';
  let pcrValuesText = '';
  let loading = false;

  async function handleAttest() {
    if (!akName || !quote || !signature || !nonce) return;

    const pcrValues: Record<string, string> = {};
    if (pcrValuesText.trim()) {
      for (const line of pcrValuesText.split('\n')) {
        const [key, value] = line.split('=').map((s) => s.trim());
        if (key && value) {
          pcrValues[key] = value;
        }
      }
    }

    loading = true;
    try {
      const res = await clientApi.deviceAttest({
        ak_name: akName,
        quote,
        signature,
        pcr_values: pcrValues,
        nonce,
      });
      notifySuccess(`Attestation ${res.status}`);
    } catch (e) {
      notifyError(`Attestation failed: ${(e as Error).message}`);
    } finally {
      loading = false;
    }
  }
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Device Attestation
  </h1>

  <div class="max-w-xl">
    <Card title="TPM Attestation" subtitle="Submit a TPM quote for platform attestation">
      <form class="space-y-4" on:submit|preventDefault={handleAttest}>
        <FormField label="AK Name" required id="attest-ak-name">
          <input
            id="attest-ak-name"
            class="input font-mono"
            type="text"
            bind:value={akName}
            required
          />
        </FormField>

        <FormField label="Nonce" required hint="Server-provided attestation nonce" id="attest-nonce">
          <input
            id="attest-nonce"
            class="input font-mono"
            type="text"
            bind:value={nonce}
            required
          />
        </FormField>

        <FormField label="Quote" required hint="Base64-encoded TPM quote" id="attest-quote">
          <textarea
            id="attest-quote"
            class="input font-mono text-xs"
            rows="3"
            bind:value={quote}
            required
          ></textarea>
        </FormField>

        <FormField label="Signature" required hint="Base64-encoded quote signature" id="attest-sig">
          <textarea
            id="attest-sig"
            class="input font-mono text-xs"
            rows="3"
            bind:value={signature}
            required
          ></textarea>
        </FormField>

        <FormField label="PCR Values" hint="One per line: PCR_INDEX=HEX_VALUE" id="pcr-values">
          <textarea
            id="pcr-values"
            class="input font-mono text-xs"
            rows="4"
            bind:value={pcrValuesText}
            placeholder="0=abc123...&#10;7=def456..."
          ></textarea>
        </FormField>

        <Button type="submit" variant="primary" {loading} disabled={!akName || !quote || !signature || !nonce}>
          Submit Attestation
        </Button>
      </form>
    </Card>
  </div>
</div>
