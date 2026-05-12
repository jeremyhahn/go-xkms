<script lang="ts">
  import Card from '@trustedca/shared/components/Card.svelte';
  import Tabs from '@trustedca/shared/components/Tabs.svelte';

  let activeTab = 'http-01';

  const tabs = [
    { label: 'HTTP-01', value: 'http-01' },
    { label: 'DNS-01', value: 'dns-01' },
    { label: 'TLS-ALPN-01', value: 'tls-alpn-01' },
    { label: 'Endorse-01', value: 'endorse-01' },
    { label: 'Enroll-01', value: 'enroll-01' },
    { label: 'Device-Attest-01', value: 'device-attest-01' },
  ];

  function handleTabChange(event: CustomEvent<string>) {
    activeTab = event.detail;
  }
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Challenge Configuration
  </h1>

  <div class="max-w-2xl">
    <Tabs {tabs} {activeTab} on:change={handleTabChange}>
      {#if activeTab === 'http-01'}
        <Card title="HTTP-01 Challenge" subtitle="Prove domain control via HTTP well-known path">
          <div class="space-y-3">
            <p class="text-sm text-slate-600 dark:text-slate-400">
              The HTTP-01 challenge requires the ACME client to serve a token at
              <code class="rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-700">
                http://DOMAIN/.well-known/acme-challenge/TOKEN
              </code>.
            </p>
            <p class="text-sm text-slate-600 dark:text-slate-400">
              This is the simplest challenge type and works for most use cases
              where port 80 is accessible.
            </p>
          </div>
        </Card>

      {:else if activeTab === 'dns-01'}
        <Card title="DNS-01 Challenge" subtitle="Prove domain control via DNS TXT record">
          <div class="space-y-3">
            <p class="text-sm text-slate-600 dark:text-slate-400">
              The DNS-01 challenge requires creating a TXT record at
              <code class="rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-700">
                _acme-challenge.DOMAIN
              </code>.
              This supports wildcard certificates.
            </p>
          </div>
        </Card>

      {:else if activeTab === 'tls-alpn-01'}
        <Card title="TLS-ALPN-01 Challenge" subtitle="Prove domain control via TLS ALPN extension">
          <div class="space-y-3">
            <p class="text-sm text-slate-600 dark:text-slate-400">
              The TLS-ALPN-01 challenge uses the ACME TLS Application-Layer Protocol
              Negotiation extension on port 443. Useful when port 80 is not available.
            </p>
          </div>
        </Card>

      {:else if activeTab === 'endorse-01'}
        <Card title="Endorse-01 Challenge" subtitle="TPM endorsement-based device identity verification">
          <div class="space-y-3">
            <p class="text-sm text-slate-600 dark:text-slate-400">
              The endorse-01 challenge verifies device identity using the TPM
              Endorsement Key certificate. This enables hardware-bound certificate
              issuance for trusted devices.
            </p>
            <p class="text-sm text-slate-600 dark:text-slate-400">
              Requires an EAB credential created with the "endorse-01" purpose.
            </p>
          </div>
        </Card>

      {:else if activeTab === 'enroll-01'}
        <Card title="Enroll-01 Challenge" subtitle="TPM enrollment and attestation-based provisioning">
          <div class="space-y-3">
            <p class="text-sm text-slate-600 dark:text-slate-400">
              The enroll-01 challenge combines TPM enrollment with platform
              attestation to issue certificates only to devices with verified
              firmware and software configurations.
            </p>
            <p class="text-sm text-slate-600 dark:text-slate-400">
              Requires the device to submit a valid TPM quote and pass
              compliance policy checks.
            </p>
          </div>
        </Card>

      {:else if activeTab === 'device-attest-01'}
        <Card title="Device-Attest-01 Challenge" subtitle="TPM quote-based platform attestation">
          <div class="space-y-3">
            <p class="text-sm text-slate-600 dark:text-slate-400">
              The device-attest-01 challenge binds a certificate to a TPM-resident
              Attestation Key by verifying a fresh TPM quote against a server-issued
              nonce. Use this to prove runtime platform integrity during certificate
              issuance.
            </p>
            <p class="text-sm text-slate-600 dark:text-slate-400">
              Submit the AK name, quote, signature, and PCR values via the
              <code class="rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-700">
                Device Attest
              </code>
              view.
            </p>
          </div>
        </Card>
      {/if}
    </Tabs>
  </div>
</div>
