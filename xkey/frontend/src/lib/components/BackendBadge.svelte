<script lang="ts">
  /**
   * BackendBadge renders a small, consistently-styled label for a crypto
   * backend (software / tpm2 / pkcs11 / cloud / xkms). It is the single badge
   * primitive for the whole app — colors, icon, and label come from
   * lib/utils/backends.ts so every page looks identical.
   */
  import Icon from './Icon.svelte';
  import {
    getBackendLabel,
    getBackendIcon,
    getBackendColor,
    isHardwareBackend,
  } from '$lib/utils/backends';

  /** The backend id (e.g. "software", "tpm2", "pkcs11", "awskms"). */
  export let backend: string;
  /** Hide the icon for a more compact badge. */
  export let showIcon = true;
  /** Show a small "HW" marker for hardware-backed backends. */
  export let showHardware = false;
  /** Smaller padding/font. */
  export let compact = false;

  $: color = getBackendColor(backend);
  $: label = getBackendLabel(backend);
  $: icon = getBackendIcon(backend);
  $: hardware = isHardwareBackend(backend);
</script>

<span
  class="backend-badge"
  class:compact
  style="background-color: {color.bg}; color: {color.fg};"
  data-backend={backend}
  title={hardware ? `${label} (hardware-backed)` : label}
>
  {#if showIcon}
    <Icon path={icon} size={compact ? 12 : 14} />
  {/if}
  <span class="backend-badge-label">{label}</span>
  {#if showHardware && hardware}
    <span class="backend-badge-hw">HW</span>
  {/if}
</span>

<style>
  .backend-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: var(--text-label-small, 0.75rem);
    font-weight: 500;
    line-height: 1.4;
    white-space: nowrap;
    vertical-align: middle;
  }

  .backend-badge.compact {
    padding: 1px 6px;
    gap: 2px;
    font-size: 0.7rem;
  }

  .backend-badge-label {
    font-weight: 500;
  }

  .backend-badge-hw {
    font-size: 0.6rem;
    font-weight: 700;
    opacity: 0.75;
    letter-spacing: 0.04em;
  }
</style>
