<script lang="ts">
  /** Test harness: renders SealPolicyPicker and shows what it binds. */
  import SealPolicyPicker from '../SealPolicyPicker.svelte';

  export let backend = 'tpm2';
  export let tpmPolicy = 'platform';
</script>

<SealPolicyPicker {backend} bind:tpmPolicy />
<span data-testid="bound-policy">{tpmPolicy}</span>
