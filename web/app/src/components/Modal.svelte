<script module lang="ts">
  // Shared with the two panels that are drawer-styled (a fixed overlay +
  // slide-in panel, not a native <dialog>) but function as a modal all the
  // same: KeyDetail and CertificatesView's certificate detail panel. Both
  // need the same Escape-to-close, focus-trap, and focus-restore behaviour
  // Modal gives native dialogs, but a plain positioned <div> has none of
  // that for free — this action is the equivalent for that case, exposed as
  // a Svelte action (`use:drawerA11y`) so a non-<dialog> element can opt in
  // without duplicating the trap/restore logic per call site.
  const focusableSelector =
    'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

  /** trapFocusIn wraps Tab at the boundary of container's focusable descendants. */
  function trapFocusIn(container: HTMLElement, e: KeyboardEvent): void {
    const focusables = Array.from(container.querySelectorAll<HTMLElement>(focusableSelector));
    if (focusables.length === 0) return;
    const first = focusables[0]!;
    const last = focusables[focusables.length - 1]!;
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  export function drawerA11y(node: HTMLElement, params: { onClose: () => void }) {
    let current = params;
    const previouslyFocused = document.activeElement as HTMLElement | null;

    const initial = node.querySelector<HTMLElement>(focusableSelector) ?? node;
    initial.focus();

    function onKeydown(e: KeyboardEvent): void {
      if (e.key === "Escape") {
        e.preventDefault();
        current.onClose();
        return;
      }
      if (e.key === "Tab") trapFocusIn(node, e);
    }

    node.addEventListener("keydown", onKeydown);

    return {
      update(next: { onClose: () => void }) {
        current = next;
      },
      destroy() {
        node.removeEventListener("keydown", onKeydown);
        previouslyFocused?.focus();
      },
    };
  }
</script>

<script lang="ts">
  // A thin wrapper around the native <dialog> element. Calling showModal()/
  // close() (rather than only toggling a CSS class) is what gives the
  // browser's own top-layer stacking, focus trap, and Escape-to-close for
  // free — daisyUI's modal CSS already targets `.modal[open]` alongside
  // `.modal.modal-open` (see node_modules/daisyui/components/modal.css), so
  // driving the element natively needs no styling changes.
  //
  // jsdom (the unit-test DOM) implements the `open` reflected property but
  // not showModal()/close() or the cancel/close events they drive, so both
  // are feature-detected; the manual Escape/Tab handling below is what
  // exercises this component under jsdom and doubles as a safety net for
  // any environment lacking full <dialog> support.
  import type { Snippet } from "svelte";

  interface Props {
    open: boolean;
    onClose: () => void;
    labelledby?: string;
    class?: string;
    boxClass?: string;
    children: Snippet;
  }
  let {
    open,
    onClose,
    labelledby,
    class: dialogClass = "modal",
    boxClass = "modal-box",
    children,
  }: Props = $props();

  let dialogEl = $state<HTMLDialogElement | undefined>(undefined);
  let previouslyFocused: HTMLElement | null = null;

  // focusableSelector is declared once in the module block above, shared
  // with the drawerA11y action.
  function focusFirst(): void {
    if (!dialogEl) return;
    const target = dialogEl.querySelector<HTMLElement>(focusableSelector) ?? dialogEl;
    target.focus();
  }

  // The cleanup returned here runs both when `open` flips back to false and
  // when this component is torn down outright (a parent that gates the
  // whole Modal behind an {#if} rather than an `open` prop) — Svelte runs
  // effect cleanups on unmount too, so focus restoration is not missed
  // just because the dialog never saw open transition to false.
  $effect(() => {
    if (!dialogEl || !open) return;
    previouslyFocused = document.activeElement as HTMLElement | null;
    if (typeof dialogEl.showModal === "function") {
      if (!dialogEl.open) dialogEl.showModal();
    } else {
      // jsdom fallback — see module comment.
      dialogEl.open = true;
    }
    focusFirst();

    return () => {
      if (!dialogEl?.open) return;
      if (typeof dialogEl.close === "function") {
        dialogEl.close();
      } else {
        dialogEl.open = false;
      }
      previouslyFocused?.focus();
      previouslyFocused = null;
    };
  });

  // Native <dialog> fires 'close' for every closing path once showModal()
  // support is present (Escape, form[method=dialog], or an explicit
  // close() call) — treat it as the single source of truth so the parent's
  // `open` state is told about closes it did not itself initiate. Guarded
  // on `open` so this does not re-fire onClose for a close we already
  // triggered ourselves from the effect above.
  function handleClose(): void {
    if (open) onClose();
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === "Escape" && typeof dialogEl?.close !== "function") {
      // Real browsers turn Escape into a native 'close' event, handled by
      // handleClose above; this branch only runs where that is unavailable.
      e.preventDefault();
      onClose();
      return;
    }
    if (e.key === "Tab" && dialogEl) trapFocusIn(dialogEl, e);
  }
</script>

<dialog
  bind:this={dialogEl}
  class={dialogClass}
  aria-labelledby={labelledby}
  onclose={handleClose}
  onkeydown={handleKeydown}
>
  <div class={boxClass}>
    {@render children()}
  </div>
</dialog>
