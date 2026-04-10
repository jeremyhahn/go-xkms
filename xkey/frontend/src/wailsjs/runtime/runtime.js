/**
 * Wails runtime bridge.
 *
 * During wails dev/build the real runtime is injected at window.runtime.
 * These re-exports bridge the module import path to the global runtime
 * so that both ESM imports and direct window.runtime access work.
 */

function getRuntime() {
  if (typeof window !== 'undefined' && window.runtime) {
    return window.runtime;
  }
  return null;
}

export function EventsOn(event, callback) {
  const rt = getRuntime();
  if (rt) return rt.EventsOn(event, callback);
}

export function EventsOff(event) {
  const rt = getRuntime();
  if (rt) return rt.EventsOff(event);
}

export function EventsEmit(event, ...data) {
  const rt = getRuntime();
  if (rt) return rt.EventsEmit(event, ...data);
}

export function LogDebug(message) {
  const rt = getRuntime();
  if (rt) return rt.LogDebug(message);
}

export function LogInfo(message) {
  const rt = getRuntime();
  if (rt) return rt.LogInfo(message);
}

export function LogWarning(message) {
  const rt = getRuntime();
  if (rt) return rt.LogWarning(message);
}

export function LogError(message) {
  const rt = getRuntime();
  if (rt) return rt.LogError(message);
}

export function WindowSetTitle(title) {
  const rt = getRuntime();
  if (rt) return rt.WindowSetTitle(title);
}

export function WindowMinimise() {
  const rt = getRuntime();
  if (rt) return rt.WindowMinimise();
}

export function WindowMaximise() {
  const rt = getRuntime();
  if (rt) return rt.WindowMaximise();
}

export function WindowUnmaximise() {
  const rt = getRuntime();
  if (rt) return rt.WindowUnmaximise();
}

export function WindowToggleMaximise() {
  const rt = getRuntime();
  if (rt) return rt.WindowToggleMaximise();
}

export function WindowFullscreen() {
  const rt = getRuntime();
  if (rt) return rt.WindowFullscreen();
}

export function WindowUnfullscreen() {
  const rt = getRuntime();
  if (rt) return rt.WindowUnfullscreen();
}

export function WindowCenter() {
  const rt = getRuntime();
  if (rt) return rt.WindowCenter();
}

export function WindowReload() {
  const rt = getRuntime();
  if (rt) return rt.WindowReload();
}

export function Quit() {
  const rt = getRuntime();
  if (rt) return rt.Quit();
}
