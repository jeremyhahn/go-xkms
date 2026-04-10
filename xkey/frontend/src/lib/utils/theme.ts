/**
 * Theme utility functions for CSS variable manipulation and system detection.
 */

/**
 * Returns the current effective theme by reading the data-theme attribute
 * from the document root element.
 */
export function getCurrentTheme(): 'light' | 'dark' {
  if (typeof document === 'undefined') return 'light';
  const attr = document.documentElement.getAttribute('data-theme');
  return attr === 'dark' ? 'dark' : 'light';
}

/**
 * Returns true if the user's operating system prefers dark mode.
 */
export function systemPrefersDark(): boolean {
  if (typeof window === 'undefined') return false;
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

/**
 * Reads a CSS custom property value from the document root.
 */
export function getCSSVariable(name: string): string {
  if (typeof document === 'undefined') return '';
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/**
 * Sets a CSS custom property value on the document root.
 */
export function setCSSVariable(name: string, value: string): void {
  if (typeof document === 'undefined') return;
  document.documentElement.style.setProperty(name, value);
}

/**
 * Removes a custom CSS property override from the document root,
 * allowing the stylesheet value to take precedence.
 */
export function removeCSSVariable(name: string): void {
  if (typeof document === 'undefined') return;
  document.documentElement.style.removeProperty(name);
}

/**
 * Returns the computed color value for a given semantic color name.
 * For example, getSemanticColor('primary') reads --color-primary.
 */
export function getSemanticColor(name: string): string {
  return getCSSVariable(`--color-${name}`);
}

/**
 * Returns the computed gradient value for a given gradient name.
 * For example, getGradient('primary') reads --gradient-primary.
 */
export function getGradient(name: string): string {
  return getCSSVariable(`--gradient-${name}`);
}

/**
 * Converts a hex color to an rgba string with the given opacity.
 */
export function hexToRgba(hex: string, opacity: number): string {
  const cleaned = hex.replace('#', '');
  const r = parseInt(cleaned.substring(0, 2), 16);
  const g = parseInt(cleaned.substring(2, 4), 16);
  const b = parseInt(cleaned.substring(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${opacity})`;
}

/**
 * Returns appropriate text color (light or dark) for a given background color.
 * Uses relative luminance calculation per WCAG guidelines.
 */
export function contrastTextColor(bgHex: string): 'light' | 'dark' {
  const cleaned = bgHex.replace('#', '');
  const r = parseInt(cleaned.substring(0, 2), 16) / 255;
  const g = parseInt(cleaned.substring(2, 4), 16) / 255;
  const b = parseInt(cleaned.substring(4, 6), 16) / 255;

  const linearize = (c: number) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
  const luminance = 0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b);

  return luminance > 0.179 ? 'dark' : 'light';
}
