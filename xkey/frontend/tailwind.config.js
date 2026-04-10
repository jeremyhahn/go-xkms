/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        // Primary: Deep Navy
        primary: {
          DEFAULT: '#1A237E',
          variant: '#0D1442',
          container: '#DEE0FF',
          10: '#00006E',
          20: '#0D1442',
          30: '#1A237E',
          40: '#303F9F',
          50: '#3949AB',
          60: '#5C6BC0',
          70: '#7986CB',
          80: '#9FA8DA',
          90: '#C5CAE9',
          95: '#DEE0FF',
          99: '#FEFBFF',
        },
        // Secondary: Warm Gold
        secondary: {
          DEFAULT: '#FFB300',
          variant: '#C68400',
          container: '#FFDEA6',
          10: '#271900',
          20: '#3E2800',
          30: '#5C3D00',
          40: '#7C5500',
          50: '#9E6D00',
          60: '#C68400',
          70: '#FFB300',
          80: '#FFCA47',
          90: '#FFDEA6',
          95: '#FFEFD4',
          99: '#FFFBFF',
        },
        // Tertiary: Rich Teal
        tertiary: {
          DEFAULT: '#00897B',
          variant: '#00695C',
          container: '#A7F3EC',
          10: '#002020',
          20: '#003D3A',
          30: '#00695C',
          40: '#00897B',
          50: '#00A99B',
          60: '#26BFAC',
          70: '#4DD0C5',
          80: '#7DE0D8',
          90: '#A7F3EC',
          95: '#C8FFF8',
          99: '#F2FFFC',
        },
        // Surface
        surface: {
          DEFAULT: '#FFFBFE',
          dim: '#DED8E1',
          bright: '#FFFBFE',
          'container-lowest': '#FFFFFF',
          'container-low': '#F7F2FA',
          container: '#F3EDF7',
          'container-high': '#ECE6F0',
          'container-highest': '#E6E0E9',
          variant: '#E7E0EC',
        },
        // Background
        background: '#FFFBFE',
        'on-background': '#1C1B1F',
        'on-surface': '#1C1B1F',
        'on-surface-variant': '#49454F',
        // Error
        error: {
          DEFAULT: '#BA1A1A',
          container: '#FFDAD6',
        },
        // Security Status
        security: {
          verified: '#1B8A50',
          'verified-container': '#C8F5D0',
          warning: '#E6A700',
          'warning-container': '#FFEFD4',
          danger: '#C62828',
          'danger-container': '#FFDAD6',
          neutral: '#6B7280',
          'neutral-container': '#E5E7EB',
        },
        // Connection Status
        status: {
          connected: '#1B8A50',
          disconnected: '#6B7280',
          advertising: '#E6A700',
          error: '#C62828',
          pairing: '#5C6BC0',
        },
        // Outline
        outline: {
          DEFAULT: '#79747E',
          variant: '#CAC4D0',
        },
      },
      borderRadius: {
        'xkey-sm': '8px',
        'xkey-md': '12px',
        'xkey-lg': '16px',
        'xkey-xl': '24px',
      },
      boxShadow: {
        'xkey-sm': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        'xkey-md': '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        'xkey-lg': '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
        'xkey-xl': '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
};
