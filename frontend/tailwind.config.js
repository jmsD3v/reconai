/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './lib/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        severity: {
          critical: '#ff4444',
          high: '#ff8800',
          medium: '#ffcc00',
          low: '#44aaff',
          info: '#888888',
        },
        recon: {
          bg: '#0d1117',
          card: '#161b22',
          border: '#30363d',
          red: '#ff4444',
          purple: '#8b5cf6',
          muted: '#8b949e',
          text: '#e6edf3',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'SF Mono', 'Menlo', 'Consolas', 'Liberation Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
