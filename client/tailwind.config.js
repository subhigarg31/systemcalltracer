/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        charcoal: {
          950: '#07090e',
          900: '#0c1017',
          850: '#111722',
          800: '#161f2e',
          700: '#1f2b3e',
          600: '#2e3d55'
        },
        slate: {
          750: '#263346',
          850: '#172233'
        },
        sec: {
          critical: '#ef4444',
          high: '#f97316',
          guarded: '#eab308',
          low: '#10b981',
          muted: '#64748b'
        }
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace']
      }
    },
  },
  plugins: [],
}
