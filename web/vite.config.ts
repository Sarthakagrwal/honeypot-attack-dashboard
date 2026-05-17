import { defineConfig } from 'vite'

// `base` MUST match the GitHub repository name, or the deployed Project Pages
// site loads its assets from the wrong path and renders blank.
export default defineConfig({
  base: '/honeypot-attack-dashboard/',
  test: {
    environment: 'jsdom',
    globals: true,
    // The e2e/ directory holds Playwright specs — vitest must not run them.
    include: ['src/**/*.test.ts'],
    exclude: ['node_modules', 'dist', 'e2e'],
  },
})
