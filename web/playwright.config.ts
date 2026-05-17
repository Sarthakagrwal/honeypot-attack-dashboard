import { defineConfig, devices } from '@playwright/test'

// E2E tests run against the *built and previewed* site (not the dev server) so
// that base-path bugs — the most common GitHub Pages failure — surface here.
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? 'line' : 'list',
  use: {
    baseURL: 'http://localhost:4173/honeypot-attack-dashboard/',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'npm run build && npm run preview',
    url: 'http://localhost:4173/honeypot-attack-dashboard/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
