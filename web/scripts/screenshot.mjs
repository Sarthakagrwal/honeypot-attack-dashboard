/**
 * Capture a screenshot of the built dashboard for the README.
 *
 * Starts `vite preview`, waits for the dashboard to finish painting (the stat
 * cards lose their placeholder), screenshots the full page, and writes it to
 * `docs/screenshot.png`.
 *
 * Run from the `web/` directory after `npm run build`:
 *   node scripts/screenshot.mjs
 */

import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { chromium } from 'playwright'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..', '..')
const outPath = resolve(repoRoot, 'docs', 'screenshot.png')
const baseURL = 'http://localhost:4173/honeypot-attack-dashboard/'

/** Poll a URL until it responds, or throw after the timeout. */
async function waitForServer(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(url)
      if (resp.ok) return
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 300))
  }
  throw new Error(`preview server did not start at ${url}`)
}

const preview = spawn('npm', ['run', 'preview'], {
  cwd: resolve(here, '..'),
  stdio: 'ignore',
})

try {
  await waitForServer(baseURL, 30_000)

  const browser = await chromium.launch()
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } })
  await page.goto(baseURL)

  // Wait for data to load so the screenshot shows real numbers and charts.
  await page.locator('#stat-attacks').waitFor({ state: 'visible' })
  await page.waitForFunction(
    () => document.getElementById('stat-attacks')?.textContent !== '—',
    { timeout: 15_000 },
  )
  await page.locator('.leaflet-tile').first().waitFor({ state: 'visible' })
  // Give charts and map tiles a moment to finish their entry animation.
  await page.waitForTimeout(1500)

  await page.screenshot({ path: outPath, fullPage: true })
  console.log(`screenshot written to ${outPath}`)
  await browser.close()
} finally {
  preview.kill()
}
