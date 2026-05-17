/**
 * End-to-end tests for the HoneyGrid dashboard.
 *
 * These run against the built-and-previewed site (see playwright.config.ts),
 * so base-path and bundling problems surface here. They assert the dashboard
 * loads cleanly, every visualisation renders, and the required DB-IP
 * attribution is present.
 */

import { expect, test } from '@playwright/test'

test.describe('HoneyGrid dashboard', () => {
  test('loads with no console errors', async ({ page }) => {
    const errors: string[] = []
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text())
    })
    page.on('pageerror', (err) => errors.push(err.message))

    await page.goto('/')
    await expect(page.locator('.site-header__brand')).toContainText('HoneyGrid')

    // Wait for data to paint before judging the console clean.
    await expect(page.locator('#stat-attacks')).not.toHaveText('—', {
      timeout: 15_000,
    })
    expect(errors, `console errors:\n${errors.join('\n')}`).toEqual([])
  })

  test('stat cards show non-zero numbers', async ({ page }) => {
    await page.goto('/')
    const ids = ['#stat-attacks', '#stat-ips', '#stat-creds', '#stat-commands']
    for (const id of ids) {
      const node = page.locator(id)
      await expect(node).not.toHaveText('—', { timeout: 15_000 })
      const text = (await node.textContent()) ?? ''
      const value = Number(text.replace(/,/g, ''))
      expect(value, `${id} should be a positive number`).toBeGreaterThan(0)
    }
  })

  test('chart canvases render with non-zero size', async ({ page }) => {
    await page.goto('/')
    await expect(page.locator('#stat-attacks')).not.toHaveText('—', {
      timeout: 15_000,
    })

    const canvasIds = [
      '#chart-timeline',
      '#chart-usernames',
      '#chart-passwords',
      '#chart-commands',
    ]
    for (const id of canvasIds) {
      const canvas = page.locator(id)
      await expect(canvas).toBeVisible()
      const box = await canvas.boundingBox()
      expect(box, `${id} should have a bounding box`).not.toBeNull()
      expect(box!.width).toBeGreaterThan(0)
      expect(box!.height).toBeGreaterThan(0)
    }
  })

  test('Leaflet map renders with tiles and markers', async ({ page }) => {
    await page.goto('/')
    await expect(page.locator('#stat-attacks')).not.toHaveText('—', {
      timeout: 15_000,
    })

    const mapContainer = page.locator('#attack-map')
    await expect(mapContainer).toBeVisible()

    // Leaflet adds .leaflet-container and loads tile <img> elements.
    await expect(page.locator('.leaflet-container')).toBeVisible()
    await expect(page.locator('.leaflet-tile').first()).toBeVisible({
      timeout: 15_000,
    })

    // Circle markers are rendered as SVG <path> elements inside the overlay.
    const markers = page.locator('#attack-map path.leaflet-interactive')
    await expect(markers.first()).toBeVisible({ timeout: 15_000 })
    expect(await markers.count()).toBeGreaterThan(0)
  })

  test('top attackers and recent sessions tables are populated', async ({
    page,
  }) => {
    await page.goto('/')
    await expect(page.locator('#stat-attacks')).not.toHaveText('—', {
      timeout: 15_000,
    })

    const attackerRows = page.locator('#attackers-body tr')
    await expect(attackerRows.first()).toBeVisible({ timeout: 15_000 })
    expect(await attackerRows.count()).toBeGreaterThan(0)

    const recentRows = page.locator('#recent-body tr')
    await expect(recentRows.first()).toBeVisible({ timeout: 15_000 })
    expect(await recentRows.count()).toBeGreaterThan(0)
  })

  test('footer contains the DB-IP attribution link', async ({ page }) => {
    await page.goto('/')
    const footer = page.locator('.site-footer')
    await expect(footer).toContainText('IP geolocation by')
    await expect(footer).toContainText('CC BY 4.0')

    const dbipLink = footer.locator('a[href="https://db-ip.com"]')
    await expect(dbipLink).toBeVisible()
    await expect(dbipLink).toHaveText('DB-IP.com')
  })
})
