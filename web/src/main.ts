/**
 * HoneyGrid — the honeypot attack dashboard entry point.
 *
 * Loads the capture dataset (live API or bundled demo), renders the static
 * page shell once, then paints the data into stat cards, charts, a world map
 * and tables. The data view auto-refreshes every 30 seconds.
 */

import './styles/theme.css'
import './styles/app.css'

import type { Chart } from 'chart.js'

import {
  buildBarSeries,
  buildTimelineSeries,
  isLiveMode,
  loadData,
  sortTopIps,
} from './api'
import { BAR_COLORS, renderBarChart, renderTimelineChart } from './charts'
import { clear, el, formatNumber, formatTimestamp } from './dom'
import { flagEmoji } from './flags'
import { createAttackMap, updateMapMarkers, type AttackMap } from './map'
import type { ExportData } from './types'

const REPO_URL = 'https://github.com/Sarthakagrwal/honeypot-attack-dashboard'
const REFRESH_MS = 30_000

// Chart instances are kept so each refresh destroys the old chart first.
let timelineChart: Chart | undefined
let usernameChart: Chart | undefined
let passwordChart: Chart | undefined
let commandChart: Chart | undefined
let attackMap: AttackMap | undefined

/** Build the site header (brand left, GitHub link right). */
function renderHeader(): HTMLElement {
  return el('header', { class: 'site-header' }, [
    el('div', { class: 'wrap site-header__inner' }, [
      el('div', { class: 'site-header__brand' }, [
        el('span', { class: 'logo', text: 'H' }),
        el('span', { text: 'HoneyGrid' }),
      ]),
      el('nav', { class: 'site-header__nav' }, [
        el('a', { href: '#timeline', text: 'Timeline' }),
        el('a', { href: '#map', text: 'Map' }),
        el('a', { href: '#attackers', text: 'Attackers' }),
        el('a', { href: REPO_URL, target: '_blank', rel: 'noopener', text: 'GitHub' }),
      ]),
    ]),
  ])
}

/** Build the intro / hero block. */
function renderIntro(): HTMLElement {
  const mode = isLiveMode()
  return el('section', { class: 'intro' }, [
    el('div', { class: 'eyebrow', text: 'Low-interaction honeypot' }),
    el('h1', { text: 'Honeypot Attack Dashboard' }),
    el('p', { class: 'lede' }, [
      'A decoy SSH and HTTP server that lures automated attackers, records ',
      'every credential and command they try, and never executes a single ',
      'byte they send. This dashboard visualises what the honeypot captured.',
    ]),
    el('div', { class: 'meta-row' }, [
      el(
        'span',
        { class: mode ? 'mode-pill mode-pill--live' : 'mode-pill' },
        [
          el('span', { class: 'pulse' }),
          el('span', { text: mode ? 'Live API data' : 'Demo snapshot data' }),
        ],
      ),
      el('span', { id: 'generated-at', class: 'dim', text: '' }),
    ]),
  ])
}

/** Build one stat card. */
function statCard(id: string, label: string): HTMLElement {
  return el('div', { class: 'stat' }, [
    el('div', { id, class: 'stat__value', text: '—' }),
    el('div', { class: 'stat__label', text: label }),
  ])
}

/** Build the row of headline stat cards. */
function renderStats(): HTMLElement {
  return el('section', { class: 'section' }, [
    el('div', { class: 'grid grid-4' }, [
      statCard('stat-attacks', 'Total attacks'),
      statCard('stat-ips', 'Unique source IPs'),
      statCard('stat-creds', 'Credentials captured'),
      statCard('stat-commands', 'Commands logged'),
    ]),
  ])
}

/** Build a titled chart panel containing a single `<canvas>`. */
function chartPanel(
  sectionId: string,
  title: string,
  hint: string,
  canvasId: string,
  boxClass = 'chart-box',
): HTMLElement {
  return el('section', { id: sectionId, class: 'section' }, [
    el('div', { class: 'section-head' }, [
      el('h2', { text: title }),
      el('span', { class: 'hint', text: hint }),
    ]),
    el('div', { class: 'chart-card' }, [
      el('div', { class: boxClass }, [el('canvas', { id: canvasId })]),
    ]),
  ])
}

/** Build the world-map section. */
function renderMapSection(): HTMLElement {
  return el('section', { id: 'map', class: 'section' }, [
    el('div', { class: 'section-head' }, [
      el('h2', { text: 'Attack origins' }),
      el('span', { class: 'hint', text: 'marker size = sessions from that location' }),
    ]),
    el('div', { id: 'attack-map' }),
  ])
}

/** Build the "top attackers" table section (tbody filled on data load). */
function renderAttackersSection(): HTMLElement {
  return el('section', { id: 'attackers', class: 'section' }, [
    el('div', { class: 'section-head' }, [
      el('h2', { text: 'Top attackers' }),
      el('span', { class: 'hint', text: 'busiest source IP addresses' }),
    ]),
    el('div', { class: 'card' }, [
      el('div', { class: 'table-scroll' }, [
        el('table', { class: 'data-table' }, [
          el('thead', {}, [
            el('tr', {}, [
              el('th', { text: 'Source IP' }),
              el('th', { text: 'Country' }),
              el('th', { text: 'Sessions' }),
              el('th', { text: 'Auth attempts' }),
            ]),
          ]),
          el('tbody', { id: 'attackers-body' }),
        ]),
      ]),
    ]),
  ])
}

/** Build the two-up credentials chart row. */
function renderCredentialsSection(): HTMLElement {
  return el('section', { class: 'section' }, [
    el('div', { class: 'section-head' }, [
      el('h2', { text: 'Credentials attackers tried' }),
      el('span', { class: 'hint', text: 'most-attempted usernames and passwords' }),
    ]),
    el('div', { class: 'grid grid-2' }, [
      el('div', { class: 'chart-card' }, [
        el('div', { class: 'card__title', text: 'Top usernames' }),
        el('div', { class: 'chart-box chart-box--short' }, [
          el('canvas', { id: 'chart-usernames' }),
        ]),
      ]),
      el('div', { class: 'chart-card' }, [
        el('div', { class: 'card__title', text: 'Top passwords' }),
        el('div', { class: 'chart-box chart-box--short' }, [
          el('canvas', { id: 'chart-passwords' }),
        ]),
      ]),
    ]),
  ])
}

/** Build the recent-sessions table section. */
function renderRecentSection(): HTMLElement {
  return el('section', { class: 'section' }, [
    el('div', { class: 'section-head' }, [
      el('h2', { text: 'Recent sessions' }),
      el('span', { class: 'hint', text: 'latest captured attacker connections' }),
    ]),
    el('div', { class: 'card' }, [
      el('div', { class: 'table-scroll' }, [
        el('table', { class: 'data-table' }, [
          el('thead', {}, [
            el('tr', {}, [
              el('th', { text: 'When (UTC)' }),
              el('th', { text: 'Proto' }),
              el('th', { text: 'Source IP' }),
              el('th', { text: 'Country' }),
              el('th', { text: 'Auth' }),
              el('th', { text: 'Commands run' }),
            ]),
          ]),
          el('tbody', { id: 'recent-body' }),
        ]),
      ]),
    ]),
  ])
}

/** Build the site footer, including the mandatory DB-IP attribution. */
function renderFooter(): HTMLElement {
  return el('footer', { class: 'site-footer' }, [
    el('div', { class: 'wrap footer-grid' }, [
      el('div', {}, [
        el('div', { text: 'HoneyGrid — Honeypot Attack Dashboard' }),
        el('div', { class: 'dim mt-3' }, [
          'Built by Sarthak Aggarwal as part of a cybersecurity learning portfolio.',
        ]),
      ]),
      el('div', {}, [
        el('div', {}, [
          'IP geolocation by ',
          el('a', { href: 'https://db-ip.com', target: '_blank', rel: 'noopener' }, [
            'DB-IP.com',
          ]),
          ', licensed ',
          el(
            'a',
            {
              href: 'https://creativecommons.org/licenses/by/4.0/',
              target: '_blank',
              rel: 'noopener',
            },
            ['CC BY 4.0'],
          ),
          '.',
        ]),
        el('div', { class: 'mt-3' }, [
          el('a', { href: REPO_URL, target: '_blank', rel: 'noopener' }, [
            'Source code on GitHub',
          ]),
        ]),
      ]),
    ]),
  ])
}

/** Assemble the full page shell once, before any data has loaded. */
function renderShell(root: HTMLElement): void {
  root.append(
    renderHeader(),
    el('main', { class: 'wrap' }, [
      renderIntro(),
      el('div', { id: 'data-state' }),
      renderStats(),
      chartPanel(
        'timeline',
        'Attacks over time',
        'daily SSH sessions vs HTTP requests',
        'chart-timeline',
        'chart-box chart-box--tall',
      ),
      renderMapSection(),
      renderAttackersSection(),
      renderCredentialsSection(),
      chartPanel(
        'commands',
        'Commands attackers ran',
        'most-run commands inside the fake shell',
        'chart-commands',
        'chart-box chart-box--short',
      ),
      renderRecentSection(),
    ]),
    renderFooter(),
  )
}

/** Update the four headline stat cards. */
function paintStats(data: ExportData): void {
  const s = data.stats
  setText('stat-attacks', formatNumber(s.total_sessions))
  setText('stat-ips', formatNumber(s.unique_ips))
  setText('stat-creds', formatNumber(s.auth_attempts))
  setText('stat-commands', formatNumber(s.commands))
}

/** Set an element's text content by id, ignoring a missing element. */
function setText(id: string, value: string): void {
  const node = document.getElementById(id)
  if (node) node.textContent = value
}

/** Render or re-render the timeline line chart. */
function paintTimeline(data: ExportData): void {
  const canvas = document.getElementById('chart-timeline') as HTMLCanvasElement | null
  if (!canvas) return
  timelineChart?.destroy()
  timelineChart = renderTimelineChart(canvas, buildTimelineSeries(data.timeline))
}

/** Render or re-render the three bar charts. */
function paintBarCharts(data: ExportData): void {
  const usernames = document.getElementById('chart-usernames') as HTMLCanvasElement | null
  const passwords = document.getElementById('chart-passwords') as HTMLCanvasElement | null
  const commands = document.getElementById('chart-commands') as HTMLCanvasElement | null

  if (usernames) {
    usernameChart?.destroy()
    usernameChart = renderBarChart(
      usernames,
      buildBarSeries(data.top_usernames),
      BAR_COLORS.username,
      'Attempts',
    )
  }
  if (passwords) {
    passwordChart?.destroy()
    passwordChart = renderBarChart(
      passwords,
      buildBarSeries(data.top_passwords),
      BAR_COLORS.password,
      'Attempts',
    )
  }
  if (commands) {
    commandChart?.destroy()
    commandChart = renderBarChart(
      commands,
      buildBarSeries(data.top_commands),
      BAR_COLORS.command,
      'Times run',
    )
  }
}

/** Render or re-render the world map markers. */
function paintMap(data: ExportData): void {
  const container = document.getElementById('attack-map')
  if (!container) return
  if (!attackMap) attackMap = createAttackMap(container)
  updateMapMarkers(attackMap, data.map_points)
}

/** Build a country cell with a flag emoji. */
function countryCell(name: string | null, code: string | null): HTMLElement {
  return el('span', { class: 'country-cell' }, [
    el('span', { class: 'flag', text: flagEmoji(code) }),
    el('span', { text: name ?? 'Unknown' }),
  ])
}

/** Fill the "top attackers" table. */
function paintAttackers(data: ExportData): void {
  const body = document.getElementById('attackers-body')
  if (!body) return
  clear(body)
  for (const ip of sortTopIps(data.top_ips)) {
    body.append(
      el('tr', {}, [
        el('td', { class: 'mono', text: ip.ip }),
        el('td', {}, [countryCell(ip.country, ip.country_code)]),
        el('td', { class: 'mono', text: formatNumber(ip.sessions) }),
        el('td', { class: 'mono', text: formatNumber(ip.attempts) }),
      ]),
    )
  }
}

/** Fill the "recent sessions" table. */
function paintRecent(data: ExportData): void {
  const body = document.getElementById('recent-body')
  if (!body) return
  clear(body)
  for (const session of data.recent_sessions) {
    const proto = session.protocol.toLowerCase()
    const cmdText =
      session.commands.length > 0
        ? session.commands.join(' ; ')
        : ''
    const cmdCell = el('td', {}, [
      cmdText
        ? el('span', { class: 'cmd-preview', title: cmdText, text: cmdText })
        : el('span', { class: 'cmd-preview dim', text: 'no shell activity' }),
    ])
    body.append(
      el('tr', {}, [
        el('td', { class: 'mono', text: formatTimestamp(session.started_at) }),
        el('td', {}, [
          el('span', {
            class: `proto proto--${proto === 'ssh' ? 'ssh' : 'http'}`,
            text: session.protocol.toUpperCase(),
          }),
        ]),
        el('td', { class: 'mono', text: session.src_ip }),
        el('td', {}, [countryCell(session.country, null)]),
        el('td', { class: 'mono', text: String(session.auth_attempts) }),
        cmdCell,
      ]),
    )
  }
}

/** Show a loading or error banner in the data-state slot. */
function setDataState(kind: 'loading' | 'error' | 'ok', message = ''): void {
  const slot = document.getElementById('data-state')
  if (!slot) return
  clear(slot)
  if (kind === 'ok') return
  const banner = el(
    'div',
    { class: kind === 'error' ? 'state-banner state-banner--error' : 'state-banner' },
    kind === 'loading'
      ? [el('span', { class: 'spinner' }), 'Loading captured attack data…']
      : [`Could not load attack data. ${message}`],
  )
  slot.append(banner)
}

// Fingerprint of the last painted dataset, used to skip redundant repaints on
// the 30s refresh. `generated_at` is excluded because it changes every fetch
// even when the underlying capture data has not.
let lastFingerprint = ''

/** Load the dataset and repaint every component when the data has changed. */
async function refresh(): Promise<void> {
  try {
    const data = await loadData()
    setDataState('ok')
    setText(
      'generated-at',
      `Snapshot generated ${formatTimestamp(data.generated_at)} UTC`,
    )

    // Skip the (chart-destroying, map-redrawing) repaint when nothing of
    // substance changed — only the timestamp label above is refreshed.
    const { generated_at: _ts, ...substantive } = data
    const fingerprint = JSON.stringify(substantive)
    if (fingerprint === lastFingerprint) return
    lastFingerprint = fingerprint

    paintStats(data)
    paintTimeline(data)
    paintMap(data)
    paintAttackers(data)
    paintBarCharts(data)
    paintRecent(data)
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error.'
    // Only show the error banner if we have nothing on screen yet.
    if (document.getElementById('stat-attacks')?.textContent === '—') {
      setDataState('error', message)
    }
    console.error('dashboard refresh failed:', err)
  }
}

/** Bootstrap the dashboard. */
function main(): void {
  const root = document.getElementById('app')
  if (!root) throw new Error('#app mount point not found')
  renderShell(root)
  setDataState('loading')
  void refresh()
  // Auto-refresh so a live deployment stays current without a reload.
  window.setInterval(() => void refresh(), REFRESH_MS)
}

main()
