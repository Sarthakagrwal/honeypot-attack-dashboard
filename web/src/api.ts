/**
 * Data layer for the dashboard.
 *
 * `loadData()` fetches from a live honeypot API when `VITE_API_BASE` is set,
 * and otherwise falls back to the committed `demo-data.json` snapshot — so the
 * identical dashboard renders against either source.
 *
 * The remaining functions are pure transforms that aggregate the raw export
 * into chart-ready structures; they are unit-tested by `api.test.ts`.
 */

import type {
  ExportData,
  MapPoint,
  TimelinePoint,
  TopIp,
  ValueCount,
} from './types'

/**
 * Fetch the dashboard dataset.
 *
 * When the `VITE_API_BASE` env var is defined (e.g. a deployed honeypot VPS),
 * the live `/api/export` endpoint is used. Otherwise the bundled demo snapshot
 * is loaded relative to the site's base path.
 */
export async function loadData(): Promise<ExportData> {
  const apiBase = import.meta.env.VITE_API_BASE
  const url = apiBase
    ? `${apiBase.replace(/\/$/, '')}/api/export`
    : `${import.meta.env.BASE_URL}demo-data.json`

  const resp = await fetch(url)
  if (!resp.ok) {
    throw new Error(`Failed to load data from ${url}: HTTP ${resp.status}`)
  }
  return (await resp.json()) as ExportData
}

/** True when the dashboard is pointed at a live honeypot API. */
export function isLiveMode(): boolean {
  return Boolean(import.meta.env.VITE_API_BASE)
}

/**
 * A chart-ready timeline series.
 *
 * `labels` are `Date` objects (Chart.js time scale); `ssh` and `http` are the
 * matching per-day counts. The input is sorted ascending by date so the line
 * chart reads left-to-right in time order.
 */
export interface TimelineSeries {
  labels: Date[]
  ssh: number[]
  http: number[]
}

/** Convert the raw timeline into parallel arrays for the line chart. */
export function buildTimelineSeries(timeline: TimelinePoint[]): TimelineSeries {
  const sorted = [...timeline].sort((a, b) => a.date.localeCompare(b.date))
  return {
    labels: sorted.map((p) => new Date(`${p.date}T00:00:00Z`)),
    ssh: sorted.map((p) => p.ssh),
    http: sorted.map((p) => p.http),
  }
}

/** A label/value pair list ready for a horizontal bar chart. */
export interface BarSeries {
  labels: string[]
  values: number[]
}

/**
 * Turn a `(value, count)` list into a bar series, keeping the top `limit`
 * entries in descending order of count.
 */
export function buildBarSeries(items: ValueCount[], limit = 10): BarSeries {
  const top = [...items]
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
  return {
    labels: top.map((i) => i.value),
    values: top.map((i) => i.count),
  }
}

/**
 * Sort attacker IPs for the "top attackers" table — most sessions first, then
 * most auth attempts as a tiebreaker.
 */
export function sortTopIps(ips: TopIp[]): TopIp[] {
  return [...ips].sort(
    (a, b) => b.sessions - a.sessions || b.attempts - a.attempts,
  )
}

/**
 * Drop map points with no usable coordinates.
 *
 * Private/un-geolocatable sources have null lat/lon in the raw data; the
 * Leaflet map can only plot real coordinates.
 */
export function validMapPoints(points: MapPoint[]): MapPoint[] {
  return points.filter(
    (p) =>
      typeof p.lat === 'number' &&
      typeof p.lon === 'number' &&
      Number.isFinite(p.lat) &&
      Number.isFinite(p.lon),
  )
}

/**
 * Compute a marker radius (in pixels) for a map point from its attack count,
 * scaled against the busiest point so the largest source stands out without
 * dwarfing the map.
 */
export function markerRadius(count: number, maxCount: number): number {
  const min = 6
  const max = 26
  if (maxCount <= 0) return min
  const ratio = Math.sqrt(count / maxCount) // sqrt keeps small counts visible
  return Math.round(min + ratio * (max - min))
}
