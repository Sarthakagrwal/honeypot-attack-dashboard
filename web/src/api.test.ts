/**
 * Unit tests for the dashboard data layer (`api.ts`).
 *
 * These verify that a sample export — shaped exactly like the real
 * `demo-data.json` — is aggregated correctly into the chart-ready structures
 * the dashboard consumes.
 */

import { describe, expect, it } from 'vitest'

import {
  buildBarSeries,
  buildTimelineSeries,
  markerRadius,
  sortTopIps,
  validMapPoints,
} from './api'
import type { ExportData } from './types'

/** A small but structurally complete sample dataset. */
const sample: ExportData = {
  generated_at: '2026-05-17T12:00:00+00:00',
  stats: {
    total_sessions: 5,
    unique_ips: 3,
    auth_attempts: 9,
    commands: 4,
    http_requests: 2,
    ssh_sessions: 3,
    http_sessions: 2,
  },
  // Deliberately out of date order to test sorting.
  timeline: [
    { date: '2026-05-03', ssh: 4, http: 1 },
    { date: '2026-05-01', ssh: 2, http: 0 },
    { date: '2026-05-02', ssh: 7, http: 3 },
  ],
  top_ips: [
    { ip: '1.1.1.1', country: 'A', country_code: 'AA', attempts: 5, sessions: 1 },
    { ip: '2.2.2.2', country: 'B', country_code: 'BB', attempts: 9, sessions: 3 },
    { ip: '3.3.3.3', country: 'C', country_code: 'CC', attempts: 9, sessions: 2 },
  ],
  top_usernames: [
    { value: 'admin', count: 3 },
    { value: 'root', count: 12 },
    { value: 'test', count: 1 },
  ],
  top_passwords: [
    { value: '123456', count: 8 },
    { value: 'password', count: 4 },
  ],
  top_commands: [
    { value: 'whoami', count: 6 },
    { value: 'uname -a', count: 2 },
  ],
  http_paths: [{ value: '/wp-login.php', count: 5 }],
  map_points: [
    { lat: 35.86, lon: 104.2, country: 'China', count: 10 },
    { lat: 37.09, lon: -95.71, country: 'United States', count: 4 },
    // An un-geolocatable point that must be filtered out.
    { lat: null as unknown as number, lon: null as unknown as number, country: null, count: 2 },
  ],
  recent_sessions: [
    {
      id: 1,
      protocol: 'ssh',
      src_ip: '2.2.2.2',
      country: 'B',
      started_at: '2026-05-03T10:00:00+00:00',
      auth_attempts: 3,
      commands: ['whoami', 'id'],
    },
  ],
}

describe('buildTimelineSeries', () => {
  it('sorts points ascending by date', () => {
    const series = buildTimelineSeries(sample.timeline)
    const isoDates = series.labels.map((d) => d.toISOString().slice(0, 10))
    expect(isoDates).toEqual(['2026-05-01', '2026-05-02', '2026-05-03'])
  })

  it('aligns ssh and http counts with the sorted dates', () => {
    const series = buildTimelineSeries(sample.timeline)
    expect(series.ssh).toEqual([2, 7, 4])
    expect(series.http).toEqual([0, 3, 1])
  })

  it('does not mutate the input array', () => {
    const original = [...sample.timeline]
    buildTimelineSeries(sample.timeline)
    expect(sample.timeline).toEqual(original)
  })
})

describe('buildBarSeries', () => {
  it('sorts entries by count descending', () => {
    const series = buildBarSeries(sample.top_usernames)
    expect(series.labels).toEqual(['root', 'admin', 'test'])
    expect(series.values).toEqual([12, 3, 1])
  })

  it('respects the limit parameter', () => {
    const series = buildBarSeries(sample.top_usernames, 2)
    expect(series.labels).toHaveLength(2)
    expect(series.labels).toEqual(['root', 'admin'])
  })

  it('handles an empty list', () => {
    const series = buildBarSeries([])
    expect(series.labels).toEqual([])
    expect(series.values).toEqual([])
  })
})

describe('sortTopIps', () => {
  it('orders by sessions then attempts', () => {
    const sorted = sortTopIps(sample.top_ips)
    expect(sorted.map((i) => i.ip)).toEqual(['2.2.2.2', '3.3.3.3', '1.1.1.1'])
  })

  it('does not mutate the input', () => {
    const before = sample.top_ips.map((i) => i.ip)
    sortTopIps(sample.top_ips)
    expect(sample.top_ips.map((i) => i.ip)).toEqual(before)
  })
})

describe('validMapPoints', () => {
  it('drops points with null or non-finite coordinates', () => {
    const valid = validMapPoints(sample.map_points)
    expect(valid).toHaveLength(2)
    expect(valid.every((p) => Number.isFinite(p.lat) && Number.isFinite(p.lon))).toBe(
      true,
    )
  })

  it('returns an empty array when nothing is geolocatable', () => {
    expect(validMapPoints([])).toEqual([])
  })
})

describe('markerRadius', () => {
  it('returns the minimum radius for the smallest count', () => {
    expect(markerRadius(0, 100)).toBe(6)
  })

  it('returns the maximum radius for the busiest point', () => {
    expect(markerRadius(100, 100)).toBe(26)
  })

  it('scales monotonically between min and max', () => {
    const small = markerRadius(10, 100)
    const large = markerRadius(80, 100)
    expect(small).toBeGreaterThanOrEqual(6)
    expect(large).toBeLessThanOrEqual(26)
    expect(large).toBeGreaterThan(small)
  })

  it('falls back to the minimum when maxCount is zero', () => {
    expect(markerRadius(0, 0)).toBe(6)
  })
})
