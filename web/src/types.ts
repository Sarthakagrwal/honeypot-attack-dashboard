/**
 * Shared data contract for the dashboard.
 *
 * This mirrors the exact JSON shape produced by the read-only API's
 * `/api/export` route and by the bundled `demo-data.json` snapshot — both are
 * built from the same Python `build_export()` function, so they cannot
 * diverge.
 */

/** Headline counters shown on the stat cards. */
export interface Stats {
  total_sessions: number
  unique_ips: number
  auth_attempts: number
  commands: number
  http_requests: number
  ssh_sessions: number
  http_sessions: number
}

/** One day's SSH vs HTTP session counts. */
export interface TimelinePoint {
  date: string
  ssh: number
  http: number
}

/** A busy source IP with its country and activity totals. */
export interface TopIp {
  ip: string
  country: string | null
  country_code: string | null
  attempts: number
  sessions: number
}

/** A generic (value, count) pair used by the bar charts. */
export interface ValueCount {
  value: string
  count: number
}

/** An aggregated attack-origin point for the world map. */
export interface MapPoint {
  lat: number
  lon: number
  country: string | null
  count: number
}

/** A recent attacker session with its captured commands. */
export interface RecentSession {
  id: number
  protocol: string
  src_ip: string
  country: string | null
  started_at: string
  auth_attempts: number
  commands: string[]
}

/** The complete dashboard dataset. */
export interface ExportData {
  generated_at: string
  stats: Stats
  timeline: TimelinePoint[]
  top_ips: TopIp[]
  top_usernames: ValueCount[]
  top_passwords: ValueCount[]
  top_commands: ValueCount[]
  http_paths: ValueCount[]
  map_points: MapPoint[]
  recent_sessions: RecentSession[]
}
