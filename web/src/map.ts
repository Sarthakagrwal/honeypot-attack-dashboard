/**
 * Leaflet world map of attack origins.
 *
 * Plots one circle marker per geolocated source, sized by how many sessions
 * came from that location. Uses CARTO's dark-matter tiles so the map matches
 * the dashboard's dark theme.
 */

import L from 'leaflet'
import 'leaflet/dist/leaflet.css'

import { markerRadius, validMapPoints } from './api'
import type { MapPoint } from './types'

// CARTO dark basemap — free for light use; attribution is required and shown.
const TILE_URL = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
const TILE_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> ' +
  'contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'

/** Holds the Leaflet map plus the layer used for markers, so it can be reused. */
export interface AttackMap {
  map: L.Map
  markerLayer: L.LayerGroup
}

/**
 * Create the attack map inside `container`.
 *
 * The map is created once; subsequent data updates go through
 * {@link updateMapMarkers}, which only swaps the marker layer.
 */
export function createAttackMap(container: HTMLElement): AttackMap {
  const map = L.map(container, {
    center: [22, 12],
    zoom: 2,
    minZoom: 2,
    maxZoom: 6,
    worldCopyJump: true,
    attributionControl: true,
  })

  L.tileLayer(TILE_URL, {
    attribution: TILE_ATTRIBUTION,
    subdomains: 'abcd',
    maxZoom: 8,
  }).addTo(map)

  const markerLayer = L.layerGroup().addTo(map)
  return { map, markerLayer }
}

/**
 * Replace the map's markers with one circle per valid attack-origin point.
 *
 * Returns the number of markers drawn (useful for tests and the empty state).
 */
export function updateMapMarkers(
  attackMap: AttackMap,
  points: MapPoint[],
): number {
  attackMap.markerLayer.clearLayers()

  const valid = validMapPoints(points)
  if (valid.length === 0) return 0

  const maxCount = Math.max(...valid.map((p) => p.count))

  for (const point of valid) {
    const marker = L.circleMarker([point.lat, point.lon], {
      radius: markerRadius(point.count, maxCount),
      color: '#f85149',
      weight: 1,
      fillColor: '#f85149',
      fillOpacity: 0.45,
    })
    const country = point.country ?? 'Unknown'
    marker.bindTooltip(
      `<strong>${country}</strong><br>${point.count} session${
        point.count === 1 ? '' : 's'
      }`,
      { direction: 'top' },
    )
    marker.addTo(attackMap.markerLayer)
  }
  return valid.length
}
