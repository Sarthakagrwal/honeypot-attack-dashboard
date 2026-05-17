/**
 * Chart.js chart builders for the dashboard.
 *
 * Wraps the timeline line chart and the credential / command bar charts. Each
 * builder registers only the Chart.js components it needs and returns the
 * `Chart` instance so the caller can destroy it before a refresh.
 */

import {
  BarController,
  BarElement,
  CategoryScale,
  Chart,
  Filler,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  TimeScale,
  Tooltip,
} from 'chart.js'
import 'chartjs-adapter-date-fns'

import type { BarSeries, TimelineSeries } from './api'

Chart.register(
  LineController,
  BarController,
  LineElement,
  PointElement,
  BarElement,
  CategoryScale,
  LinearScale,
  TimeScale,
  Filler,
  Legend,
  Tooltip,
)

// Shared palette pulled from the design-system CSS variables.
const COLORS = {
  ssh: '#2f81f7',
  http: '#39d0d8',
  danger: '#f85149',
  warn: '#d29922',
  grid: 'rgba(48, 54, 61, 0.6)',
  text: '#8b949e',
}

// Apply consistent dark-theme defaults to every chart on the page.
Chart.defaults.color = COLORS.text
Chart.defaults.font.family =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
Chart.defaults.maintainAspectRatio = false

/** Render the SSH-vs-HTTP attacks-over-time line chart. */
export function renderTimelineChart(
  canvas: HTMLCanvasElement,
  series: TimelineSeries,
): Chart {
  return new Chart(canvas, {
    type: 'line',
    data: {
      labels: series.labels,
      datasets: [
        {
          label: 'SSH sessions',
          data: series.ssh,
          borderColor: COLORS.ssh,
          backgroundColor: 'rgba(47, 129, 247, 0.15)',
          fill: true,
          tension: 0.3,
          pointRadius: 2,
          pointHoverRadius: 5,
        },
        {
          label: 'HTTP requests',
          data: series.http,
          borderColor: COLORS.http,
          backgroundColor: 'rgba(57, 208, 216, 0.12)',
          fill: true,
          tension: 0.3,
          pointRadius: 2,
          pointHoverRadius: 5,
        },
      ],
    },
    options: {
      responsive: true,
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: {
          type: 'time',
          time: { unit: 'day', tooltipFormat: 'MMM d, yyyy' },
          grid: { color: COLORS.grid },
          ticks: { maxRotation: 0, autoSkipPadding: 24 },
        },
        y: {
          beginAtZero: true,
          grid: { color: COLORS.grid },
          ticks: { precision: 0 },
        },
      },
      plugins: {
        legend: { labels: { boxWidth: 12, usePointStyle: true } },
      },
    },
  })
}

/**
 * Render a horizontal bar chart for a `(label, value)` series — used for the
 * most-tried usernames, passwords and commands.
 */
export function renderBarChart(
  canvas: HTMLCanvasElement,
  series: BarSeries,
  color: string,
  axisLabel: string,
): Chart {
  return new Chart(canvas, {
    type: 'bar',
    data: {
      labels: series.labels,
      datasets: [
        {
          label: axisLabel,
          data: series.values,
          backgroundColor: color,
          borderRadius: 4,
          maxBarThickness: 26,
        },
      ],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      scales: {
        x: {
          beginAtZero: true,
          grid: { color: COLORS.grid },
          ticks: { precision: 0 },
        },
        y: { grid: { display: false } },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${axisLabel}: ${ctx.parsed.x}`,
          },
        },
      },
    },
  })
}

/** The accent colours used for the three bar charts. */
export const BAR_COLORS = {
  username: '#2f81f7',
  password: '#f85149',
  command: '#d29922',
}
