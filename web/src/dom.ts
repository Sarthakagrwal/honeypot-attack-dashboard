/**
 * Tiny DOM helpers.
 *
 * Keeps the dashboard's rendering code declarative without pulling in a
 * framework. `el()` builds an element with attributes and children; `text()`
 * is a safe shorthand for a text node.
 */

type Child = Node | string

/**
 * Create an element with the given attributes and children.
 *
 * Attribute keys map directly to HTML attributes; `class` and `text` are
 * supported as conveniences. All text goes through `textContent`, so no value
 * is ever interpreted as HTML — attacker-supplied strings (IPs, usernames,
 * commands) are rendered inertly.
 */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  children: Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'class') node.className = value
    else if (key === 'text') node.textContent = value
    else node.setAttribute(key, value)
  }
  for (const child of children) {
    node.append(typeof child === 'string' ? document.createTextNode(child) : child)
  }
  return node
}

/** Remove every child of an element. */
export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild)
}

/** Format an integer with thousands separators. */
export function formatNumber(value: number): string {
  return value.toLocaleString('en-US')
}

/** Format an ISO timestamp as a short, readable UTC string. */
export function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString('en-GB', {
    timeZone: 'UTC',
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  })
}
