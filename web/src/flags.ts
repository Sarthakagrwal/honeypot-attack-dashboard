/**
 * Turn an ISO 3166-1 alpha-2 country code into a flag emoji.
 *
 * Flag emoji are formed from two Regional Indicator Symbol code points, one
 * per letter of the country code, so any valid two-letter code maps to a flag
 * without needing image assets.
 */

/** Base offset: 'A' (U+0041) maps to Regional Indicator 'A' (U+1F1E6). */
const REGIONAL_INDICATOR_BASE = 0x1f1e6
const LETTER_A = 0x41

/**
 * Return the flag emoji for a country code, or a neutral globe when the code
 * is missing or malformed.
 */
export function flagEmoji(code: string | null | undefined): string {
  if (!code || code.length !== 2 || !/^[A-Za-z]{2}$/.test(code)) {
    return '\u{1F310}' // globe
  }
  const upper = code.toUpperCase()
  const chars = [...upper].map((ch) =>
    String.fromCodePoint(REGIONAL_INDICATOR_BASE + (ch.charCodeAt(0) - LETTER_A)),
  )
  return chars.join('')
}
