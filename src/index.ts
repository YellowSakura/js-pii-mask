import { applyCustomRules, CustomRule } from './pii-custom-rules'
import { applyFixedRules, FixedPIIEntity } from './pii-fixed-rules'

// Types and enums are re-exported while implementation details
// (pii-custom-rules and pii-fixed-rules) remain internal.
export type { CustomRule } from './pii-custom-rules'
export { FixedPIIEntity } from './pii-fixed-rules'

/**
 * Normalizes a Unicode string and removes invisible zero-width characters.
 *
 * Text from various sources may contain visually identical characters with
 * different Unicode representations, or invisible characters that can bypass
 * simple pattern matching. This function ensures consistent representation.
 *
 * It also removes zero-width Unicode characters such as:
 *
 * - ZERO WIDTH SPACE (U+200B)
 * - ZERO WIDTH NON-JOINER (U+200C)
 * - ZERO WIDTH JOINER (U+200D)
 * - WORD JOINER (U+2060)
 * - ZERO WIDTH NO-BREAK SPACE / BOM (U+FEFF)
 *
 * If Unicode normalization is not supported by the runtime environment,
 * the function gracefully falls back to only removing zero-width characters.
 *
 * @param text - The input string to normalize.
 *
 * @returns The normalized string without zero-width characters.
 */
function _normalizeUnicode(text: string): string {
  if (!text) {
    return text
  }

  const zeroWidthCharacters = /(?:\u200B|\u200C|\u200D|\u2060|\uFEFF)/g

  try {
    return text.normalize('NFKC').replace(zeroWidthCharacters, '')
  } catch {
    return text.replace(zeroWidthCharacters, '')
  }
}

/**
 * Configuration options for the `mask` function.
 *
 * - customRules: Optional array of custom rules for masking text patterns.
 *   Each rule defines a regex pattern and its replacement string.
 * - fixedPiiEntities: Optional array of predefined PII (Personally
 *   Identifiable Information) entities to mask in the input text.
 *
 * Both properties are optional.
 */
type MaskOptions = {
  customRules?: CustomRule[]
  fixedPiiEntities?: FixedPIIEntity[]
}

/**
 * Mask PII (Personally Identifiable Information) in text.
 *
 * Detects and replaces PII entities with placeholder tokens.
 *
 * @param text - The text to scan and mask
 * @param options - Optional configuration object for masking rules,
 *        see .MaskOptions
 *
 * @returns The text with PII entities replaced by placeholders
 *
 * @example
 * // Basic usage with default fixed rules
 * mask("Contact me at john@example.com or call 555-123-4567")
 * // Returns: "Contact me at <EMAIL_ADDRESS> or call <PHONE_NUMBER>"
 *
 * @example
 * // With custom rules
 * mask("My name is John Doe", {
 *   customRules: [
 *     { pattern: /John/gi, replacement: 'FIRST_NAME' },
 *     { pattern: /Doe/gi, replacement: 'LAST_NAME' }
 *   ]
 * })
 * // Returns: "My name is <FIRST_NAME> <LAST_NAME>"
 */
export function mask(inputText: string, options?: MaskOptions): string {
  const { customRules = [], fixedPiiEntities = [] } = options || {}
  let text = _normalizeUnicode(inputText)

  // Apply custom rules first (if provided)
  if (customRules.length > 0) {
    text = applyCustomRules(text, customRules)
  }

  // Apply fixed rules after custom rules
  return (fixedPiiEntities.length > 0) ? applyFixedRules(text, fixedPiiEntities) : applyFixedRules(text)
}
