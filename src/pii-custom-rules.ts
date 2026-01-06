/**
 * PII Custom Rules Engine
 *
 * This module provides a simple mechanism for applying user-defined masking rules
 * to text content. Unlike fixed rules, custom rules are provided at runtime and
 * allow users to mask domain-specific or organization-specific sensitive data.
 */

/**
 * Custom masking rule defined by the user.
 *
 * A custom rule consists of a regex pattern to match and a replacement string.
 * The pattern should use the global flag (`g`) to match all occurrences.
 */
export interface CustomRule {
  pattern: RegExp
  replacement: string
}

/**
 * Apply custom masking rules to text.
 *
 * Rules are processed sequentially in the order they appear in the array.
 * Each rule's pattern is matched against the text, and all matches are
 * replaced with the corresponding replacement string.
 *
 * Processing Behavior
 *
 * - Sequential: Rules are applied one after another
 * - Stateful: Later rules operate on text modified by earlier rules
 * - No validation: Patterns are used as-is without checking
 * - No overlap handling: First match wins
 *
 * @param text - The text to scan and mask
 * @param rules - Array of custom masking rules to apply
 *
 * @returns The text with all custom rules applied
 *
 * @example
 * // Basic usage
 * const text = "Employee EMP-12345 logged in"
 * const rules: CustomRule[] = [
 *   { pattern: /EMP-\d{5}/g, replacement: 'EMPLOYEE_ID' }
 * ]
 * applyCustomRules(text, rules)
 * // Returns: "Employee <EMPLOYEE_ID> logged in"
 *
 * @example
 * // Multiple rules
 * const text2 = "Ticket T-123 assigned to EMP-99999"
 * const rules2: CustomRule[] = [
 *   { pattern: /T-\d{3}/g, replacement: 'TICKET_ID' },
 *   { pattern: /EMP-\d{5}/g, replacement: 'EMPLOYEE_ID' }
 * ]
 * applyCustomRules(text2, rules2)
 * // Returns: "Ticket <TICKET_ID> assigned to <EMPLOYEE_ID>"
 */
export function applyCustomRules(text: string, rules: CustomRule[]): string {
  if (!text) {
    return text
  }

  if (!rules || rules.length === 0) {
    return text
  }

  for (const rule of rules) {
    // Skip invalid rules (no pattern or replacement)
    if (!rule.pattern || rule.replacement === undefined) {
      continue
    }

    // Apply the pattern replacement
    text = text.replace(rule.pattern, `<${rule.replacement}>`)
  }

  return text
}