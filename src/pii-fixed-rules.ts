/**
 * PII Detection and Masking - Fixed Rules Engine
 *
 * This module provides a simplified PII detection system based on fixed regex patterns.
 * It is adapted from OpenAI's guardrails-js project with significant simplifications.
 *
 * Original Source:
 * https://github.com/openai/openai-guardrails-js/blob/main/src/checks/pii.ts
 *
 * Key differences from original:
 *
 * 1. Simplified Architecture: Removed guardrail system infrastructure, blocking/tripwire
 *    functionality, and encoded PII detection (base64, hex, URL encoding)
 *
 * 2. Sequential Processing: Removed complex overlap detection and span deduplication.
 *    Entities are now processed sequentially, first match wins.
 *    This heuristic makes behavior more predictable but requires careful ordering of entity
 *    types when overlap is possible.
 *
 * 3. No Capture Groups: Removed group-based pattern matching (previously used for CVV
 *    and BIC_SWIFT). All patterns now match the entire entity directly.
 * 
 * 4. Pure Masking Focus: Designed exclusively for text masking operations, not for
 *    validation or blocking.
 *
 * This is a "fixed rules engine", patterns are predefined and well-tested. Users who need
 * flexibility should use custom rules rather than modifying these patterns.
 *
 * License:
 *
 * The original OpenAI guardrails-js project is licensed under the MIT License.
 * Copyright (c) OpenAI
 *
 * This adapted version maintains the same MIT License.
 *
 * @see https://github.com/openai/openai-guardrails-js
 */

/**
 * Supported PII entity types for detection.
 *
 * These represent common personally identifiable information patterns across
 * different regions and use cases. Each entity type maps to one or more regex
 * patterns optimized for that specific format.
 */
export enum FixedPIIEntity {
  // Global
  CREDIT_CARD = 'CREDIT_CARD',
  CRYPTO = 'CRYPTO',
  DATE_TIME = 'DATE_TIME',
  EMAIL_ADDRESS = 'EMAIL_ADDRESS',
  IBAN_CODE = 'IBAN_CODE',
  IP_ADDRESS = 'IP_ADDRESS',
  PHONE_NUMBER = 'PHONE_NUMBER',
  URL = 'URL',

  // Custom recognizers
  CVV = 'CVV',
  BIC_SWIFT = 'BIC_SWIFT',

  // USA
  US_BANK_NUMBER = 'US_BANK_NUMBER',
  US_DRIVER_LICENSE = 'US_DRIVER_LICENSE',
  US_ITIN = 'US_ITIN',
  US_PASSPORT = 'US_PASSPORT',
  US_SSN = 'US_SSN',

  // UK
  UK_NHS = 'UK_NHS',
  UK_NINO = 'UK_NINO',

  // Spain
  ES_NIF = 'ES_NIF',
  ES_NIE = 'ES_NIE',

  // Italy
  IT_FISCAL_CODE = 'IT_FISCAL_CODE',
  IT_DOCUMENT = 'IT_DOCUMENT',
  IT_VAT_CODE = 'IT_VAT_CODE',

  // Poland
  PL_PESEL = 'PL_PESEL',

  // Finland
  FI_PERSONAL_IDENTITY_CODE = 'FI_PERSONAL_IDENTITY_CODE',

  // Singapore
  SG_NRIC_FIN = 'SG_NRIC_FIN',
  SG_UEN = 'SG_UEN',

  // Australia
  AU_ABN = 'AU_ABN',
  AU_ACN = 'AU_ACN',
  AU_TFN = 'AU_TFN',
  AU_MEDICARE = 'AU_MEDICARE',

  // India
  IN_PAN = 'IN_PAN',
  IN_AADHAAR = 'IN_AADHAAR',
  IN_VEHICLE_REGISTRATION = 'IN_VEHICLE_REGISTRATION',
  IN_VOTER = 'IN_VOTER',
  IN_PASSPORT = 'IN_PASSPORT',

  // Korea
  KR_RRN = 'KR_RRN'
}

/**
 * Context keywords that typically precede BIC/SWIFT codes in text.
 * Used to reduce false positives by requiring contextual clues.
 */
const BIC_CONTEXT_PREFIX_PATTERN = [
  '(?:[sS][wW][iI][fF][tT])',
  '(?:[bB][iI][cC])',
  '(?:[bB][aA][nN][kK][\\s-]?[cC][oO][dD][eE])',
  '(?:[sS][wW][iI][fF][tT][\\s-]?[cC][oO][dD][eE])',
  '(?:[bB][iI][cC][\\s-]?[cC][oO][dD][eE])',
].join('|')

/**
 * Matches BIC/SWIFT codes when preceded by context keywords.
 *
 * Format: AAAABBCCXXX where:
 * - AAAA: Bank code (4 letters)
 * - BB: Country code (2 letters)
 * - CC: Location code (2 alphanumeric)
 * - XXX: Branch code (3 alphanumeric, optional)
 */
const BIC_WITH_CONTEXT_REGEX = new RegExp(
  `(?:${BIC_CONTEXT_PREFIX_PATTERN})[:\\s=]+([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\\b`,
  'g'
)

/**
 * Fixed regex patterns for PII entity detection.
 *
 * Pattern Design Principles:
 *
 * 1. Word boundaries: Most patterns use \b to avoid matching within larger strings
 * 2. Format flexibility: Patterns accommodate common format variations (spaces, dashes, etc.)
 * 3. False positive minimization: Patterns balance sensitivity vs. specificity
 * 4. Global Flag: All patterns use /g flag for multiple matches
 *
 * Maintenance notes:
 *
 * - Test thoroughly before modifying patterns
 * - Consider false positive rate when adding new patterns
 * - Document any regional format specifics
 * - Keep patterns performant (avoid catastrophic backtracking)
 */
const DEFAULT_PII_PATTERNS: Record<FixedPIIEntity, RegExp[]> = {
  [FixedPIIEntity.CREDIT_CARD]: [/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g],
  [FixedPIIEntity.CRYPTO]: [/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g],
  [FixedPIIEntity.DATE_TIME]: [/\b(0[1-9]|1[0-2])[/-](0[1-9]|[12]\d|3[01])[/-](19|20)\d{2}\b/g],
  [FixedPIIEntity.EMAIL_ADDRESS]: [
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    new RegExp('(?<=[?&=/])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}', 'g')
  ],
  [FixedPIIEntity.IBAN_CODE]: [/\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b/g],
  [FixedPIIEntity.IP_ADDRESS]: [
    /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
    /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
    /\b(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}\b/g
  ],
  [FixedPIIEntity.PHONE_NUMBER]: [/\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g],
  [FixedPIIEntity.URL]: [
    /\bhttps?:\/\/(?:[-\w.])+(?::[0-9]+)?(?:\/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?/g
  ],
  [FixedPIIEntity.CVV]: [/\b(?:cvv|cvc|security\s*code|card\s*code)[\s:=]*[0-9]{3,4}\b/gi],
  [FixedPIIEntity.BIC_SWIFT]: [
    BIC_WITH_CONTEXT_REGEX
  ],

  // USA
  [FixedPIIEntity.US_BANK_NUMBER]: [/\b\d{8,17}\b/g],
  [FixedPIIEntity.US_DRIVER_LICENSE]: [/\b[A-Z]\d{7}\b/g],
  [FixedPIIEntity.US_ITIN]: [/\b9\d{2}-\d{2}-\d{4}\b/g],
  [FixedPIIEntity.US_PASSPORT]: [/\b[A-Z]\d{8}\b/g],
  [FixedPIIEntity.US_SSN]: [/\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b/g],

  // UK
  [FixedPIIEntity.UK_NHS]: [/\b\d{3} \d{3} \d{4}\b/g],
  [FixedPIIEntity.UK_NINO]: [/\b[A-Z]{2}\d{6}[A-Z]\b/g],

  // Spain
  [FixedPIIEntity.ES_NIF]: [/\b\d{8}[A-Z]\b/g],
  [FixedPIIEntity.ES_NIE]: [/\b[XYZ]\d{7}[A-Z]\b/g],

  // Italy
  [FixedPIIEntity.IT_FISCAL_CODE]: [/\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b/g],
  [FixedPIIEntity.IT_DOCUMENT]: [/\b[A-Z]{2}\d{7}\b/g],
  [FixedPIIEntity.IT_VAT_CODE]: [/\bIT\d{11}\b/g],

  // Poland
  [FixedPIIEntity.PL_PESEL]: [/\b\d{11}\b/g],

  // Finland
  [FixedPIIEntity.FI_PERSONAL_IDENTITY_CODE]: [/\b\d{6}[+-A]\d{3}[A-Z0-9]\b/g],

  // Singapore
  [FixedPIIEntity.SG_NRIC_FIN]: [/\b[A-Z]\d{7}[A-Z]\b/g],
  [FixedPIIEntity.SG_UEN]: [/\b\d{8}[A-Z]\b|\b\d{9}[A-Z]\b/g],

  // Australia
  [FixedPIIEntity.AU_ABN]: [/\b\d{2} \d{3} \d{3} \d{3}\b/g],
  [FixedPIIEntity.AU_ACN]: [/\b\d{3} \d{3} \d{3}\b/g],
  [FixedPIIEntity.AU_TFN]: [/\b\d{9}\b/g],
  [FixedPIIEntity.AU_MEDICARE]: [/\b\d{4} \d{5} \d{1}\b/g],

  // India
  [FixedPIIEntity.IN_PAN]: [/\b[A-Z]{5}\d{4}[A-Z]\b/g],
  [FixedPIIEntity.IN_AADHAAR]: [/\b\d{4} \d{4} \d{4}\b/g],
  [FixedPIIEntity.IN_VEHICLE_REGISTRATION]: [/\b[A-Z]{2}\d{2}[A-Z]{2}\d{4}\b/g],
  [FixedPIIEntity.IN_VOTER]: [/\b[A-Z]{3}\d{7}\b/g],
  [FixedPIIEntity.IN_PASSPORT]: [/\b[A-Z]\d{7}\b/g],

  // Korea
  [FixedPIIEntity.KR_RRN]: [/\b\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])-[1-4]\d{6}\b/g]
}

/**
 * Apply fixed PII masking rules to text
 * 
 * This function uses a sequential, non-overlapping approach:
 *
 * 1. Entities are processed in the order provided
 * 2. Once text is masked, it won't be re-matched by subsequent patterns
 * 3. No overlap detection or resolution is performed
 *
 * This design prioritizes predictability and performance over handling edge cases.
 *
 * If patterns might overlap (e.g., CREDIT_CARD vs US_BANK_NUMBER), place the
 * more specific pattern first in the entities array to ensure it takes precedence.
 *
 * @param text - The text to scan and mask
 * @param entities - List of PII entity types to detect
 *
 * @returns The text with PII entities replaced
 *
 * @example
 * // Default behavior
 * applyFixedRules("Email: test@example.com")
 * // Returns: "Email: <EMAIL_ADDRESS>"
 *
 * // Specific entities only
 * applyFixedRules(
 *   "Email: test@example.com, SSN: 123-45-6789",
 *   [FixedPIIEntity.EMAIL_ADDRESS]
 * )
 * // Returns: "Email: <EMAIL_ADDRESS>, SSN: 123-45-6789"
 *
 * // Priority ordering matters
 * applyFixedRules(
 *   "1234567890123456",
 *   [FixedPIIEntity.CREDIT_CARD, FixedPIIEntity.US_BANK_NUMBER]  // Credit card checked first
 * )
 * // Returns: "<CREDIT_CARD>"
 */
export function applyFixedRules(text: string, entities: FixedPIIEntity[] = Object.values(FixedPIIEntity)): string {
  if (!text) {
    return text
  }

  // Process each entity type in order (sequential processing)
  for (const entity of entities) {
    const patterns = DEFAULT_PII_PATTERNS[entity]
    if (!patterns || !patterns.length) {
      continue
    }

    // Apply each pattern for this entity
    for (const pattern of patterns) {
      text = text.replace(pattern, `<${entity}>`)
    }
  }

  return text
}
