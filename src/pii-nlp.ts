/**
 * PII NLP Rules Engine (Lightweight)
 *
 * This module provides dynamic PII detection using Natural Language Processing (NLP).
 * It leverages the `compromise` library to detect named entities such as people,
 * organizations, and places that cannot be easily captured by static regex patterns.
 *
 * Trade-offs:
 * - More flexible than regex (can detect "John Doe" without a strict pattern)
 * - Slower than regex-based masking
 * - Heuristic-based: May produce false positives or miss entities depending on context
 * - Primary support is for English
 */
import nlp from "compromise";

/**
 * Supported NLP entity types.
 *
 * These map directly to `compromise` library methods for entity extraction.
 * Useful for detecting dynamic PII that lacks a fixed structure.
 */
export enum NlpEntity {
  ACRONYMS = 'acronyms',
  MONEY = 'money',
  ORGS = 'organizations',
  PEOPLE = 'people',
  PLACES = 'places'
}

/**
 * Apply NLP-based masking rules to text.
 *
 * Uses the `compromise` library to identify and mask dynamic entities.
 * This function handles the entities sequentially.
 *
 * Use Cases:
 * - Masking names in free text
 * - Masking cities or organizations
 *
 * Limitations:
 * - Performance: Slower than `applyFixedRules`. Use only when necessary.
 * - Accuracy: Depends on `compromise` heuristics. Best suited for complete sentences in English.
 *
 * @param text - The text to scan and mask
 * @param entities - List of NLP entity types to detect (defaults to ALL)
 *
 * @returns The text with detected entities replaced by placeholders (e.g. <PEOPLE>)
 *
 * @example
 * // Default usage (masks all supported NLP entities)
 * applyNlpRules("John Smith visited Paris")
 * // Returns: "<PEOPLE> visited <PLACES>"
 *
 * @example
 * // Selective masking
 * applyNlpRules("Google bought Fitbit for $2.1 billion", [NlpEntity.ORGS])
 * // Returns: "<ORGS> bought <ORGS> for $2.1 billion"
 */
export function applyNlpRules(text: string, entities: NlpEntity[] = Object.values(NlpEntity)): string {
  if (!text || entities.length === 0) {
    return text
  }

  const doc = nlp(text)

  entities.forEach((entity) => {
    // Compromise returns a View, .out('array') gives us the matched text strings
    const result = doc[entity]().out('array')

    result.forEach((item: string) => {
      text = text.replaceAll(item, `<${entity.toUpperCase()}>`)
    })
  })

  return text
}

