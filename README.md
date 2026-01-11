# JS PII Mask

[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](https://opensource.org/licenses/MIT)
[![TypeScript](https://shields.io/badge/TypeScript-3178C6?logo=TypeScript&logoColor=FFF&style=flat-square)](https://www.typescriptlang.org)
[![npm](https://img.shields.io/npm/v/@yellowsakura/js-pii-mask)](https://www.npmjs.com/package/@yellowsakura/js-pii-mask)

<img align="left" width="100px" src="docs/logo.webp">

Simple lightweight PII (Personally Identifiable Information) masking library for **TypeScript / JavaScript**.

It provides **regex-based detection and masking** of common PII patterns, inspired by [OpenAI's guardrails-js](https://github.com/openai/openai-guardrails-js), with **basic NLP capabilities** to enhance its detection power, and a strong focus on simplicity, predictability, and extensibility.

> Heuristic-based detection: useful in practice, **not a compliance guarantee**.

## Contents

1. [Features](#features)
2. [Installation and use](#installation-and-use)
3. [Supported PII entities](#supported-pii-entities)
4. [API reference](#api-reference)
5. [How it works and recommended use cases](#how-it-works-and-recommended-use-cases)
6. [License](#license)

## Features

- 🔎 Detects **40+ common PII types** (global + regional)
- 🧩 **Custom rules** for managing specific domains
- ⚡ Fast, sequential processing
- 🧠 **Optional lightweight NLP** for dynamic named entities (names, places, orgs)
- 🔍 **Trade-offs**: Balanced for minimal false positives, but may miss some edge cases

This library is **pattern-based**.

**Works well for**:
- Structured formats (emails, credit cards, SSNs, IBANs, phone numbers)

**Does NOT**:
- Understand semantic context
- Detect unstructured personal data
- Perform deep NER or NLP
- Guarantee 100% accuracy

**Expect**:
- False positives (numbers matching known formats)
- False negatives (PII without clear patterns)

Always combine with **manual review, access controls, encryption, and legal validation** for sensitive use cases.

## Installation and use

```bash
npm install @yellowsakura/js-pii-mask
```

Quick start:

For ESM:

```ts
import { mask } from '@yellowsakura/js-pii-mask'

mask('Email: admin@example.com, SSN: 123-45-6789')
// → "Email: <EMAIL_ADDRESS>, SSN: <US_SSN>"

mask('Contact john@example.com or call +1-555-123-4567')
// → "Contact <EMAIL_ADDRESS> or call +1-<PHONE_NUMBER>"
```

For CommonJS:

```js
const { mask, FixedPIIEntity } = require('@yellowsakura/js-pii-mask');

mask('Email: admin@example.com, SSN: 123-45-6789')
// → "Email: <EMAIL_ADDRESS>, SSN: <US_SSN>"
```

**Note:** all the following examples use **ESM syntax**. 

### Selective fixed rule

```ts
import { mask, FixedPIIEntity } from '@yellowsakura/js-pii-mask'

// Mask only specific entity types
mask('Email: test@example.com, SSN: 123-45-6789', {
  fixedPiiEntities: [FixedPIIEntity.EMAIL_ADDRESS]
})
// → "Email: <EMAIL_ADDRESS>, SSN: 123-45-6789"

// Mask only financial information
mask('Card: 1234-5678-9012-3456, Email: test@example.com', {
  fixedPiiEntities: [FixedPIIEntity.CREDIT_CARD, FixedPIIEntity.US_BANK_NUMBER]
})
// → "Card: <CREDIT_CARD>, Email: test@example.com"
```

### Custom rules

Use custom rules for internal or domain-specific identifiers.

```ts
import { mask } from '@yellowsakura/js-pii-mask'
import type { CustomRule } from '@yellowsakura/js-pii-mask'

const rules: CustomRule[] = [
  { pattern: /EMP-\d{5}/g, replacement: 'EMPLOYEE_ID' },
  { pattern: /TICKET-[A-Z0-9]{8}/gi, replacement: 'TICKET_ID' }
]

mask('Employee EMP-12345 opened TICKET-ABC12345', { customRules: rules })
// → "Employee <EMPLOYEE_ID> opened <TICKET_ID>"
```

> Custom rules are applied **before** built-in PII detection.

### Custom + fixed rules

```ts
import { mask, FixedPIIEntity } from '@yellowsakura/js-pii-mask'
import type { CustomRule } from '@yellowsakura/js-pii-mask'

mask('Employee EMP-12345 (email: john@company.com) submitted ticket', {
  customRules: [
    { pattern: /EMP-\d{5}/g, replacement: 'EMPLOYEE_ID' }
  ],
  fixedPiiEntities: [FixedPIIEntity.EMAIL_ADDRESS]
})
// → "Employee <EMPLOYEE_ID> (email: <EMAIL_ADDRESS>) submitted ticket"
```

### Using NLP (Lightweight)

You can enable **N**atural **L**anguage **P**rocessing to detect dynamic entities like names, places, and organizations.  
This uses the [compromise](https://www.npmjs.com/package/compromise) library.

```ts
import { mask, NlpEntity } from '@yellowsakura/js-pii-mask'

// Enable default NLP entities (People, Places, Orgs, etc.)
mask('John Smith visited Paris', { nlp: true })
// → "<PEOPLE> visited <PLACES>"

// Selective NLP entities
mask('Google bought Fitbit for $2.1 billion', { 
  nlpRules: [NlpEntity.ORGS, NlpEntity.MONEY] 
})
// → "<ORGS> bought <ORGS> for <MONEY>"
```

> **⚠️ NLP Limitations & Best Practices**
> 
> The NLP feature is powered by `compromise`, a lightweight library designed to be fast rather than perfect.
>
> - **Language Support**: Optimized primarily for **English**. Accuracy in other languages is limited.
> - **Accuracy**: Expect higher false positives/negatives than deep-learning based NER models.
> - **Performance**: Little slower than pure regex regex-based masking.

## Supported PII entities

The library includes **40+ predefined patterns**, including:

### Global
- EMAIL_ADDRESS
- PHONE_NUMBER
- CREDIT_CARD
- IP_ADDRESS (IPv4 / IPv6)
- IBAN_CODE
- URL
- DATE_TIME

### NLP Entities (Dynamic)
- PEOPLE (Names)
- PLACES (Locations, Cities, Countries)
- ORGS (Organizations, Companies)
- MONEY (Currency amounts)
- ACRONYMS

### Country-specific (examples)
- US: SSN, Passport, Bank Number, ITIN
- UK: NHS, NINO
- EU: IT Fiscal Code, VAT, PESEL, NIF/NIE
- APAC: Aadhaar, PAN, NRIC/FIN, TFN, Medicare

Some entities require **context keywords** (e.g. `CVV`, `BIC_SWIFT`) to reduce false positives.

See [`src/pii-nlp.ts`](./src/pii-nlp.ts) and [`src/pii-fixed-rules.ts`](./src/pii-fixed-rules.ts) for an exhaustive list.

## API reference

### `mask(text: string, options?: MaskOptions): string`

Main function to mask PII in text.

**Parameters:**
- `text: string` - The text to scan and mask
- `options?: MaskOptions` - Optional configuration object

**Mask options:**

```ts
type MaskOptions = {
  // Array of custom masking rules (always applied FIRST)
  customRules?: CustomRule[]

  // Enable NLP processing (default: false)
  nlp?: boolean

  // Specific NLP entities to detect (default: all if nlp=true)
  nlpRules?: NlpEntity[]

  // Array of specific fixed PII entities to detect (always applied AFTER custom rules)
  // If empty or undefined, ALL fixed entities are checked
  fixedPiiEntities?: FixedPIIEntity[]
}
```

**Order of execution:**
1. **NLP Rules** (if enabled)
2. **Custom Rules** (if defined)
3. **Fixed PII Rules**
```

**Returns:** 
- `string` - The masked text with PII replaced by `<REPLACED>` placeholders

### `CustomRule` interface

```ts
interface CustomRule {
  // Regular expression pattern to match (should use global flag /g)
  pattern: RegExp
  
  // Replacement string (will be wrapped in < >)
  replacement: string
}
```

**Guidelines:**
- Always use global flag (`/g`) to match all occurrences
- Be specific to avoid matching unintended text
- Use word boundaries (`\b`) when appropriate
- Test thoroughly with representative data

**Examples:**
```ts
// Good: Case-insensitive matching
{
  pattern: /ticket-[a-z0-9]{8}/gi,
  replacement: 'TICKET_ID'
}

// Warning: Too broad
{
  pattern: /\d{5}/g, // Matches any 5 digits
  replacement: 'NUMBER'
}
```
### `NlpEntity` Enum

Enumeration of all predefined NLP entity types, import to specify which entities to detect:

```ts
import { NlpEntity } from '@yellowsakura/js-pii-mask'

mask(text, {
  nlpRules: [
    NlpEntity.ACRONYMS,
    NlpEntity.MONEY,
    NlpEntity.ORGS,
    NlpEntity.PEOPLE,
    NlpEntity.PLACES
  ]
})
```

### `FixedPIIEntity` Enum

Enumeration of all predefined PII entity types, import to specify which entities to detect:

```ts
import { FixedPIIEntity } from '@yellowsakura/js-pii-mask'

mask(text, {
  fixedPiiEntities: [
    FixedPIIEntity.EMAIL_ADDRESS,
    FixedPIIEntity.PHONE_NUMBER,
    FixedPIIEntity.US_SSN,
    ...
  ]
})
```

## How it works and recommended use cases:

1. Unicode normalization (NFKC, zero-width removal)
2. Apply NLP Rules
3. Apply custom rules (in order)
4. Apply fixed PII rules (all or selected)

Deterministic, sequential, and predictable.

### Use cases

✅ Test / staging data anonymization  
✅ API response redaction  
✅ Preprocessing before third-party services (e.g. LLM)  
✅ Masking internal identifiers

⚠️ Use with caution for:
- Legal, medical, or financial documents  
- Automated compliance enforcement

❌ Not suitable as a standalone compliance solution.

## License

The code is licensed under the [MIT](https://opensource.org/licenses/MIT) by [Yellow Sakura](https://www.yellowsakura.com), [support@yellowsakura.com](mailto:support@yellowsakura.com), see the LICENSE file.  

This library is adapted from [OpenAI's guardrails-js](https://github.com/openai/openai-guardrails-js) PII detection patterns.
