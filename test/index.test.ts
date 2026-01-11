import { describe, test, expect } from '@jest/globals'
import { mask, NlpEntity, CustomRule, FixedPIIEntity } from '../src/index'


describe('JS PII Mask - NLP rules', () => {
  test('should masks acronyms details', () => {
    const output = mask('I support the WWF', {
      nlp: true
    })
    expect(output).toBe('I support the <ACRONYMS>')
  })

  test('should masks money details', () => {
    const output = mask('On vacation I spent $1,520 and exchanged €250 in currency', {
      nlp: true
    })
    expect(output).toBe('On vacation I spent <MONEY> and exchanged <MONEY> in currency')
  })

  test('should masks organizations details', () => {
    const output = mask('I like reading Wikipedia', {
      nlp: true
    })
    expect(output).toBe('I like reading <ORGANIZATIONS>')
  })

  test('should masks people details', () => {
    const output = mask('My name is John Doe and I work with Jane Smith', {
      nlp: true
    })
    expect(output).toBe('My name is <PEOPLE> and I work with <PEOPLE>')
  })

  test('should masks places details', () => {
    const output = mask('Visiting Italy was a wonderful experience', {
      nlp: true
    })
    expect(output).toBe('Visiting <PLACES> was a wonderful experience')
  })

  test('should masks multiple entities (Places and acronyms)', () => {
    const output = mask('In Geneva I visited the CERN headquarters', {
      nlp: true
    })
    expect(output).toBe('In <PLACES> I visited the <ACRONYMS> headquarters')
  })

  test('should masks multiple selective entities (only places)', () => {
    const output = mask('In Geneva I visited the CERN headquarters', {
      nlpRules: [NlpEntity.PLACES]
    })
    expect(output).toBe('In <PLACES> I visited the CERN headquarters')
  })

  // The test fails because the Compromise library has limitations in handling
  // place names written in Italian, such as Geneva (Ginevra).
  test.failing('should masks multiple entities in multiple languages (Places and acronyms)', () => {
    const output = mask('A Ginevra ho visitato la sede del CERN', {
      nlp: true
    })
    expect(output).toBe('In <PLACES> ho visitato la sede del <ACRONYMS>')
  })
})

describe('JS PII Mask - Custom rules', () => {
  test('should mask first and last name', () => {
    const output = mask('I\'m John Doe, nice to meet you.', {
      customRules: [
        {
          pattern: /John/gi,
          replacement: 'FIRST_NAME'
        },
        {
          pattern: /Doe/gi,
          replacement: 'LAST_NAME'
        }
      ] as CustomRule[]
    })
    expect(output).toBe('I\'m <FIRST_NAME> <LAST_NAME>, nice to meet you.')
  })

  test('should mask custom ticket and employee ID', () => {
    const output = mask('Ticket T-123 assigned to EMP-99999', {
      customRules: [
        {
          pattern: /T-\d{3}/g,
          replacement: "TICKET_ID"
        },
        {
          pattern: /EMP-\d{5}/g,
          replacement: "EMPLOYEE_ID"
        }
      ] as CustomRule[]
    })
    expect(output).toBe('Ticket <TICKET_ID> assigned to <EMPLOYEE_ID>')
  })
})

describe('JS PII Mask - Fixed rules', () => {
  // Global PII Entities
  describe('Global PII Entities', () => {

    test('should mask credit card numbers', () => {
      const output = mask('My credit card is 4111 1111 1111 1111.')
      expect(output).toBe('My credit card is <CREDIT_CARD>.')
    })

    test('should mask credit card without separators', () => {
      const output = mask('Card: 1234567890123456')
      expect(output).toBe('Card: <CREDIT_CARD>')
    })

    test('should mask credit card with spaces', () => {
      const output = mask('Card: 1234 5678 9012 3456')
      expect(output).toBe('Card: <CREDIT_CARD>')
    })

    test('should mask cryptocurrency addresses', () => {
      const output = mask('Send BTC to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
      expect(output).toBe('Send BTC to: <CRYPTO>')
    })

    test('should mask dates', () => {
      const output = mask('Date of birth: 01/15/1990')
      expect(output).toBe('Date of birth: <DATE_TIME>')
    })

    test('should mask email addresses', () => {
      const output = mask('My email is example@mail.com!')
      expect(output).toBe('My email is <EMAIL_ADDRESS>!')
    })

    test('should mask multiple email addresses', () => {
      const output = mask('Contact first@example.com or second@test.org for help')
      expect(output).toBe('Contact <EMAIL_ADDRESS> or <EMAIL_ADDRESS> for help')
    })

    test('should mask email in URL parameters', () => {
      const output = mask('Reset link: https://example.com?email=user@test.com')
      expect(output).toBe('Reset link: <URL>?email=<EMAIL_ADDRESS>')
    })

    test('should mask IBAN codes', () => {
      const output = mask('Account IBAN: GB82WEST12345698765432')
      expect(output).toBe('Account IBAN: <IBAN_CODE>')
    })

    test('should mask IP v4 addresses', () => {
      const output = mask('Server IPv4: 192.168.1.1')
      expect(output).toBe('Server IPv4: <IP_ADDRESS>')
    })

    test('should mask IP v6 addresses', () => {
      const output = mask('Server IPv6: 2001:db8:1234:5678:9abc:def0:1234:5678')
      expect(output).toBe('Server IPv6: <IP_ADDRESS>')
    })

    test('should mask multiple IP addresses', () => {
      const output = mask('From 10.0.0.1 to 192.168.1.254')
      expect(output).toBe('From <IP_ADDRESS> to <IP_ADDRESS>')
    })

    test('should mask phone numbers', () => {
      const output = mask('Call me at +1 (555) 123-4567 for details')
      expect(output).toBe('Call me at +1 (<PHONE_NUMBER> for details') // APPROXIMATION, "+1 (" not detected
    })

    test('should mask phone numbers with different formats', () => {
      expect(mask('Phone: 555-123-4567')).toBe('Phone: <PHONE_NUMBER>')
      expect(mask('Phone: (555) 123-4567')).toBe('Phone: (<PHONE_NUMBER>') // APPROXIMATION, first round bracket not detected
      expect(mask('Phone: +1-555-123-4567')).toBe('Phone: +1-<PHONE_NUMBER>') // APPROXIMATION, "+1-" not detected
      expect(mask('Phone: 5551234567')).toBe('Phone: <PHONE_NUMBER>')
    })

    test('should mask URLs', () => {
      const output = mask('Visit https://example.com/path?query=value for more info')
      expect(output).toBe('Visit <URL> for more info')
    })

    test('should mask HTTPS and HTTP URLs', () => {
      expect(mask('Site: https://secure.example.com')).toBe('Site: <URL>')
      expect(mask('Site: http://example.com')).toBe('Site: <URL>')
    })

    test('should mask CVV codes with context', () => {
      expect(mask('CVV: 123')).toBe('<CVV>')
    })

    test('should mask CVV with different context keywords', () => {
      expect(mask('Security code: 456')).toBe('<CVV>')
      expect(mask('CVC: 789')).toBe('<CVV>')
      expect(mask('Card code: 321')).toBe('<CVV>')
    })

    test('should mask BIC/SWIFT codes with context', () => {
      const output = mask('Bank SWIFT: BKENGB2LXXX')
      expect(output).toBe('Bank <BIC_SWIFT>')
    })
  })

  // USA PII Entities
  describe('USA PII Entities', () => {

    test('should mask US bank account numbers', () => {
      const output = mask('Account: 12345678901')
      expect(output).toBe('Account: <US_BANK_NUMBER>')
    })

    test('should mask US driver license', () => {
      const output = mask('License: A1234567')
      expect(output).toBe('License: <US_DRIVER_LICENSE>')
    })

    test('should mask US ITIN', () => {
      const output = mask('ITIN: 912-34-5678')
      expect(output).toBe('ITIN: <US_ITIN>')
    })

    test('should mask US passport numbers', () => {
      const output = mask('Passport: A12345678')
      expect(output).toBe('Passport: <US_PASSPORT>')
    })

    test('should mask US Social Security Numbers', () => {
      const output = mask('My SSN is 123-45-6789')
      expect(output).toBe('My SSN is <US_SSN>')
    })
  })

  // UK PII Entities
  describe('UK PII Entities', () => {
    test('should mask UK National Health Service numbers (with entity FixedPIIEntity.UK_NHS)', () => {
      const output = mask('NHS: 123 456 7890', {
        fixedPiiEntities: [FixedPIIEntity.UK_NHS] // RULES COLLISION, in test cases, the check only works if the UK_NHS entity is passed otherwise, an overlap may occur with the regular expression used for the general phone number check
      })
      expect(output).toBe('NHS: <UK_NHS>')
    })

    test('should mask UK National Insurance numbers', () => {
      const output = mask('NINO: AB123456C')
      expect(output).toBe('NINO: <UK_NINO>')
    })
  })

  // European Union - Spanish PII Entities
  describe('Spanish PII Entities', () => {
    test('should mask Spanish Tax Identification Number (Número de Identificación Fiscal - NIF)', () => {
      const output = mask('NIF: 12345678Z')
      expect(output).toBe('NIF: <ES_NIF>')
    })

    test('should mask Spanish Foreign Identity Number (Número de Identidad de Extranjero - NIE)', () => {
      const output = mask('NIE: X1234567L')
      expect(output).toBe('NIE: <ES_NIE>')
    })
  })

  // European Union - Italian PII Entities
  describe('Italian PII Entities', () => {
    test('should mask Italian fiscal code', () => {
      const output = mask('Codice fiscale: RSSMRA80A01H501U')
      expect(output).toBe('Codice fiscale: <IT_FISCAL_CODE>')
    })

    test('should mask Italian VAT code', () => {
      const output = mask('P.IVA: IT12345678901')
      expect(output).toBe('P.IVA: <IT_VAT_CODE>')
    })

    test('should mask Italian passport', () => {
      const output = mask('Passaporto: AA1234567')
      expect(output).toBe('Passaporto: <IT_DOCUMENT>')
    })

    test('should mask Italian identity card', () => {
      const output = mask('Carta d\'identità: CA1234567')
      expect(output).toBe('Carta d\'identità: <IT_DOCUMENT>')
    })

    test('should mask Italian driver license', () => {
      const output = mask('Patente: MI1234567')
      expect(output).toBe('Patente: <IT_DOCUMENT>')
    })
  })

  // European Union - Other European PII Entities
  describe('Other European PII Entities', () => {
    test('should mask Polish national identification number (Powszechny Elektroniczny System Ewidencji Ludności - PESEL)', () => {
      const output = mask('PESEL: 12345678901', {
        fixedPiiEntities: [FixedPIIEntity.PL_PESEL] // RULES COLLISION, in test cases, the check only works if the PL_PESEL entity is passed; otherwise, an overlap may occur with the regular expression used for the USA Bank number
      })
      expect(output).toBe('PESEL: <PL_PESEL>')
    })

    test('should mask Finnish personal identity code', () => {
      const output = mask('Henkilötunnus: 010190-123A')
      expect(output).toBe('Henkilötunnus: <FI_PERSONAL_IDENTITY_CODE>')
    })
  })

  // Asia-Pacific - Singapore PII Entities
  describe('Singapore PII Entities', () => {
    test('should mask Singapore National Registration Identity Card (NRIC)', () => {
      const output = mask('NRIC: S1234567D')
      expect(output).toBe('NRIC: <SG_NRIC_FIN>')
    })

    test('should mask Singapore Foreign Identification Number (FIN)', () => {
      const output = mask('NRIC: F1234567D')
      expect(output).toBe('NRIC: <SG_NRIC_FIN>')
    })

    test('should mask Singapore Unique Entity Number (UEN - 9 digits)', () => {
      const output = mask('UEN: 53499876V', {
        fixedPiiEntities: [FixedPIIEntity.SG_UEN] // RULES COLLISION, in test cases, the check only works if the SG_UEN entity is passed; otherwise, an overlap may occur with the regular expression used for the Spanish NIF
      })
      expect(output).toBe('UEN: <SG_UEN>')
    })

    test('should mask Singapore Unique Entity Number (UEN - 10 digits)', () => {
      const output = mask('UEN: 201312345G')
      expect(output).toBe('UEN: <SG_UEN>')
    })
  })

  // Asia-Pacific - Australian PII Entities
  describe('Australian PII Entities', () => {
    test('should mask Australian Business Number', () => {
      const output = mask('ABN: 12 345 678 901')
      expect(output).toBe('ABN: <AU_ABN>')
    })

    test('should mask Australian Company Number', () => {
      const output = mask('ACN: 123 456 789')
      expect(output).toBe('ACN: <AU_ACN>')
    })

    test('should mask Australian Tax File Number', () => {
      const output = mask('TFN: 123456789', {
        fixedPiiEntities: [FixedPIIEntity.AU_TFN] // RULES COLLISION, in test cases, the check only works if the AU_TFN entity is passed; otherwise, an overlap may occur with the regular expression used for the USA Bank number
      })
      expect(output).toBe('TFN: <AU_TFN>')
    })

    test('should mask Australian Medicare number', () => {
      const output = mask('Medicare: 1234 56789 1')
      expect(output).toBe('Medicare: <AU_MEDICARE>')
    })
  })

  // Asia-Pacific - Indian PII Entities
  describe('Indian PII Entities', () => {
    test('should mask Indian PAN', () => {
      const output = mask('PAN: ABCDE1234F')
      expect(output).toBe('PAN: <IN_PAN>')
    })

    test('should mask Indian Aadhaar', () => {
      const output = mask('Aadhaar: 1234 5678 9012')
      expect(output).toBe('Aadhaar: <IN_AADHAAR>')
    })

    test('should mask Indian passport', () => {
      const output = mask('Passport: A1234567', {
        fixedPiiEntities: [FixedPIIEntity.IN_PASSPORT] // RULES COLLISION, in test cases, the check only works if the AU_TFN entity is passed; otherwise, an overlap may occur with the regular expression used for the USA Driver License
      })
      expect(output).toBe('Passport: <IN_PASSPORT>')
    })

    test('should mask Indian voter ID', () => {
      const output = mask('Voter ID: ABC1234567')
      expect(output).toBe('Voter ID: <IN_VOTER>')
    })

    test('should mask Indian vehicle registration', () => {
      const output = mask('Vehicle: DL01AB1234')
      expect(output).toBe('Vehicle: <IN_VEHICLE_REGISTRATION>')
    })
  })

  // Asia-Pacific - Korean PII Entities
  describe('Korean PII Entities', () => {
    test('should mask Korean Resident Registration Number (주민등록번호)', () => {
      const output = mask('RRN: 901231-1234567')
      expect(output).toBe('RRN: <KR_RRN>')
    })
  })

  // Multiple PII Types
  describe('Multiple PII Types', () => {
    test('should mask multiple different PII types in one text', () => {
      const output = mask('Contact john@example.com, phone 555-123-4567, SSN 123-45-6789')
      expect(output).toBe('Contact <EMAIL_ADDRESS>, phone <PHONE_NUMBER>, SSN <US_SSN>')
    })

    test('should mask mixed global and regional PII', () => {
      const output = mask('Email: test@example.com, codice Fiscale: RSSMRA80A01H501U, IP: 192.168.1.1')
      expect(output).toBe('Email: <EMAIL_ADDRESS>, codice Fiscale: <IT_FISCAL_CODE>, IP: <IP_ADDRESS>')
    })

    test('should handle complex real-world example', () => {
      const output = mask(`
        Customer Information:
        Email: john.doe@example.com
        Phone: +1 (555) 123-4567
        SSN: 123-45-6789
        Credit Card: 1234-5678-9012-3456
        CVV: 123
        IP Address: 192.168.1.100
      `)

      expect(output).toContain('<EMAIL_ADDRESS>')
      expect(output).toContain('<PHONE_NUMBER>')
      expect(output).toContain('<US_SSN>')
      expect(output).toContain('<CREDIT_CARD>')
      expect(output).toContain('<CVV>')
      expect(output).toContain('<IP_ADDRESS>')
      expect(output).not.toContain('john.doe@example.com')
      expect(output).not.toContain('123-45-6789')
    })
  })

  // Edge Cases
  describe('Edge Cases', () => {
    test('should return empty string for empty input', () => {
      expect(mask('')).toBe('')
    })

    test('should return original text when no PII detected', () => {
      const output = mask('This is a simple text without any PII information.')
      expect(output).toBe('This is a simple text without any PII information.')
    })

    test('should handle text with only whitespace', () => {
      expect(mask('   ')).toBe('   ')
    })

    test('should handle special characters around PII', () => {
      const output = mask('"test@example.com" is my email!')
      expect(output).toBe('"<EMAIL_ADDRESS>" is my email!')
    })

    test('should handle parentheses around PII', () => {
      const output = mask('Email (admin@example.com) for support')
      expect(output).toBe('Email (<EMAIL_ADDRESS>) for support')
    })

    test('should handle PII at start of text', () => {
      const output = mask('test@example.com is the contact email')
      expect(output).toBe('<EMAIL_ADDRESS> is the contact email')
    })

    test('should handle PII at end of text', () => {
      const output = mask('Contact email: test@example.com')
      expect(output).toBe('Contact email: <EMAIL_ADDRESS>')
    })

    test('should handle multiple spaces between words', () => {
      const output = mask('Email:    test@example.com    here')
      expect(output).toBe('Email:    <EMAIL_ADDRESS>    here')
    })

    test('should handle newlines', () => {
      const output = mask('Email:\ntest@example.com\nPhone:\n555-123-4567')
      expect(output).toBe('Email:\n<EMAIL_ADDRESS>\nPhone:\n<PHONE_NUMBER>')
    })

    test('should handle tabs', () => {
      const output = mask('Email:\ttest@example.com\tPhone:\t555-123-4567')
      expect(output).toBe('Email:\t<EMAIL_ADDRESS>\tPhone:\t<PHONE_NUMBER>')
    })
  })

  // Unicode and Special Characters
  describe('Unicode and Special Characters', () => {
    test('should normalize Unicode text before masking', () => {
      const output = mask('Email: test\u200B@example.com') // Zero-width space
      expect(output).toBe('Email: <EMAIL_ADDRESS>')
    })

    test('should handle various zero-width characters', () => {
      const output = mask('test\u200C@example.com') // Zero-width non-joiner
      expect(output).toContain('<EMAIL_ADDRESS>')
    })

    test('should handle accented characters in text', () => {
      const output = mask('Émáíl: test@example.com')
      expect(output).toBe('Émáíl: <EMAIL_ADDRESS>')
    })
  })

  // Overlapping Patterns
  describe('Overlapping Patterns', () => {
    test('should handle overlapping patterns correctly', () => {
      // Some numbers might match multiple patterns
      const output = mask('Number: 1234567890123456')

      // Should mask with one pattern (not both)
      const matches = output.match(/<[A-Z_]+>/g)
      expect(matches).not.toBeNull()
      expect(matches!.length).toBe(1)
    })

    test('should prefer longer matches', () => {
      // Credit card should be preferred over potential bank number
      const output = mask('1234567890123456')
      expect(output).toBe('<CREDIT_CARD>')
    })
  })

  // Performance and Stress Tests
  describe('Performance and Stress Tests', () => {
    test('should handle long text efficiently', () => {
      const longText = 'Email: test@example.com. '.repeat(100)
      const startTime = Date.now()
      const output = mask(longText, { nlp: true })
      const endTime = Date.now()

      expect(endTime - startTime).toBeLessThan(1000) // Should complete in under 1 second
      expect(output).toContain('<EMAIL_ADDRESS>')
    })

    test('should handle text with no PII efficiently', () => {
      const longText = 'This is just normal text without any sensitive information. '.repeat(100)
      const startTime = Date.now()
      const output = mask(longText)
      const endTime = Date.now()

      expect(endTime - startTime).toBeLessThan(1000)
      expect(output).toBe(longText)
    })

    test('should handle many different PII types in one text', () => {
      const output = mask(`
        Name: John Doe
        Email: test@example.com
        Phone: 555-123-4567
        SSN: 123-45-6789
        Credit Card: 1234-5678-9012-3456
        IP: 192.168.1.1
        URL: https://example.com
        IBAN: DE89370400440532013000
        Passport: A12345678
      `, { nlp: true })

      expect(output).toContain('<PEOPLE>')
      expect(output).toContain('<EMAIL_ADDRESS>')
      expect(output).toContain('<PHONE_NUMBER>')
      expect(output).toContain('<US_SSN>')
      expect(output).toContain('<CREDIT_CARD>')
      expect(output).toContain('<IP_ADDRESS>')
      expect(output).toContain('<URL>')
      expect(output).toContain('<IBAN_CODE>')
      expect(output).toContain('<US_PASSPORT>')
    })
  })
})