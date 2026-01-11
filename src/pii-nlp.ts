import nlp from "compromise";

export enum NlpEntity {
  ACRONYMS = 'acronyms',
  MONEY = 'money',
  ORGS = 'organizations',
  PEOPLE = 'people',
  PLACES = 'places'
}

export function applyNlpRules(text: string, entities: NlpEntity[] = Object.values(NlpEntity)): string {
  if (!text || entities.length === 0) {
    return text
  }

  const doc = nlp(text)

  entities.forEach((entity) => {
    const result = (doc as any)[entity]().out("array")

    result.forEach((item: string) => {
      text = text.replaceAll(item, `<${entity.toUpperCase()}>`)
    })
  })

  return text
}
