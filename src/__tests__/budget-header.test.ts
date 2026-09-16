// AAuth-Budget response header parsing (draft-hardt-aauth-budgets §AAuth-Budget
// Response Header): an RFC 9651 Dictionary; unrecognized members are ignored.

import { describe, it, expect } from 'vitest'
import { parseBudget } from '../agent.js'

describe('parseBudget', () => {
  it('reads remaining and cost', () => {
    expect(parseBudget('cost=2, remaining=98')).toEqual({ cost: 2, remaining: 98 })
  })

  it('reads the unit and decimals pair, including folded whitespace', () => {
    expect(parseBudget('cost=221200, remaining=1568800,\n    unit="USD", decimals=6')).toEqual({
      cost: 221200,
      remaining: 1568800,
      unit: 'USD',
      decimals: 6,
    })
  })

  it('reads reserved and required', () => {
    expect(parseBudget('remaining=40, reserved=10')).toEqual({ remaining: 40, reserved: 10 })
    expect(parseBudget('remaining=1, required=8')).toEqual({ remaining: 1, required: 8 })
  })

  it('ignores unrecognized members and mistyped values', () => {
    expect(parseBudget('remaining=5, future=7, note="x", unit=3')).toEqual({ remaining: 5 })
  })

  it('returns undefined for an absent or empty header', () => {
    expect(parseBudget(null)).toBeUndefined()
    expect(parseBudget('')).toBeUndefined()
    expect(parseBudget('granted')).toBeUndefined()
  })
})
