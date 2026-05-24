import { describe, it } from 'node:test'
import { strict as assert } from 'node:assert'

import { bufFromString, stringFromBuf } from './lmbcs.js'

describe('codepage handling', () => {
  it('should be able to convert an ascii string and back again', () => {
    const input = 'my test username'
    const buf = bufFromString(input)
    const backAgain = stringFromBuf(buf)
    assert.equal(input, backAgain)
  })

  it('should convert a string of LMBCS-1 characters to the correct buffer', () => {
    const input = 'åäö'
    const expected = Buffer.from([0x01, 0x86, 0x01, 0x84, 0x01, 0x94])
    const buf = bufFromString(input)
    assert.deepEqual(buf, expected)

    const backAgain = stringFromBuf(expected)
    assert.equal(input, backAgain)
  })

  it('should be able to convert LMBCS-6 string and back again', () => {
    const input = 'Łuczak'
    const expected = Buffer.from([0x06, 0x9d, 0x75, 0x63, 0x7a, 0x61, 0x6b])
    const buf = bufFromString(input)
    assert.deepEqual(buf, expected)

    const backAgain = stringFromBuf(expected)
    assert.equal(input, backAgain)
  })

  it('should be able to handle a string containing both LMBCS-1 and LMBCS-6 characters', () => {
    const input = 'Måns Östen Łučzak'
    const expected = Buffer.from([
      0x4d, 0x01, 0x86, 0x6e, 0x73, 0x20, 0x01, 0x99, 0x73, 0x74, 0x65, 0x6e,
      0x20, 0x06, 0x9d, 0x75, 0x06, 0x9f, 0x7a, 0x61, 0x6b,
    ])
    const buf = bufFromString(input)
    assert.deepEqual(buf, expected)

    const backAgain = stringFromBuf(expected)
    assert.equal(input, backAgain)
  })

  it('should handle Lithuanian characters correctly', () => {
    const input = 'Ąžuolasė'
    const expected = Buffer.from([
      0x06, 0xa4, 0x06, 0xa7, 0x75, 0x6f, 0x6c, 0x61, 0x73, 0x06, 0x09,
    ])
    const buf = bufFromString(input)
    assert.deepEqual(buf, expected)

    const backAgain = stringFromBuf(expected)
    assert.equal(input, backAgain)
  })
})
