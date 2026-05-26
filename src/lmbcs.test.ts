import { describe, it } from 'node:test'
import { strict as assert } from 'node:assert'

import { bufFromString, stringFromBuf } from './lmbcs.js'

describe('codepage handling', () => {
  it('should be able to convert an ascii string and back again', () => {
    const strInput: string = 'my test username'
    const bufConverted: Buffer = bufFromString(strInput)
    const backAgain: string = stringFromBuf(bufConverted)
    assert.equal(strInput, backAgain)
  })

  describe('LMBCS-1', () => {
    it('should properly prefix lower LMBCS-1 characters with the 0x01 lead byte', () => {
      const strInput: string = '☺☻♥'
      const bufExpected: Buffer = Buffer.from([
        0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
      ])
      const bufConverted: Buffer = bufFromString(strInput)
      assert.deepEqual(bufConverted, bufExpected)

      const backAgain: string = stringFromBuf(bufConverted)
      assert.equal(strInput, backAgain)
    })

    it('should default to LMBCS-1 for single characters over 0x1F', () => {
      // leading bytes are not needed for upper LMBCS-1 characters
      const strInput: string = 'åäö'
      const bufExpected: Buffer = Buffer.from([0x86, 0x84, 0x94])
      const bufConverted: Buffer = bufFromString(strInput)
      assert.deepEqual(bufConverted, bufExpected)

      const backAgain: string = stringFromBuf(bufConverted)
      assert.equal(strInput, backAgain)
    })

    it('should decode high LMBCS-1 characters even with the 0x01 lead byte', () => {
      const bufInput: Buffer = Buffer.from([0x01, 0x86, 0x01, 0x84, 0x01, 0x94])
      const strExpected: string = 'åäö'
      const strConverted: string = stringFromBuf(bufInput)
      assert.deepEqual(strConverted, strExpected)
    })
  })

  it('should be able to convert an LMBCS-6 string and back again', () => {
    const strInput: string = 'Łuczak'
    const bufExpected: Buffer = Buffer.from([
      0x06, 0x9d, 0x75, 0x63, 0x7a, 0x61, 0x6b,
    ])
    const bufConverted: Buffer = bufFromString(strInput)
    assert.deepEqual(bufConverted, bufExpected)

    const backAgain: string = stringFromBuf(bufConverted)
    assert.equal(strInput, backAgain)
  })

  it('should be able to handle a string containing both LMBCS-1 and LMBCS-6 characters', () => {
    const strInput: string = 'Måns Östen Łučzak'
    const bufExpected: Buffer = Buffer.from([
      0x4d, 0x86, 0x6e, 0x73, 0x20, 0x99, 0x73, 0x74, 0x65, 0x6e, 0x20, 0x06,
      0x9d, 0x75, 0x06, 0x9f, 0x7a, 0x61, 0x6b,
    ])
    const bufConverted: Buffer = bufFromString(strInput)
    assert.deepEqual(bufConverted, bufExpected)

    const backAgain: string = stringFromBuf(bufConverted)
    assert.equal(strInput, backAgain)
  })

  it('should handle Lithuanian characters correctly', () => {
    const strInput: string = 'Ąžuolasė'
    const bufExpected: Buffer = Buffer.from([
      0x06, 0xa4, 0x06, 0xa7, 0x75, 0x6f, 0x6c, 0x61, 0x73, 0x06, 0x09,
    ])
    const bufConverted: Buffer = bufFromString(strInput)
    assert.deepEqual(bufConverted, bufExpected)

    const backAgain: string = stringFromBuf(bufConverted)
    assert.equal(strInput, backAgain)
  })

  describe('LMBCS-20', () => {
    it('should encode unknown characters into LMBCS-20', () => {
      const strInput: string = 'Hello, 世界'
      // 世 = U+4E16 → [0x14, 0x4E, 0x16] (BE), 界 = U+754C → [0x14, 0x75, 0x4C] (BE)
      const bufExpected: Buffer = Buffer.from([
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x14, 0x4e, 0x16, 0x14, 0x75,
        0x4c,
      ])
      const bufConverted: Buffer = bufFromString(strInput)
      assert.deepEqual(bufConverted, bufExpected)

      const backAgain: string = stringFromBuf(bufConverted)
      assert.equal(backAgain, strInput)
    })

    it('should remap code units with low byte 0x00 to avoid NUL bytes', () => {
      // Ȁ = U+0200: high=0x02, low=0x00 → remapped to [0x14, 0xF6, 0x02]
      const strInput: string = 'Ȁ'
      const bufExpected: Buffer = Buffer.from([0x14, 0xf6, 0x02])
      const bufConverted: Buffer = bufFromString(strInput)
      assert.deepEqual(bufConverted, bufExpected)

      const backAgain: string = stringFromBuf(bufConverted)
      assert.equal(backAgain, strInput)
    })
  })

  it('should properly encode null characters', () => {
    const strInput: string = 'Null char:\0end'
    const bufExpected: Buffer = Buffer.from([
      0x4e, 0x75, 0x6c, 0x6c, 0x20, 0x63, 0x68, 0x61, 0x72, 0x3a, 0x00, 0x65,
      0x6e, 0x64,
    ])
    const bufConverted: Buffer = bufFromString(strInput)
    assert.deepEqual(bufConverted, bufExpected)

    const backAgain: string = stringFromBuf(bufConverted)
    assert.equal(backAgain, strInput)
  })

  it('should throw an error when trying to decode unsupported characters', () => {
    // 0x11 is not a valid lead byte in our implementation
    const bufInput: Buffer = Buffer.from([0x11, 0x34])
    assert.throws(
      () => stringFromBuf(bufInput),
      /Unsupported lead byte 17 at position 0/,
    )
  })
})
