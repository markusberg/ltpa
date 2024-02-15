import * as ltpa from './index.js'

import { describe, it, beforeEach } from 'vitest'
import { strict as assert } from 'node:assert'

const secrets = {
  'example.com': 'AAECAwQFBgcICQoLDA0ODxAREhM=',
  'invalid.example.com': 'AAABAQICAwMEBAUFBgYHBwgICQk=',
}
ltpa.setSecrets(secrets)

const knownTokens = [
  {
    timeCreation: 1234567890,
    validity: 5400,
    gracePeriod: 300,
    base64:
      'AAECAzQ5OTYwMWE2NDk5NjE5MTZNeSBUZXN0IFVzZXJjcHMKyXIrtD4SZcV7DKWd67EFng==',
  },
  {
    timeCreation: 1234567890,
    validity: 5400,
    gracePeriod: 0,
    base64:
      'AAECAzQ5OTYwMmQyNDk5NjE3ZWFNeSBUZXN0IFVzZXJ1HUi4fVHSeb8JgA2xsVK0kjromg==',
  },
  {
    timeCreation: 1234567890,
    validity: 10,
    gracePeriod: 0,
    base64:
      'AAECAzQ5OTYwMmQyNDk5NjAyZGNNeSBUZXN0IFVzZXJs8zRFVehH/c9RpQ/KvUPhBM5tdQ==',
  },
]

let userName: string
let userNameBuf: Buffer
let newToken: string
let invalidToken: string
let now: number

describe('Ltpa', function () {
  beforeEach(() => {
    ltpa.setGracePeriod(300)
    ltpa.setValidity(5400)
    ltpa.setStrictExpirationValidation(false)

    userName = 'My Test User'
    userNameBuf = ltpa.generateUserNameBuf(userName)
    newToken = ltpa.generate(userNameBuf, 'example.com')
    invalidToken = ltpa.generate(userNameBuf, 'invalid.example.com')
    now = Math.floor(Date.now() / 1000)
  })

  describe('basic sanity checks', () => {
    it('should fail to validate a non-existent token', () => {
      assert.throws(
        () => ltpa.validate('', 'example.com'),
        Error,
        'No token provided',
      )
    })

    it('should fail to validate a non-existent domain', () => {
      assert.throws(
        () => ltpa.validate(newToken, ''),
        Error,
        'No domain provided',
      )
    })

    it("should fail to validate a token that's impossibly short", () => {
      const size = Buffer.byteLength(newToken, 'base64')
      const myBuffer = Buffer.alloc(size)
      myBuffer.write(newToken, 0, size, 'base64')
      const corruptToken = myBuffer.subarray(0, 33).toString('base64')
      assert.throws(
        () => ltpa.validate(corruptToken, 'example.com'),
        Error,
        'Ltpa Token too short',
      )
    })

    it('should get the userName from the token', () => {
      const result = ltpa.getUserName(newToken)
      assert.equal(result, userName)
    })

    it('should fail to validate a token with an invalid magic string', () => {
      const size = Buffer.byteLength(newToken, 'base64')
      const myBuffer = Buffer.alloc(size)
      myBuffer.write(newToken, 0, size, 'base64')
      myBuffer.write('99', 0, 1, 'hex')
      const corruptToken = myBuffer.toString('base64')
      assert.throws(
        () => ltpa.validate(corruptToken, 'example.com'),
        Error,
        'Incorrect magic string',
      )
    })

    it('should fail to validate a token with an incorrect secret key', () => {
      assert.throws(
        () => ltpa.validate(newToken, 'blabla.example.com'),
        Error,
        'No such server secret exists',
      )
    })
  })

  describe('known tokens regression tests', () => {
    it('should generate', () => {
      knownTokens.forEach((token) => {
        ltpa.setGracePeriod(token.gracePeriod)
        ltpa.setValidity(token.validity)
        assert.equal(
          ltpa.generate(userNameBuf, 'example.com', token.timeCreation),
          token.base64,
        )
      })
    })

    /* TODO: Use rewire to unit-test these parts
    it("should validate the hashes", () => {
      const tok = new Token()
      knownTokens.forEach((token) => {
        tok.parse(token.base64)
        assert(() => tok.validateHash(secrets["example.com"])).not.to.throw()
      })
    })

    it("should validate creation and reject expiration times", () => {
      const tok = new Token()
      knownTokens.forEach((token) => {
        tok.parse(token.base64)
        assert(() => tok.validateTimeCreation(0)).to.not.throw()
        assert(() => tok.validateTimeExpirationStrict()).to.throw(
          Error,
          "Ltpa Token has expired",
        )
      })
    })
    */
  })

  describe('token generation and refresh', () => {
    it('should generate a token', () => {
      assert.equal(typeof newToken, 'string')
    })

    it('should generate a valid token', () => {
      assert.doesNotThrow(() => ltpa.validate(newToken, 'example.com'))
    })

    it('should refresh a valid token', () => {
      const result = ltpa.refresh(newToken, 'example.com')
      const size = Buffer.byteLength(result, 'base64')
      assert.equal(typeof result, 'string')
      assert.equal(size, 40 + userName.length)
    })

    it('should fail to validate an invalid token', () => {
      assert.throws(
        () => ltpa.validate(invalidToken, 'example.com'),
        Error,
        "Ltpa Token signature doesn't validate",
      )
    })

    it('should fail to refresh an invalid token', () => {
      assert.throws(
        () => ltpa.refresh(invalidToken, 'example.com'),
        Error,
        "Ltpa Token signature doesn't validate",
      )
    })
  })

  describe('expiration and grace period', () => {
    it('should generate, but fail to validate an expired token', () => {
      const token = ltpa.generate(userNameBuf, 'example.com', 12)
      assert.throws(
        () => ltpa.validate(token, 'example.com'),
        Error,
        'Ltpa Token has expired',
      )
    })

    it('should validate a token that has expired, but is within the grace period', () => {
      const justExpired = now - 5500
      const justExpiredToken = ltpa.generate(
        userNameBuf,
        'example.com',
        justExpired,
      )
      assert.doesNotThrow(() => ltpa.validate(justExpiredToken, 'example.com'))
    })

    it('should be possible to change the grace period', () => {
      ltpa.setGracePeriod(0)
      assert.doesNotThrow(() => ltpa.validate(newToken, 'example.com'))
    })

    it('should be possible to change the token validity', () => {
      ltpa.setValidity(10)
      ltpa.setGracePeriod(0)
      const inThePast = now - 15
      const expiredToken = ltpa.generate(userNameBuf, 'example.com', inThePast)
      assert.throws(
        () => ltpa.validate(expiredToken, 'example.com'),
        Error,
        'Ltpa Token has expired',
      )
    })

    it('should generate, but fail to validate a not yet valid token', () => {
      // Generate a token that starts being valid more than two gracePeriods into the future
      const futureTime = now + 700
      const futureToken = ltpa.generate(userNameBuf, 'example.com', futureTime)
      assert.throws(
        () => ltpa.validate(futureToken, 'example.com'),
        Error,
        'Ltpa Token not yet valid',
      )
    })
  })

  describe('strict expiration validation', () => {
    it('should validate a token using the token expiration date', () => {
      // this token is invalid with non-strict validation
      ltpa.setStrictExpirationValidation(true)
      ltpa.setValidity(10800)
      const twoHoursAgo = now - 2 * 60 * 60
      const myToken = ltpa.generate(userNameBuf, 'example.com', twoHoursAgo)
      ltpa.setValidity(5400)
      assert.doesNotThrow(() => ltpa.validate(myToken, 'example.com'))
    })

    it('should fail to validate an expired token using the token expiration date', () => {
      // this token is valid with non-strict validation
      ltpa.setStrictExpirationValidation(true)
      ltpa.setValidity(3600)
      const ninetyMinutesAgo = now - 90 * 60
      const expiredToken = ltpa.generate(
        userNameBuf,
        'example.com',
        ninetyMinutesAgo,
      )
      ltpa.setValidity(5400)

      assert.throws(
        () => ltpa.validate(expiredToken, 'example.com'),
        Error,
        'Ltpa Token has expired',
      )
    })
  })

  describe('codepage handling', () => {
    it('should be able to convert an ascii username and back again', () => {
      const username = 'my test username'
      const buf = ltpa.generateUserNameBuf(username)
      const token = ltpa.generate(buf, 'example.com')
      const backAgain = ltpa.getUserName(token)
      assert.equal(username, backAgain)
    })

    it('should be able to convert an ibm852 username and back again', () => {
      const username = 'Łuczak'
      const buf = ltpa.generateUserNameBuf(username)
      const token = ltpa.generate(buf, 'example.com')
      const backAgain = ltpa.getUserName(token)
      assert.equal(username, backAgain)
    })

    it('should be able to handle a username containing both ibm850 and ibm852 characters', () => {
      const username = 'Måns Östen Łučzak'
      const buf = ltpa.generateUserNameBuf(username)
      const token = ltpa.generate(buf, 'example.com')
      const backAgain = ltpa.getUserName(token)
      assert.equal(username, backAgain)
    })
  })
})
