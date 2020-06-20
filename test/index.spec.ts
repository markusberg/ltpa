import { expect } from "chai"
import * as ltpa from "../index"

ltpa.setSecrets({
  "example.com": "AAECAwQFBgcICQoLDA0ODxAREhM=",
  "invalid.example.com": "AAABAQICAwMEBAUFBgYHBwgICQk=",
})

let userName: string
let userNameBuf: Buffer
let token: string
let invalidToken: string
let now: number

describe("Ltpa", function () {
  beforeEach(() => {
    ltpa.setGracePeriod(300)
    ltpa.setValidity(5400)
    ltpa.setStrictExpirationValidation(false)

    userName = "My Test User"
    userNameBuf = ltpa.generateUserNameBuf(userName)
    token = ltpa.generate(userNameBuf, "example.com")
    invalidToken = ltpa.generate(userNameBuf, "invalid.example.com")
    now = Math.floor(Date.now() / 1000)
  })

  describe("positive tests", () => {
    it("should generate known tokens", () => {
      const knownToken = ltpa.generate(userNameBuf, "example.com", 1234567890)
      expect(knownToken).to.equal(
        "AAECAzQ5OTYwMWE2NDk5NjE5MTZNeSBUZXN0IFVzZXJjcHMKyXIrtD4SZcV7DKWd67EFng==",
      )

      ltpa.setGracePeriod(0)
      const knownToken2 = ltpa.generate(userNameBuf, "example.com", 1234567890)
      expect(knownToken2).to.equal(
        "AAECAzQ5OTYwMmQyNDk5NjE3ZWFNeSBUZXN0IFVzZXJ1HUi4fVHSeb8JgA2xsVK0kjromg==",
      )

      ltpa.setValidity(10)
      const knownToken3 = ltpa.generate(userNameBuf, "example.com", 1234567890)
      expect(knownToken3).to.equal(
        "AAECAzQ5OTYwMmQyNDk5NjAyZGNNeSBUZXN0IFVzZXJs8zRFVehH/c9RpQ/KvUPhBM5tdQ==",
      )
    })

    it("should generate a token", () => {
      expect(token).to.be.a("string")
    })

    it("should generate a valid token", () => {
      expect(() => ltpa.validate(token, "example.com")).to.not.throw()
    })

    it("should refresh a valid token", () => {
      const result = ltpa.refresh(token, "example.com")
      const size = Buffer.byteLength(result, "base64")
      expect(result).to.be.a("string")
      expect(size).to.equal(40 + userName.length)
    })

    it("should get the userName from the token", () => {
      const result = ltpa.getUserName(token)
      expect(result).to.equal(userName)
    })

    it("should validate a token that has expired, but is within the grace period", () => {
      const justExpired = now - 5401
      const justExpiredToken = ltpa.generate(
        userNameBuf,
        "example.com",
        justExpired,
      )
      expect(() =>
        ltpa.validate(justExpiredToken, "example.com"),
      ).to.not.throw()
    })

    it("should be possible to change the grace period", () => {
      ltpa.setGracePeriod(0)
      expect(() => ltpa.validate(token, "example.com")).to.not.throw()
    })

    it("should be possible to change the token validity", () => {
      ltpa.setValidity(10)
      ltpa.setGracePeriod(0)
      const inThePast = now - 15
      const expiredToken = ltpa.generate(userNameBuf, "example.com", inThePast)
      expect(() => ltpa.validate(expiredToken, "example.com")).to.throw(
        Error,
        "Ltpa Token has expired",
      )
    })
  })

  describe("negative tests", () => {
    it("should fail to validate an invalid token", () => {
      expect(() => ltpa.validate(invalidToken, "example.com")).to.throw(
        Error,
        "Ltpa Token signature doesn't validate",
      )
    })

    it("should fail to refresh an invalid token", () => {
      expect(() => ltpa.refresh(invalidToken, "example.com")).to.throw(
        Error,
        "Ltpa Token signature doesn't validate",
      )
    })

    it("should generate, but fail to validate an expired token", () => {
      const token = ltpa.generate(userNameBuf, "example.com", 12)
      expect(() => ltpa.validate(token, "example.com")).to.throw(
        Error,
        "Ltpa Token has expired",
      )
    })

    it("should generate, but fail to validate a not yet valid token", () => {
      // Generate a token that starts being valid more than two gracePeriods into the future
      const futureTime = now + 605
      const futureToken = ltpa.generate(userNameBuf, "example.com", futureTime)
      expect(() => ltpa.validate(futureToken, "example.com")).to.throw(
        Error,
        "Ltpa Token not yet valid",
      )
    })

    it("should fail to validate a non-existent token", () => {
      expect(() => ltpa.validate("", "example.com")).to.throw(
        Error,
        "No token provided",
      )
    })

    it("should fail to validate a non-existent domain", () => {
      expect(() => ltpa.validate(token, "")).to.throw(
        Error,
        "No domain provided",
      )
    })

    it("should fail to validate a token with an invalid magic string", () => {
      const size = Buffer.byteLength(token, "base64")
      const myBuffer = Buffer.alloc(size)
      myBuffer.write(token, 0, size, "base64")
      myBuffer.write("99", 0, 1, "hex")
      const corruptToken = myBuffer.toString("base64")
      expect(() => ltpa.validate(corruptToken, "example.com")).to.throw(
        Error,
        "Incorrect magic string",
      )
    })

    it("should fail to validate a token that's impossibly short", () => {
      const size = Buffer.byteLength(token, "base64")
      const myBuffer = Buffer.alloc(size)
      myBuffer.write(token, 0, size, "base64")
      const corruptToken = myBuffer.slice(0, 33).toString("base64")
      expect(() => ltpa.validate(corruptToken, "example.com")).to.throw(
        Error,
        "Ltpa Token too short",
      )
    })

    it("should fail to validate a token with an incorrect secret key", () => {
      expect(() => ltpa.validate(token, "blabla.example.com")).to.throw(
        Error,
        "No such server secret exists",
      )
    })
  })

  describe("strict expiration validation", () => {
    it("should validate a token using the token expiration date", () => {
      // this token is invalid with non-strict validation
      ltpa.setStrictExpirationValidation(true)
      ltpa.setValidity(10800)
      const twoHoursAgo = now - 2 * 60 * 60
      const myToken = ltpa.generate(userNameBuf, "example.com", twoHoursAgo)
      ltpa.setValidity(5400)
      expect(() => ltpa.validate(myToken, "example.com")).to.not.throw()
    })

    it("should fail to validate an expired token using the token expiration date", () => {
      // this token is valid with non-strict validation
      ltpa.setStrictExpirationValidation(true)
      ltpa.setValidity(3600)
      const ninetyMinutesAgo = now - 90 * 60
      const expiredToken = ltpa.generate(
        userNameBuf,
        "example.com",
        ninetyMinutesAgo,
      )
      ltpa.setValidity(5400)

      expect(() => ltpa.validate(expiredToken, "example.com")).to.throw(
        Error,
        "Ltpa Token has expired",
      )
    })
  })
})
