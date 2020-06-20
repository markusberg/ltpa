import { createHash } from "crypto"

export const VERSION = "00010203"

export class Token {
  version: string = VERSION
  timeCreation: number = 0
  timeExpiration: number = 0
  username: Buffer = Buffer.alloc(0)
  hash: Buffer = Buffer.alloc(20)

  /***
   * Parse provided token in Base64
   * @param {string} token Base64-encoded token to be parsed
   */
  parse(token: string) {
    if (!token) {
      throw new Error("No token provided")
    }

    const len = Buffer.byteLength(token, "base64")
    const tokenBuffer = Buffer.alloc(len, token, "base64")

    if (tokenBuffer.length < 41) {
      // userName must be at least one character long
      throw new Error("Ltpa Token too short")
    }

    this.version = tokenBuffer.toString("hex", 0, 4)
    this.timeCreation = parseInt(tokenBuffer.toString("utf8", 4, 12), 16)
    this.timeExpiration = parseInt(tokenBuffer.toString("utf8", 12, 20), 16)
    this.username = tokenBuffer.slice(20, len - 20)
    this.hash = tokenBuffer.slice(len - 20)
  }

  /***
   * Calculate token hash using the provided serverSecret
   * @param {string} serverSecret The server secret with which to sign the token
   * @returns {Buffer} The generated signature
   */
  getCalculatedHash(serverSecret: string): Buffer {
    let tokenBuffer = this.getBuffer()
    tokenBuffer.write(serverSecret, this.getBufferLength() - 20, 20, "base64")
    const hash = createHash("sha1")
    hash.update(tokenBuffer)

    return hash.digest()
  }

  /***
   * Get the full length of the generated buffer
   * @returns {number} Length of the buffer
   */
  private getBufferLength(): number {
    return 40 + this.username.length
  }

  /***
   * Generate a token Buffer from the data in this Token
   * @returns {Buffer} Token buffer
   */
  getBuffer(): Buffer {
    let tokenBuffer = Buffer.alloc(this.getBufferLength())

    tokenBuffer.write(this.version, 0, 4, "hex")
    tokenBuffer.write(this.timeCreation.toString(16), 4)
    tokenBuffer.write(this.timeExpiration.toString(16), 12)
    this.username.copy(tokenBuffer, 20)
    this.hash.copy(tokenBuffer, this.getBufferLength() - 20)
    return tokenBuffer
  }

  /***
   * Update the token hash, by signing the token with the provided serverSecret
   * @param {string} serverSecret Server secret with which to sign token
   */
  sign(serverSecret: string) {
    this.hash = this.getCalculatedHash(serverSecret)
  }

  /***
   * Ensure that the token version is the only one that's supported
   */
  validateVersion() {
    if (this.version !== VERSION) {
      throw new Error("Incorrect magic string")
    }
  }

  /***
   * Calculate hash for this token, and compare to the provided hash
   * @param {string} serverSecret The server secret used to hash token
   */
  validateHash(serverSecret: string) {
    if (!this.getCalculatedHash(serverSecret).equals(this.hash)) {
      throw new Error("Ltpa Token signature doesn't validate")
    }
  }

  /***
   * Validate that the token issue-date is not in the future
   * @param {number} gracePeriod Number of seconds of leeway where an invalid token is still valid
   */
  validateTimeCreation(gracePeriod: number) {
    const now = Math.floor(Date.now() / 1000)
    if (this.timeCreation - gracePeriod > now) {
      throw new Error("Ltpa Token not yet valid")
    }
  }

  /***
   * Validate that the token is still valid according to this server's validity settings.
   * @param {number} validity Number of seconds that the token should be valid
   * @param {number} gracePeriod Number of seconds of leeway where an invalid token is still valid
   */
  validateTimeExpiration(validity: number, gracePeriod: number) {
    const now = Math.floor(Date.now() / 1000)
    if (this.timeCreation + validity + gracePeriod * 2 < now) {
      throw new Error("Ltpa Token has expired")
    }
  }

  /***
   * Validate that the token is still valid according to the token's expiration date
   */
  validateTimeExpirationStrict() {
    const now = Math.floor(Date.now() / 1000)
    if (this.timeExpiration < now) {
      throw new Error("Ltpa Token has expired")
    }
  }
}
