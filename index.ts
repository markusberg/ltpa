import { createHash } from "crypto"
import { decode, encode } from "iconv-lite"

export {
  generate,
  generateUserNameBuf,
  getUserNameBuf,
  getUserName,
  refresh,
  setGracePeriod,
  setSecrets,
  setValidity,
  validate,
}

interface Secrets {
  [key: string]: string
}

/**
 * LtpaToken generator and verifier
 */
let ltpaSecrets: Secrets
let validity = 5400
let gracePeriod = 300

/***
 * Set how long a generated token is valid. Default is 5400 seconds (90 minutes)
 * @param {number} seconds Number of seconds that tokens are valid
 */
function setValidity(seconds: number): void {
  validity = seconds
}

/***
 * Set the amount of time outside a ticket's validity that we will still accept it.
 * This time is also added to the validity of tokens that we generate
 * Default is 300 seconds (5 minutes).
 * @param {number} seconds Number of seconds grace
 */
function setGracePeriod(seconds: number): void {
  gracePeriod = seconds
}

/***
 * Set the ltpa secrets
 * @param {object} secrets domain to secret (base64) mapping
 */
function setSecrets(secrets: Secrets) {
  ltpaSecrets = secrets
}

/***
 * Generate a userName Buffer. Currently hardcoded to CP-850, but the
 * true char encoding is LMBCS
 * @param {string} userName The username to be converted to a CP-850 buffer
 * @returns {buffer} Username encoded in CP-850 and stuffed into a Buffer
 */
function generateUserNameBuf(userName: string): Buffer {
  return encode(userName, "ibm850")
}

/***
 * Generate an LtpaToken suitable for writing to a cookie
 * @param {buffer} userName The username for whom the cookie is signed
 * @param {string} domain The domain for which the cookie is generated
 * @param {number} timeStart Timestamp (seconds) for when the token validity should start. Default: now
 * @returns {string} The LtpaToken encoded as Base64
 */
function generate(userNameBuf: Buffer, domain: string, timeStart?: number) {
  const start = timeStart ? timeStart : Math.floor(Date.now() / 1000)

  const timeCreation = (start - gracePeriod).toString(16)
  const timeExpiration = (start + validity + gracePeriod).toString(16)

  const size = userNameBuf.length + 40
  const ltpaToken = Buffer.alloc(size)

  ltpaToken.write("00010203", 0, 4, "hex")
  ltpaToken.write(timeCreation, 4)
  ltpaToken.write(timeExpiration, 12)
  userNameBuf.copy(ltpaToken, 20)
  const serverSecret = ltpaSecrets[domain]
  ltpaToken.write(serverSecret, size - 20, 20, "base64")

  const hash = createHash("sha1")
  hash.update(ltpaToken)

  // Paranoid overwrite of the server secret
  ltpaToken.write("0123456789abcdefghij", size - 20, 20, "utf8")

  // Append the token hash
  ltpaToken.write(hash.digest("hex"), size - 20, 20, "hex")
  return ltpaToken.toString("base64")
}

/***
 * Validate a token. Throws an error if validation fails.
 * @param {string} token The LtpaToken string in Base64 encoded format
 * @param {string} domain The id of the key for which to validate the provided token
 */
function validate(token: string, domain: string): void {
  /**
   * Basic sanity checking of in-data
   */
  if (!token || token.length === 0) {
    throw new Error("No token provided")
  }
  if (!domain || domain.length === 0) {
    throw new Error("No domain provided")
  }

  const serverSecret = ltpaSecrets[domain]
  if (!serverSecret) {
    throw new Error("No such server secret exists")
  }

  const tokenSize = Buffer.byteLength(token, "base64")
  const ltpaToken = Buffer.alloc(tokenSize, token, "base64")
  if (ltpaToken.length < 41) {
    // userName must be at least one character long
    throw new Error("Ltpa Token too short")
  }

  /**
   * Check time validity
   */
  const timeCreation = parseInt(ltpaToken.toString("utf8", 4, 12), 16)
  // we don't look at the expiration stored in the token, but calculate our own
  const timeExpiration = parseInt(ltpaToken.toString("utf8", 12, 20), 16)
  const now = Math.floor(Date.now() / 1000)

  if (timeCreation - gracePeriod > now) {
    throw new Error("Ltpa Token not yet valid")
  }

  // need to check two gracePeriods into the future because we add one to the beginning
  if (timeCreation + validity + gracePeriod * 2 < now) {
    throw new Error("Ltpa Token has expired")
  }

  /**
   * Check version, and hash itself
   */
  const version = ltpaToken.toString("hex", 0, 4)
  if (version !== "00010203") {
    throw new Error("Incorrect magic string")
  }

  const signature = ltpaToken.toString("hex", ltpaToken.length - 20)
  ltpaToken.write(serverSecret, ltpaToken.length - 20, 20, "base64")

  const hash = createHash("sha1")
  hash.update(ltpaToken)

  if (hash.digest("hex") !== signature) {
    throw new Error("Ltpa Token signature doesn't validate")
  }
}

/***
 * Retrieve the username from the token. No validation of the token takes place
 * @param {string} token The LtpaToken string in Base64 encoded format
 * @returns {buffer} Buffer containing the encoded username
 */
function getUserNameBuf(token: string): Buffer {
  const size = Buffer.byteLength(token, "base64")
  const ltpaToken = Buffer.alloc(size, token, "base64")
  return ltpaToken.slice(20, ltpaToken.length - 20)
}

/***
 * Retrieve the username from the token as a string. No validation of the token takes place
 * @returns {string} Username as a UTF-8 string
 */
function getUserName(token: string): string {
  return decode(getUserNameBuf(token), "ibm850")
}

/***
 * Refresh token if it's valid. Otherwise, throw an error.
 * @param {string} token The LtpaToken string in Base64 encoded format
 * @returns {string} The refreshed LtpaToken, or throw an exception
 */
function refresh(token: string, domain: string): string {
  validate(token, domain)
  return generate(getUserNameBuf(token), domain)
}
