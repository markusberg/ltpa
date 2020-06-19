import { decode, encode } from "iconv-lite"
import { Token } from "./Token.class"

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
 * @returns {Buffer} Username encoded in CP-850 and stuffed into a Buffer
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
  let token = new Token()
  const start = timeStart ? timeStart : Math.floor(Date.now() / 1000)

  token.timeCreation = start - gracePeriod
  token.timeExpiration = start + validity + gracePeriod
  token.username = userNameBuf
  token.sign(ltpaSecrets[domain])
  return token.getBuffer().toString("base64")
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
  if (!domain || domain.length === 0) {
    throw new Error("No domain provided")
  }

  const serverSecret = ltpaSecrets[domain]
  if (!serverSecret) {
    throw new Error("No such server secret exists")
  }

  const ltpaToken = new Token()
  ltpaToken.parse(token)
  ltpaToken.validateTimeCreation(gracePeriod)
  ltpaToken.validateTimeExpiration(validity, gracePeriod)
  ltpaToken.validateVersion()
  ltpaToken.validateHash(serverSecret)
}

/***
 * Retrieve the username from the token. No validation of the token is performed
 * @param {string} token The LtpaToken string in Base64 encoded format
 * @returns {buffer} Buffer containing the encoded username
 */
function getUserNameBuf(token: string): Buffer {
  const ltpaToken = new Token()
  ltpaToken.parse(token)
  return ltpaToken.username
}

/***
 * Retrieve the username from the token as a string. No validation of the token
 * is performed
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
