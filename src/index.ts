/**
 * Generate and validate LTPA tokens for IBM WebSphere authentication
 *
 * @module ltpa
 */

import { createHash } from 'node:crypto'
import iconv from 'iconv-lite'

/**
 * Mapping of domains to their corresponding LTPA secrets (base64-encoded)
 */
export type Secrets = Record<string, string>

/**
 * LtpaToken generator and verifier
 */
let ltpaSecrets: Secrets
let validity = 5400
let gracePeriod = 300
let strictExpirationValidation = true

/**
 * Special handling of Codepage 852
 */
const ibm852Chars =
  'ÇüéâäůćçłëŐőîŹÄĆÉĹĺôöĽľŚśÖÜŤťŁčáíóúĄąŽžĘę¬źČşÁÂĚŞŻżĂăđĐĎËďŇÍÎěŢŮÓßÔŃńňŠšŔÚŕŰýÝţűŘř'.split(
    '',
  )
const buf852 = Buffer.from([0x06])

/**
 * Set how long a generated token is valid
 * @param seconds - Default is 5400 seconds (90 minutes)
 */
export function setValidity(seconds: number): void {
  validity = seconds
}

/**
 * Set the grace period for token acceptance outside validity window
 * Also adds this time to generated token validity
 * @param seconds - Default is 300 seconds (5 minutes)
 */
export function setGracePeriod(seconds: number): void {
  gracePeriod = seconds
}

/**
 * Set strict token expiration validation mode
 * When true (default), check actual validation timestamp instead of calculated expiration
 * @param strict - Enable/disable strict validation
 */
export function setStrictExpirationValidation(strict: boolean): void {
  strictExpirationValidation = strict
}

/**
 * Set the LTPA secrets for token generation/validation
 * @param secrets - Domain to secret (base64) mapping
 */
export function setSecrets(secrets: Secrets): void {
  ltpaSecrets = secrets
}

/**
 * Generate a username buffer encoded in CP-850/852
 * Note: True char encoding should be LMBCS
 * @param username - Username to encode
 * @returns Username encoded in CP-850/852 buffer
 */
export function generateUserNameBuf(username: string): Buffer {
  const bufUsername = username.split('').reduce((acc, char) => {
    if (ibm852Chars.includes(char)) {
      const bufChar = iconv.encode(char, 'ibm852')
      return Buffer.concat([acc, buf852, bufChar])
    }
    const bufChar = iconv.encode(char, 'ibm850')
    return Buffer.concat([acc, bufChar])
  }, Buffer.from(''))

  return bufUsername
}

/**
 * Generate an LTPA token for cookie usage
 * @param userNameBuf - Username buffer to include in token
 * @param domain - Domain for cookie generation
 * @param timeStart - Optional timestamp (seconds) for token validity start
 * @returns Base64 encoded LTPA token
 */
export function generate(
  userNameBuf: Buffer,
  domain: string,
  timeStart?: number,
): string {
  const start = timeStart ? timeStart : Math.floor(Date.now() / 1000)

  const timeCreation = (start - gracePeriod).toString(16)
  const timeExpiration = (start + validity + gracePeriod).toString(16)

  const size = userNameBuf.length + 40
  const ltpaToken = Buffer.alloc(size)

  ltpaToken.write('00010203', 0, 4, 'hex')
  ltpaToken.write(timeCreation, 4)
  ltpaToken.write(timeExpiration, 12)
  userNameBuf.copy(ltpaToken, 20)
  const serverSecret = ltpaSecrets[domain]
  ltpaToken.write(serverSecret, size - 20, 20, 'base64')

  const hash = createHash('sha1')
  hash.update(ltpaToken)

  // Paranoid overwrite of the server secret
  ltpaToken.write('0123456789abcdefghij', size - 20, 20, 'utf8')

  // Append the token hash
  ltpaToken.write(hash.digest('hex'), size - 20, 20, 'hex')
  return ltpaToken.toString('base64')
}

/**
 * Validate an LTPA token
 * @param token - Base64 encoded LTPA token
 * @param domain - Domain key for token validation
 * @throws Error if validation fails
 */
export function validate(token: string, domain: string): void {
  /**
   * Basic sanity checking of in-data
   */
  if (!token || token.length === 0) {
    throw new Error('No token provided')
  }
  if (!domain || domain.length === 0) {
    throw new Error('No domain provided')
  }

  const serverSecret = ltpaSecrets[domain]
  if (!serverSecret) {
    throw new Error('No such server secret exists')
  }

  const tokenSize = Buffer.byteLength(token, 'base64')
  const ltpaToken = Buffer.alloc(tokenSize, token, 'base64')
  if (ltpaToken.length < 41) {
    // userName must be at least one character long
    throw new Error('Ltpa Token too short')
  }

  /**
   * Check time validity
   */
  const timeCreation = parseInt(ltpaToken.toString('utf8', 4, 12), 16)
  // we don't look at the expiration stored in the token, but calculate our own
  const strictExpiration = parseInt(ltpaToken.toString('utf8', 12, 20), 16)
  const now = Math.floor(Date.now() / 1000)

  if (timeCreation - gracePeriod > now) {
    throw new Error('Ltpa Token not yet valid')
  }

  const exp = strictExpirationValidation
    ? strictExpiration
    : timeCreation + validity + gracePeriod * 2
  // need to check two gracePeriods into the future because we add one to the beginning
  if (exp < now) {
    throw new Error('Ltpa Token has expired')
  }

  /**
   * Check version, and hash itself
   */
  const version = ltpaToken.toString('hex', 0, 4)
  if (version !== '00010203') {
    throw new Error('Incorrect magic string')
  }

  const signature = ltpaToken.toString('hex', ltpaToken.length - 20)
  ltpaToken.write(serverSecret, ltpaToken.length - 20, 20, 'base64')

  const hash = createHash('sha1')
  hash.update(ltpaToken)

  if (hash.digest('hex') !== signature) {
    throw new Error("Ltpa Token signature doesn't validate")
  }
}

/**
 * Extract username buffer from token without validation
 * @param token - Base64 encoded LTPA token
 * @returns Buffer containing encoded username
 */
export function getUserNameBuf(token: string): Buffer {
  const size = Buffer.byteLength(token, 'base64')
  const ltpaToken = Buffer.alloc(size, token, 'base64')
  return ltpaToken.subarray(20, ltpaToken.length - 20)
}

/**
 * Extract username string from token without validation
 * @param token - Base64 encoded LTPA token
 * @returns UTF-8 encoded username string
 */
export function getUserName(token: string): string {
  const bufUsername = getUserNameBuf(token)
  let username: string[] = []
  for (let i = 0; i < bufUsername.length; i++) {
    const char = bufUsername.subarray(i, i + 1)
    if (char.equals(buf852)) {
      const utf8 = iconv.decode(bufUsername.subarray(i + 1, i + 2), 'ibm852')
      username.push(utf8)
      i++
    } else {
      const utf8 = iconv.decode(char, 'ibm850')
      username.push(utf8)
    }
  }

  return username.join('')
}

/**
 * Create new token from existing valid token
 * @param token - Base64 encoded LTPA token
 * @param domain - Domain for token validation/generation
 * @returns New Base64 encoded LTPA token
 * @throws Error if validation fails
 */
export function refresh(token: string, domain: string): string {
  validate(token, domain)
  return generate(getUserNameBuf(token), domain)
}
