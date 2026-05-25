/**
 * LMBCS (Lotus Multi-Byte Character Set) encoding and decoding
 *
 * LMBCS is a multi-byte character encoding used by Lotus Notes/Domino and IBM systems.
 * It uses lead bytes to identify multi-byte sequences for extended character support.
 *
 * Implementation based on Wikipedia documentation:
 * https://en.wikipedia.org/wiki/Lotus_Multi-Byte_Character_Set
 *
 * This is a first, naïve implementation, there are likely major performance improvements possible
 *
 * @example
 * // Encoding a string with special characters
 * const encoded = bufFromString('Héllo');
 *
 * @example
 * // Decoding LMBCS bytes back to string
 * const decoded = stringFromBuf(encoded);
 *
 * @module lmbcs
 */

// base ascii characters from 0x20 to 0x7f
const ASCII = Array.from({ length: 0x7f - 0x20 + 1 }, (_, i) =>
  String.fromCharCode(0x20 + i),
).join('')

/**
 * Supported LMBCS codepages
 *
 * - Index 0: Default codepage (ASCII 0x20-0x7F, no lead byte)
 * - Index 1: LMBCS-1 (IBM850-based, lead byte 0x01)
 * - Index 2: LMBCS-6 (IBM852-based, lead byte 0x06)
 *
 * Note: Undefined/unsupported characters are represented as space (0x20)
 */

/**
 * lmbcs1 - ibm850 but with exceptions in the 0x01 to 0x7F range
 *
 * lead byte: 0x01
 * bytes: 2
 */
const lmbcs1 =
  ' ☺☻♥♦♣♠•◘○◙♂♀♪♫☼' +
  '►◄↕‼¶§▬↨↑↓→←∟↔▲▼' +
  "¨~˚^`´“'…-—‘’ ‹›" +
  '¨~˚^`´„‚”‗ \u00A0    ' +
  'ŒœŸ˙˚ ╞╟▌▐◊⌘  Ω ' +
  '╨╤╥╙╘╒╓╫╪╡╢╖╕╜╛╧' +
  'ĳĲﬁﬂŉ\u0140\u013F¯˘˝˛ˇ~^  ' +
  '†‡ĦħŦŧ™ℓŊŋĸ \uF8FB⌐₤₧' +
  'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜø£Ø×ƒáíóúñÑªº¿®¬½¼¡«»░▒▓│┤ÁÂÀ©╣║╗╝¢¥┐└┴┬├─┼ãÃ╚╔╩╦╠═╬¤ðÐÊËÈıÍÎÏ┘┌█▄¦Ì▀ÓßÔÒõÕµþÞÚÛÙýÝ¯´­±‗¾¶§÷¸°¨·¹³²■ '

/**
 * lmbcs6 - ibm852 but with exceptions in the 0x01 to 0x7F range
 *
 * lead byte: 0x06
 * bytes: 2
 */
const lmbcs6 =
  ' āĈĉĊċĒēĖėĜĝĠġĢģ' +
  'ĤĥĨĩĪīĮįĴĵĶķĻļŅņ' +
  'ŌōŖŗŜŝŨũŪūŬŭŲųĀ ' +
  ' '.repeat(80) +
  'ÇüéâäůćçłëŐőîŹÄĆÉĹĺôöĽľŚśÖÜŤťŁ×čáíóúĄąŽžĘę¬źČş«»░▒▓│┤ÁÂĚŞ╣║╗╝Żż┐└┴┬├─┼Ăă╚╔╩╦╠═╬¤đĐĎËďŇÍÎě┘┌█▄ŢŮ▀ÓßÔŃńňŠšŔÚŕŰýÝţ´­˝˛ˇ˘§÷¸°¨˙űŘř■ '

const lookup = new Map<string, number[]>()
for (const char of lmbcs6) {
  const idx = lmbcs6.indexOf(char)
  lookup.set(char, [0x06, idx])
}
for (const char of lmbcs1) {
  const idx = lmbcs1.indexOf(char)
  lookup.set(char, [0x01, idx])
}
for (const char of ASCII) {
  lookup.set(char, [char.charCodeAt(0)])
}

/**
 * Encode a single character to LMBCS format
 *
 * Maps the character to the appropriate LMBCS codepage and returns the encoded bytes.
 * Single-byte characters from the default codepage are returned as-is.
 * Multi-byte characters use their codepage's lead byte followed by the character index.
 *
 * @param char - A single Unicode character to encode
 * @returns LMBCS-encoded bytes (1-2 bytes depending on codepage)
 * @throws If the character is not found in any supported LMBCS codepage
 *
 * @example
 * encode('A') // Returns [0x41]
 * encode('é') // Returns [0x01, 0x82] (LMBCS-1 codepage)
 *
 * @internal
 */
function encode(char: string): number[] {
  const encoded = lookup.get(char)
  if (encoded) {
    return encoded
  }
  throw new Error(`Character ${char} not found in any codepage`)
}

/**
 * Encode a string to LMBCS-encoded buffer
 *
 * Converts each character in the input string to its LMBCS representation.
 * Uses the most compact encoding available for each character.
 *
 * @param input - UTF-8 string to encode (all characters must be in supported codepages)
 * @returns LMBCS-encoded bytes
 * @throws If any character in the string is not supported in LMBCS codepages
 *
 * @example
 * const buf = bufFromString('Lotus');
 * // Returns Buffer containing LMBCS-encoded "Lotus"
 *
 * @example
 * const buf = bufFromString('Ñoño');
 * // Returns Buffer with mix of LMBCS-1 encoded characters
 */
export function bufFromString(input: string): Buffer {
  return Buffer.from(input.split('').flatMap((char) => encode(char)))
}

/**
 * Decode an LMBCS-encoded buffer to a UTF-8 string
 *
 * Processes the buffer sequentially, detecting lead bytes to identify multi-byte sequences
 * and decoding each character according to its codepage definition.
 * Single bytes (0x20-0x7F) without lead bytes are treated as ASCII characters.
 *
 * @param bufLMBCS - LMBCS-encoded buffer to decode
 * @returns Decoded Unicode string
 *
 * @example
 * const str = stringFromBuf(Buffer.from([0x4C, 0x6F, 0x74, 0x75, 0x73]));
 * // Returns 'Lotus'
 *
 * @example
 * // Multi-byte sequence: lead byte 0x01 followed by character index
 * const str = stringFromBuf(Buffer.from([0x01, 0x82]));
 * // Returns character from LMBCS-1 codepage
 */
export function stringFromBuf(bufLMBCS: Buffer): string {
  let username: string[] = []
  for (let i = 0; i < bufLMBCS.length; i++) {
    const char = bufLMBCS[i]

    if (char >= 0x20) {
      // single byte ascii character
      username.push(String.fromCharCode(char))
      continue
    }

    let charBuf: Buffer
    let length: number
    let charStr: string
    switch (char) {
      case 0x01:
        length = 2
        charBuf = bufLMBCS.subarray(i + 1, i + length)
        charStr = lmbcs1[charBuf[0]]
        break
      case 0x06:
        length = 2
        charBuf = bufLMBCS.subarray(i + 1, i + length)
        charStr = lmbcs6[charBuf[0]]
        break
      default:
        throw new Error(`Invalid lead byte ${char} at position ${i}`)
    }

    username.push(charStr)
    i += length - 1
  }

  return username.join('')
}
