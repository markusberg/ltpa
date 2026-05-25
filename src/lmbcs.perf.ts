import { Suite } from 'bench-node'
import { bufFromString, stringFromBuf } from './lmbcs.js'

const suite = new Suite()

const encodingStrings = {
  ascii: 'abcdefghijklmnopqrstuvwxyz',
  lmbcs1: 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖ',
  lmbcs6: 'āĈĉĊċĒēĖėĜĝĠġĢģĤĥĨĩĪīĮįĴĵĶ',
  mixed: 'abcdefghiÇüéâäàåçêāĈĉĊċĒēĖ',
}

for (const [encoding, str] of Object.entries(encodingStrings)) {
  suite.add(`bufFromString - ${encoding}`, () => {
    bufFromString(str)
  })
}

for (const [encoding, str] of Object.entries(encodingStrings)) {
  const buf = bufFromString(str)

  suite.add(`stringFromBuf - ${encoding}`, () => {
    stringFromBuf(buf)
  })
}

suite.run()
