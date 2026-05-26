import { Suite } from 'bench-node'
import { bufFromString, stringFromBuf } from './lmbcs.js'

const suite = new Suite()

const encodingStrings = {
  ascii: 'abcdefghijklmnopqrstuvwxyz',
  lmbcs1: '☺☻♥♦♣♠•◘○◙♂♀♪Çüéâäàåçêëèïî',
  lmbcs6: 'āĈĉĊċĒēĖėĜĝĠġĢģĤĥĨĩĪīĮįĴĵĶ',
  lmbcs20: '가나다라마바사아자차카타파하개내대래매배새애재채캐태',
  mixed: 'abcdefgÇüéâäàåāĈĉĊċĒ가나다라마바',
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
