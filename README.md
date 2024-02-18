# ltpa

[![node.js build](https://github.com/markusberg/ltpa/actions/workflows/master.yaml/badge.svg)](https://github.com/markusberg/ltpa/actions/workflows/master.yaml)
[![coverage](https://markusberg.github.io/ltpa/badges/coverage-2.0.0.svg)](https://github.com/markusberg/ltpa/actions)
[![version](https://img.shields.io/npm/v/ltpa.svg)](https://codecov.io/github/markusberg/ltpa)
[![license](https://img.shields.io/github/license/markusberg/ltpa.svg)](https://www.apache.org/licenses/LICENSE-2.0)

A small library for generating and validating ltpa tokens. Based on the
[IBM specification](http://www-12.lotus.com/ldd/doc/tools/c/7.0/api70ug.nsf/85255d56004d2bfd85255b1800631684/ceda2cb8df47607f85256c3d005f816d).

## Who is this for?

For developers integrating [Node.js](https://nodejs.org/) applications with the world of IBM Domino and/or Websphere.

Since version 2.0, this module is strictly ESmodule. If you require CommonJS, you can still use the 1.x versions.

## Retrieving the server secret

In IBM Domino, the server secret can be found in the
`names.nsf` database,
`($WebSSOConfigs)` view,
`LTPA_DominoSecret` field.

## Getting the module

```bash
$ npm install ltpa
```

or clone it from github:

```bash
$ git clone https://github.com/markusberg/ltpa.git
```

## API

This is the full API, but normally you'll only use a few of these methods. See examples below.

- `setSecrets(secrets: Secrets)`: Add your server secrets to the library, for later use in validation and signing of tokens
- `refresh(token: string, domain: string)`: Validate provided token, and return a fresh token
- `generateUserNameBuf(userName: string)`: Generate a userName Buffer. Currently hardcoded to CP-850, but the true char encoding is LMBCS
- `generate(userNameBuf: Buffer, domain: string)`: Generate a Base64-encoded Ltpa token
- `setValidity(seconds: number)`: Set how long a generated token is valid. Default is 5400 seconds (90 minutes).
- `setStrictExpirationValidation(strict: boolean)`: If set to true, token expiration validation will check the actual validation timestamp in the token instead of the calculated expiration. See the "Known Issues" section below.
- `setGracePeriod(seconds: number)`: Set the amount of time outside a ticket's validity that we will still accept it. This time is also added to the validity of tokens that are generated. Default is 300 seconds (5 minutes).  
  **NOTE:** since the grace period is added both on token generation, and during validation, the actual grace period is double what is set here.
- `getUserName(token: string)`: Retrieve the username as a `string` from the provided token. No validation of the token is performed
- `getUserNameBuf(token: string)`: Retrieve the username as a `Buffer` from the provided token. No validation of the token is performed
- `validate(token: string, domain: string)`: Validate provided token. Throws an error if validation fails

## Example 1

These examples are for [Express](https://expressjs.com/), but the functionality should be easy to adapt to [Koa](https://koajs.com/) or other frameworks.

Add the dependency and create a simple middleware:

```javascript
import { getUserName, refresh, setSecrets } from 'ltpa'
import { NextFunction, Request, Response } from 'express'

setSecrets({
  'example.com': 'AAECAwQFBgcICQoLDA0ODxAREhM=',
})

/**
 * Express Middleware
 * Authenticate user by verifying the provided LtpaToken cookie
 */
export function mwLtpaAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const ltpaToken = refresh(req.cookies.LtpaToken, 'example.com')
    const newCookie =
      'LtpaToken=' + ltpaToken + '; Path=/; Domain=' + 'example.com'
    res.setHeader('Set-Cookie', newCookie)
    next()
  } catch (err) {
    console.log(err)
    res.status(401).json({ message: 'Not authorized for this resource' })
  }
}

/**
 * Express route
 */
router.get('/testAuth', mwLtpaAuth, (req: Request, res: Response) => {
  res.send('user is logged in as ' + getUserName(req.cookies.LtpaToken))
})
```

## Example 2

If you need to access a backend Domino database using a specific user account,
you can generate an LtpaToken for that account using the `generate` method:

```typescript
import { Request, Response } from 'express'
import { generate, generateUserNameBuf, setSecrets } from 'ltpa'

setSecrets({
  'example.com': 'AAECAwQFBgcICQoLDA0ODxAREhM=',
})

router.get('/myDominoView', async (req: Request, res: Response) => {
  const userNameBuf = generateUserNameBuf('CN=Sysadmin Account,O=Example Inc')
  const backendToken = generate(userNameBuf, 'example.com')

  const url = new URL(
    '/api/data/collections/name/myDominoView',
    'https://domino.example.com/',
  )
  const headers = { Cookie: `LtpaToken=${backendToken}` }

  try {
    const response = await fetch(url, { headers })
    const json = await response.json()
    res.json(json)
  } catch (err) {
    console.error(err)
    res.status(500).send(err)
  }
})
```

## Tests

```bash
$ npm test
```

or to run it continuously, while watching for changes

```bash
$ npm run test:watch
```

## Known issues

### Token validity

When validating token expiration, the library will only respect its internal `validity` setting, and will disregard the expiration-date setting in provided tokens. To force the library to use the actual timestamp in the token, use the setStrictExpirationValidation() method. This behaviour might change in version 2.

### Character sets

The module only works with usernames containing characters in the `ibm850`, and `ibm852` codepages (this covers most of Europe). The username in the token is encoded in an old IBM/Lotus format called [`LMBCS` (Lotus Multi-Byte Character Set)](https://en.wikipedia.org/wiki/Lotus_Multi-Byte_Character_Set) for which I have found no javascript implementation.

### LTPA1 only

The package only supports LTPA1, and not LTPA2. WebSphere Application Server Version 5 and later supports LTPA1. WebSphere Application Server Version 7 and later supports LTPA2:

https://www.ibm.com/support/knowledgecenter/en/SSAW57_8.5.5/com.ibm.websphere.nd.doc/ae/cwbs_ltpatokens.html

However, there is a package by Benjamin Kröger for dealing with LTPA2:

- https://github.com/benkroeger/oniyi-ltpa
- https://www.npmjs.com/package/oniyi-ltpa
