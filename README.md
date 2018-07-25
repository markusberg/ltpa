# ltpa
A small library for generating and validating ltpa tokens. Based on the
[IBM specification](http://www-12.lotus.com/ldd/doc/tools/c/7.0/api70ug.nsf/85255d56004d2bfd85255b1800631684/ceda2cb8df47607f85256c3d005f816d).

## Who is this for?
For developers integrating [Node.js](https://nodejs.org/) applications with the world of IBM Domino and/or Websphere.

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

## Example 1
These examples are for [Express](https://expressjs.com/), but the functionality should be easy to adapt to [Koa](https://koajs.com/) or other frameworks.

Add the dependency and create a simple middleware:

```javascript
let ltpa = require("ltpa");
ltpa.setSecrets({
  "example.com": "AAECAwQFBgcICQoLDA0ODxAREhM="
});

/***
 * Express Middleware
 * Authenticate user by verifying the provided LtpaToken cookie
 */
function mwLtpaAuth(req, res, next) {
  try {
    let ltpaToken = ltpa.refresh(req.cookies.LtpaToken, "example.com");
    let newCookie = "LtpaToken=" + ltpaToken + "; Path=/; Domain=" + "example.com";
    res.setHeader("Set-Cookie", newCookie);
    next();
  } catch (err) {
    console.log(err);
    res.status(401).json({ message: "Not authorized for this resource" });
  }
}

/***
 * Express route
 */
router.get("/testAuth", mwLtpaAuth, function (req, res) {
  res.send("user is logged in as " + ltpa.getUserName(req.cookies.LtpaToken));
});
```

## Example 2
If you need to access a backend Domino database using a specific user account,
you can generate an LtpaToken for that account using the `generate` method:

```javascript
let ltpa = require("ltpa");
let rp = require("request-promise");

ltpa.setSecrets({
  "example.com": "AAECAwQFBgcICQoLDA0ODxAREhM="
});

router.get("/myDominoView", function(req, res) {
  let userNameBuf = ltpa.generateUserNameBuf("Sysadmin Account");
  let backendToken = ltpa.generate(userNameBuf, "example.com");

  let dominoRequest = {
    uri: "https://domino.example.com/api/data/collections/name/myDominoView",
    method: "GET",
    strictSSL: true,
    timeout: 30000,
    headers: {
      Cookie: "LtpaToken=" + backendToken
    }
  };

  rp(dominoRequest)
    .then(response => res.json(response))
    .catch(err => {
      console.log(err);
      res.status(500).send(err);
    });
});
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

### Character set
The module only works with usernames containing characters in the `ibm850` codepage (basically Latin-1). The username in the token *should be* encoded in an IBM proprietary format called `LMBCS` (Lotus Multi-Byte Character Set) for which I have found no javascript implementation. However, `LMBCS` is backwards compatible with `ibm850` for all characters in that codepage so if your usernames don't contain characters outside of `ibm850`, then you're good to go.

### LTPA1 only
The package only supports LTPA1, and not LTPA2. WebSphere Application Server Version 5 and later supports LTPA1. WebSphere Application Server Version 7 and later supports LTPA2:

https://www.ibm.com/support/knowledgecenter/en/SSAW57_8.5.5/com.ibm.websphere.nd.doc/ae/cwbs_ltpatokens.html

However, there is a package by Benjamin Kröger for dealing with LTPA2:
* https://github.com/benkroeger/oniyi-ltpa
* https://www.npmjs.com/package/oniyi-ltpa
