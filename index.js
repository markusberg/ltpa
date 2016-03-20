"use strict";

let ltpa = module.exports;

ltpa.generate = generate;
ltpa.generateUserNameBuf = generateUserNameBuf;
ltpa.getUserNameBuf = getUserNameBuf;
ltpa.getUserName = getUserName;
ltpa.refresh = refresh;
ltpa.setGracePeriod = setGracePeriod;
ltpa.setSecrets = setSecrets;
ltpa.setValidity = setValidity;
ltpa.validate = validate;

/**
 * LtpaToken generator and verifier
 */

let crypto = require("crypto");
let iconv = require('iconv-lite');

let ltpaSecrets;
let validity = 5400;
let gracePeriod = 300;

/***
 * Set how long a generated token is valid. Default is 5400 seconds (90 minutes)
 * @param Number seconds Number of seconds that tokens are valid
 */
function setValidity(seconds) {
    validity = seconds;
}

/***
 * Set the amount of time outside a ticket's validity that we will still accept it.
 * This time is also added to the validity of tokens that we generate
 * Default is 300 seconds (5 minutes).
 * @param Number seconds Number of seconds grace
 */
function setGracePeriod(seconds) {
    gracePeriod = seconds;
}

/***
 * Set the ltpa secrets
 * @param Object secrets domain to secret (base64) mapping
 */
function setSecrets(secrets) {
    ltpaSecrets = secrets;
}

/***
 * Generate a userName Buffer. Currently hardcoded to CP-850, but the
 * true char encoding is LMBCS
 * @param String userName The username to be converted to a CP-850 buffer
 * @returns Buffer Username encoded in cp-850 and stuffed into a Buffer
 */
function generateUserNameBuf(userName) {
    return iconv.encode(userName, "ibm850");
};

/***
 * Generate an LtpaToken suitable for writing to a cookie
 * @param Buffer userName The username for whom the cookie is signed
 * @param String domain The domain for which the cookie is generated
 * @param Number timeStart Timestamp (seconds) for when the token validity should start. Default: now
 * @returns String The LtpaToken encoded as Base64
 */
function generate(userNameBuf, domain, timeStart) {
    let start = timeStart ? timeStart : Math.floor(Date.now() / 1000);

    let timeCreation = (start - gracePeriod).toString(16);
    let timeExpiration = (start + validity + gracePeriod).toString(16);

    let size = userNameBuf.length + 40;
    let ltpaToken = new Buffer(size);

    ltpaToken.write("00010203", "hex");
    ltpaToken.write(timeCreation, 4);
    ltpaToken.write(timeExpiration, 12);
    userNameBuf.copy(ltpaToken, 20);
    let serverSecret = ltpaSecrets[domain];
    ltpaToken.write(serverSecret, size - 20, "base64");

    let hash = crypto.createHash("sha1");
    hash.update(ltpaToken);

    // Paranoid overwrite of the server secret 
    ltpaToken.write("0123456789abcdefghij", size - 20, "utf-8");

    // Append the token hash
    ltpaToken.write(hash.digest("hex"), size - 20, "hex");
    return ltpaToken.toString("base64");
};

/***
 * Validate a token. Throws an error if validation fails.
 * @param token String The LtpaToken string in Base64 encoded format
 * @param domain String The domain for which to validate the provided token
 */
function validate(token, domain) {
    let ltpaToken;
    ltpaToken = new Buffer(token, "base64");

    if (ltpaToken.length < 41) {
        // userName must be at least one character long
        throw new Error("Ltpa Token too short");
    }

    let signature = ltpaToken.toString("hex", ltpaToken.length - 20);
    let serverSecret = ltpaSecrets[domain];
    ltpaToken.write(serverSecret, ltpaToken.length - 20, "base64");

    let hash = crypto.createHash("sha1");
    hash.update(ltpaToken);

    let hexDigest = hash.digest("hex");
    if (hexDigest !== signature) {
        throw new Error("Ltpa Token signature doesn't validate");
    }
    let version = ltpaToken.toString("hex", 0, 4);
    if (version !== "00010203") {
        console.log(version);
        throw new Error("Incorrect magic string");
    }

    let timeCreation = parseInt(ltpaToken.toString("utf8", 4, 12), 16);
    let timeExpiration = parseInt(ltpaToken.toString("utf8", 12, 20), 16);
    let now = Math.floor(Date.now() / 1000);

    if (timeCreation > (now + gracePeriod)) {
        throw new Error("Ltpa Token not yet valid");
    }

    if ((timeCreation + validity) < (now - gracePeriod)) {
        throw new Error("Ltpa Token has expired");
    }
};

/***
 * Retrieve the username from the token. No validation of the token takes place
 * @param token String The LtpaToken string in Base64 encoded format
 * @returns Buffer Containing the username
 */
function getUserNameBuf(token) {
    let ltpaToken = new Buffer(token, "base64");
    return (ltpaToken.slice(20, ltpaToken.length - 20));
};

/***
 * Retrieve the username from the token as a string. No validation of the token takes place
 */
function getUserName(token) {
    return iconv.decode(getUserNameBuf(token), "ibm850");
};

/***
 * Refresh token if it's valid. Otherwise, throw an error.
 * @param token String The LtpaToken string in Base64 encoded format
 * @returns String Either the new cookie, or empty string
 */
function refresh(token, domain) {
    if (!token) {
        throw new Error("No token provided");
    }

    validate(token, domain);
    return generate(getUserNameBuf(token), domain);
};
