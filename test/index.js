'use strict';

let expect = require('chai').expect;
let ltpa = require('../index');
ltpa.setSecrets({
    "example.com": "AAECAwQFBgcICQoLDA0ODxAREhM=",
    "invalid.example.com": "AAABAQICAwMEBAUFBgYHBwgICQk="
});

let userName = "My Test User";
let userNameBuf = ltpa.generateUserNameBuf(userName);

describe('#ltpa', function() {
    it('should generate a token', function() {
        let result = ltpa.generate(userNameBuf, "example.com");
        expect(result).to.be.a('string');
    });

    it('should generate a valid token', function() {
        let token = ltpa.generate(userNameBuf, "example.com");
        let result = ltpa.validate(token, "example.com");
        expect(result).to.be.a('undefined');
    });

    it('should refresh a valid token', function() {
        let token = ltpa.generate(userNameBuf, "example.com");
        let result = ltpa.refresh(token, "example.com");
        expect(result).to.be.a('string');
    });

    it('should generate an invalid token', function() {
        let token = ltpa.generate(userNameBuf, "invalid.example.com");
        expect(function() {
            ltpa.validate(token, "example.com");
        }).to.throw(Error, "Ltpa Token signature doesn't validate");
    });

    it('should not refresh an invalid token', function() {
        let token = ltpa.generate(userNameBuf, "invalid.example.com");
        expect(function() {
            ltpa.refresh(token, "example.com");
        }).to.throw(Error, "Ltpa Token signature doesn't validate");
    });

    it('should generate an expired token', function() {
        let token = ltpa.generate(userNameBuf, "example.com", 12);
        expect(function() {
            ltpa.validate(token, "example.com");
        }).to.throw(Error, "Ltpa Token has expired");
    });

    it('should generate a not yet valid token', function() {
        // Generate a token that starts being valid more than two gracePeriods into the future
        let d = Math.floor(Date.now()/1000) + 605;
        let token = ltpa.generate(userNameBuf, "example.com", d);
        expect(function() {
            ltpa.validate(token, "example.com");
        }).to.throw(Error, "Ltpa Token not yet valid");
    });

    it('should get the userName from the token', function() {
        let token = ltpa.generate(userNameBuf, "example.com");
        let result = ltpa.getUserName(token);
        expect(result).to.equal(userName);
    });


});