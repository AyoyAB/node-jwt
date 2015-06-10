var expect      = require('chai').expect;
var asn1        = require('../lib/asn1');
var base64url   = require('../lib/base64url');
var jwk         = require('../lib/jwk');

describe('jwk', function() {
    describe('.jwkToOpenSSL()', function() {
        it('should throw an error on a null input', function () {
            expect(function () { jwk.jwkToOpenSSL(); }).to.throw('jwk can not be null or undefined');
            expect(function () { jwk.jwkToOpenSSL(null); }).to.throw('jwk can not be null or undefined');
        });
        it('should throw an error on a missing key type', function () {
            expect(function () { jwk.jwkToOpenSSL({}); }).to.throw('Key type (kty) missing');
        });
        it('should throw an error on an invalid key type', function () {
            expect(function () { jwk.jwkToOpenSSL({ kty: 'invalid' }); }).to.throw('Unsupported key type (kty): invalid');
        });
        it('should throw an error on missing symmetric key data', function () {
            expect(function () { jwk.jwkToOpenSSL({ kty: 'oct' }); }).to.throw('Key data (k) missing');
        });
        it('should correctly convert symmetric key from JWS example A.1', function() {
            var KEY = {
                'kty': 'oct',
                'k': 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'
            }, EXPECTED_ENCODING = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ+EstJQLr/T+1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow==';

            expect(jwk.jwkToOpenSSL(KEY).equals(new Buffer(EXPECTED_ENCODING, 'base64'))).to.equal(true);
        });
        it('should throw an error on missing elliptic curve', function () {
            expect(function () { jwk.jwkToOpenSSL({ kty: 'EC', x: 'x', y: 'y' }); }).to.throw('Curve (crv) missing');
        });
        it('should throw an error on missing x coordinate', function () {
            expect(function () { jwk.jwkToOpenSSL({ kty: 'EC', crv: 'crv', y: 'y' }); }).to.throw('X coordinate (x) missing');
        });
        it('should throw an error on missing y coordinate', function () {
            expect(function () { jwk.jwkToOpenSSL({ kty: 'EC', crv: 'crv', x: 'x' }); }).to.throw('Y coordinate (y) missing');
        });
        it('should throw an error on an invalid curve', function () {
            expect(function () { jwk.jwkToOpenSSL({ kty: 'EC', crv: 'crv', x: 'x', y: 'y' }); }).to.throw('Unsupported Curve (crv): crv');
        });
        it('should correctly convert elliptic curve key from JWS example A.3', function() {
            var KEY = {
                'kty': 'EC',
                'crv': 'P-256',
                'x': 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                'y': 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
                'd': 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI'
            }, EXPECTED_PRIVATE_KEY_ENCODING = new Buffer(
                '-----BEGIN EC PRIVATE KEY-----\n' +
                'MHcCAQEEII6bEJ5xkJi/mASH3x9dd+nLKWBuvtImO19XwhPfhPSyoAoGCCqGSM49\n' +
                'AwEHoUQDQgAEf83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEXH8UTNG72b\n' +
                'focs3+257rn0s2ldbqkLJK2KRiMohYjlrQ==\n' +
                '-----END EC PRIVATE KEY-----\n'
            ), EXPECTED_PUBLIC_KEY_ENCODING = new Buffer(
                '-----BEGIN PUBLIC KEY-----\n' +
                'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf83OJ3D2xF1Bg8vub9tLe1gHMzV7\n' +
                '6e8Tus9uPHvRVEXH8UTNG72bfocs3+257rn0s2ldbqkLJK2KRiMohYjlrQ==\n' +
                '-----END PUBLIC KEY-----\n'
            );

            expect(jwk.jwkToOpenSSL(KEY).equals(EXPECTED_PRIVATE_KEY_ENCODING)).to.equal(true);
            expect(jwk.jwkToOpenSSL(KEY, { "public": true }).equals(EXPECTED_PUBLIC_KEY_ENCODING)).to.equal(true);
            delete KEY.d;
            expect(jwk.jwkToOpenSSL(KEY).equals(EXPECTED_PUBLIC_KEY_ENCODING)).to.equal(true);
        });
        it('should correctly convert elliptic curve key from JWS example A.4', function() {
            var KEY = {
                'kty': 'EC',
                'crv': 'P-521',
                'x': 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
                'y': 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
                'd': 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C'
            }, EXPECTED_PRIVATE_KEY_ENCODING = new Buffer(
                '-----BEGIN EC PRIVATE KEY-----\n' +
                'MIHcAgEBBEIBjmlvsDRQWIHdEQtIPrh9Ms5JX+NrN0Xt8tjK5PDyU59GFaDpjqtS\n' +
                's8DF6sTOB1GFqOe7R96sHR3ne8z2YTXmPYKgBwYFK4EEACOhgYkDgYYABAHpKQUP\n' +
                'Ek/GvFXH1TkzZd+d70qwwiyyV5j5NOsE48a643AaV6eRDp2BvzYxWejryxVdY0n0\n' +
                'vbbM+KlMXFnHqsEBpAA0pkQON2dQ0jcf0b3CyPO3HS9O5eo0MsgVzKMVYP5dk4fs\n' +
                'd0tVg4Yw5cu/Woy+CpHdAGTGmZofbm5n+t3t5MjI9g==\n' +
                '-----END EC PRIVATE KEY-----\n'
            ), EXPECTED_PUBLIC_KEY_ENCODING = new Buffer (
                '-----BEGIN PUBLIC KEY-----\n' +
                'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB6SkFDxJPxrxVx9U5M2Xfne9KsMIs\n' +
                'sleY+TTrBOPGuuNwGlenkQ6dgb82MVno68sVXWNJ9L22zPipTFxZx6rBAaQANKZE\n' +
                'DjdnUNI3H9G9wsjztx0vTuXqNDLIFcyjFWD+XZOH7HdLVYOGMOXLv1qMvgqR3QBk\n' +
                'xpmaH25uZ/rd7eTIyPY=\n' +
                '-----END PUBLIC KEY-----\n'
            );

            expect(jwk.jwkToOpenSSL(KEY).equals(EXPECTED_PRIVATE_KEY_ENCODING)).to.equal(true);
            expect(jwk.jwkToOpenSSL(KEY, { "public": true }).equals(EXPECTED_PUBLIC_KEY_ENCODING)).to.equal(true);
            delete KEY.d;
            expect(jwk.jwkToOpenSSL(KEY).equals(EXPECTED_PUBLIC_KEY_ENCODING)).to.equal(true);
        });
    });
});
