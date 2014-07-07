var expect      = require('chai').expect;
var util        = require('./util');
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

            expect(util.bufferEquals(jwk.jwkToOpenSSL(KEY), new Buffer(EXPECTED_ENCODING, 'base64'))).to.equal(true);
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
            }, EXPECTED_PRIVATE_KEY_ENCODING = Buffer.concat([
                new Buffer([ 0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20 ]),
                new Buffer(base64url.toBase64String(KEY.d), 'base64'),
                new Buffer([ 0xa0, 0x0a ]),
                asn1.namedCurve[KEY.crv],
                new Buffer([ 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04 ]),
                new Buffer(base64url.toBase64String(KEY.x), 'base64'),
                new Buffer(base64url.toBase64String(KEY.y), 'base64')
            ]), EXPECTED_PUBLIC_KEY_ENCODING = Buffer.concat([
                new Buffer([ 0x30, 0x59, 0x30, 0x13 ]),
                asn1.algorithm['id-ecPublicKey'],
                asn1.namedCurve[KEY.crv],
                new Buffer([ 0x03, 0x42, 0x00, 0x04 ]),
                new Buffer(base64url.toBase64String(KEY.x), 'base64'),
                new Buffer(base64url.toBase64String(KEY.y), 'base64')
            ]);

            expect(util.bufferEquals(jwk.jwkToOpenSSL(KEY), EXPECTED_PRIVATE_KEY_ENCODING)).to.equal(true);
            delete KEY.d;
            expect(util.bufferEquals(jwk.jwkToOpenSSL(KEY), EXPECTED_PUBLIC_KEY_ENCODING)).to.equal(true);
        });
        it('should correctly convert elliptic curve key from JWS example A.4', function() {
            var KEY = {
                'kty': 'EC',
                'crv': 'P-521',
                'x': 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
                'y': 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
                'd': 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C'
            }, EXPECTED_PRIVATE_KEY_ENCODING = Buffer.concat([
                new Buffer([ 0x30, 0x81, 0xdc, 0x02, 0x01, 0x01, 0x04, 0x42 ]),
                new Buffer(base64url.toBase64String(KEY.d), 'base64'),
                new Buffer([ 0xa0, 0x07 ]),
                asn1.namedCurve[KEY.crv],
                new Buffer([ 0xa1, 0x81, 0x89, 0x03, 0x81, 0x86, 0x00, 0x04 ]),
                new Buffer(base64url.toBase64String(KEY.x), 'base64'),
                new Buffer(base64url.toBase64String(KEY.y), 'base64')
            ]), EXPECTED_PUBLIC_KEY_ENCODING = Buffer.concat([
                new Buffer([ 0x30, 0x81, 0x9b, 0x30, 0x10 ]),
                asn1.algorithm['id-ecPublicKey'],
                asn1.namedCurve[KEY.crv],
                new Buffer([ 0x03, 0x81, 0x86, 0x00, 0x04 ]),
                new Buffer(base64url.toBase64String(KEY.x), 'base64'),
                new Buffer(base64url.toBase64String(KEY.y), 'base64')
            ]);

            expect(util.bufferEquals(jwk.jwkToOpenSSL(KEY), EXPECTED_PRIVATE_KEY_ENCODING)).to.equal(true);
            delete KEY.d;
            expect(util.bufferEquals(jwk.jwkToOpenSSL(KEY), EXPECTED_PUBLIC_KEY_ENCODING)).to.equal(true);
        });
    });
});
