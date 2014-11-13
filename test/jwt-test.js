var expect      = require('chai').expect;
var jwt         = require('../lib/jwt');
var jws         = require('../lib/jws');
var base64url   = require('../lib/base64url');

describe('jwt', function() {
    // Test data from JWS Internet Draft example A.1
    var jwsDraftExampleA1 = {
        algorithm: jws.signatureAlgorithm.HmacWithSha256,
        key: {
            'kty': 'oct',
            'k': 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'
        },
        protectedHeader: { typ: 'JWT', alg: jws.signatureAlgorithm.HmacWithSha256 },
        encodedHeader: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
        payload: '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}',
        encodedPayload: 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
        encodedSignature: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        encodedToken: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.' +
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.' +
            'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    };
    // Test data from JWS Internet Draft example A.3
    var jwsDraftExampleA3 = {
        algorithm: jws.signatureAlgorithm.EcdsaP256WithSha256,
        key: {
            'kty': 'EC',
            'crv': 'P-256',
            'x': 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y': 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd': 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI'
        },
        encodedHeader: 'eyJhbGciOiJFUzI1NiJ9',
        encodedPayload: 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
        encodedSignature: 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q',
        encodedToken: 'eyJhbGciOiJFUzI1NiJ9.' +
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.' +
            'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q'
    };
    // Test data from JWS Internet Draft example A.4
    var jwsDraftExampleA4 = {
        algorithm: jws.signatureAlgorithm.EcdsaP521WithSha512,
        key: {
            'kty': 'EC',
            'crv': 'P-521',
            'x': 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
            'y': 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
            'd': 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C'
        },
        encodedHeader: 'eyJhbGciOiJFUzUxMiJ9',
        encodedPayload: 'UGF5bG9hZA',
        encodedSignature: 'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn',
        encodedToken: 'eyJhbGciOiJFUzUxMiJ9.' +
            'UGF5bG9hZA.' +
            'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn'
    };
    // Test data from JWS Internet Draft example A.5
    var jwsDraftExampleA5 = {
        protectedHeader: { alg: jws.signatureAlgorithm.None },
        payload: '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}',
        encodedToken: 'eyJhbGciOiJub25lIn0.' +
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
    };
    // Test data from JOSE Cookbook Internet Draft chapter 4.3
    var cookbookExample43 = {
        algorithm: jws.signatureAlgorithm.EcdsaP521WithSha512,
        key: {
            'kty': 'EC',
            'kid': 'bilbo.baggins@hobbiton.example',
            'use': 'sig',
            'crv': 'P-521',
            'x': 'AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt',
            'y': 'AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1',
            'd': 'AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt'
        },
        protectedHeader: { "alg": "ES512", "kid": "bilbo.baggins@hobbiton.example" },
        encodedHeader: 'eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9',
        // NB: We'll just base64url-decode the encoded payload instead...
        payload: 'It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don\'t keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.',
        encodedPayload: 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
        encodedSignature: 'AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2',
        encodedToken: 'eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.' +
            'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.' +
            'AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2'
    };
    // Test data from JOSE Cookbook Internet Draft chapter 4.4
    var cookbookExample44 = {
        algorithm: jws.signatureAlgorithm.HmacWithSha256,
        key: {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "alg": "HS256",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
        },
        protectedHeader: { "alg": "HS256", "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037" },
        encodedHeader: 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9',
        // NB: We'll just base64url-decode the encoded payload instead...
        payload: 'It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don\'t keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.',
        encodedPayload: 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
        encodedSignature: 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0',
        encodedToken: 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.' +
            'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.' +
            's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0'
    };

    describe('.encodeJwt()', function() {
        it('should complain if no algorithm is specified', function() {
            expect(function() { jwt.encodeJwt({ typ: 'JWT' }, jwsDraftExampleA1.payload, jwsDraftExampleA1.key); }).to.throw('alg parameter must be present in header');
        });

        it('should complain if an invalid algorithm is specified', function() {
            expect(function() { jwt.encodeJwt({ typ: 'JWT', alg: 'ABC123' }, jwsDraftExampleA1.payload, jwsDraftExampleA1.key); }).to.throw('Unknown alg value in token header: ABC123');
        });

        it('should correctly generate JWS draft example A1', function () {
            var encodedToken = jwt.encodeJwt(jwsDraftExampleA1.protectedHeader, jwsDraftExampleA1.payload, jwsDraftExampleA1.key);

            // NB: We can't do a straight comparison with the test data here, since the JSON lib used in the draft spec adds line feeds during serialization.
            var encodedHeader = encodedToken.split('.')[0];
            var encodedPayload = encodedToken.split('.')[1];
            var encodedSignature = encodedToken.split('.')[2];
            var isValid = jws.validateHmac(jwsDraftExampleA1.algorithm, jwsDraftExampleA1.key, encodedHeader, encodedPayload, encodedSignature);
            expect(isValid).to.equal(true);

            var expectedEncodedHeader = base64url.fromBase64String(new Buffer(JSON.stringify(jwsDraftExampleA1.protectedHeader)).toString('base64'));
            expect(expectedEncodedHeader).to.equal(encodedHeader);

            var expectedEncodedPayload = base64url.fromBase64String(new Buffer(jwsDraftExampleA1.payload).toString('base64'));
            expect(expectedEncodedPayload).to.equal(encodedPayload);
        });

        it('should correctly generate JWS draft example A5', function () {
            var encodedToken = jwt.encodeJwt(jwsDraftExampleA5.protectedHeader, jwsDraftExampleA5.payload);

            expect(jwsDraftExampleA5.encodedToken).to.equal(encodedToken);
        });

        it('should "correctly" generate JOSE Cookbook draft example 4.3', function () {
            var encodedToken = jwt.encodeJwt(cookbookExample43.protectedHeader,
                new Buffer(base64url.toBase64String(cookbookExample43.encodedPayload), 'base64').toString(),
                cookbookExample43.key);

            expect(jwt.validateJwt(encodedToken, cookbookExample43.key)).to.equal(true);
        });

        it('should correctly generate JOSE Cookbook draft example 4.4', function () {
            var encodedToken = jwt.encodeJwt(cookbookExample44.protectedHeader,
                new Buffer(base64url.toBase64String(cookbookExample44.encodedPayload), 'base64').toString(),
                cookbookExample44.key);

            expect(cookbookExample44.encodedToken).to.equal(encodedToken);
        });
    });

    describe('.validateJwt()', function() {
        it('should complain if less than three fields are present', function () {
            expect(function () {
                jwt.validateJwt('aaaa.bbbb', jwsDraftExampleA1.key);
            }).to.throw('Invalid JWT');
        });

        it('should complain if more than three fields are present', function () {
            expect(function () {
                jwt.validateJwt('aaaa.bbbb.cccc.dddd', jwsDraftExampleA1.key);
            }).to.throw('Invalid JWT');
        });

        it('should complain if a non-JSON header is supplied', function () {
            expect(function () {
                jwt.validateJwt('aaaa' + '.' + jwsDraftExampleA1.encodedPayload + '.' + jwsDraftExampleA1.encodedSignature, jwsDraftExampleA1.key);
            }).to.throw('JWS protected header is not valid JSON');
        });

        it('should not validate a modified signature', function () {
            expect(jwt.validateJwt(jwsDraftExampleA1.encodedToken.substring(0, jwsDraftExampleA1.encodedToken.length - 1) + '1', jwsDraftExampleA1.key)).to.equal(false);
        });

        it('should not validate a truncated signature', function () {
            expect(jwt.validateJwt(jwsDraftExampleA1.encodedToken.substring(0, jwsDraftExampleA1.encodedToken.length - 1), jwsDraftExampleA1.key)).to.equal(false);
        });

        it('should not validate a padded signature', function () {
            expect(jwt.validateJwt(jwsDraftExampleA1.encodedToken + '1', jwsDraftExampleA1.key)).to.equal(false);
        });

        it('should not validate with a truncated key', function () {
            expect(jwt.validateJwt(jwsDraftExampleA1.encodedToken, {
                'kty': jwsDraftExampleA1.key.kty,
                'k': jwsDraftExampleA1.key.k.substring(0, jwsDraftExampleA1.key.k.length - 2)
            })).to.equal(false);
        });

        it('should not validate with a padded key', function () {
            expect(jwt.validateJwt(jwsDraftExampleA1.encodedToken, {
                'kty': jwsDraftExampleA1.key.kty,
                'k': jwsDraftExampleA1.key.k + '12'
            })).to.equal(false);
        });

        it('should not validate with a modified key', function () {
            expect(jwt.validateJwt(jwsDraftExampleA1.encodedToken, {
                'kty': jwsDraftExampleA1.key.kty,
                'k': jwsDraftExampleA1.key.k.substring(0, jwsDraftExampleA1.key.k.length - 2) + '12'
            })).to.equal(false);
        });

        it('should correctly validate JWS draft example A1', function () {
            expect(jwt.validateJwt(jwsDraftExampleA1.encodedToken, jwsDraftExampleA1.key)).to.equal(true);
        });

        it('should correctly validate JWS draft example A3', function () {
            expect(jwt.validateJwt(jwsDraftExampleA3.encodedToken, jwsDraftExampleA3.key)).to.equal(true);
        });

        it('should correctly validate JWS draft example A4', function () {
            expect(jwt.validateJwt(jwsDraftExampleA4.encodedToken, jwsDraftExampleA4.key)).to.equal(true);
        });

        it('should correctly validate JWS draft example A5', function () {
            expect(jwt.validateJwt(jwsDraftExampleA5.encodedToken)).to.equal(true);
        });

        it('should correctly validate JOSE Cookbook draft example 4.3', function () {
            expect(jwt.validateJwt(cookbookExample43.encodedToken, cookbookExample43.key)).to.equal(true);
        });

        it('should correctly validate JOSE Cookbook draft example 4.4', function () {
            expect(jwt.validateJwt(cookbookExample44.encodedToken, cookbookExample44.key)).to.equal(true);
        });
    });
});
