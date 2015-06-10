var expect      = require('chai').expect;
var jws         = require('../lib/jws');
var base64url   = require('../lib/base64url');

describe('jws', function() {
    // Test data from RFC 7515 example A.1
    var rfc7515ExampleA1 = {
        algorithm: jws.signatureAlgorithm.HmacWithSha256,
        key: {
            'kty': 'oct',
            'k': 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'
        },
        encodedHeader: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
        encodedPayload: 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
        encodedSignature: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    };
    // Test data from RFC 7515 example A.3
    var rfc7515ExampleA3 = {
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
        encodedSignature: 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q'
    };
    // Test data from RFC 7515 example A.4
    var rfc7515ExampleA4 = {
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
        encodedSignature: 'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn'
    };
    // Test data from RFC 7520 chapter 4.3
    var rfc7520Example43 = {
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
        encodedHeader: 'eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9',
        encodedPayload: 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
        encodedSignature: 'AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2'
    };

    describe('.createHmac()', function() {
        it('should correctly generate RFC 7515 example A1', function () {
            var mac = jws.createHmac(
                rfc7515ExampleA1.algorithm,
                rfc7515ExampleA1.key,
                rfc7515ExampleA1.encodedHeader,
                rfc7515ExampleA1.encodedPayload);

            expect(mac).to.equal(rfc7515ExampleA1.encodedSignature);
        });
    });

    describe('.validateHmac()', function() {
        it('should correctly validate RFC 7515 example A1', function() {
            var isValid = jws.validateHmac(
                rfc7515ExampleA1.algorithm,
                rfc7515ExampleA1.key,
                rfc7515ExampleA1.encodedHeader,
                rfc7515ExampleA1.encodedPayload,
                rfc7515ExampleA1.encodedSignature);

            expect(isValid).to.equal(true);
        });
    });

    describe('.createSignature()', function() {
        it('should "correctly" generate and validate RFC 7515 example A3', function () {
            var signature = jws.createSignature(
                rfc7515ExampleA3.algorithm,
                rfc7515ExampleA3.key,
                rfc7515ExampleA3.encodedHeader,
                rfc7515ExampleA3.encodedPayload);

            expect(jws.validateSignature(
                rfc7515ExampleA3.algorithm,
                rfc7515ExampleA3.key,
                rfc7515ExampleA3.encodedHeader,
                rfc7515ExampleA3.encodedPayload,
                signature)).to.equal(true);
        });

        it('should "correctly" generate and validate RFC 7515 example A4', function () {
            var signature = jws.createSignature(
                rfc7515ExampleA4.algorithm,
                rfc7515ExampleA4.key,
                rfc7515ExampleA4.encodedHeader,
                rfc7515ExampleA4.encodedPayload);

            expect(jws.validateSignature(
                rfc7515ExampleA4.algorithm,
                rfc7515ExampleA4.key,
                rfc7515ExampleA4.encodedHeader,
                rfc7515ExampleA4.encodedPayload,
                signature)).to.equal(true);
        });

        it('should "correctly" generate and validate RFC 7520 example 4.3', function () {
            var signature = jws.createSignature(
                rfc7520Example43.algorithm,
                rfc7520Example43.key,
                rfc7520Example43.encodedHeader,
                rfc7520Example43.encodedPayload);

            expect(jws.validateSignature(
                rfc7520Example43.algorithm,
                rfc7520Example43.key,
                rfc7520Example43.encodedHeader,
                rfc7520Example43.encodedPayload,
                signature)).to.equal(true);
        });
    });

    describe('.validateSignature()', function() {
        it('should correctly validate RFC 7515 example A3', function () {
            expect(jws.validateSignature(
                rfc7515ExampleA3.algorithm,
                rfc7515ExampleA3.key,
                rfc7515ExampleA3.encodedHeader,
                rfc7515ExampleA3.encodedPayload,
                rfc7515ExampleA3.encodedSignature)).to.equal(true);
        });

        it('should correctly validate RFC 7515 example A4', function () {
            expect(jws.validateSignature(
                rfc7515ExampleA4.algorithm,
                rfc7515ExampleA4.key,
                rfc7515ExampleA4.encodedHeader,
                rfc7515ExampleA4.encodedPayload,
                rfc7515ExampleA4.encodedSignature)).to.equal(true);
        });

        it('should correctly validate RFC 7520 example 4.3', function () {
            expect(jws.validateSignature(
                rfc7520Example43.algorithm,
                rfc7520Example43.key,
                rfc7520Example43.encodedHeader,
                rfc7520Example43.encodedPayload,
                rfc7520Example43.encodedSignature)).to.equal(true);
        });
    });
});
