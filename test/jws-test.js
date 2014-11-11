var expect      = require('chai').expect;
var jws         = require('../lib/jws');
var base64url   = require('../lib/base64url');

describe('jws', function() {
    // Test data from JWS Internet Draft example A.1
    var jwsDraftExampleA1 = {
        algorithm: jws.signatureAlgorithm.HmacWithSha256,
        key: {
            'kty': 'oct',
            'k': 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'
        },
        encodedHeader: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
        encodedPayload: 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
        encodedSignature: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
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
        encodedSignature: 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q'
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
        encodedSignature: 'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn'
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
        encodedHeader: 'eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9',
        encodedPayload: 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
        encodedSignature: 'AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2'
    };

    describe('.createHmac()', function() {
        it('should correctly generate JWS draft example A1', function () {
            var mac = jws.createHmac(
                jwsDraftExampleA1.algorithm,
                jwsDraftExampleA1.key,
                jwsDraftExampleA1.encodedHeader,
                jwsDraftExampleA1.encodedPayload);

            expect(mac).to.equal(jwsDraftExampleA1.encodedSignature);
        });
    });

    describe('.validateHmac()', function() {
        it('should correctly validate JWS draft example A1', function() {
            var isValid = jws.validateHmac(
                jwsDraftExampleA1.algorithm,
                jwsDraftExampleA1.key,
                jwsDraftExampleA1.encodedHeader,
                jwsDraftExampleA1.encodedPayload,
                jwsDraftExampleA1.encodedSignature);

            expect(isValid).to.equal(true);
        });
    });

    describe('.createSignature()', function() {
        it('should "correctly" generate and validate JWS draft example A3', function () {
            var signature = jws.createSignature(
                jwsDraftExampleA3.algorithm,
                jwsDraftExampleA3.key,
                jwsDraftExampleA3.encodedHeader,
                jwsDraftExampleA3.encodedPayload);

            // Remove the private key component, to make sure validation works without it.
            delete jwsDraftExampleA3.key.d;

            expect(jws.validateSignature(
                jwsDraftExampleA3.algorithm,
                jwsDraftExampleA3.key,
                jwsDraftExampleA3.encodedHeader,
                jwsDraftExampleA3.encodedPayload,
                signature)).to.equal(true);
        });
    });

    describe('.createSignature()', function() {
        it('should "correctly" validate the signature in JWS draft example A3', function () {
            expect(jws.validateSignature(
                jwsDraftExampleA3.algorithm,
                jwsDraftExampleA3.key,
                jwsDraftExampleA3.encodedHeader,
                jwsDraftExampleA3.encodedPayload,
                jwsDraftExampleA3.encodedSignature)).to.equal(true);
        });
    });

    /*
    describe('.createSignature()', function() {
        it('should "correctly" generate and validate JWS draft example A4', function () {
            var signature = jws.createSignature(
                jwsDraftExampleA4.algorithm,
                jwsDraftExampleA4.key,
                jwsDraftExampleA4.encodedHeader,
                jwsDraftExampleA4.encodedPayload);

            // Remove the private key component, to make sure validation works without it.
            delete jwsDraftExampleA4.key.d;

            expect(jws.validateSignature(
                jwsDraftExampleA4.algorithm,
                jwsDraftExampleA4.key,
                jwsDraftExampleA4.encodedHeader,
                jwsDraftExampleA4.encodedPayload,
                signature)).to.equal(true);
        });
    });
    */

    describe('.createSignature()', function() {
        it('should "correctly" validate the signature in JWS draft example A4', function () {
            delete jwsDraftExampleA4.key.d;

            expect(jws.validateSignature(
                jwsDraftExampleA4.algorithm,
                jwsDraftExampleA4.key,
                jwsDraftExampleA4.encodedHeader,
                jwsDraftExampleA4.encodedPayload,
                jwsDraftExampleA4.encodedSignature)).to.equal(true);
        });
    });

    describe('.createSignature()', function() {
        it('should "correctly" validate the signature in the Jose Cookbook draft example 4.3', function () {
            delete cookbookExample43.key.d;

            expect(jws.validateSignature(
                cookbookExample43.algorithm,
                cookbookExample43.key,
                cookbookExample43.encodedHeader,
                cookbookExample43.encodedPayload,
                cookbookExample43.encodedSignature)).to.equal(true);
        });
    });
});
