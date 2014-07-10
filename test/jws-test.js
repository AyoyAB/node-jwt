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
        encodedPayload: 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
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
});
