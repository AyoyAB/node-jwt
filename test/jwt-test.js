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

    describe('.encodeJws()', function() {
        it('should complain if no algorithm is specified', function() {
            expect(function() { jwt.encodeJwt({ typ: 'JWT' }, jwsDraftExampleA1.payload, jwsDraftExampleA1.key); }).to.throw('alg parameter must be present in header');
        });

        it('should complain if an invalid algorithm is specified', function() {
            expect(function() { jwt.encodeJwt({ typ: 'JWT', alg: 'ABC123' }, jwsDraftExampleA1.payload, jwsDraftExampleA1.key); }).to.throw('Unsupported algorithm: ABC123');
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
    });

    describe('.validateJws()', function() {
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
    });
});
