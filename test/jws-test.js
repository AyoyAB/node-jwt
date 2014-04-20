var expect    = require('chai').expect;
var jws       = require('../lib/jws');
var base64url = require('../lib/base64url');

describe('jws', function() {
    // Test data from JWS Internet Draft example A.1
    var HMAC_ALGORITHM = jws.Algorithms.HmacWithSha256;
    var HMAC_KEY = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';
    var PROTECTED_HEADER = { typ: 'JWT', alg: 'HS256' };
    var ENCODED_PROTECTED_HEADER = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9';
    var PAYLOAD = { iss: 'joe', exp: 1300819380, 'http://example.com/is_root': true };
    var ENCODED_PAYLOAD = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
    var ENCODED_SIGNATURE = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    var ENCODED_TOKEN = ENCODED_PROTECTED_HEADER + '.' + ENCODED_PAYLOAD + '.' + ENCODED_SIGNATURE;

    describe('.createHmac()', function() {
        it('should correctly generate JWS draft example A1', function () {
            var mac = jws.createHmac(HMAC_ALGORITHM, HMAC_KEY, ENCODED_PROTECTED_HEADER, ENCODED_PAYLOAD);

            expect(mac).to.equal(ENCODED_SIGNATURE);
        });
    });

    describe('.validateHmac()', function() {
        it('should correctly validate JWS draft example A1', function() {
            var isValid = jws.validateHmac(HMAC_ALGORITHM, HMAC_KEY, ENCODED_PROTECTED_HEADER, ENCODED_PAYLOAD, ENCODED_SIGNATURE);

            expect(isValid).to.be.true;
        })
    });

    describe('.encodeJws()', function() {
        it('should complain if no algorithm is specified', function() {
            expect(function() { jws.encodeJws({ typ: 'JWT' }, PAYLOAD, HMAC_KEY); }).to.throw('alg parameter must be present in header');
        });

        it('should complain if an invalid algorithm is specified', function() {
            expect(function() { jws.encodeJws({ typ: 'JWT', alg: 'ABC123' }, PAYLOAD, HMAC_KEY); }).to.throw('Unsupported algorithm: ABC123');
        });

        it('should correctly generate JWS draft example A1', function () {
            var encodedToken = jws.encodeJws(PROTECTED_HEADER, PAYLOAD, HMAC_KEY);

            // NB: We can't do a straight comparison with the test data here, since the JSON lib used in the draft spec adds line feeds during serialization.
            var encodedHeader = encodedToken.split('.')[0];
            var encodedPayload = encodedToken.split('.')[1];
            var encodedSignature = encodedToken.split('.')[2];
            var isValid = jws.validateHmac(HMAC_ALGORITHM, HMAC_KEY, encodedHeader, encodedPayload, encodedSignature);
            expect(isValid).to.be.true;

            var expectedEncodedHeader = base64url.fromBase64String(new Buffer(JSON.stringify(PROTECTED_HEADER)).toString('base64'));
            expect(expectedEncodedHeader).to.equal(encodedHeader);

            var expectedEncodedPayload = base64url.fromBase64String(new Buffer(JSON.stringify(PAYLOAD)).toString('base64'));
            expect(expectedEncodedPayload).to.equal(encodedPayload);
        });
    });

    describe('.validateJws()', function() {
        it('should complain if less than three fields are present', function () {
            expect(function () {
                jws.validateJws('aaaa.bbbb', HMAC_KEY);
            }).to.throw('Invalid JWS');
        });

        it('should complain if a more than three fields are present', function () {
            expect(function () {
                jws.validateJws('aaaa.bbbb.cccc.dddd', HMAC_KEY);
            }).to.throw('Invalid JWS');
        });

        it('should correctly validate JWS draft example A1', function () {
            expect(jws.validateJws(ENCODED_TOKEN, HMAC_KEY)).to.be.true;
        });
    });
});
