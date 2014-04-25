var expect      = require('chai').expect;
var jwt         = require('../lib/jwt');
var jws         = require('../lib/jws');
var base64url   = require('../lib/base64url');

describe('jwt', function() {
    // Test data from JWS Internet Draft example A.1
    var HMAC_ALGORITHM = jws.algorithm.HmacWithSha256;
    var HMAC_KEY = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';
    var PROTECTED_HEADER = { typ: 'JWT', alg: HMAC_ALGORITHM };
    var ENCODED_PROTECTED_HEADER = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9';
    var PAYLOAD = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}';
    var ENCODED_PAYLOAD = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
    var ENCODED_SIGNATURE = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    var ENCODED_TOKEN = ENCODED_PROTECTED_HEADER + '.' + ENCODED_PAYLOAD + '.' + ENCODED_SIGNATURE;

    describe('.encodeJws()', function() {
        it('should complain if no algorithm is specified', function() {
            expect(function() { jwt.encodeJwt({ typ: 'JWT' }, PAYLOAD, HMAC_KEY); }).to.throw('alg parameter must be present in header');
        });

        it('should complain if an invalid algorithm is specified', function() {
            expect(function() { jwt.encodeJwt({ typ: 'JWT', alg: 'ABC123' }, PAYLOAD, HMAC_KEY); }).to.throw('Unsupported algorithm: ABC123');
        });

        it('should correctly generate JWS draft example A1', function () {
            var encodedToken = jwt.encodeJwt(PROTECTED_HEADER, PAYLOAD, HMAC_KEY);

            // NB: We can't do a straight comparison with the test data here, since the JSON lib used in the draft spec adds line feeds during serialization.
            var encodedHeader = encodedToken.split('.')[0];
            var encodedPayload = encodedToken.split('.')[1];
            var encodedSignature = encodedToken.split('.')[2];
            var isValid = jws.validateHmac(HMAC_ALGORITHM, HMAC_KEY, encodedHeader, encodedPayload, encodedSignature);
            expect(isValid).to.equal(true);

            var expectedEncodedHeader = base64url.fromBase64String(new Buffer(JSON.stringify(PROTECTED_HEADER)).toString('base64'));
            expect(expectedEncodedHeader).to.equal(encodedHeader);

            var expectedEncodedPayload = base64url.fromBase64String(new Buffer(PAYLOAD).toString('base64'));
            expect(expectedEncodedPayload).to.equal(encodedPayload);
        });
    });

    describe('.validateJws()', function() {
        it('should complain if less than three fields are present', function () {
            expect(function () {
                jwt.validateJwt('aaaa.bbbb', HMAC_KEY);
            }).to.throw('Invalid JWT');
        });

        it('should complain if more than three fields are present', function () {
            expect(function () {
                jwt.validateJwt('aaaa.bbbb.cccc.dddd', HMAC_KEY);
            }).to.throw('Invalid JWT');
        });

        it('should complain if a non-JSON header is supplied', function () {
            expect(function () {
                jwt.validateJwt('aaaa' + '.' + ENCODED_PAYLOAD + '.' + ENCODED_SIGNATURE, HMAC_KEY);
            }).to.throw('JWS protected header is not valid JSON');
        });

        it('should not validate a modified signature', function () {
            expect(jwt.validateJwt(ENCODED_TOKEN.substring(0, ENCODED_TOKEN.length - 1) + '1', HMAC_KEY)).to.equal(false);
        });

        it('should not validate a truncated signature', function () {
            expect(jwt.validateJwt(ENCODED_TOKEN.substring(0, ENCODED_TOKEN.length - 1), HMAC_KEY)).to.equal(false);
        });

        it('should not validate a padded signature', function () {
            expect(jwt.validateJwt(ENCODED_TOKEN+"1", HMAC_KEY)).to.equal(false);
        });

        it('should not validate with a modified key', function () {
            expect(jwt.validateJwt(ENCODED_TOKEN, HMAC_KEY.substring(0, HMAC_KEY.length - 2) + '12')).to.equal(false);
        });

        it('should not validate with a truncated key', function () {
            expect(jwt.validateJwt(ENCODED_TOKEN, HMAC_KEY.substring(0, HMAC_KEY.length - 2))).to.equal(false);
        });

        it('should not validate with a padded key', function () {
            expect(jwt.validateJwt(ENCODED_TOKEN, HMAC_KEY+"1")).to.equal(false);
        });

        it('should correctly validate JWS draft example A1', function () {
            expect(jwt.validateJwt(ENCODED_TOKEN, HMAC_KEY)).to.equal(true);
        });
    });
});
