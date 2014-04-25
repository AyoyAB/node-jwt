var expect      = require('chai').expect;
var jws         = require('../lib/jws');
var base64url   = require('../lib/base64url');

describe('jws', function() {
    // Test data from JWS Internet Draft example A.1
    var HMAC_ALGORITHM = jws.algorithm.HmacWithSha256;
    var HMAC_KEY = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

    var ENCODED_PROTECTED_HEADER = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9';

    var ENCODED_PAYLOAD = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
    var ENCODED_SIGNATURE = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    describe('.createHmac()', function() {
        it('should correctly generate JWS draft example A1', function () {
            var mac = jws.createHmac(HMAC_ALGORITHM, HMAC_KEY, ENCODED_PROTECTED_HEADER, ENCODED_PAYLOAD);

            expect(mac).to.equal(ENCODED_SIGNATURE);
        });
    });

    describe('.validateHmac()', function() {
        it('should correctly validate JWS draft example A1', function() {
            var isValid = jws.validateHmac(HMAC_ALGORITHM, HMAC_KEY, ENCODED_PROTECTED_HEADER, ENCODED_PAYLOAD, ENCODED_SIGNATURE);

            expect(isValid).to.equal(true);
        });
    });
});
