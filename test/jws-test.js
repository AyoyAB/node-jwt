var expect = require('chai').expect;
var jws = require('../lib/jws');

describe('jws', function() {
    describe('.createHmac()', function() {
        it('should correctly generate JWS draft example A1', function () {
            var key = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';
            var protectedHeader = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9';
            var payload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';

            var mac = jws.createHmac(jws.Algorithms.HmacWithSha256, key, protectedHeader, payload);

            expect(mac).to.equal('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
        });
    });

    describe('.validateHmac()', function() {
        it('should correctly validate JWS draft example A1', function() {
            var key = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';
            var protectedHeader = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9';
            var payload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
            var hmac = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

            var isValid = jws.validateHmac(jws.Algorithms.HmacWithSha256, key, protectedHeader, payload, hmac);

            expect(isValid).to.be.true;
        })
    });
});
