var fs     = require('fs');
var expect = require('chai').expect;
var pubKey = require('../lib/pubkey');

describe('pubKey', function() {
    var PAYLOAD = new Buffer('Hello, world!', 'ascii');
    var ALICE_P256_PRIVATE_KEY;
    var ALICE_P256_PUBLIC_KEY;
    var ALICE_RSA_PRIVATE_KEY;
    var ALICE_RSA_PUBLIC_KEY;

    before(function() {
        ALICE_P256_PRIVATE_KEY = fs.readFileSync(__dirname + '/../testdata/es256-alice-priv.pem').toString();
        ALICE_P256_PUBLIC_KEY  = fs.readFileSync(__dirname + '/../testdata/es256-alice-pub.pem').toString();
        ALICE_RSA_PRIVATE_KEY  = fs.readFileSync(__dirname + '/../testdata/rs256-alice-priv.pem').toString();
        ALICE_RSA_PUBLIC_KEY   = fs.readFileSync(__dirname + '/../testdata/rs256-alice-pub.pem').toString();
    });

    describe('ES256', function() {
        it('should correctly sign and verify ES256 signatures', function() {
            var signature = pubKey.doSign('sha256', ALICE_P256_PRIVATE_KEY, PAYLOAD);

            expect(pubKey.doVerify('sha256', ALICE_P256_PUBLIC_KEY, PAYLOAD, signature)).to.be.true;
        });
    });

    describe('RS256', function() {
        it('should correctly sign and verify RS256 signatures', function() {
            var signature = pubKey.doSign('sha256', ALICE_RSA_PRIVATE_KEY, PAYLOAD);

            expect(pubKey.doVerify('sha256', ALICE_RSA_PUBLIC_KEY, PAYLOAD, signature)).to.be.true;
        });
    });

    describe('RS384', function() {
        it('should correctly sign and verify RS384 signatures', function() {
            var signature = pubKey.doSign('sha384', ALICE_RSA_PRIVATE_KEY, PAYLOAD);

            expect(pubKey.doVerify('sha384', ALICE_RSA_PUBLIC_KEY, PAYLOAD, signature)).to.be.true;
        });
    });

    describe('RS512', function() {
        it('should correctly sign and verify RS512 signatures', function() {
            var signature = pubKey.doSign('sha512', ALICE_RSA_PRIVATE_KEY, PAYLOAD);

            expect(pubKey.doVerify('sha512', ALICE_RSA_PUBLIC_KEY, PAYLOAD, signature)).to.be.true;
        });
    });
});
