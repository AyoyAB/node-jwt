var fs     = require('fs');
var expect = require('chai').expect;
var pubKey = require('../lib/pubkey');

describe('pubKey', function() {
    var PAYLOAD = new Buffer('Hello, world!', 'ascii'),
        ALICE_ES256_PRIVATE_KEY,
        ALICE_ES256_PUBLIC_KEY,
        ALICE_ES384_PRIVATE_KEY,
        ALICE_ES384_PUBLIC_KEY,
        ALICE_ES521_PRIVATE_KEY,
        ALICE_ES521_PUBLIC_KEY,
        ALICE_RS256_PRIVATE_KEY,
        ALICE_RS256_PUBLIC_KEY,
        ALICE_RS384_PRIVATE_KEY,
        ALICE_RS384_PUBLIC_KEY,
        ALICE_RS512_PRIVATE_KEY,
        ALICE_RS512_PUBLIC_KEY;

    before(function() {
        ALICE_ES256_PRIVATE_KEY = fs.readFileSync(__dirname + '/../testdata/es256-alice-priv.pem').toString();
        ALICE_ES256_PUBLIC_KEY  = fs.readFileSync(__dirname + '/../testdata/es256-alice-pub.pem').toString();
        ALICE_ES384_PRIVATE_KEY = fs.readFileSync(__dirname + '/../testdata/es384-alice-priv.pem').toString();
        ALICE_ES384_PUBLIC_KEY  = fs.readFileSync(__dirname + '/../testdata/es384-alice-pub.pem').toString();
        ALICE_ES521_PRIVATE_KEY = fs.readFileSync(__dirname + '/../testdata/es512-alice-priv.pem').toString();
        ALICE_ES521_PUBLIC_KEY  = fs.readFileSync(__dirname + '/../testdata/es512-alice-pub.pem').toString();
        ALICE_RS256_PRIVATE_KEY  = fs.readFileSync(__dirname + '/../testdata/rs256-alice-priv.pem').toString();
        ALICE_RS256_PUBLIC_KEY   = fs.readFileSync(__dirname + '/../testdata/rs256-alice-pub.pem').toString();
        ALICE_RS384_PRIVATE_KEY  = fs.readFileSync(__dirname + '/../testdata/rs384-alice-priv.pem').toString();
        ALICE_RS384_PUBLIC_KEY   = fs.readFileSync(__dirname + '/../testdata/rs384-alice-pub.pem').toString();
        ALICE_RS512_PRIVATE_KEY  = fs.readFileSync(__dirname + '/../testdata/rs512-alice-priv.pem').toString();
        ALICE_RS512_PUBLIC_KEY   = fs.readFileSync(__dirname + '/../testdata/rs512-alice-pub.pem').toString();
    });

    describe('ES256', function() {
        it('should correctly sign and verify ES256 signatures', function() {
            var signature = pubKey.doSign('sha256', ALICE_ES256_PRIVATE_KEY, PAYLOAD);

            expect(pubKey.doVerify('sha256', ALICE_ES256_PUBLIC_KEY, PAYLOAD, signature)).to.equal(true);
        });
    });

    describe('ES384', function() {
        it('should correctly sign and verify ES384 signatures', function() {
            var signature = pubKey.doSign('sha384', ALICE_ES384_PRIVATE_KEY, PAYLOAD);

            expect(pubKey.doVerify('sha384', ALICE_ES384_PUBLIC_KEY, PAYLOAD, signature)).to.equal(true);
        });
    });

    describe('ES512', function() {
        it('should correctly sign and verify ES512 signatures', function() {
            var signature = pubKey.doSign('sha512', ALICE_ES521_PRIVATE_KEY, PAYLOAD);

            expect(pubKey.doVerify('sha512', ALICE_ES521_PUBLIC_KEY, PAYLOAD, signature)).to.equal(true);
        });
    });

    describe('RS256', function() {
        it('should correctly sign and verify RS256 signatures', function() {
            var signature = pubKey.doSign('sha256', ALICE_RS256_PRIVATE_KEY, PAYLOAD);

            expect(pubKey.doVerify('sha256', ALICE_RS256_PUBLIC_KEY, PAYLOAD, signature)).to.equal(true);
        });
    });

    describe('RS384', function() {
        it('should correctly sign and verify RS384 signatures', function() {
            var signature = pubKey.doSign('sha384', ALICE_RS384_PRIVATE_KEY, PAYLOAD);

            expect(pubKey.doVerify('sha384', ALICE_RS384_PUBLIC_KEY, PAYLOAD, signature)).to.equal(true);
        });
    });

    describe('RS512', function() {
        it('should correctly sign and verify RS512 signatures', function() {
            var signature = pubKey.doSign('sha512', ALICE_RS512_PRIVATE_KEY, PAYLOAD);

            expect(pubKey.doVerify('sha512', ALICE_RS512_PUBLIC_KEY, PAYLOAD, signature)).to.equal(true);
        });
    });
});
