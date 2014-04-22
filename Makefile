REPORTER = spec

all: jshint test

jshint:
	./node_modules/.bin/jshint lib test index.js

test: test/keys
	@NODE_ENV=test ./node_modules/.bin/mocha --recursive --reporter $(REPORTER) --timeout 3000

test/keys:
	@openssl genrsa 2048 > test/rs256-alice-priv.pem
	@openssl genrsa 2048 > test/rs256-bob-priv.pem
	@openssl rsa -in test/rs256-alice-priv.pem -pubout > test/rs256-alice-pub.pem
	@openssl rsa -in test/rs256-bob-priv.pem -pubout > test/rs256-bob-pub.pem
	@openssl ecparam -out test/es256-alice-priv.pem -name secp256r1 -genkey
	@openssl ecparam -out test/es256-bob-priv.pem -name secp256r1 -genkey
	@openssl ec -in test/es256-alice-priv.pem -pubout > test/es256-alice-pub.pem
	@openssl ec -in test/es256-bob-priv.pem -pubout > test/es256-bob-pub.pem
	@touch test/keys

clean:
	@rm test/*.pem
	@rm test/keys

.PHONY: all test jshint clean
