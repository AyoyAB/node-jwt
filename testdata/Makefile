all: testdata

testdata: es256-alice-pub.pem es256-bob-pub.pem rs256-alice-pub.pem rs256-bob-pub.pem

es256-alice-pub.pem: es256-alice-priv.pem
	@openssl ec -in es256-alice-priv.pem -pubout > es256-alice-pub.pem

es256-bob-pub.pem: es256-bob-priv.pem
	@openssl ec -in es256-bob-priv.pem -pubout > es256-bob-pub.pem

es256-alice-priv.pem:
	@openssl ecparam -out es256-alice-priv.pem -name secp256r1 -genkey

es256-bob-priv.pem:
	@openssl ecparam -out es256-bob-priv.pem -name secp256r1 -genkey

rs256-alice-pub.pem: rs256-alice-priv.pem
	@openssl rsa -in rs256-alice-priv.pem -pubout > rs256-alice-pub.pem

rs256-bob-pub.pem: rs256-bob-priv.pem
	@openssl rsa -in rs256-bob-priv.pem -pubout > rs256-bob-pub.pem

rs256-alice-priv.pem:
	@openssl genrsa 2048 > rs256-alice-priv.pem

rs256-bob-priv.pem:
	@openssl genrsa 2048 > rs256-bob-priv.pem

clean:
	@rm *.pem

.PHONY: all testdata clean
