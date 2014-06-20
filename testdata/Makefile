all: testdata

testdata: es256-alice-pub.pem es256-bob-pub.pem es384-alice-pub.pem es384-bob-pub.pem es512-alice-pub.pem es512-bob-pub.pem rs256-alice-pub.pem rs256-bob-pub.pem

es256-alice-pub.pem: es256-alice-priv.pem
	@openssl ec -in es256-alice-priv.pem -pubout > es256-alice-pub.pem

es256-bob-pub.pem: es256-bob-priv.pem
	@openssl ec -in es256-bob-priv.pem -pubout > es256-bob-pub.pem

es256-alice-priv.pem:
	@openssl ecparam -out es256-alice-priv.pem -name prime256v1 -genkey

es256-bob-priv.pem:
	@openssl ecparam -out es256-bob-priv.pem -name prime256v1 -genkey

es384-alice-pub.pem: es384-alice-priv.pem
	@openssl ec -in es384-alice-priv.pem -pubout > es384-alice-pub.pem

es384-bob-pub.pem: es384-bob-priv.pem
	@openssl ec -in es384-bob-priv.pem -pubout > es384-bob-pub.pem

es384-alice-priv.pem:
	@openssl ecparam -out es384-alice-priv.pem -name secp384r1 -genkey

es384-bob-priv.pem:
	@openssl ecparam -out es384-bob-priv.pem -name secp384r1 -genkey

es512-alice-pub.pem: es512-alice-priv.pem
	@openssl ec -in es512-alice-priv.pem -pubout > es512-alice-pub.pem

es512-bob-pub.pem: es512-bob-priv.pem
	@openssl ec -in es512-bob-priv.pem -pubout > es512-bob-pub.pem

es512-alice-priv.pem:
	@openssl ecparam -out es512-alice-priv.pem -name secp521r1 -genkey

es512-bob-priv.pem:
	@openssl ecparam -out es512-bob-priv.pem -name secp521r1 -genkey

rs256-alice-pub.pem: rs256-alice-priv.pem
	@openssl rsa -in rs256-alice-priv.pem -pubout > rs256-alice-pub.pem

rs256-bob-pub.pem: rs256-bob-priv.pem
	@openssl rsa -in rs256-bob-priv.pem -pubout > rs256-bob-pub.pem

rs256-alice-priv.pem:
	@openssl genrsa 2048 > rs256-alice-priv.pem

rs256-bob-priv.pem:
	@openssl genrsa 2048 > rs256-bob-priv.pem

clean:
	-rm *.pem

.PHONY: all testdata clean
