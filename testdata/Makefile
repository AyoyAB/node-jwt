all: testdata

testdata: es256-alice-pub.pem es256-bob-pub.pem es384-alice-pub.pem es384-bob-pub.pem es512-alice-pub.pem es512-bob-pub.pem

es256-alice-pub.pem: es256-alice-priv.pem
	@openssl ec -in es256-alice-priv.pem -pubout > es256-alice-pub.pem

es256-bob-pub.pem: es256-bob-priv.pem
	@openssl ec -in es256-bob-priv.pem -pubout > es256-bob-pub.pem

es256-alice-priv.pem:
	@openssl ecparam -out es256-alice-priv.pem -name prime256v1 -genkey -noout

es256-bob-priv.pem:
	@openssl ecparam -out es256-bob-priv.pem -name prime256v1 -genkey -noout

es384-alice-pub.pem: es384-alice-priv.pem
	@openssl ec -in es384-alice-priv.pem -pubout > es384-alice-pub.pem

es384-bob-pub.pem: es384-bob-priv.pem
	@openssl ec -in es384-bob-priv.pem -pubout > es384-bob-pub.pem

es384-alice-priv.pem:
	@openssl ecparam -out es384-alice-priv.pem -name secp384r1 -genkey -noout

es384-bob-priv.pem:
	@openssl ecparam -out es384-bob-priv.pem -name secp384r1 -genkey -noout

es512-alice-pub.pem: es512-alice-priv.pem
	@openssl ec -in es512-alice-priv.pem -pubout > es512-alice-pub.pem

es512-bob-pub.pem: es512-bob-priv.pem
	@openssl ec -in es512-bob-priv.pem -pubout > es512-bob-pub.pem

es512-alice-priv.pem:
	@openssl ecparam -out es512-alice-priv.pem -name secp521r1 -genkey -noout

es512-bob-priv.pem:
	@openssl ecparam -out es512-bob-priv.pem -name secp521r1 -genkey -noout

clean:
	-rm *.pem

.PHONY: all testdata clean
