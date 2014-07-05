all: testdata

testdata: es256-alice-pub.pem es256-bob-pub.pem es384-alice-pub.pem es384-bob-pub.pem es512-alice-pub.pem es512-bob-pub.pem rs256-alice-pub.pem rs256-bob-pub.pem rs384-alice-pub.pem rs384-bob-pub.pem rs512-alice-pub.pem rs512-bob-pub.pem

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

rs256-alice-pub.pem: rs256-alice-priv.pem
	@openssl rsa -in rs256-alice-priv.pem -pubout > rs256-alice-pub.pem

rs256-bob-pub.pem: rs256-bob-priv.pem
	@openssl rsa -in rs256-bob-priv.pem -pubout > rs256-bob-pub.pem

rs256-alice-priv.pem:
	@openssl genrsa 3072 > rs256-alice-priv.pem

rs256-bob-priv.pem:
	@openssl genrsa 3072 > rs256-bob-priv.pem

rs384-alice-pub.pem: rs384-alice-priv.pem
	@openssl rsa -in rs384-alice-priv.pem -pubout > rs384-alice-pub.pem

rs384-bob-pub.pem: rs384-bob-priv.pem
	@openssl rsa -in rs384-bob-priv.pem -pubout > rs384-bob-pub.pem

rs384-alice-priv.pem:
	$(info Generating 7680 bit RSA key 1/2 - be patient...)
	@openssl genrsa 7680 > rs384-alice-priv.pem

rs384-bob-priv.pem:
	$(info Generating 7680 bit RSA key 2/2 - be patient...)
	@openssl genrsa 7680 > rs384-bob-priv.pem

rs512-alice-pub.pem: rs512-alice-priv.pem
	@openssl rsa -in rs512-alice-priv.pem -pubout > rs512-alice-pub.pem

rs512-bob-pub.pem: rs512-bob-priv.pem
	@openssl rsa -in rs512-bob-priv.pem -pubout > rs512-bob-pub.pem

rs512-alice-priv.pem:
	$(info Generating 15360 bit RSA key 1/2 - get coffee...)
	@openssl genrsa 15360 > rs512-alice-priv.pem

rs512-bob-priv.pem:
	$(info Generating 15360 bit RSA key 2/2 - get coffee...)
	@openssl genrsa 15360 > rs512-bob-priv.pem

clean:
	-rm *.pem

.PHONY: all testdata clean
