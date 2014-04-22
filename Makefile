REPORTER = spec

all: jshint test

jshint:
	@./node_modules/.bin/jshint lib test index.js

test: testdata
	@NODE_ENV=test ./node_modules/.bin/mocha --recursive --reporter $(REPORTER) --timeout 3000

testdata:
	@$(MAKE) -C testdata testdata

clean:
	@$(MAKE) -C testdata clean

.PHONY: all jshint test testdata clean
