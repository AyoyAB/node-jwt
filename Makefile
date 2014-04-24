REPORTER_TEST = spec
REPORTER_COVERAGE = html-cov

all: jshint test coverage docs

jshint:
	@./node_modules/.bin/jshint lib test index.js

test: testdata
	@NODE_ENV=test ./node_modules/.bin/mocha --recursive --reporter $(REPORTER_TEST) --timeout 3000

coverage: testdata
	@NODE_ENV=test ./node_modules/.bin/mocha --require blanket --recursive --reporter $(REPORTER_COVERAGE) --timeout 3000 > coverage.html

testdata:
	@$(MAKE) -C testdata testdata

docs:
	@./node_modules/.bin/groc lib/*.js README.md -o docs

clean:
	@$(MAKE) -C testdata clean
	-rm -rf docs

.PHONY: all jshint test coverage testdata docs clean
