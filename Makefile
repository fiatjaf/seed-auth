static/bundle.js: $(shell find src)
	./node_modules/.bin/rollup -c
