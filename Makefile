static/bundle.js: $(shell find src) rollup.config.js package.json
	./node_modules/.bin/rollup -c

deploy: static/bundle.js
	netlify deploy --prod -d static/
