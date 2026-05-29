.PHONY: types

types:
	mkdir -p examples/demo/frontend/src
	TS_OUTPUT_PATH=examples/demo/frontend/src/types.ts cargo run --example gen-types --features ts

demo:
	cd examples/demo/frontend && npm install && npm run build
	cargo run --example demo --features ts
