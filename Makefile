.PHONY: all compile test eqc dialyzer fmt fmt-check bench bench-save bench-compare rustcrypto_reference schnorr_reference frost_reference reference_nifs clean

all: compile

fmt:
	erlfmt -w {src,include,test,eqc,bench}/*.{erl,hrl,app.src} rebar.config

fmt-check:
	erlfmt -c {src,include,test,eqc,bench}/*.{erl,hrl,app.src} rebar.config

compile:
	rebar3 compile

bench:
	rebar3 as bench compile
	./bin/bench $(ARGS)

bench-save:
	rebar3 as bench compile
	./bin/bench --save baseline.json $(ARGS)

bench-compare:
	rebar3 as bench compile
	./bin/bench --compare baseline.json $(ARGS)

test:
	rebar3 eunit

eqc:
	rebar3 as test eqc

dialyzer:
	rebar3 dialyzer

rustcrypto_reference:
	mkdir -p priv
	cd crates/rustcrypto_nif && cargo build --release
	@if [ -f crates/rustcrypto_nif/target/release/libecu_rustcrypto_nif.dylib ]; then \
		cp crates/rustcrypto_nif/target/release/libecu_rustcrypto_nif.dylib priv/ecu_rustcrypto_nif.so; \
	elif [ -f crates/rustcrypto_nif/target/release/libecu_rustcrypto_nif.so ]; then \
		cp crates/rustcrypto_nif/target/release/libecu_rustcrypto_nif.so priv/ecu_rustcrypto_nif.so; \
	elif [ -f crates/rustcrypto_nif/target/release/ecu_rustcrypto_nif.dll ]; then \
		cp crates/rustcrypto_nif/target/release/ecu_rustcrypto_nif.dll priv/ecu_rustcrypto_nif.dll; \
	fi

schnorr_reference: rustcrypto_reference

frost_reference:
	mkdir -p priv
	cd crates/frost_nif && cargo build --release
	@if [ -f crates/frost_nif/target/release/libecu_frost_nif.dylib ]; then \
		cp crates/frost_nif/target/release/libecu_frost_nif.dylib priv/ecu_frost_nif.so; \
	elif [ -f crates/frost_nif/target/release/libecu_frost_nif.so ]; then \
		cp crates/frost_nif/target/release/libecu_frost_nif.so priv/ecu_frost_nif.so; \
	elif [ -f crates/frost_nif/target/release/ecu_frost_nif.dll ]; then \
		cp crates/frost_nif/target/release/ecu_frost_nif.dll priv/ecu_frost_nif.dll; \
	fi

musig2_reference:
	mkdir -p priv
	cd crates/musig2_nif && cargo build --release
	@if [ -f crates/musig2_nif/target/release/libecu_musig2_nif.dylib ]; then \
		cp crates/musig2_nif/target/release/libecu_musig2_nif.dylib priv/ecu_musig2_nif.so; \
	elif [ -f crates/musig2_nif/target/release/libecu_musig2_nif.so ]; then \
		cp crates/musig2_nif/target/release/libecu_musig2_nif.so priv/ecu_musig2_nif.so; \
	elif [ -f crates/musig2_nif/target/release/ecu_musig2_nif.dll ]; then \
		cp crates/musig2_nif/target/release/ecu_musig2_nif.dll priv/ecu_musig2_nif.dll; \
	fi

fn_dsa_reference:
	mkdir -p priv
	cd crates/fn_dsa_nif && cargo build --release
	@if [ -f crates/fn_dsa_nif/target/release/libecu_fn_dsa_nif.dylib ]; then \
		cp crates/fn_dsa_nif/target/release/libecu_fn_dsa_nif.dylib priv/ecu_fn_dsa_nif.so; \
	elif [ -f crates/fn_dsa_nif/target/release/libecu_fn_dsa_nif.so ]; then \
		cp crates/fn_dsa_nif/target/release/libecu_fn_dsa_nif.so priv/ecu_fn_dsa_nif.so; \
	elif [ -f crates/fn_dsa_nif/target/release/ecu_fn_dsa_nif.dll ]; then \
		cp crates/fn_dsa_nif/target/release/ecu_fn_dsa_nif.dll priv/ecu_fn_dsa_nif.dll; \
	fi

bls12_381_reference:
	mkdir -p priv
	cd crates/bls12_381_nif && cargo build --release
	@if [ -f crates/bls12_381_nif/target/release/libecu_bls12_381_nif.dylib ]; then \
		cp crates/bls12_381_nif/target/release/libecu_bls12_381_nif.dylib priv/ecu_bls12_381_nif.so; \
	elif [ -f crates/bls12_381_nif/target/release/libecu_bls12_381_nif.so ]; then \
		cp crates/bls12_381_nif/target/release/libecu_bls12_381_nif.so priv/ecu_bls12_381_nif.so; \
	elif [ -f crates/bls12_381_nif/target/release/ecu_bls12_381_nif.dll ]; then \
		cp crates/bls12_381_nif/target/release/ecu_bls12_381_nif.dll priv/ecu_bls12_381_nif.dll; \
	fi

reference_nifs: rustcrypto_reference frost_reference musig2_reference fn_dsa_reference bls12_381_reference

clean:
	rebar3 clean
	rm -rf priv/ecu_rustcrypto_nif.* priv/ecu_schnorr_nif.* priv/ecu_frost_nif.* priv/ecu_musig2_nif.* priv/ecu_fn_dsa_nif.* priv/ecu_bls12_381_nif.* crates/rustcrypto_nif/target crates/frost_nif/target crates/musig2_nif/target crates/fn_dsa_nif/target crates/bls12_381_nif/target

