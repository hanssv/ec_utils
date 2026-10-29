.PHONY: all compile test eqc dialyzer rustcrypto_reference schnorr_reference frost_reference reference_nifs clean

all: compile

compile:
	rebar3 compile

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

reference_nifs: rustcrypto_reference frost_reference

clean:
	rebar3 clean
	rm -rf priv/ecu_rustcrypto_nif.* priv/ecu_schnorr_nif.* priv/ecu_frost_nif.* crates/rustcrypto_nif/target crates/frost_nif/target
