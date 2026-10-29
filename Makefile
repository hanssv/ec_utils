.PHONY: all compile test eqc dialyzer schnorr_reference clean

all: compile

compile:
	rebar3 compile

test:
	rebar3 eunit

eqc:
	rebar3 as test eqc

dialyzer:
	rebar3 dialyzer

schnorr_reference:
	mkdir -p priv
	cd crates/schnorr_nif && cargo build --release
	@if [ -f crates/schnorr_nif/target/release/libecu_schnorr_nif.dylib ]; then \
		cp crates/schnorr_nif/target/release/libecu_schnorr_nif.dylib priv/ecu_schnorr_nif.so; \
	elif [ -f crates/schnorr_nif/target/release/libecu_schnorr_nif.so ]; then \
		cp crates/schnorr_nif/target/release/libecu_schnorr_nif.so priv/ecu_schnorr_nif.so; \
	elif [ -f crates/schnorr_nif/target/release/ecu_schnorr_nif.dll ]; then \
		cp crates/schnorr_nif/target/release/ecu_schnorr_nif.dll priv/ecu_schnorr_nif.dll; \
	fi

clean:
	rebar3 clean
	rm -rf priv/ecu_schnorr_nif.* crates/schnorr_nif/target
