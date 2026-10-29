use rand::thread_rng;
use rustler::{Binary, Env, NewBinary};
use std::collections::BTreeMap;
use std::time::Instant;

#[rustler::nif]
fn is_loaded() -> bool {
    true
}

macro_rules! verify_suite {
    ($mod:ident, $sig:expr, $msg:expr, $pubkey:expr) => {{
        let Ok(vk) = $mod::VerifyingKey::deserialize($pubkey) else {
            return false;
        };
        let Ok(sig) = $mod::Signature::deserialize($sig) else {
            return false;
        };
        vk.verify($msg, &sig).is_ok()
    }};
}

#[rustler::nif]
fn verify_nif(suite: &str, sig: Binary, msg: Binary, pubkey: Binary) -> bool {
    let s_sig = sig.as_slice();
    let s_msg = msg.as_slice();
    let s_pk = pubkey.as_slice();

    match suite {
        "ed25519" => verify_suite!(frost_ed25519, s_sig, s_msg, s_pk),
        "secp256k1" => verify_suite!(frost_secp256k1, s_sig, s_msg, s_pk),
        "bip340" => {
            if s_pk.len() == 32 {
                let mut pk33 = Vec::with_capacity(33);
                pk33.push(0x02);
                pk33.extend_from_slice(s_pk);
                verify_suite!(frost_secp256k1_tr, s_sig, s_msg, &pk33)
            } else {
                verify_suite!(frost_secp256k1_tr, s_sig, s_msg, s_pk)
            }
        }
        "ed448" => verify_suite!(frost_ed448, s_sig, s_msg, s_pk),
        _ => false,
    }
}

macro_rules! run_bench {
    ($mod:ident, $t:expr, $n:expr) => {{
        let mut rng = thread_rng();
        let max_signers = $n;
        let min_signers = $t;
        let (shares, pubkeys) = $mod::keys::generate_with_dealer(
            max_signers,
            min_signers,
            $mod::keys::IdentifierList::Default,
            &mut rng,
        )
        .map_err(|_| rustler::Error::BadArg)?;

        let iters = 100;
        let (id, share) = shares.iter().next().unwrap();

        // 1. Commit
        let start = Instant::now();
        for _ in 0..iters {
            let _ = $mod::round1::commit(share.signing_share(), &mut rng);
        }
        let commit_us = start.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

        // Round 1 nonces & commitments for T signers
        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();
        for (id, s) in shares.iter().take(min_signers as usize) {
            let (nonces, commitments) = $mod::round1::commit(s.signing_share(), &mut rng);
            nonces_map.insert(*id, nonces);
            commitments_map.insert(*id, commitments);
        }
        let message = b"FROST benchmark round test message";
        let signing_package = $mod::SigningPackage::new(commitments_map, message);
        let key_package = $mod::keys::KeyPackage::try_from(share.clone())
            .map_err(|_| rustler::Error::BadArg)?;

        // 2. Part sign
        let start = Instant::now();
        for _ in 0..iters {
            let _ = $mod::round2::sign(&signing_package, &nonces_map[id], &key_package)
                .map_err(|_| rustler::Error::BadArg)?;
        }
        let sign_us = start.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

        // Sig shares for T signers
        let mut signature_shares = BTreeMap::new();
        for (id, s) in shares.iter().take(min_signers as usize) {
            let kp = $mod::keys::KeyPackage::try_from(s.clone())
                .map_err(|_| rustler::Error::BadArg)?;
            let sig_share = $mod::round2::sign(&signing_package, &nonces_map[id], &kp)
                .map_err(|_| rustler::Error::BadArg)?;
            signature_shares.insert(*id, sig_share);
        }

        // 3. Aggregate
        let start = Instant::now();
        for _ in 0..iters {
            let _ = $mod::aggregate(&signing_package, &signature_shares, &pubkeys)
                .map_err(|_| rustler::Error::BadArg)?;
        }
        let agg_us = start.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

        let group_sig = $mod::aggregate(&signing_package, &signature_shares, &pubkeys)
            .map_err(|_| rustler::Error::BadArg)?;

        // 4. Verify
        let start = Instant::now();
        for _ in 0..iters {
            let _ = pubkeys.verifying_key().verify(message, &group_sig);
        }
        let verify_us = start.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

        Ok((commit_us, sign_us, agg_us, verify_us))
    }};
}

#[rustler::nif]
fn bench_round_nif(suite: &str, t: u16, n: u16) -> Result<(f64, f64, f64, f64), rustler::Error> {
    if t == 0 || n < t {
        return Err(rustler::Error::BadArg);
    }
    match suite {
        "ed25519" => run_bench!(frost_ed25519, t, n),
        "secp256k1" => run_bench!(frost_secp256k1, t, n),
        "bip340" => run_bench!(frost_secp256k1_tr, t, n),
        "ed448" => run_bench!(frost_ed448, t, n),
        _ => Err(rustler::Error::BadArg),
    }
}

macro_rules! sign_sample_suite {
    ($mod:ident, $env:expr, $t:expr, $n:expr, $msg:expr, $is_bip340:expr) => {{
        let mut rng = thread_rng();
        let (shares, pubkeys) = $mod::keys::generate_with_dealer(
            $n,
            $t,
            $mod::keys::IdentifierList::Default,
            &mut rng,
        )
        .map_err(|_| rustler::Error::BadArg)?;

        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();
        for (id, s) in shares.iter().take($t as usize) {
            let (nonces, commitments) = $mod::round1::commit(s.signing_share(), &mut rng);
            nonces_map.insert(*id, nonces);
            commitments_map.insert(*id, commitments);
        }

        let signing_package = $mod::SigningPackage::new(commitments_map, $msg);
        let mut signature_shares = BTreeMap::new();
        for (id, s) in shares.iter().take($t as usize) {
            let kp = $mod::keys::KeyPackage::try_from(s.clone())
                .map_err(|_| rustler::Error::BadArg)?;
            let sig_share = $mod::round2::sign(&signing_package, &nonces_map[id], &kp)
                .map_err(|_| rustler::Error::BadArg)?;
            signature_shares.insert(*id, sig_share);
        }

        let group_sig = $mod::aggregate(&signing_package, &signature_shares, &pubkeys)
            .map_err(|_| rustler::Error::BadArg)?;

        let sig_bytes = group_sig.serialize().map_err(|_| rustler::Error::BadArg)?;
        let pk_bytes = pubkeys
            .verifying_key()
            .serialize()
            .map_err(|_| rustler::Error::BadArg)?;

        // If BIP-340, standard public key is 32-byte x-only
        let pk_slice = if $is_bip340 && pk_bytes.len() == 33 {
            &pk_bytes[1..]
        } else {
            &pk_bytes[..]
        };

        let mut erl_sig = NewBinary::new($env, sig_bytes.len());
        erl_sig.as_mut_slice().copy_from_slice(&sig_bytes);

        let mut erl_pk = NewBinary::new($env, pk_slice.len());
        erl_pk.as_mut_slice().copy_from_slice(pk_slice);

        Ok((erl_sig.into(), erl_pk.into()))
    }};
}

#[rustler::nif]
fn sign_sample_nif<'a>(
    env: Env<'a>,
    suite: &str,
    t: u16,
    n: u16,
    msg: Binary,
) -> Result<(Binary<'a>, Binary<'a>), rustler::Error> {
    if t == 0 || n < t {
        return Err(rustler::Error::BadArg);
    }
    let m = msg.as_slice();
    match suite {
        "ed25519" => sign_sample_suite!(frost_ed25519, env, t, n, m, false),
        "secp256k1" => sign_sample_suite!(frost_secp256k1, env, t, n, m, false),
        "bip340" => sign_sample_suite!(frost_secp256k1_tr, env, t, n, m, true),
        "ed448" => sign_sample_suite!(frost_ed448, env, t, n, m, false),
        _ => Err(rustler::Error::BadArg),
    }
}

rustler::init!("ecu_frost_nif");
