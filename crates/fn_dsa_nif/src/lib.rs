use pqcrypto_falcon::{falcon512, falcon1024};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _};
use rustler::{Binary, Env, NewBinary};

#[rustler::nif]
fn is_available() -> bool {
    true
}

#[rustler::nif]
fn falcon512_keypair<'a>(env: Env<'a>) -> Result<(Binary<'a>, Binary<'a>), String> {
    let (pk, sk) = falcon512::keypair();
    let pk_bytes = pk.as_bytes();
    let sk_bytes = sk.as_bytes();

    let mut pk_bin = NewBinary::new(env, pk_bytes.len());
    pk_bin.as_mut_slice().copy_from_slice(pk_bytes);

    let mut sk_bin = NewBinary::new(env, sk_bytes.len());
    sk_bin.as_mut_slice().copy_from_slice(sk_bytes);

    Ok((pk_bin.into(), sk_bin.into()))
}

#[rustler::nif]
fn falcon512_sign<'a>(
    env: Env<'a>,
    sk_bytes: Binary<'a>,
    msg_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let sk = falcon512::SecretKey::from_bytes(sk_bytes.as_slice())
        .map_err(|e| format!("Invalid secret key: {:?}", e))?;
    let sig = falcon512::detached_sign(msg_bytes.as_slice(), &sk);
    let sig_bytes = sig.as_bytes();

    let mut sig_bin = NewBinary::new(env, sig_bytes.len());
    sig_bin.as_mut_slice().copy_from_slice(sig_bytes);

    Ok(sig_bin.into())
}

#[rustler::nif]
fn falcon512_verify<'a>(
    pk_bytes: Binary<'a>,
    msg_bytes: Binary<'a>,
    sig_bytes: Binary<'a>,
) -> bool {
    let pk = match falcon512::PublicKey::from_bytes(pk_bytes.as_slice()) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match falcon512::DetachedSignature::from_bytes(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    falcon512::verify_detached_signature(&sig, msg_bytes.as_slice(), &pk).is_ok()
}

#[rustler::nif]
fn falcon1024_keypair<'a>(env: Env<'a>) -> Result<(Binary<'a>, Binary<'a>), String> {
    let (pk, sk) = falcon1024::keypair();
    let pk_bytes = pk.as_bytes();
    let sk_bytes = sk.as_bytes();

    let mut pk_bin = NewBinary::new(env, pk_bytes.len());
    pk_bin.as_mut_slice().copy_from_slice(pk_bytes);

    let mut sk_bin = NewBinary::new(env, sk_bytes.len());
    sk_bin.as_mut_slice().copy_from_slice(sk_bytes);

    Ok((pk_bin.into(), sk_bin.into()))
}

#[rustler::nif]
fn falcon1024_sign<'a>(
    env: Env<'a>,
    sk_bytes: Binary<'a>,
    msg_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let sk = falcon1024::SecretKey::from_bytes(sk_bytes.as_slice())
        .map_err(|e| format!("Invalid secret key: {:?}", e))?;
    let sig = falcon1024::detached_sign(msg_bytes.as_slice(), &sk);
    let sig_bytes = sig.as_bytes();

    let mut sig_bin = NewBinary::new(env, sig_bytes.len());
    sig_bin.as_mut_slice().copy_from_slice(sig_bytes);

    Ok(sig_bin.into())
}

#[rustler::nif]
fn falcon1024_verify<'a>(
    pk_bytes: Binary<'a>,
    msg_bytes: Binary<'a>,
    sig_bytes: Binary<'a>,
) -> bool {
    let pk = match falcon1024::PublicKey::from_bytes(pk_bytes.as_slice()) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match falcon1024::DetachedSignature::from_bytes(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    falcon1024::verify_detached_signature(&sig, msg_bytes.as_slice(), &pk).is_ok()
}

rustler::init!("ecu_fn_dsa_nif");
