use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use rustler::{Binary, Env, NewBinary};
use sha3::{Digest, Keccak256};

#[rustler::nif]
fn sign<'a>(
    env: Env<'a>,
    privkey: Binary,
    msg: Binary,
    aux_rand: Binary,
) -> Result<Binary<'a>, rustler::Error> {
    let key_bytes: &[u8; 32] = privkey
        .as_slice()
        .try_into()
        .map_err(|_| rustler::Error::BadArg)?;
    let aux: &[u8; 32] = if aux_rand.is_empty() {
        &[0u8; 32]
    } else {
        aux_rand
            .as_slice()
            .try_into()
            .map_err(|_| rustler::Error::BadArg)?
    };
    let signing_key =
        SigningKey::from_bytes(key_bytes.into()).map_err(|_| rustler::Error::BadArg)?;
    let signature: Signature = signing_key
        .sign_raw(msg.as_slice(), aux)
        .map_err(|_| rustler::Error::BadArg)?;
    let sig_bytes = signature.to_bytes();
    let mut erl_bin = NewBinary::new(env, sig_bytes.len());
    erl_bin.as_mut_slice().copy_from_slice(&sig_bytes);
    Ok(erl_bin.into())
}

#[rustler::nif]
fn verify(sig: Binary, msg: Binary, pubkey: Binary) -> bool {
    let Ok(pk_bytes): Result<&[u8; 32], _> = pubkey.as_slice().try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(pk_bytes.into()) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(sig.as_slice()) else {
        return false;
    };
    verifying_key.verify_raw(msg.as_slice(), &signature).is_ok()
}

#[rustler::nif]
fn public_key<'a>(env: Env<'a>, privkey: Binary) -> Result<Binary<'a>, rustler::Error> {
    let key_bytes: &[u8; 32] = privkey
        .as_slice()
        .try_into()
        .map_err(|_| rustler::Error::BadArg)?;
    let signing_key =
        SigningKey::from_bytes(key_bytes.into()).map_err(|_| rustler::Error::BadArg)?;
    let verifying_key = signing_key.verifying_key();
    let pk_bytes = verifying_key.to_bytes();
    let mut erl_bin = NewBinary::new(env, pk_bytes.len());
    erl_bin.as_mut_slice().copy_from_slice(&pk_bytes);
    Ok(erl_bin.into())
}

#[rustler::nif]
fn keccak256<'a>(env: Env<'a>, data: Binary) -> Binary<'a> {
    let mut hasher = Keccak256::new();
    hasher.update(data.as_slice());
    let res = hasher.finalize();
    let mut erl_bin = NewBinary::new(env, res.len());
    erl_bin.as_mut_slice().copy_from_slice(&res);
    erl_bin.into()
}

rustler::init!("ecu_rustcrypto_nif");
