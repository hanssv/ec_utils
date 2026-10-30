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

#[rustler::nif]
fn bech32_encode<'a>(
    env: Env<'a>,
    hrp_str: &str,
    data_5bit: Binary,
    variant: &str,
) -> Result<Binary<'a>, rustler::Error> {
    use bech32::primitives::encode::Encoder;
    use bech32::{Bech32, Bech32m, Fe32, Hrp};

    let hrp = Hrp::parse(hrp_str).map_err(|_| rustler::Error::BadArg)?;
    let fes = data_5bit
        .as_slice()
        .iter()
        .map(|&b| Fe32::try_from(b).map_err(|_| rustler::Error::BadArg))
        .collect::<Result<Vec<_>, _>>()?;

    let s = match variant {
        "bech32" => Encoder::<_, Bech32>::new(fes.into_iter(), &hrp)
            .chars()
            .collect::<String>(),
        "bech32m" => Encoder::<_, Bech32m>::new(fes.into_iter(), &hrp)
            .chars()
            .collect::<String>(),
        _ => return Err(rustler::Error::BadArg),
    };

    let bytes = s.as_bytes();
    let mut erl_bin = NewBinary::new(env, bytes.len());
    erl_bin.as_mut_slice().copy_from_slice(bytes);
    Ok(erl_bin.into())
}

#[rustler::nif]
fn bech32_decode<'a>(
    env: Env<'a>,
    s: &str,
) -> Result<(Binary<'a>, Binary<'a>, rustler::Atom), rustler::Error> {
    use bech32::primitives::decode::UncheckedHrpstring;
    use bech32::{Bech32, Bech32m};

    let unchecked = UncheckedHrpstring::new(s).map_err(|_| rustler::Error::BadArg)?;
    let (variant_atom, checked) = if unchecked.has_valid_checksum::<Bech32>() {
        (
            rustler::Atom::from_str(env, "bech32").map_err(|_| rustler::Error::BadArg)?,
            unchecked.remove_checksum::<Bech32>(),
        )
    } else if unchecked.has_valid_checksum::<Bech32m>() {
        (
            rustler::Atom::from_str(env, "bech32m").map_err(|_| rustler::Error::BadArg)?,
            unchecked.remove_checksum::<Bech32m>(),
        )
    } else {
        return Err(rustler::Error::BadArg);
    };

    let hrp = checked.hrp();
    let hrp_bytes = hrp.as_bytes();
    let mut hrp_bin = NewBinary::new(env, hrp_bytes.len());
    hrp_bin.as_mut_slice().copy_from_slice(hrp_bytes);

    let fes: Vec<u8> = checked.fe32_iter().map(|f| f.to_u8()).collect();
    let mut data_bin = NewBinary::new(env, fes.len());
    data_bin.as_mut_slice().copy_from_slice(&fes);

    Ok((hrp_bin.into(), data_bin.into(), variant_atom))
}

#[rustler::nif]
fn bech32_segwit_encode<'a>(
    env: Env<'a>,
    hrp_str: &str,
    witver: u8,
    program: Binary,
) -> Result<Binary<'a>, rustler::Error> {
    use bech32::{segwit, Fe32, Hrp};

    let hrp = Hrp::parse(hrp_str).map_err(|_| rustler::Error::BadArg)?;
    let version = Fe32::try_from(witver).map_err(|_| rustler::Error::BadArg)?;
    let s = segwit::encode(hrp, version, program.as_slice()).map_err(|_| rustler::Error::BadArg)?;
    let bytes = s.as_bytes();
    let mut erl_bin = NewBinary::new(env, bytes.len());
    erl_bin.as_mut_slice().copy_from_slice(bytes);
    Ok(erl_bin.into())
}

#[rustler::nif]
fn bech32_segwit_decode<'a>(
    env: Env<'a>,
    s: &str,
) -> Result<(Binary<'a>, u8, Binary<'a>), rustler::Error> {
    use bech32::segwit;

    let (hrp, witver, program) = segwit::decode(s).map_err(|_| rustler::Error::BadArg)?;
    let hrp_bytes = hrp.as_bytes();
    let mut hrp_bin = NewBinary::new(env, hrp_bytes.len());
    hrp_bin.as_mut_slice().copy_from_slice(hrp_bytes);

    let mut prog_bin = NewBinary::new(env, program.len());
    prog_bin.as_mut_slice().copy_from_slice(&program);

    Ok((hrp_bin.into(), witver.to_u8(), prog_bin.into()))
}

rustler::init!("ecu_rustcrypto_nif");


