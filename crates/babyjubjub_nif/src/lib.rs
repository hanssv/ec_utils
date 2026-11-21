use babyjubjub_rs::{Point, PrivateKey, Q, decompress_point, decompress_signature, verify};
use num_bigint::{BigInt, Sign};
use rustler::{Atom, Binary, Env, NewBinary};

mod atoms {
    rustler::atoms! {
        ok,
        error,
        badarg,
    }
}

fn bigint_to_32bytes_be(b: &BigInt) -> [u8; 32] {
    let (_, bytes) = b.to_bytes_be();
    let mut out = [0u8; 32];
    if bytes.len() <= 32 {
        out[32 - bytes.len()..].copy_from_slice(&bytes);
    }
    out
}

fn binary_to_point(b: Binary) -> Result<Point, Atom> {
    if b.len() != 32 {
        return Err(atoms::badarg());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(b.as_slice());
    decompress_point(arr).map_err(|_| atoms::badarg())
}

#[rustler::nif]
fn is_available_nif() -> bool {
    true
}

#[rustler::nif]
fn point_add_nif<'a>(env: Env<'a>, p1_bin: Binary, p2_bin: Binary) -> Result<Binary<'a>, Atom> {
    let p1 = binary_to_point(p1_bin)?;
    let p2 = binary_to_point(p2_bin)?;
    let res = p1.projective().add(&p2.projective()).affine();
    let comp = res.compress();
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&comp);
    Ok(bin.into())
}

#[rustler::nif]
fn point_mul_nif<'a>(env: Env<'a>, p_bin: Binary, scalar_be: Binary) -> Result<Binary<'a>, Atom> {
    let p = binary_to_point(p_bin)?;
    let scalar = BigInt::from_bytes_be(Sign::Plus, scalar_be.as_slice());
    let res = p.mul_scalar(&scalar);
    let comp = res.compress();
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&comp);
    Ok(bin.into())
}

#[rustler::nif]
fn decompress_point_nif<'a>(env: Env<'a>, p_bin: Binary) -> Result<(Binary<'a>, Binary<'a>), Atom> {
    let p = binary_to_point(p_bin)?;
    // Extract x and y coordinates
    let x_str = format!("{}", p.x);
    let y_str = format!("{}", p.y);
    let x_hex = x_str.trim_start_matches("Fr(0x").trim_end_matches(')');
    let y_hex = y_str.trim_start_matches("Fr(0x").trim_end_matches(')');
    let x_big = BigInt::parse_bytes(x_hex.as_bytes(), 16).ok_or_else(atoms::badarg)?;
    let y_big = BigInt::parse_bytes(y_hex.as_bytes(), 16).ok_or_else(atoms::badarg)?;

    let x_be = bigint_to_32bytes_be(&x_big);
    let y_be = bigint_to_32bytes_be(&y_big);

    let mut x_bin = NewBinary::new(env, 32);
    x_bin.as_mut_slice().copy_from_slice(&x_be);
    let mut y_bin = NewBinary::new(env, 32);
    y_bin.as_mut_slice().copy_from_slice(&y_be);

    Ok((x_bin.into(), y_bin.into()))
}

#[rustler::nif]
fn eddsa_prv2pub_nif<'a>(env: Env<'a>, sk_bytes: Binary) -> Result<Binary<'a>, Atom> {
    if sk_bytes.len() != 32 {
        return Err(atoms::badarg());
    }
    let sk = PrivateKey::import(sk_bytes.as_slice().to_vec()).map_err(|_| atoms::badarg())?;
    let pk = sk.public();
    let comp = pk.compress();
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&comp);
    Ok(bin.into())
}

#[rustler::nif]
fn eddsa_sign_nif<'a>(
    env: Env<'a>,
    sk_bytes: Binary,
    msg_scalar_be: Binary,
) -> Result<Binary<'a>, Atom> {
    if sk_bytes.len() != 32 {
        return Err(atoms::badarg());
    }
    let sk = PrivateKey::import(sk_bytes.as_slice().to_vec()).map_err(|_| atoms::badarg())?;
    let msg = BigInt::from_bytes_be(Sign::Plus, msg_scalar_be.as_slice());
    if msg >= *Q {
        return Err(atoms::badarg());
    }
    let sig = sk.sign(msg).map_err(|_| atoms::badarg())?;
    let sig_bytes = sig.compress();
    let mut bin = NewBinary::new(env, 64);
    bin.as_mut_slice().copy_from_slice(&sig_bytes);
    Ok(bin.into())
}

#[rustler::nif]
fn eddsa_verify_nif(
    pk_comp: Binary,
    sig_bytes: Binary,
    msg_scalar_be: Binary,
) -> Result<bool, Atom> {
    let pk = binary_to_point(pk_comp)?;
    if sig_bytes.len() != 64 {
        return Err(atoms::badarg());
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes.as_slice());
    let sig = decompress_signature(&sig_arr).map_err(|_| atoms::badarg())?;
    let msg = BigInt::from_bytes_be(Sign::Plus, msg_scalar_be.as_slice());
    if msg >= *Q {
        return Err(atoms::badarg());
    }
    Ok(verify(pk, sig, msg))
}

rustler::init!("ecu_babyjubjub_nif");
