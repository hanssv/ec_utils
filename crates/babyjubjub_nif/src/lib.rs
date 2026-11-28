use babyjubjub_rs::{Point, PrivateKey, Q, decompress_point, decompress_signature, verify};
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
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

#[rustler::nif]
fn montgomery_ladder_nif<'a>(
    env: Env<'a>,
    scalar_bin: Binary,
    u_bin: Binary,
) -> Result<Binary<'a>, Atom> {
    if scalar_bin.len() != 32 || u_bin.len() != 32 {
        return Err(atoms::badarg());
    }
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(scalar_bin.as_slice());
    let k = BigInt::from_bytes_le(Sign::Plus, &scalar_bytes);

    let mut u_bytes = [0u8; 32];
    u_bytes.copy_from_slice(u_bin.as_slice());
    let u_init = BigInt::from_bytes_le(Sign::Plus, &u_bytes);

    let q = Q.clone();
    if u_init >= q {
        return Err(atoms::badarg());
    }
    if k.is_zero() || u_init.is_zero() {
        let mut bin = NewBinary::new(env, 32);
        bin.as_mut_slice().fill(0);
        return Ok(bin.into());
    }

    let a24 = BigInt::from(42174);
    let x1 = u_init.clone();
    let mut x2 = BigInt::one();
    let mut z2 = BigInt::zero();
    let mut x3 = x1.clone();
    let mut z3 = BigInt::one();
    let mut swap = 0;

    for t in (0..=255).rev() {
        let kt = if k.bit(t as u64) { 1 } else { 0 };
        let new_swap = swap ^ kt;
        if new_swap == 1 {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = kt;

        let a = (&x2 + &z2) % &q;
        let aa = (&a * &a) % &q;
        let b = (&x2 - &z2 + &q) % &q;
        let bb = (&b * &b) % &q;
        let e = (&aa - &bb + &q) % &q;
        let c = (&x3 + &z3) % &q;
        let d = (&x3 - &z3 + &q) % &q;
        let da = (&d * &a) % &q;
        let cb = (&c * &b) % &q;
        let da_plus_cb = (&da + &cb) % &q;
        let x3_next = (&da_plus_cb * &da_plus_cb) % &q;
        let da_minus_cb = (&da - &cb + &q) % &q;
        let z3_next = (&x1 * ((&da_minus_cb * &da_minus_cb) % &q)) % &q;
        let x2_next = (&aa * &bb) % &q;
        let z2_next = (&e * (&aa + &a24 * &e)) % &q;

        x2 = x2_next;
        z2 = z2_next;
        x3 = x3_next;
        z3 = z3_next;
    }

    if swap == 1 {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }

    let res_u = if z2.is_zero() {
        BigInt::zero()
    } else {
        let inv_z = babyjubjub_rs::utils::modinv(&z2, &q).map_err(|_| atoms::badarg())?;
        (&x2 * inv_z) % &q
    };

    let (_, mut u_res_bytes) = res_u.to_bytes_le();
    u_res_bytes.resize(32, 0);
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&u_res_bytes);
    Ok(bin.into())
}

const BASE_POINTS_HEX: [&str; 10] = [
    "1d1a2f1759e26271d2d3b44e56c1e89de65252d1d2df8af8a9bcfb97d807d42b",
    "66372fb0bb56cfa9461b1b754ed925418948c608767d66a69e44079c2652e305",
    "78124013e8822a6c5fd33d684af0893f4d580f6de3a6c2eeeed72c47a2cd380d",
    "3697e2fee43bd28794d26b4e5ffeb7716e19db874e4f9fcded21496e397f5106",
    "229a60dfd1035daff9de02ff642cec78482fa545c96f94d431c235cb48cc9082",
    "63eb580dc0604e85db259698005534e50fa0b60c0e6a2fc527a412b7797cfd1e",
    "9c0d9e4cd79028118489605855b23e5b4b57459f8b044e1b1baa5b6bf2f6fe9c",
    "3f43af2d3991696a8c6e0963d5e7d16b5b9646dcc5db45da26186c703275331e",
    "aab29c03f1cb17654640fda73deefa22bad0a3eaf205a48dc6cd31ee53347d1a",
    "8997284438f59a2f86e475ef50fdb6c5c50a030a010c07c3998420e1b63eee8e",
];

fn get_base_point(idx: usize) -> Result<Point, Atom> {
    if idx >= 10 {
        return Err(atoms::badarg());
    }
    let hex_bytes = hex::decode(BASE_POINTS_HEX[idx]).map_err(|_| atoms::badarg())?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hex_bytes);
    decompress_point(arr).map_err(|_| atoms::badarg())
}

fn pedersen_hash_internal(data: &[u8]) -> Result<Point, Atom> {
    if data.len() > 250 {
        return Err(atoms::badarg());
    }
    let mut bits = Vec::with_capacity(data.len() * 8);
    for &byte in data {
        for b in 0..8 {
            bits.push((byte >> b) & 1);
        }
    }
    if bits.len() > 2000 {
        return Err(atoms::badarg());
    }

    let curve_order = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088614511777268538073601725287587578984328",
        10,
    )
    .unwrap();

    let mut acc: Option<babyjubjub_rs::PointProjective> = None;

    for (seg_idx, seg_bits) in bits.chunks(200).enumerate() {
        let base_pt = get_base_point(seg_idx)?;
        let mut seg_scalar = BigInt::zero();
        for (w_idx, window) in seg_bits.chunks(4).enumerate() {
            let b0 = window[0] as i64;
            let b1 = if window.len() > 1 {
                window[1] as i64
            } else {
                0
            };
            let b2 = if window.len() > 2 {
                window[2] as i64
            } else {
                0
            };
            let b3 = if window.len() > 3 {
                window[3] as i64
            } else {
                0
            };
            let mag = 1 + b0 + 2 * b1 + 4 * b2;
            let val = if b3 == 1 { -mag } else { mag };
            let shift = w_idx * 5;
            let term = BigInt::from(val) << shift;
            seg_scalar += term;
        }

        if !seg_scalar.is_zero() {
            let pos_scalar = ((&seg_scalar % &curve_order) + &curve_order) % &curve_order;
            let pt = base_pt.mul_scalar(&pos_scalar);
            acc = match acc {
                None => Some(pt.projective()),
                Some(cur) => Some(cur.add(&pt.projective())),
            };
        }
    }

    match acc {
        Some(res) => Ok(res.affine()),
        None => {
            let base0 = get_base_point(0)?;
            Ok(base0.mul_scalar(&BigInt::zero()))
        }
    }
}

#[rustler::nif]
fn pedersen_hash_nif<'a>(env: Env<'a>, data_bin: Binary) -> Result<Binary<'a>, Atom> {
    let hash_pt = pedersen_hash_internal(data_bin.as_slice())?;
    let comp = hash_pt.compress();
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&comp);
    Ok(bin.into())
}

#[rustler::nif]
fn pedersen_commit_nif<'a>(
    env: Env<'a>,
    data_bin: Binary,
    blinding_bin: Binary,
) -> Result<Binary<'a>, Atom> {
    if blinding_bin.len() > 32 || data_bin.len() > 225 {
        return Err(atoms::badarg());
    }
    let hash_pt = pedersen_hash_internal(data_bin.as_slice())?;
    let blinding = BigInt::from_bytes_le(Sign::Plus, blinding_bin.as_slice());
    let curve_order = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088614511777268538073601725287587578984328",
        10,
    )
    .unwrap();
    let blinding_pos = ((&blinding % &curve_order) + &curve_order) % &curve_order;

    let base9 = get_base_point(9)?;
    let blinding_pt = base9.mul_scalar(&blinding_pos);
    let commit_pt = hash_pt.projective().add(&blinding_pt.projective()).affine();
    let comp = commit_pt.compress();
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&comp);
    Ok(bin.into())
}

rustler::init!("ecu_babyjubjub_nif");
