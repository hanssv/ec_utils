use ff::{Field, PrimeField};
use group::Group;
use jubjub::{AffinePoint, ExtendedPoint, Fq, Fr, SubgroupPoint};
use rustler::{Atom, Binary, Env, NewBinary};

mod atoms {
    rustler::atoms! {
        ok,
        error,
        badarg,
        spend_auth,
        binding,
    }
}

fn binary_to_bytes32(b: Binary) -> Result<[u8; 32], Atom> {
    if b.len() != 32 {
        return Err(atoms::badarg());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(b.as_slice());
    Ok(arr)
}

fn binary_to_affine(b: Binary) -> Result<AffinePoint, Atom> {
    let bytes = binary_to_bytes32(b)?;
    let opt = AffinePoint::from_bytes(bytes);
    if bool::from(opt.is_some()) {
        Ok(opt.unwrap())
    } else {
        Err(atoms::badarg())
    }
}

#[rustler::nif]
fn is_available_nif() -> bool {
    true
}

#[rustler::nif]
fn generator_nif<'a>(env: Env<'a>) -> Binary<'a> {
    let g = SubgroupPoint::generator();
    let ext = ExtendedPoint::from(g);
    let affine = AffinePoint::from(ext);
    let bytes = affine.to_bytes();
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&bytes);
    bin.into()
}

#[rustler::nif]
fn point_add_nif<'a>(env: Env<'a>, p1_bin: Binary, p2_bin: Binary) -> Result<Binary<'a>, Atom> {
    let p1 = binary_to_affine(p1_bin)?;
    let p2 = binary_to_affine(p2_bin)?;
    let sum = ExtendedPoint::from(p1) + ExtendedPoint::from(p2);
    let aff_sum = AffinePoint::from(sum);
    let bytes = aff_sum.to_bytes();
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&bytes);
    Ok(bin.into())
}

#[rustler::nif]
fn point_double_nif<'a>(env: Env<'a>, p_bin: Binary) -> Result<Binary<'a>, Atom> {
    let p = binary_to_affine(p_bin)?;
    let dbl = ExtendedPoint::from(p).double();
    let aff_dbl = AffinePoint::from(dbl);
    let bytes = aff_dbl.to_bytes();
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&bytes);
    Ok(bin.into())
}

#[rustler::nif]
fn point_mul_nif<'a>(
    env: Env<'a>,
    p_bin: Binary,
    scalar_le_bin: Binary,
) -> Result<Binary<'a>, Atom> {
    let p = binary_to_affine(p_bin)?;
    let scalar_bytes = binary_to_bytes32(scalar_le_bin)?;
    let scalar_opt = Fr::from_repr(scalar_bytes);
    let scalar = if bool::from(scalar_opt.is_some()) {
        scalar_opt.unwrap()
    } else {
        return Err(atoms::badarg());
    };
    let res = ExtendedPoint::from(p) * scalar;
    let aff_res = AffinePoint::from(res);
    let bytes = aff_res.to_bytes();
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&bytes);
    Ok(bin.into())
}

#[rustler::nif]
fn decompress_point_nif<'a>(env: Env<'a>, p_bin: Binary) -> Result<(Binary<'a>, Binary<'a>), Atom> {
    let p = binary_to_affine(p_bin)?;
    let u_bytes = p.get_u().to_repr();
    let v_bytes = p.get_v().to_repr();

    let mut u_bin = NewBinary::new(env, 32);
    u_bin.as_mut_slice().copy_from_slice(&u_bytes);
    let mut v_bin = NewBinary::new(env, 32);
    v_bin.as_mut_slice().copy_from_slice(&v_bytes);

    Ok((u_bin.into(), v_bin.into()))
}

#[rustler::nif]
fn compress_point_nif<'a>(env: Env<'a>, u_bin: Binary, v_bin: Binary) -> Result<Binary<'a>, Atom> {
    let u_bytes = binary_to_bytes32(u_bin)?;
    let v_bytes = binary_to_bytes32(v_bin)?;

    let u_opt = Fq::from_repr(u_bytes);
    let v_opt = Fq::from_repr(v_bytes);
    if bool::from(u_opt.is_none()) || bool::from(v_opt.is_none()) {
        return Err(atoms::badarg());
    }
    let u = u_opt.unwrap();
    let v = v_opt.unwrap();

    let mut bytes = v.to_bytes();
    let u_b = u.to_bytes();
    bytes[31] |= (u_b[0] & 1) << 7;

    let opt = AffinePoint::from_bytes(bytes);
    if bool::from(opt.is_none()) {
        return Err(atoms::badarg());
    }

    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&bytes);
    Ok(bin.into())
}

#[rustler::nif]
fn is_on_curve_nif(p_bin: Binary) -> bool {
    binary_to_affine(p_bin).is_ok()
}

#[rustler::nif]
fn is_in_subgroup_nif(p_bin: Binary) -> bool {
    if let Ok(p) = binary_to_affine(p_bin) {
        bool::from(ExtendedPoint::from(p).is_torsion_free())
    } else {
        false
    }
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
    let scalar_bytes = binary_to_bytes32(scalar_bin)?;
    let u_bytes = binary_to_bytes32(u_bin)?;

    let u_opt = Fq::from_repr(u_bytes);
    if !bool::from(u_opt.is_some()) {
        return Err(atoms::badarg());
    }
    let u_init = u_opt.unwrap();

    let a24 = Fq::from(10240u64);

    let x1 = u_init;
    let mut x2 = Fq::ONE;
    let mut z2 = Fq::ZERO;
    let mut x3 = x1;
    let mut z3 = Fq::ONE;
    let mut swap = 0u8;

    for t in (0..=255).rev() {
        let byte_idx = t / 8;
        let bit_idx = t % 8;
        let kt = (scalar_bytes[byte_idx] >> bit_idx) & 1;
        let new_swap = swap ^ kt;
        if new_swap == 1 {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = kt;

        let a = x2 + z2;
        let aa = a.square();
        let b = x2 - z2;
        let bb = b.square();
        let e = aa - bb;
        let c = x3 + z3;
        let d = x3 - z3;
        let da = d * a;
        let cb = c * b;
        let da_plus_cb = da + cb;
        let x3_next = da_plus_cb.square();
        let da_minus_cb = da - cb;
        let z3_next = x1 * da_minus_cb.square();
        let x2_next = aa * bb;
        let z2_next = e * (aa + a24 * e);

        x2 = x2_next;
        z2 = z2_next;
        x3 = x3_next;
        z3 = z3_next;
    }

    if swap == 1 {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }

    let res_u = if bool::from(z2.is_zero()) {
        Fq::ZERO
    } else {
        let inv_z = z2.invert().unwrap();
        x2 * inv_z
    };

    let res_bytes = res_u.to_repr();
    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&res_bytes);
    Ok(bin.into())
}

#[rustler::nif]
fn redjubjub_derive_public_key_nif<'a>(
    env: Env<'a>,
    sk_bin: Binary,
    sig_type: Atom,
) -> Result<Binary<'a>, Atom> {
    let sk_bytes = binary_to_bytes32(sk_bin)?;
    let pk_bytes: [u8; 32] = if sig_type == atoms::spend_auth() {
        let sk = redjubjub::SigningKey::<redjubjub::SpendAuth>::from_bytes(&sk_bytes)
            .map_err(|_| atoms::badarg())?;
        let pk: redjubjub::VerificationKey<redjubjub::SpendAuth> = (&sk).into();
        pk.into()
    } else if sig_type == atoms::binding() {
        let sk = redjubjub::SigningKey::<redjubjub::Binding>::from_bytes(&sk_bytes)
            .map_err(|_| atoms::badarg())?;
        let pk: redjubjub::VerificationKey<redjubjub::Binding> = (&sk).into();
        pk.into()
    } else {
        return Err(atoms::badarg());
    };

    let mut bin = NewBinary::new(env, 32);
    bin.as_mut_slice().copy_from_slice(&pk_bytes);
    Ok(bin.into())
}

#[rustler::nif]
fn redjubjub_sign_nif<'a>(
    env: Env<'a>,
    sk_bin: Binary,
    msg_bin: Binary,
    sig_type: Atom,
) -> Result<Binary<'a>, Atom> {
    let sk_bytes = binary_to_bytes32(sk_bin)?;
    let msg = msg_bin.as_slice();
    let mut rng = rand::rng();

    let sig_bytes: [u8; 64] = if sig_type == atoms::spend_auth() {
        let sk = redjubjub::SigningKey::<redjubjub::SpendAuth>::from_bytes(&sk_bytes)
            .map_err(|_| atoms::badarg())?;
        let sig: redjubjub::Signature<redjubjub::SpendAuth> = sk.sign(&mut rng, msg);
        sig.into()
    } else if sig_type == atoms::binding() {
        let sk = redjubjub::SigningKey::<redjubjub::Binding>::from_bytes(&sk_bytes)
            .map_err(|_| atoms::badarg())?;
        let sig: redjubjub::Signature<redjubjub::Binding> = sk.sign(&mut rng, msg);
        sig.into()
    } else {
        return Err(atoms::badarg());
    };

    let mut bin = NewBinary::new(env, 64);
    bin.as_mut_slice().copy_from_slice(&sig_bytes);
    Ok(bin.into())
}

#[rustler::nif]
fn redjubjub_verify_nif(pk_bin: Binary, msg_bin: Binary, sig_bin: Binary, sig_type: Atom) -> bool {
    let pk_bytes = match binary_to_bytes32(pk_bin) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if sig_bin.len() != 64 {
        return false;
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(sig_bin.as_slice());
    let msg = msg_bin.as_slice();

    if sig_type == atoms::spend_auth() {
        let vk_bytes = redjubjub::VerificationKeyBytes::<redjubjub::SpendAuth>::from(pk_bytes);
        let vk = match redjubjub::VerificationKey::<redjubjub::SpendAuth>::try_from(vk_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = redjubjub::Signature::<redjubjub::SpendAuth>::from(sig_bytes);
        vk.verify(msg, &sig).is_ok()
    } else if sig_type == atoms::binding() {
        let vk_bytes = redjubjub::VerificationKeyBytes::<redjubjub::Binding>::from(pk_bytes);
        let vk = match redjubjub::VerificationKey::<redjubjub::Binding>::try_from(vk_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = redjubjub::Signature::<redjubjub::Binding>::from(sig_bytes);
        vk.verify(msg, &sig).is_ok()
    } else {
        false
    }
}

rustler::init!("ecu_jubjub_nif");
