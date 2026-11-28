use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use rustler::{Binary, Env, NewBinary};

#[rustler::nif]
fn is_available() -> bool {
    true
}

fn parse_fq(bytes: &[u8]) -> Result<Fq, String> {
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes for Fq, got {}", bytes.len()));
    }
    let elem = Fq::from_be_bytes_mod_order(bytes);
    // Strict range check: ensure input was strictly < modulus
    let mut check_bytes = [0u8; 32];
    let bi = elem.into_bigint();
    let be_bytes = bi.to_bytes_be();
    check_bytes.copy_from_slice(&be_bytes);
    if check_bytes != bytes {
        return Err("Fq element exceeds modulus or not canonically encoded".to_string());
    }
    Ok(elem)
}

fn fq_to_bytes(elem: &Fq) -> [u8; 32] {
    let bi = elem.into_bigint();
    let be = bi.to_bytes_be();
    let mut out = [0u8; 32];
    out.copy_from_slice(&be);
    out
}

fn parse_fr(bytes: &[u8]) -> Result<Fr, String> {
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes for Fr, got {}", bytes.len()));
    }
    let elem = Fr::from_be_bytes_mod_order(bytes);
    let mut check_bytes = [0u8; 32];
    let bi = elem.into_bigint();
    let be_bytes = bi.to_bytes_be();
    check_bytes.copy_from_slice(&be_bytes);
    if check_bytes != bytes {
        return Err("Fr element exceeds modulus or not canonically encoded".to_string());
    }
    Ok(elem)
}

fn parse_g1(bytes: &[u8]) -> Result<G1Affine, String> {
    if bytes.len() == 64 {
        if bytes.iter().all(|&b| b == 0) {
            return Ok(G1Affine::zero());
        }
        let x = parse_fq(&bytes[0..32])?;
        let y = parse_fq(&bytes[32..64])?;
        let p = G1Affine::new_unchecked(x, y);
        if !p.is_on_curve() {
            return Err("G1 point not on curve".to_string());
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err("G1 point not in subgroup".to_string());
        }
        Ok(p)
    } else {
        Err(format!("Expected 64 bytes for G1, got {}", bytes.len()))
    }
}

fn g1_to_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if p.is_zero() {
        return out;
    }
    let x_bytes = fq_to_bytes(&p.x);
    let y_bytes = fq_to_bytes(&p.y);
    out[0..32].copy_from_slice(&x_bytes);
    out[32..64].copy_from_slice(&y_bytes);
    out
}

fn parse_g2(bytes: &[u8]) -> Result<G2Affine, String> {
    if bytes.len() == 128 {
        if bytes.iter().all(|&b| b == 0) {
            return Ok(G2Affine::zero());
        }
        // EIP-197 format: [x1 (32B), x0 (32B), y1 (32B), y0 (32B)]
        let x1 = parse_fq(&bytes[0..32])?;
        let x0 = parse_fq(&bytes[32..64])?;
        let y1 = parse_fq(&bytes[64..96])?;
        let y0 = parse_fq(&bytes[96..128])?;
        let x = Fq2::new(x0, x1);
        let y = Fq2::new(y0, y1);
        let p = G2Affine::new_unchecked(x, y);
        if !p.is_on_curve() {
            return Err("G2 point not on curve".to_string());
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err("G2 point not in subgroup".to_string());
        }
        Ok(p)
    } else {
        Err(format!("Expected 128 bytes for G2, got {}", bytes.len()))
    }
}

fn g2_to_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if p.is_zero() {
        return out;
    }
    let x0_bytes = fq_to_bytes(&p.x.c0);
    let x1_bytes = fq_to_bytes(&p.x.c1);
    let y0_bytes = fq_to_bytes(&p.y.c0);
    let y1_bytes = fq_to_bytes(&p.y.c1);
    out[0..32].copy_from_slice(&x1_bytes);
    out[32..64].copy_from_slice(&x0_bytes);
    out[64..96].copy_from_slice(&y1_bytes);
    out[96..128].copy_from_slice(&y0_bytes);
    out
}

/// G1 generator (64 bytes uncompressed)
#[rustler::nif]
fn g1_generator<'a>(env: Env<'a>) -> Binary<'a> {
    let g1 = G1Affine::generator();
    let bytes = g1_to_bytes(&g1);
    let mut bin = NewBinary::new(env, 64);
    bin.as_mut_slice().copy_from_slice(&bytes);
    bin.into()
}

/// G1 scalar multiplication
#[rustler::nif]
fn g1_mult<'a>(
    env: Env<'a>,
    p_bytes: Binary<'a>,
    scalar_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let p = parse_g1(p_bytes.as_slice())?;
    let s = parse_fr(scalar_bytes.as_slice())?;
    let res = (G1Projective::from(p) * s).into_affine();
    let bytes = g1_to_bytes(&res);
    let mut bin = NewBinary::new(env, 64);
    bin.as_mut_slice().copy_from_slice(&bytes);
    Ok(bin.into())
}

/// G1 point addition
#[rustler::nif]
fn g1_add<'a>(
    env: Env<'a>,
    p1_bytes: Binary<'a>,
    p2_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let p1 = parse_g1(p1_bytes.as_slice())?;
    let p2 = parse_g1(p2_bytes.as_slice())?;
    let res = (G1Projective::from(p1) + G1Projective::from(p2)).into_affine();
    let bytes = g1_to_bytes(&res);
    let mut bin = NewBinary::new(env, 64);
    bin.as_mut_slice().copy_from_slice(&bytes);
    Ok(bin.into())
}

/// G2 generator (128 bytes uncompressed)
#[rustler::nif]
fn g2_generator<'a>(env: Env<'a>) -> Binary<'a> {
    let g2 = G2Affine::generator();
    let bytes = g2_to_bytes(&g2);
    let mut bin = NewBinary::new(env, 128);
    bin.as_mut_slice().copy_from_slice(&bytes);
    bin.into()
}

/// G2 scalar multiplication
#[rustler::nif]
fn g2_mult<'a>(
    env: Env<'a>,
    p_bytes: Binary<'a>,
    scalar_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let p = parse_g2(p_bytes.as_slice())?;
    let s = parse_fr(scalar_bytes.as_slice())?;
    let res = (G2Projective::from(p) * s).into_affine();
    let bytes = g2_to_bytes(&res);
    let mut bin = NewBinary::new(env, 128);
    bin.as_mut_slice().copy_from_slice(&bytes);
    Ok(bin.into())
}

/// G2 point addition
#[rustler::nif]
fn g2_add<'a>(
    env: Env<'a>,
    p1_bytes: Binary<'a>,
    p2_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let p1 = parse_g2(p1_bytes.as_slice())?;
    let p2 = parse_g2(p2_bytes.as_slice())?;
    let res = (G2Projective::from(p1) + G2Projective::from(p2)).into_affine();
    let bytes = g2_to_bytes(&res);
    let mut bin = NewBinary::new(env, 128);
    bin.as_mut_slice().copy_from_slice(&bytes);
    Ok(bin.into())
}

/// Optimal Ate Pairing: e(P, Q)
#[rustler::nif]
fn pairing(p1_bytes: Binary, p2_bytes: Binary) -> Result<bool, String> {
    let p1 = parse_g1(p1_bytes.as_slice())?;
    let p2 = parse_g2(p2_bytes.as_slice())?;
    let gt = Bn254::pairing(p1, p2);
    Ok(!gt.0.is_zero())
}

/// Pairing check: verifies prod_i e(P_i, Q_i) == 1
#[rustler::nif]
fn pairing_check(pairs: Vec<(Binary, Binary)>) -> bool {
    if pairs.is_empty() {
        return false;
    }
    let mut g1_pts = Vec::with_capacity(pairs.len());
    let mut g2_pts = Vec::with_capacity(pairs.len());

    for (p1_bin, p2_bin) in pairs {
        match (parse_g1(p1_bin.as_slice()), parse_g2(p2_bin.as_slice())) {
            (Ok(p1), Ok(p2)) => {
                g1_pts.push(p1);
                g2_pts.push(p2);
            }
            _ => return false,
        }
    }

    let ml = Bn254::multi_pairing(g1_pts, g2_pts);
    ml.0 == ark_bn254::Fq12::one()
}

/// Groth16 verification check using Arkworks
#[allow(clippy::too_many_arguments)]
#[rustler::nif]
fn groth16_verify(
    alpha_bytes: Binary,
    beta_bytes: Binary,
    gamma_bytes: Binary,
    delta_bytes: Binary,
    ic_bytes: Vec<Binary>,
    input_scalars: Vec<Binary>,
    a_bytes: Binary,
    b_bytes: Binary,
    c_bytes: Binary,
) -> bool {
    let alpha = match parse_g1(alpha_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let beta = match parse_g2(beta_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let gamma = match parse_g2(gamma_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let delta = match parse_g2(delta_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if ic_bytes.len() != input_scalars.len() + 1 {
        return false;
    }

    let ic0 = match parse_g1(ic_bytes[0].as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let mut k_pub = G1Projective::from(ic0);
    for (ic_bin, s_bin) in ic_bytes[1..].iter().zip(input_scalars.iter()) {
        let ic_pt = match parse_g1(ic_bin.as_slice()) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let s = match parse_fr(s_bin.as_slice()) {
            Ok(fr) => fr,
            Err(_) => return false,
        };
        k_pub += G1Projective::from(ic_pt) * s;
    }

    let a = match parse_g1(a_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let b = match parse_g2(b_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let c = match parse_g1(c_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if alpha.is_zero()
        || beta.is_zero()
        || gamma.is_zero()
        || delta.is_zero()
        || a.is_zero()
        || b.is_zero()
        || c.is_zero()
    {
        return false;
    }

    // e(-A, B) * e(alpha, beta) * e(K_pub, gamma) * e(C, delta) == 1
    let g1_list = vec![-a, alpha, k_pub.into_affine(), c];
    let g2_list = vec![b, beta, gamma, delta];

    let ml = Bn254::multi_pairing(g1_list, g2_list);
    ml.0 == ark_bn254::Fq12::one()
}

rustler::init!("ecu_bn254_nif");
