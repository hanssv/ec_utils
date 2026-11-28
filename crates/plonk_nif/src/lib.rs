use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use rustler::{Binary, Env};
use sha3::{Digest, Keccak256};

#[rustler::nif]
fn is_available() -> bool {
    true
}

fn parse_fq(bytes: &[u8]) -> Result<Fq, String> {
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes for Fq, got {}", bytes.len()));
    }
    let elem = Fq::from_be_bytes_mod_order(bytes);
    let mut check_bytes = [0u8; 32];
    let bi = elem.into_bigint();
    let be_bytes = bi.to_bytes_be();
    check_bytes.copy_from_slice(&be_bytes);
    if check_bytes != bytes {
        return Err("Fq element exceeds modulus or not canonically encoded".to_string());
    }
    Ok(elem)
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

fn fr_to_be_bytes(elem: &Fr) -> [u8; 32] {
    let bi = elem.into_bigint();
    let be = bi.to_bytes_be();
    let mut out = [0u8; 32];
    out.copy_from_slice(&be);
    out
}

fn keccak_fr(data: &[u8]) -> Fr {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    Fr::from_be_bytes_mod_order(&hash)
}

#[allow(clippy::too_many_arguments)]
#[rustler::nif]
fn verify_bn254<'a>(
    env: Env<'a>,
    power: usize,
    k1_bytes: Binary<'a>,
    k2_bytes: Binary<'a>,
    w_bytes: Binary<'a>,
    qm_bytes: Binary<'a>,
    ql_bytes: Binary<'a>,
    qr_bytes: Binary<'a>,
    qo_bytes: Binary<'a>,
    qc_bytes: Binary<'a>,
    s1_bytes: Binary<'a>,
    s2_bytes: Binary<'a>,
    s3_bytes: Binary<'a>,
    x2_bytes: Binary<'a>,
    public_inputs: Vec<Binary<'a>>,
    a_bytes: Binary<'a>,
    b_bytes: Binary<'a>,
    c_bytes: Binary<'a>,
    z_bytes: Binary<'a>,
    t1_bytes: Binary<'a>,
    t2_bytes: Binary<'a>,
    t3_bytes: Binary<'a>,
    eval_a_bytes: Binary<'a>,
    eval_b_bytes: Binary<'a>,
    eval_c_bytes: Binary<'a>,
    eval_s1_bytes: Binary<'a>,
    eval_s2_bytes: Binary<'a>,
    eval_zw_bytes: Binary<'a>,
    wxi_bytes: Binary<'a>,
    wxiw_bytes: Binary<'a>,
) -> bool {
    let _ = env;
    if power == 0 || power > 28 {
        return false;
    }
    let k1 = match parse_fr(k1_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let k2 = match parse_fr(k2_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let w_omega = match parse_fr(w_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let qm = match parse_g1(qm_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let ql = match parse_g1(ql_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let qr = match parse_g1(qr_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let qo = match parse_g1(qo_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let qc = match parse_g1(qc_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let s1 = match parse_g1(s1_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let s2 = match parse_g1(s2_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let s3 = match parse_g1(s3_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let x2 = match parse_g2(x2_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let mut pub_frs = Vec::with_capacity(public_inputs.len());
    for p_bin in &public_inputs {
        match parse_fr(p_bin.as_slice()) {
            Ok(fr) => pub_frs.push(fr),
            Err(_) => return false,
        }
    }

    let a = match parse_g1(a_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let b = match parse_g1(b_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let c = match parse_g1(c_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let z = match parse_g1(z_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let t1 = match parse_g1(t1_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let t2 = match parse_g1(t2_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let t3 = match parse_g1(t3_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let eval_a = match parse_fr(eval_a_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let eval_b = match parse_fr(eval_b_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let eval_c = match parse_fr(eval_c_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let eval_s1 = match parse_fr(eval_s1_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let eval_s2 = match parse_fr(eval_s2_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let eval_zw = match parse_fr(eval_zw_bytes.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let wxi = match parse_g1(wxi_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let wxiw = match parse_g1(wxiw_bytes.as_slice()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if qm.is_zero()
        || ql.is_zero()
        || qr.is_zero()
        || qo.is_zero()
        || qc.is_zero()
        || s1.is_zero()
        || s2.is_zero()
        || s3.is_zero()
        || x2.is_zero()
        || a.is_zero()
        || b.is_zero()
        || c.is_zero()
        || z.is_zero()
        || t1.is_zero()
        || t2.is_zero()
        || t3.is_zero()
        || wxi.is_zero()
        || wxiw.is_zero()
    {
        return false;
    }

    // 1. Beta transcript
    let mut beta_hasher = Keccak256::new();
    beta_hasher.update(qm_bytes.as_slice());
    beta_hasher.update(ql_bytes.as_slice());
    beta_hasher.update(qr_bytes.as_slice());
    beta_hasher.update(qo_bytes.as_slice());
    beta_hasher.update(qc_bytes.as_slice());
    beta_hasher.update(s1_bytes.as_slice());
    beta_hasher.update(s2_bytes.as_slice());
    beta_hasher.update(s3_bytes.as_slice());
    for p_bin in &public_inputs {
        beta_hasher.update(p_bin.as_slice());
    }
    beta_hasher.update(a_bytes.as_slice());
    beta_hasher.update(b_bytes.as_slice());
    beta_hasher.update(c_bytes.as_slice());
    let beta = Fr::from_be_bytes_mod_order(&beta_hasher.finalize());
    let beta_bytes_arr = fr_to_be_bytes(&beta);

    // 2. Gamma transcript
    let gamma = keccak_fr(&beta_bytes_arr);
    let gamma_bytes_arr = fr_to_be_bytes(&gamma);

    // 3. Alpha transcript
    let mut alpha_hasher = Keccak256::new();
    alpha_hasher.update(&beta_bytes_arr);
    alpha_hasher.update(&gamma_bytes_arr);
    alpha_hasher.update(z_bytes.as_slice());
    let alpha = Fr::from_be_bytes_mod_order(&alpha_hasher.finalize());
    let alpha_bytes_arr = fr_to_be_bytes(&alpha);

    // 4. Xi transcript
    let mut xi_hasher = Keccak256::new();
    xi_hasher.update(&alpha_bytes_arr);
    xi_hasher.update(t1_bytes.as_slice());
    xi_hasher.update(t2_bytes.as_slice());
    xi_hasher.update(t3_bytes.as_slice());
    let xi = Fr::from_be_bytes_mod_order(&xi_hasher.finalize());
    let xi_bytes_arr = fr_to_be_bytes(&xi);

    // 5. V1..V5 transcript
    let mut v_hasher = Keccak256::new();
    v_hasher.update(&xi_bytes_arr);
    v_hasher.update(eval_a_bytes.as_slice());
    v_hasher.update(eval_b_bytes.as_slice());
    v_hasher.update(eval_c_bytes.as_slice());
    v_hasher.update(eval_s1_bytes.as_slice());
    v_hasher.update(eval_s2_bytes.as_slice());
    v_hasher.update(eval_zw_bytes.as_slice());
    let v1 = Fr::from_be_bytes_mod_order(&v_hasher.finalize());
    let v2 = v1 * v1;
    let v3 = v2 * v1;
    let v4 = v3 * v1;
    let v5 = v4 * v1;

    // 6. U transcript
    let mut u_hasher = Keccak256::new();
    u_hasher.update(wxi_bytes.as_slice());
    u_hasher.update(wxiw_bytes.as_slice());
    let u = Fr::from_be_bytes_mod_order(&u_hasher.finalize());

    // Domain and evaluations
    let domain_size = 1usize << power;
    let n_fr = Fr::from(domain_size as u64);

    let mut xin = xi;
    for _ in 0..power {
        xin = xin.square();
    }
    let zh = xin - Fr::one();

    // Lagrange evaluations L_i(xi)
    let n_public = pub_frs.len();
    let num_l = if n_public == 0 { 1 } else { n_public };
    let mut l = Vec::with_capacity(num_l + 1);
    l.push(Fr::zero()); // 1-indexed

    let mut w_curr = Fr::one();
    for _ in 1..=num_l {
        let den = n_fr * (xi - w_curr);
        let num = w_curr * zh;
        let l_i = num * den.inverse().unwrap_or(Fr::zero());
        l.push(l_i);
        w_curr *= w_omega;
    }

    // PI(xi)
    let mut pi = Fr::zero();
    for (i, p_val) in pub_frs.iter().enumerate() {
        pi -= *p_val * l[i + 1];
    }

    // r0
    let alpha2 = alpha.square();
    let e1 = pi;
    let e2 = l[1] * alpha2;
    let e3a = eval_a + beta * eval_s1 + gamma;
    let e3b = eval_b + beta * eval_s2 + gamma;
    let e3c = eval_c + gamma;
    let e3 = e3a * e3b * e3c * eval_zw * alpha;
    let r0 = e1 - e2 - e3;

    // Linearization polynomial D
    let d1_proj = G1Projective::from(qc)
        + G1Projective::from(qm) * (eval_a * eval_b)
        + G1Projective::from(ql) * eval_a
        + G1Projective::from(qr) * eval_b
        + G1Projective::from(qo) * eval_c;

    let betaxi = beta * xi;
    let d2a1 = eval_a + betaxi + gamma;
    let d2a2 = eval_b + betaxi * k1 + gamma;
    let d2a3 = eval_c + betaxi * k2 + gamma;
    let d2a = d2a1 * d2a2 * d2a3 * alpha;
    let d2b = l[1] * alpha2;
    let d2_scalar = d2a + d2b + u;
    let d2_proj = G1Projective::from(z) * d2_scalar;

    let d3_scalar = (eval_a + beta * eval_s1 + gamma)
        * (eval_b + beta * eval_s2 + gamma)
        * (alpha * beta * eval_zw);
    let d3_proj = G1Projective::from(s3) * d3_scalar;

    let d4_inner = G1Projective::from(t1)
        + G1Projective::from(t2) * xin
        + G1Projective::from(t3) * xin.square();
    let d4_proj = d4_inner * zh;

    let d_proj = d1_proj + d2_proj - d3_proj - d4_proj;

    // F
    let f_proj = d_proj
        + G1Projective::from(a) * v1
        + G1Projective::from(b) * v2
        + G1Projective::from(c) * v3
        + G1Projective::from(s1) * v4
        + G1Projective::from(s2) * v5;

    // E
    let e_scalar =
        -r0 + v1 * eval_a + v2 * eval_b + v3 * eval_c + v4 * eval_s1 + v5 * eval_s2 + u * eval_zw;
    let e_proj = G1Projective::from(G1Affine::generator()) * e_scalar;

    // A1 & B1
    let a1_proj = G1Projective::from(wxi) + G1Projective::from(wxiw) * u;
    let s_param = u * xi * w_omega;
    let b1_proj =
        G1Projective::from(wxi) * xi + G1Projective::from(wxiw) * s_param + f_proj - e_proj;

    let a1 = a1_proj.into_affine();
    let b1 = b1_proj.into_affine();

    let g2_gen = G2Affine::generator();

    let ml = Bn254::multi_pairing([-a1, b1], [x2, g2_gen]);
    ml.0 == ark_bn254::Fq12::one()
}

rustler::init!("ecu_plonk_nif");
