use blst::BLST_ERROR;
use blst::min_pk as bls;
use blst::min_sig as bls_ms;
use rustler::{Binary, Env, NewBinary};

#[rustler::nif]
fn is_available() -> bool {
    true
}

/// G1 generator (48 bytes compressed)
#[rustler::nif]
fn g1_generator<'a>(env: Env<'a>) -> Binary<'a> {
    let g1 = unsafe { *blst::blst_p1_affine_generator() };
    let mut comp = [0u8; 48];
    unsafe { blst::blst_p1_affine_compress(comp.as_mut_ptr(), &g1) };
    let mut bin = NewBinary::new(env, 48);
    bin.as_mut_slice().copy_from_slice(&comp);
    bin.into()
}

/// G1 scalar multiplication by a 32-byte big-endian scalar
#[rustler::nif]
fn g1_mult<'a>(
    env: Env<'a>,
    p_bytes: Binary<'a>,
    scalar_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let mut aff = blst::blst_p1_affine::default();
    let err = unsafe { blst::blst_p1_uncompress(&mut aff, p_bytes.as_slice().as_ptr()) };
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(format!("Invalid G1 point: {:?}", err));
    }
    let mut p = blst::blst_p1::default();
    unsafe { blst::blst_p1_from_affine(&mut p, &aff) };

    let mut out_p = blst::blst_p1::default();
    let s = scalar_bytes.as_slice();
    unsafe { blst::blst_p1_mult(&mut out_p, &p, s.as_ptr(), s.len() * 8) };

    let mut out_aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut out_aff, &out_p) };

    let mut comp = [0u8; 48];
    unsafe { blst::blst_p1_affine_compress(comp.as_mut_ptr(), &out_aff) };
    let mut bin = NewBinary::new(env, 48);
    bin.as_mut_slice().copy_from_slice(&comp);
    Ok(bin.into())
}

/// G1 point addition
#[rustler::nif]
fn g1_add<'a>(
    env: Env<'a>,
    p1_bytes: Binary<'a>,
    p2_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let mut aff1 = blst::blst_p1_affine::default();
    let err1 = unsafe { blst::blst_p1_uncompress(&mut aff1, p1_bytes.as_slice().as_ptr()) };
    if err1 != BLST_ERROR::BLST_SUCCESS {
        return Err(format!("Invalid G1 point 1: {:?}", err1));
    }
    let mut aff2 = blst::blst_p1_affine::default();
    let err2 = unsafe { blst::blst_p1_uncompress(&mut aff2, p2_bytes.as_slice().as_ptr()) };
    if err2 != BLST_ERROR::BLST_SUCCESS {
        return Err(format!("Invalid G1 point 2: {:?}", err2));
    }

    let mut p1 = blst::blst_p1::default();
    unsafe { blst::blst_p1_from_affine(&mut p1, &aff1) };

    let mut out_p = blst::blst_p1::default();
    unsafe { blst::blst_p1_add_or_double_affine(&mut out_p, &p1, &aff2) };

    let mut out_aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut out_aff, &out_p) };

    let mut comp = [0u8; 48];
    unsafe { blst::blst_p1_affine_compress(comp.as_mut_ptr(), &out_aff) };
    let mut bin = NewBinary::new(env, 48);
    bin.as_mut_slice().copy_from_slice(&comp);
    Ok(bin.into())
}

/// G2 generator (96 bytes compressed)
#[rustler::nif]
fn g2_generator<'a>(env: Env<'a>) -> Binary<'a> {
    let g2 = unsafe { *blst::blst_p2_affine_generator() };
    let mut comp = [0u8; 96];
    unsafe { blst::blst_p2_affine_compress(comp.as_mut_ptr(), &g2) };
    let mut bin = NewBinary::new(env, 96);
    bin.as_mut_slice().copy_from_slice(&comp);
    bin.into()
}

/// G2 scalar multiplication by a 32-byte big-endian scalar
#[rustler::nif]
fn g2_mult<'a>(
    env: Env<'a>,
    p_bytes: Binary<'a>,
    scalar_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let mut aff = blst::blst_p2_affine::default();
    let err = unsafe { blst::blst_p2_uncompress(&mut aff, p_bytes.as_slice().as_ptr()) };
    if err != BLST_ERROR::BLST_SUCCESS {
        return Err(format!("Invalid G2 point: {:?}", err));
    }
    let mut p = blst::blst_p2::default();
    unsafe { blst::blst_p2_from_affine(&mut p, &aff) };

    let mut out_p = blst::blst_p2::default();
    let s = scalar_bytes.as_slice();
    unsafe { blst::blst_p2_mult(&mut out_p, &p, s.as_ptr(), s.len() * 8) };

    let mut out_aff = blst::blst_p2_affine::default();
    unsafe { blst::blst_p2_to_affine(&mut out_aff, &out_p) };

    let mut comp = [0u8; 96];
    unsafe { blst::blst_p2_affine_compress(comp.as_mut_ptr(), &out_aff) };
    let mut bin = NewBinary::new(env, 96);
    bin.as_mut_slice().copy_from_slice(&comp);
    Ok(bin.into())
}

/// G2 point addition
#[rustler::nif]
fn g2_add<'a>(
    env: Env<'a>,
    p1_bytes: Binary<'a>,
    p2_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let mut aff1 = blst::blst_p2_affine::default();
    let err1 = unsafe { blst::blst_p2_uncompress(&mut aff1, p1_bytes.as_slice().as_ptr()) };
    if err1 != BLST_ERROR::BLST_SUCCESS {
        return Err(format!("Invalid G2 point 1: {:?}", err1));
    }
    let mut aff2 = blst::blst_p2_affine::default();
    let err2 = unsafe { blst::blst_p2_uncompress(&mut aff2, p2_bytes.as_slice().as_ptr()) };
    if err2 != BLST_ERROR::BLST_SUCCESS {
        return Err(format!("Invalid G2 point 2: {:?}", err2));
    }

    let mut p1 = blst::blst_p2::default();
    unsafe { blst::blst_p2_from_affine(&mut p1, &aff1) };

    let mut out_p = blst::blst_p2::default();
    unsafe { blst::blst_p2_add_or_double_affine(&mut out_p, &p1, &aff2) };

    let mut out_aff = blst::blst_p2_affine::default();
    unsafe { blst::blst_p2_to_affine(&mut out_aff, &out_p) };

    let mut comp = [0u8; 96];
    unsafe { blst::blst_p2_affine_compress(comp.as_mut_ptr(), &out_aff) };
    let mut bin = NewBinary::new(env, 96);
    bin.as_mut_slice().copy_from_slice(&comp);
    Ok(bin.into())
}

/// Pairing evaluation e(P, Q) -> 576-byte Fp12
#[rustler::nif]
fn pairing<'a>(
    env: Env<'a>,
    p1_bytes: Binary<'a>,
    p2_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let mut aff1 = blst::blst_p1_affine::default();
    let err1 = unsafe { blst::blst_p1_uncompress(&mut aff1, p1_bytes.as_slice().as_ptr()) };
    if err1 != BLST_ERROR::BLST_SUCCESS {
        return Err(format!("Invalid G1 point: {:?}", err1));
    }
    let mut aff2 = blst::blst_p2_affine::default();
    let err2 = unsafe { blst::blst_p2_uncompress(&mut aff2, p2_bytes.as_slice().as_ptr()) };
    if err2 != BLST_ERROR::BLST_SUCCESS {
        return Err(format!("Invalid G2 point: {:?}", err2));
    }

    let mut pt = blst::blst_fp12::default();
    unsafe {
        blst::blst_miller_loop(&mut pt, &aff2, &aff1);
        blst::blst_final_exp(&mut pt, &pt);
    }

    let mut bin = NewBinary::new(env, std::mem::size_of::<blst::blst_fp12>());
    unsafe {
        std::ptr::copy_nonoverlapping(
            &pt as *const blst::blst_fp12 as *const u8,
            bin.as_mut_slice().as_mut_ptr(),
            std::mem::size_of::<blst::blst_fp12>(),
        );
    }
    Ok(bin.into())
}

/// Pairing check: verifies prod_i e(P_i, Q_i) == 1
#[rustler::nif]
fn pairing_check(pairs: Vec<(Binary, Binary)>) -> bool {
    if pairs.is_empty() {
        return false;
    }
    let mut ctx = blst::Pairing::new(false, &[]);

    for (p1_bin, p2_bin) in pairs {
        let mut p1 = blst::blst_p1_affine::default();
        let err1 = unsafe { blst::blst_p1_uncompress(&mut p1, p1_bin.as_slice().as_ptr()) };
        if err1 != BLST_ERROR::BLST_SUCCESS {
            return false;
        }
        let mut p2 = blst::blst_p2_affine::default();
        let err2 = unsafe { blst::blst_p2_uncompress(&mut p2, p2_bin.as_slice().as_ptr()) };
        if err2 != BLST_ERROR::BLST_SUCCESS {
            return false;
        }
        ctx.raw_aggregate(&p2, &p1);
    }

    ctx.commit();
    ctx.finalverify(None)
}

/// Groth16 verification check using blst
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
    if ic_bytes.len() != input_scalars.len() + 1 {
        return false;
    }
    let mut alpha = blst::blst_p1_affine::default();
    if unsafe { blst::blst_p1_uncompress(&mut alpha, alpha_bytes.as_slice().as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }
    let mut beta = blst::blst_p2_affine::default();
    if unsafe { blst::blst_p2_uncompress(&mut beta, beta_bytes.as_slice().as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }
    let mut gamma = blst::blst_p2_affine::default();
    if unsafe { blst::blst_p2_uncompress(&mut gamma, gamma_bytes.as_slice().as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }
    let mut delta = blst::blst_p2_affine::default();
    if unsafe { blst::blst_p2_uncompress(&mut delta, delta_bytes.as_slice().as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }
    let mut a_aff = blst::blst_p1_affine::default();
    if unsafe { blst::blst_p1_uncompress(&mut a_aff, a_bytes.as_slice().as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }
    let mut b = blst::blst_p2_affine::default();
    if unsafe { blst::blst_p2_uncompress(&mut b, b_bytes.as_slice().as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }
    let mut c = blst::blst_p1_affine::default();
    if unsafe { blst::blst_p1_uncompress(&mut c, c_bytes.as_slice().as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }
    if unsafe {
        blst::blst_p1_affine_is_inf(&alpha)
            || blst::blst_p2_affine_is_inf(&beta)
            || blst::blst_p2_affine_is_inf(&gamma)
            || blst::blst_p2_affine_is_inf(&delta)
            || blst::blst_p1_affine_is_inf(&a_aff)
            || blst::blst_p2_affine_is_inf(&b)
            || blst::blst_p1_affine_is_inf(&c)
    } {
        return false;
    }

    let mut neg_a = blst::blst_p1::default();
    unsafe { blst::blst_p1_from_affine(&mut neg_a, &a_aff) };
    unsafe { blst::blst_p1_cneg(&mut neg_a, true) };
    let mut neg_a_aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut neg_a_aff, &neg_a) };

    let mut ic0_aff = blst::blst_p1_affine::default();
    if unsafe { blst::blst_p1_uncompress(&mut ic0_aff, ic_bytes[0].as_slice().as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }
    let mut k_pub = blst::blst_p1::default();
    unsafe { blst::blst_p1_from_affine(&mut k_pub, &ic0_aff) };

    for (scalar_bin, ic_bin) in input_scalars.iter().zip(ic_bytes.iter().skip(1)) {
        let mut ic_pt = blst::blst_p1_affine::default();
        if unsafe { blst::blst_p1_uncompress(&mut ic_pt, ic_bin.as_slice().as_ptr()) }
            != BLST_ERROR::BLST_SUCCESS
        {
            return false;
        }
        let mut ic_proj = blst::blst_p1::default();
        unsafe { blst::blst_p1_from_affine(&mut ic_proj, &ic_pt) };
        let s = scalar_bin.as_slice();
        let mut term = blst::blst_p1::default();
        unsafe { blst::blst_p1_mult(&mut term, &ic_proj, s.as_ptr(), s.len() * 8) };
        unsafe { blst::blst_p1_add_or_double(&mut k_pub, &k_pub, &term) };
    }
    let mut k_pub_aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut k_pub_aff, &k_pub) };

    let mut ctx = blst::Pairing::new(false, &[]);
    ctx.raw_aggregate(&b, &neg_a_aff);
    ctx.raw_aggregate(&beta, &alpha);
    ctx.raw_aggregate(&gamma, &k_pub_aff);
    ctx.raw_aggregate(&delta, &c);
    ctx.commit();
    ctx.finalverify(None)
}

/// Minimal-pubkey BLS keygen: PK in G1 (48 bytes), SK (32 bytes)
#[rustler::nif]
fn min_pk_keygen<'a>(
    env: Env<'a>,
    ikm_bytes: Binary<'a>,
) -> Result<(Binary<'a>, Binary<'a>), String> {
    let ikm = ikm_bytes.as_slice();
    let sk = bls::SecretKey::key_gen(ikm, &[])
        .map_err(|e| format!("Failed to generate secret key: {:?}", e))?;
    let pk = sk.sk_to_pk();

    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();

    let mut sk_bin = NewBinary::new(env, sk_bytes.len());
    sk_bin.as_mut_slice().copy_from_slice(&sk_bytes);

    let mut pk_bin = NewBinary::new(env, pk_bytes.len());
    pk_bin.as_mut_slice().copy_from_slice(&pk_bytes);

    Ok((pk_bin.into(), sk_bin.into()))
}

/// Minimal-pubkey BLS sign: returns Sig in G2 (96 bytes)
#[rustler::nif]
fn min_pk_sign<'a>(
    env: Env<'a>,
    sk_bytes: Binary<'a>,
    msg_bytes: Binary<'a>,
    dst_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let sk = bls::SecretKey::from_bytes(sk_bytes.as_slice())
        .map_err(|e| format!("Invalid secret key: {:?}", e))?;
    let sig = sk.sign(msg_bytes.as_slice(), dst_bytes.as_slice(), &[]);
    let sig_bytes = sig.to_bytes();

    let mut sig_bin = NewBinary::new(env, sig_bytes.len());
    sig_bin.as_mut_slice().copy_from_slice(&sig_bytes);

    Ok(sig_bin.into())
}

/// Minimal-pubkey BLS verify
#[rustler::nif]
fn min_pk_verify(
    pk_bytes: Binary,
    msg_bytes: Binary,
    sig_bytes: Binary,
    dst_bytes: Binary,
) -> bool {
    let pk = match bls::PublicKey::from_bytes(pk_bytes.as_slice()) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match bls::Signature::from_bytes(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sig.verify(
        true,
        msg_bytes.as_slice(),
        dst_bytes.as_slice(),
        &[],
        &pk,
        true,
    ) == BLST_ERROR::BLST_SUCCESS
}

/// Minimal-pubkey BLS aggregate signatures
#[rustler::nif]
fn min_pk_aggregate<'a>(env: Env<'a>, sigs_bytes: Vec<Binary<'a>>) -> Result<Binary<'a>, String> {
    if sigs_bytes.is_empty() {
        return Err("Empty signature list".into());
    }
    let sigs: Result<Vec<bls::Signature>, String> = sigs_bytes
        .iter()
        .map(|b| {
            bls::Signature::from_bytes(b.as_slice()).map_err(|e| format!("Invalid sig: {:?}", e))
        })
        .collect();
    let sigs = sigs?;
    let sig_refs: Vec<&bls::Signature> = sigs.iter().collect();

    let agg = bls::AggregateSignature::aggregate(&sig_refs, true)
        .map_err(|e| format!("Aggregate failed: {:?}", e))?;
    let agg_sig = agg.to_signature();
    let bytes = agg_sig.to_bytes();

    let mut bin = NewBinary::new(env, bytes.len());
    bin.as_mut_slice().copy_from_slice(&bytes);
    Ok(bin.into())
}

/// Minimal-pubkey BLS fast aggregate verify (all signers signed same message)
#[rustler::nif]
fn min_pk_fast_aggregate_verify(
    pks_bytes: Vec<Binary>,
    msg_bytes: Binary,
    sig_bytes: Binary,
    dst_bytes: Binary,
) -> bool {
    if pks_bytes.is_empty() {
        return false;
    }
    let pks: Result<Vec<bls::PublicKey>, _> = pks_bytes
        .iter()
        .map(|b| bls::PublicKey::from_bytes(b.as_slice()))
        .collect();
    let pks = match pks {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pk_refs: Vec<&bls::PublicKey> = pks.iter().collect();

    let sig = match bls::Signature::from_bytes(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    sig.fast_aggregate_verify(true, msg_bytes.as_slice(), dst_bytes.as_slice(), &pk_refs)
        == BLST_ERROR::BLST_SUCCESS
}

/// Minimal-signature BLS keygen: PK in G2 (96 bytes), SK (32 bytes)
#[rustler::nif]
fn min_sig_keygen<'a>(
    env: Env<'a>,
    ikm_bytes: Binary<'a>,
) -> Result<(Binary<'a>, Binary<'a>), String> {
    let ikm = ikm_bytes.as_slice();
    let sk = bls_ms::SecretKey::key_gen(ikm, &[])
        .map_err(|e| format!("Failed to generate secret key: {:?}", e))?;
    let pk = sk.sk_to_pk();

    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();

    let mut sk_bin = NewBinary::new(env, sk_bytes.len());
    sk_bin.as_mut_slice().copy_from_slice(&sk_bytes);

    let mut pk_bin = NewBinary::new(env, pk_bytes.len());
    pk_bin.as_mut_slice().copy_from_slice(&pk_bytes);

    Ok((pk_bin.into(), sk_bin.into()))
}

/// Minimal-signature BLS sign: returns Sig in G1 (48 bytes)
#[rustler::nif]
fn min_sig_sign<'a>(
    env: Env<'a>,
    sk_bytes: Binary<'a>,
    msg_bytes: Binary<'a>,
    dst_bytes: Binary<'a>,
) -> Result<Binary<'a>, String> {
    let sk = bls_ms::SecretKey::from_bytes(sk_bytes.as_slice())
        .map_err(|e| format!("Invalid secret key: {:?}", e))?;
    let sig = sk.sign(msg_bytes.as_slice(), dst_bytes.as_slice(), &[]);
    let sig_bytes = sig.to_bytes();

    let mut sig_bin = NewBinary::new(env, sig_bytes.len());
    sig_bin.as_mut_slice().copy_from_slice(&sig_bytes);

    Ok(sig_bin.into())
}

/// Minimal-signature BLS verify
#[rustler::nif]
fn min_sig_verify(
    pk_bytes: Binary,
    msg_bytes: Binary,
    sig_bytes: Binary,
    dst_bytes: Binary,
) -> bool {
    let pk = match bls_ms::PublicKey::from_bytes(pk_bytes.as_slice()) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match bls_ms::Signature::from_bytes(sig_bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sig.verify(
        true,
        msg_bytes.as_slice(),
        dst_bytes.as_slice(),
        &[],
        &pk,
        true,
    ) == BLST_ERROR::BLST_SUCCESS
}

/// G1 hash_to_curve (RFC 9380)
#[rustler::nif]
fn g1_hash_to_curve<'a>(
    env: Env<'a>,
    msg_bytes: Binary<'a>,
    dst_bytes: Binary<'a>,
    aug_bytes: Binary<'a>,
) -> Binary<'a> {
    let mut p = blst::blst_p1::default();
    let msg = msg_bytes.as_slice();
    let dst = dst_bytes.as_slice();
    let aug = aug_bytes.as_slice();
    unsafe {
        blst::blst_hash_to_g1(
            &mut p,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            aug.as_ptr(),
            aug.len(),
        )
    };
    let mut aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut aff, &p) };
    let mut comp = [0u8; 48];
    unsafe { blst::blst_p1_affine_compress(comp.as_mut_ptr(), &aff) };
    let mut bin = NewBinary::new(env, 48);
    bin.as_mut_slice().copy_from_slice(&comp);
    bin.into()
}

/// G1 encode_to_curve (RFC 9380)
#[rustler::nif]
fn g1_encode_to_curve<'a>(
    env: Env<'a>,
    msg_bytes: Binary<'a>,
    dst_bytes: Binary<'a>,
    aug_bytes: Binary<'a>,
) -> Binary<'a> {
    let mut p = blst::blst_p1::default();
    let msg = msg_bytes.as_slice();
    let dst = dst_bytes.as_slice();
    let aug = aug_bytes.as_slice();
    unsafe {
        blst::blst_encode_to_g1(
            &mut p,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            aug.as_ptr(),
            aug.len(),
        )
    };
    let mut aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut aff, &p) };
    let mut comp = [0u8; 48];
    unsafe { blst::blst_p1_affine_compress(comp.as_mut_ptr(), &aff) };
    let mut bin = NewBinary::new(env, 48);
    bin.as_mut_slice().copy_from_slice(&comp);
    bin.into()
}

/// G2 hash_to_curve (RFC 9380)
#[rustler::nif]
fn g2_hash_to_curve<'a>(
    env: Env<'a>,
    msg_bytes: Binary<'a>,
    dst_bytes: Binary<'a>,
    aug_bytes: Binary<'a>,
) -> Binary<'a> {
    let mut p = blst::blst_p2::default();
    let msg = msg_bytes.as_slice();
    let dst = dst_bytes.as_slice();
    let aug = aug_bytes.as_slice();
    unsafe {
        blst::blst_hash_to_g2(
            &mut p,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            aug.as_ptr(),
            aug.len(),
        )
    };
    let mut aff = blst::blst_p2_affine::default();
    unsafe { blst::blst_p2_to_affine(&mut aff, &p) };
    let mut comp = [0u8; 96];
    unsafe { blst::blst_p2_affine_compress(comp.as_mut_ptr(), &aff) };
    let mut bin = NewBinary::new(env, 96);
    bin.as_mut_slice().copy_from_slice(&comp);
    bin.into()
}

/// G2 encode_to_curve (RFC 9380)
#[rustler::nif]
fn g2_encode_to_curve<'a>(
    env: Env<'a>,
    msg_bytes: Binary<'a>,
    dst_bytes: Binary<'a>,
    aug_bytes: Binary<'a>,
) -> Binary<'a> {
    let mut p = blst::blst_p2::default();
    let msg = msg_bytes.as_slice();
    let dst = dst_bytes.as_slice();
    let aug = aug_bytes.as_slice();
    unsafe {
        blst::blst_encode_to_g2(
            &mut p,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            aug.as_ptr(),
            aug.len(),
        )
    };
    let mut aff = blst::blst_p2_affine::default();
    unsafe { blst::blst_p2_to_affine(&mut aff, &p) };
    let mut comp = [0u8; 96];
    unsafe { blst::blst_p2_affine_compress(comp.as_mut_ptr(), &aff) };
    let mut bin = NewBinary::new(env, 96);
    bin.as_mut_slice().copy_from_slice(&comp);
    bin.into()
}

/// Internal helper for KZG verification
fn kzg_verify_inner(
    commitment_bytes: &[u8],
    z_bytes: &[u8],
    y_bytes: &[u8],
    proof_bytes: &[u8],
    g2_gen_bytes: &[u8],
    tau_g2_bytes: &[u8],
) -> bool {
    let mut c_aff = blst::blst_p1_affine::default();
    if unsafe { blst::blst_p1_uncompress(&mut c_aff, commitment_bytes.as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }

    let mut proof_aff = blst::blst_p1_affine::default();
    if unsafe { blst::blst_p1_uncompress(&mut proof_aff, proof_bytes.as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }

    let mut g2_gen_aff = blst::blst_p2_affine::default();
    if unsafe { blst::blst_p2_uncompress(&mut g2_gen_aff, g2_gen_bytes.as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }

    let mut tau_g2_aff = blst::blst_p2_affine::default();
    if unsafe { blst::blst_p2_uncompress(&mut tau_g2_aff, tau_g2_bytes.as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }

    // P1 = [y]_1 - C
    let g1_gen = unsafe { *blst::blst_p1_affine_generator() };
    let mut g1_gen_p = blst::blst_p1::default();
    unsafe { blst::blst_p1_from_affine(&mut g1_gen_p, &g1_gen) };

    let mut y_le = y_bytes.to_vec();
    y_le.reverse();
    let mut y_g1 = blst::blst_p1::default();
    unsafe { blst::blst_p1_mult(&mut y_g1, &g1_gen_p, y_le.as_ptr(), y_le.len() * 8) };

    let mut neg_c_p = blst::blst_p1::default();
    unsafe { blst::blst_p1_from_affine(&mut neg_c_p, &c_aff) };
    unsafe { blst::blst_p1_cneg(&mut neg_c_p, true) };

    let mut p1 = blst::blst_p1::default();
    unsafe { blst::blst_p1_add(&mut p1, &y_g1, &neg_c_p) };

    let mut p1_aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut p1_aff, &p1) };

    // Q2 = [tau]_2 - [z]_2
    let mut g2_gen_p = blst::blst_p2::default();
    unsafe { blst::blst_p2_from_affine(&mut g2_gen_p, &g2_gen_aff) };

    let mut z_le = z_bytes.to_vec();
    z_le.reverse();
    let mut z_g2 = blst::blst_p2::default();
    unsafe { blst::blst_p2_mult(&mut z_g2, &g2_gen_p, z_le.as_ptr(), z_le.len() * 8) };

    let mut neg_z_g2 = z_g2;
    unsafe { blst::blst_p2_cneg(&mut neg_z_g2, true) };

    let mut tau_g2_p = blst::blst_p2::default();
    unsafe { blst::blst_p2_from_affine(&mut tau_g2_p, &tau_g2_aff) };

    let mut q2 = blst::blst_p2::default();
    unsafe { blst::blst_p2_add(&mut q2, &tau_g2_p, &neg_z_g2) };

    let mut q2_aff = blst::blst_p2_affine::default();
    unsafe { blst::blst_p2_to_affine(&mut q2_aff, &q2) };

    let mut ctx = blst::Pairing::new(false, &[]);
    ctx.raw_aggregate(&g2_gen_aff, &p1_aff);
    ctx.raw_aggregate(&q2_aff, &proof_aff);
    ctx.commit();
    ctx.finalverify(None)
}

/// KZG proof verification using blst
/// Checks e([y]_1 - C, [1]_2) * e(Proof, [tau]_2 - [z]_2) == 1
#[rustler::nif]
fn kzg_verify(
    commitment_bytes: Binary,
    z_bytes: Binary,
    y_bytes: Binary,
    proof_bytes: Binary,
    g2_gen_bytes: Binary,
    tau_g2_bytes: Binary,
) -> bool {
    kzg_verify_inner(
        commitment_bytes.as_slice(),
        z_bytes.as_slice(),
        y_bytes.as_slice(),
        proof_bytes.as_slice(),
        g2_gen_bytes.as_slice(),
        tau_g2_bytes.as_slice(),
    )
}

/// KZG commitment using blst Pippenger multi-scalar multiplication
#[rustler::nif]
fn kzg_commit<'a>(
    env: Env<'a>,
    points_bytes: Vec<Binary<'a>>,
    scalars_bytes: Vec<Binary<'a>>,
) -> Result<Binary<'a>, String> {
    if points_bytes.len() < scalars_bytes.len() {
        return Err("Degree exceeds SRS points".to_string());
    }
    let n = scalars_bytes.len();
    if n == 0 {
        let mut comp = [0u8; 48];
        comp[0] = 0xc0;
        let mut bin = NewBinary::new(env, 48);
        bin.as_mut_slice().copy_from_slice(&comp);
        return Ok(bin.into());
    }

    let mut affines: Vec<blst::blst_p1_affine> = Vec::with_capacity(n);
    let mut scalars_le: Vec<u8> = Vec::with_capacity(n * 32);

    for (p_bin, s_bin) in points_bytes.iter().take(n).zip(scalars_bytes.iter()) {
        let mut aff = blst::blst_p1_affine::default();
        let err = unsafe { blst::blst_p1_uncompress(&mut aff, p_bin.as_slice().as_ptr()) };
        if err != BLST_ERROR::BLST_SUCCESS {
            return Err(format!("Invalid G1 point in SRS: {:?}", err));
        }
        affines.push(aff);

        let s_slice = s_bin.as_slice();
        let mut s_be = [0u8; 32];
        if s_slice.len() <= 32 {
            s_be[32 - s_slice.len()..].copy_from_slice(s_slice);
        } else {
            return Err("Scalar exceeds 32 bytes".to_string());
        }
        let mut sc = blst::blst_scalar::default();
        unsafe { blst::blst_scalar_from_bendian(&mut sc, s_be.as_ptr()) };
        let mut s_le = [0u8; 32];
        unsafe { blst::blst_lendian_from_scalar(s_le.as_mut_ptr(), &sc) };
        scalars_le.extend_from_slice(&s_le);
    }

    use blst::MultiPoint;
    let out_p = affines.as_slice().mult(&scalars_le, 255);

    let mut out_aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut out_aff, &out_p) };

    let mut comp = [0u8; 48];
    unsafe { blst::blst_p1_affine_compress(comp.as_mut_ptr(), &out_aff) };
    let mut bin = NewBinary::new(env, 48);
    bin.as_mut_slice().copy_from_slice(&comp);
    Ok(bin.into())
}

/// KZG proof creation using blst (evaluation + Ruffini synthetic division + MSM)
#[rustler::nif]
fn kzg_create_proof<'a>(
    env: Env<'a>,
    srs_points_bytes: Vec<Binary<'a>>,
    poly_coeffs_bytes: Vec<Binary<'a>>,
    z_bytes: Binary<'a>,
) -> Result<(Binary<'a>, Binary<'a>), String> {
    let z_slice = z_bytes.as_slice();
    let mut z_be = [0u8; 32];
    if z_slice.len() <= 32 {
        z_be[32 - z_slice.len()..].copy_from_slice(z_slice);
    } else {
        return Err("Z exceeds 32 bytes".to_string());
    }
    let mut z_sc = blst::blst_scalar::default();
    unsafe { blst::blst_scalar_from_bendian(&mut z_sc, z_be.as_ptr()) };
    let mut z_fr = blst::blst_fr::default();
    unsafe { blst::blst_fr_from_scalar(&mut z_fr, &z_sc) };

    let mut poly_fr: Vec<blst::blst_fr> = Vec::with_capacity(poly_coeffs_bytes.len());
    for c_bin in &poly_coeffs_bytes {
        let c_slice = c_bin.as_slice();
        let mut c_be = [0u8; 32];
        if c_slice.len() <= 32 {
            c_be[32 - c_slice.len()..].copy_from_slice(c_slice);
        } else {
            return Err("Coefficient exceeds 32 bytes".to_string());
        }
        let mut sc = blst::blst_scalar::default();
        unsafe { blst::blst_scalar_from_bendian(&mut sc, c_be.as_ptr()) };
        let mut fr = blst::blst_fr::default();
        unsafe { blst::blst_fr_from_scalar(&mut fr, &sc) };
        poly_fr.push(fr);
    }

    while poly_fr.len() > 1 {
        let mut sc = blst::blst_scalar::default();
        unsafe { blst::blst_scalar_from_fr(&mut sc, poly_fr.last().unwrap()) };
        let mut be = [0u8; 32];
        unsafe { blst::blst_bendian_from_scalar(be.as_mut_ptr(), &sc) };
        if be.iter().all(|&b| b == 0) {
            poly_fr.pop();
        } else {
            break;
        }
    }

    let deg = poly_fr.len() - 1;

    let mut y_fr = poly_fr[deg];
    if deg > 0 {
        for i in (0..deg).rev() {
            let mut prod = blst::blst_fr::default();
            unsafe { blst::blst_fr_mul(&mut prod, &y_fr, &z_fr) };
            unsafe { blst::blst_fr_add(&mut y_fr, &prod, &poly_fr[i]) };
        }
    }

    let mut y_sc = blst::blst_scalar::default();
    unsafe { blst::blst_scalar_from_fr(&mut y_sc, &y_fr) };
    let mut y_be = [0u8; 32];
    unsafe { blst::blst_bendian_from_scalar(y_be.as_mut_ptr(), &y_sc) };
    let mut y_bin = NewBinary::new(env, 32);
    y_bin.as_mut_slice().copy_from_slice(&y_be);

    if deg == 0 {
        let mut comp = [0u8; 48];
        comp[0] = 0xc0;
        let mut proof_bin = NewBinary::new(env, 48);
        proof_bin.as_mut_slice().copy_from_slice(&comp);
        return Ok((proof_bin.into(), y_bin.into()));
    }

    if srs_points_bytes.len() < deg {
        return Err("SRS degree insufficient for proof".to_string());
    }

    let mut q_fr: Vec<blst::blst_fr> = vec![blst::blst_fr::default(); deg];
    q_fr[deg - 1] = poly_fr[deg];
    for i in (1..deg).rev() {
        let mut prod = blst::blst_fr::default();
        unsafe { blst::blst_fr_mul(&mut prod, &q_fr[i], &z_fr) };
        unsafe { blst::blst_fr_add(&mut q_fr[i - 1], &poly_fr[i], &prod) };
    }

    let mut affines: Vec<blst::blst_p1_affine> = Vec::with_capacity(deg);
    let mut q_scalars_le: Vec<u8> = Vec::with_capacity(deg * 32);
    for (i, q) in q_fr.iter().enumerate() {
        let mut aff = blst::blst_p1_affine::default();
        let err =
            unsafe { blst::blst_p1_uncompress(&mut aff, srs_points_bytes[i].as_slice().as_ptr()) };
        if err != BLST_ERROR::BLST_SUCCESS {
            return Err(format!("Invalid SRS G1 point: {:?}", err));
        }
        affines.push(aff);

        let mut sc = blst::blst_scalar::default();
        unsafe { blst::blst_scalar_from_fr(&mut sc, q) };
        let mut le = [0u8; 32];
        unsafe { blst::blst_lendian_from_scalar(le.as_mut_ptr(), &sc) };
        q_scalars_le.extend_from_slice(&le);
    }

    use blst::MultiPoint;
    let out_p = affines.as_slice().mult(&q_scalars_le, 255);

    let mut out_aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut out_aff, &out_p) };

    let mut comp = [0u8; 48];
    unsafe { blst::blst_p1_affine_compress(comp.as_mut_ptr(), &out_aff) };
    let mut proof_bin = NewBinary::new(env, 48);
    proof_bin.as_mut_slice().copy_from_slice(&comp);

    Ok((proof_bin.into(), y_bin.into()))
}

/// KZG randomized batch verification using blst
#[rustler::nif]
fn kzg_batch_verify<'a>(
    tuples: Vec<(Binary<'a>, Binary<'a>, Binary<'a>, Binary<'a>)>,
    g2_gen_bytes: Binary<'a>,
    tau_g2_bytes: Binary<'a>,
) -> bool {
    if tuples.is_empty() {
        return true;
    }

    let mut g2_gen_aff = blst::blst_p2_affine::default();
    if unsafe { blst::blst_p2_uncompress(&mut g2_gen_aff, g2_gen_bytes.as_slice().as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }

    let mut tau_g2_aff = blst::blst_p2_affine::default();
    if unsafe { blst::blst_p2_uncompress(&mut tau_g2_aff, tau_g2_bytes.as_slice().as_ptr()) }
        != BLST_ERROR::BLST_SUCCESS
    {
        return false;
    }

    let mut gamma_bytes = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut gamma_bytes);
    } else {
        gamma_bytes[0] = 0x5a;
        gamma_bytes[15] = 0xa5;
    }
    if gamma_bytes.iter().all(|&b| b == 0) {
        gamma_bytes[0] = 1;
    }

    let mut gamma_be = [0u8; 32];
    gamma_be[16..32].copy_from_slice(&gamma_bytes);
    let mut gamma_sc = blst::blst_scalar::default();
    unsafe { blst::blst_scalar_from_bendian(&mut gamma_sc, gamma_be.as_ptr()) };
    let mut gamma_fr = blst::blst_fr::default();
    unsafe { blst::blst_fr_from_scalar(&mut gamma_fr, &gamma_sc) };

    let mut weight_sc = blst::blst_scalar::default();
    let mut one_be = [0u8; 32];
    one_be[31] = 1;
    unsafe { blst::blst_scalar_from_bendian(&mut weight_sc, one_be.as_ptr()) };
    let mut weight_fr = blst::blst_fr::default();
    unsafe { blst::blst_fr_from_scalar(&mut weight_fr, &weight_sc) };

    let g1_gen = unsafe { *blst::blst_p1_affine_generator() };
    let mut g1_gen_p = blst::blst_p1::default();
    unsafe { blst::blst_p1_from_affine(&mut g1_gen_p, &g1_gen) };

    let mut p_total = blst::blst_p1::default();
    let mut pi_total = blst::blst_p1::default();

    for (c_bin, z_bin, y_bin, proof_bin) in &tuples {
        let mut c_aff = blst::blst_p1_affine::default();
        if unsafe { blst::blst_p1_uncompress(&mut c_aff, c_bin.as_slice().as_ptr()) }
            != BLST_ERROR::BLST_SUCCESS
        {
            return false;
        }

        let mut pi_aff = blst::blst_p1_affine::default();
        if unsafe { blst::blst_p1_uncompress(&mut pi_aff, proof_bin.as_slice().as_ptr()) }
            != BLST_ERROR::BLST_SUCCESS
        {
            return false;
        }

        let mut z_sc = blst::blst_scalar::default();
        if !unsafe {
            blst::blst_scalar_from_be_bytes(
                &mut z_sc,
                z_bin.as_slice().as_ptr(),
                z_bin.as_slice().len(),
            )
        } {
            return false;
        }
        let mut y_sc = blst::blst_scalar::default();
        if !unsafe {
            blst::blst_scalar_from_be_bytes(
                &mut y_sc,
                y_bin.as_slice().as_ptr(),
                y_bin.as_slice().len(),
            )
        } {
            return false;
        }

        let mut z_fr = blst::blst_fr::default();
        unsafe { blst::blst_fr_from_scalar(&mut z_fr, &z_sc) };
        let mut y_fr = blst::blst_fr::default();
        unsafe { blst::blst_fr_from_scalar(&mut y_fr, &y_sc) };

        let mut wy_fr = blst::blst_fr::default();
        unsafe { blst::blst_fr_mul(&mut wy_fr, &weight_fr, &y_fr) };
        let mut wy_sc = blst::blst_scalar::default();
        unsafe { blst::blst_scalar_from_fr(&mut wy_sc, &wy_fr) };
        let mut wy_le = [0u8; 32];
        unsafe { blst::blst_lendian_from_scalar(wy_le.as_mut_ptr(), &wy_sc) };

        let mut term_y = blst::blst_p1::default();
        unsafe { blst::blst_p1_mult(&mut term_y, &g1_gen_p, wy_le.as_ptr(), 255) };

        let mut w_sc = blst::blst_scalar::default();
        unsafe { blst::blst_scalar_from_fr(&mut w_sc, &weight_fr) };
        let mut w_le = [0u8; 32];
        unsafe { blst::blst_lendian_from_scalar(w_le.as_mut_ptr(), &w_sc) };

        let mut c_p = blst::blst_p1::default();
        unsafe { blst::blst_p1_from_affine(&mut c_p, &c_aff) };
        let mut term_c = blst::blst_p1::default();
        unsafe { blst::blst_p1_mult(&mut term_c, &c_p, w_le.as_ptr(), 255) };
        unsafe { blst::blst_p1_cneg(&mut term_c, true) };

        let mut wz_fr = blst::blst_fr::default();
        unsafe { blst::blst_fr_mul(&mut wz_fr, &weight_fr, &z_fr) };
        let mut wz_sc = blst::blst_scalar::default();
        unsafe { blst::blst_scalar_from_fr(&mut wz_sc, &wz_fr) };
        let mut wz_le = [0u8; 32];
        unsafe { blst::blst_lendian_from_scalar(wz_le.as_mut_ptr(), &wz_sc) };

        let mut pi_p = blst::blst_p1::default();
        unsafe { blst::blst_p1_from_affine(&mut pi_p, &pi_aff) };
        let mut term_z_pi = blst::blst_p1::default();
        unsafe { blst::blst_p1_mult(&mut term_z_pi, &pi_p, wz_le.as_ptr(), 255) };
        unsafe { blst::blst_p1_cneg(&mut term_z_pi, true) };

        unsafe { blst::blst_p1_add(&mut p_total, &p_total, &term_y) };
        unsafe { blst::blst_p1_add(&mut p_total, &p_total, &term_c) };
        unsafe { blst::blst_p1_add(&mut p_total, &p_total, &term_z_pi) };

        let mut term_pi = blst::blst_p1::default();
        unsafe { blst::blst_p1_mult(&mut term_pi, &pi_p, w_le.as_ptr(), 255) };
        unsafe { blst::blst_p1_add(&mut pi_total, &pi_total, &term_pi) };

        let mut next_w = blst::blst_fr::default();
        unsafe { blst::blst_fr_mul(&mut next_w, &weight_fr, &gamma_fr) };
        weight_fr = next_w;
    }

    let mut p_total_aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut p_total_aff, &p_total) };

    let mut pi_total_aff = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut pi_total_aff, &pi_total) };

    let mut ctx = blst::Pairing::new(false, &[]);
    ctx.raw_aggregate(&g2_gen_aff, &p_total_aff);
    ctx.raw_aggregate(&tau_g2_aff, &pi_total_aff);
    ctx.commit();
    ctx.finalverify(None)
}

/// EIP-4844 Point Evaluation verification using blst
#[rustler::nif]
fn kzg_eip4844_point_eval(input: Binary, g2_gen_bytes: Binary, tau_g2_bytes: Binary) -> bool {
    let s = input.as_slice();
    if s.len() != 192 {
        return false;
    }

    let versioned_hash = &s[0..32];
    let z_bytes = &s[32..64];
    let y_bytes = &s[64..96];
    let commitment_bytes = &s[96..144];
    let proof_bytes = &s[144..192];

    let mut sha = [0u8; 32];
    unsafe { blst::blst_sha256(sha.as_mut_ptr(), commitment_bytes.as_ptr(), 48) };
    if versioned_hash[0] != 0x01 || &versioned_hash[1..32] != &sha[1..32] {
        return false;
    }

    let mut z_sc = blst::blst_scalar::default();
    if !unsafe { blst::blst_scalar_from_be_bytes(&mut z_sc, z_bytes.as_ptr(), 32) } {
        return false;
    }
    let mut y_sc = blst::blst_scalar::default();
    if !unsafe { blst::blst_scalar_from_be_bytes(&mut y_sc, y_bytes.as_ptr(), 32) } {
        return false;
    }

    kzg_verify_inner(
        commitment_bytes,
        z_bytes,
        y_bytes,
        proof_bytes,
        g2_gen_bytes.as_slice(),
        tau_g2_bytes.as_slice(),
    )
}

rustler::init!("ecu_bls12_381_nif");
