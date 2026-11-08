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

rustler::init!("ecu_bls12_381_nif");
