use musig2::secp::{MaybeScalar, Point, Scalar};
use musig2::secp256k1::{PublicKey, SecretKey};
use musig2::{
    AggNonce, BinaryEncoding, CompactSignature, KeyAggContext, PartialSignature, PubNonce,
    SecNonce, SecNonceBuilder,
};
use rustler::{Binary, Env, NewBinary};

#[rustler::nif]
fn is_loaded() -> bool {
    true
}

#[rustler::nif]
fn key_agg_nif<'a>(
    env: Env<'a>,
    pubkeys_bin: Vec<Binary>,
) -> Result<(Binary<'a>, Binary<'a>), rustler::Error> {
    let mut pks = Vec::with_capacity(pubkeys_bin.len());
    for b in pubkeys_bin {
        let pk = match b.len() {
            33 => Point::from_slice(b.as_slice()).map_err(|_| rustler::Error::BadArg)?,
            32 => {
                let mut comp = [0u8; 33];
                comp[0] = 0x02;
                comp[1..33].copy_from_slice(b.as_slice());
                Point::from_slice(&comp).map_err(|_| rustler::Error::BadArg)?
            }
            _ => return Err(rustler::Error::BadArg),
        };
        pks.push(pk);
    }

    let ctx = KeyAggContext::new(pks).map_err(|_| rustler::Error::BadArg)?;
    let agg_pk: PublicKey = ctx.aggregated_pubkey();
    let agg_pk_bytes = agg_pk.serialize();

    let mut out_pk = NewBinary::new(env, 32);
    out_pk.as_mut_slice().copy_from_slice(&agg_pk_bytes[1..33]);

    let ctx_bytes = ctx.to_bytes();
    let mut out_ctx = NewBinary::new(env, ctx_bytes.len());
    out_ctx.as_mut_slice().copy_from_slice(&ctx_bytes);

    Ok((out_pk.into(), out_ctx.into()))
}

#[rustler::nif]
fn nonce_gen_nif<'a>(
    env: Env<'a>,
    seckey_bin: Binary,
    opt_msg: Binary,
) -> Result<(Binary<'a>, Binary<'a>), rustler::Error> {
    let key_bytes: &[u8; 32] = seckey_bin
        .as_slice()
        .try_into()
        .map_err(|_| rustler::Error::BadArg)?;
    let seckey = SecretKey::from_byte_array(*key_bytes).map_err(|_| rustler::Error::BadArg)?;
    let pubkey = seckey.public_key(&musig2::secp256k1::Secp256k1::new());
    let pt = Point::from_slice(&pubkey.serialize()).map_err(|_| rustler::Error::BadArg)?;

    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut seed);
    let mut builder = SecNonceBuilder::from_pubkey(seed, pt);

    let msg_slice = opt_msg.as_slice();
    if !msg_slice.is_empty() {
        builder = builder.with_message(&msg_slice);
    }

    let secnonce: SecNonce = builder.build();
    let pubnonce: PubNonce = secnonce.public_nonce();

    let sec_bytes = secnonce.to_bytes();
    let pub_bytes = pubnonce.to_bytes();

    let mut out_sec = NewBinary::new(env, sec_bytes.len());
    out_sec.as_mut_slice().copy_from_slice(&sec_bytes);

    let mut out_pub = NewBinary::new(env, pub_bytes.len());
    out_pub.as_mut_slice().copy_from_slice(&pub_bytes);

    Ok((out_sec.into(), out_pub.into()))
}

#[rustler::nif]
fn nonce_agg_nif<'a>(
    env: Env<'a>,
    pubnonces_bin: Vec<Binary>,
) -> Result<Binary<'a>, rustler::Error> {
    let mut pnonces = Vec::with_capacity(pubnonces_bin.len());
    for b in pubnonces_bin {
        let pn = PubNonce::from_bytes(b.as_slice()).map_err(|_| rustler::Error::BadArg)?;
        pnonces.push(pn);
    }

    let aggnonce: AggNonce = AggNonce::sum(&pnonces);
    let agg_bytes = aggnonce.to_bytes();

    let mut out_agg = NewBinary::new(env, agg_bytes.len());
    out_agg.as_mut_slice().copy_from_slice(&agg_bytes);

    Ok(out_agg.into())
}

#[rustler::nif]
fn sign_nif<'a>(
    env: Env<'a>,
    ctx_bin: Binary,
    seckey_bin: Binary,
    secnonce_bin: Binary,
    aggnonce_bin: Binary,
    msg_bin: Binary,
) -> Result<Binary<'a>, rustler::Error> {
    let ctx = KeyAggContext::from_bytes(ctx_bin.as_slice()).map_err(|_| rustler::Error::BadArg)?;
    let key_bytes: &[u8; 32] = seckey_bin
        .as_slice()
        .try_into()
        .map_err(|_| rustler::Error::BadArg)?;
    let scalar = Scalar::from_slice(key_bytes).map_err(|_| rustler::Error::BadArg)?;
    let secnonce =
        SecNonce::from_bytes(secnonce_bin.as_slice()).map_err(|_| rustler::Error::BadArg)?;
    let aggnonce =
        AggNonce::from_bytes(aggnonce_bin.as_slice()).map_err(|_| rustler::Error::BadArg)?;

    let psig: PartialSignature =
        musig2::sign_partial(&ctx, scalar, secnonce, &aggnonce, msg_bin.as_slice())
            .map_err(|_| rustler::Error::BadArg)?;

    let psig_bytes = psig.serialize();
    let mut out_psig = NewBinary::new(env, psig_bytes.len());
    out_psig.as_mut_slice().copy_from_slice(&psig_bytes);

    Ok(out_psig.into())
}

#[rustler::nif]
fn verify_nif(
    ctx_bin: Binary,
    psig_bin: Binary,
    pubnonce_bin: Binary,
    signer_pk_bin: Binary,
    aggnonce_bin: Binary,
    msg_bin: Binary,
) -> bool {
    let Ok(ctx) = KeyAggContext::from_bytes(ctx_bin.as_slice()) else {
        return false;
    };
    let Ok(psig) = MaybeScalar::from_slice(psig_bin.as_slice()) else {
        return false;
    };
    let Ok(pubnonce) = PubNonce::from_bytes(pubnonce_bin.as_slice()) else {
        return false;
    };
    let Ok(signer_pk) = (match signer_pk_bin.len() {
        33 => Point::from_slice(signer_pk_bin.as_slice()),
        32 => {
            let mut comp = [0u8; 33];
            comp[0] = 0x02;
            comp[1..33].copy_from_slice(signer_pk_bin.as_slice());
            Point::from_slice(&comp)
        }
        _ => return false,
    }) else {
        return false;
    };
    let Ok(aggnonce) = AggNonce::from_bytes(aggnonce_bin.as_slice()) else {
        return false;
    };

    musig2::verify_partial(
        &ctx,
        psig,
        &aggnonce,
        signer_pk,
        &pubnonce,
        msg_bin.as_slice(),
    )
    .is_ok()
}

#[rustler::nif]
fn aggregate_nif<'a>(
    env: Env<'a>,
    ctx_bin: Binary,
    aggnonce_bin: Binary,
    msg_bin: Binary,
    psigs_bin: Vec<Binary>,
) -> Result<Binary<'a>, rustler::Error> {
    let ctx = KeyAggContext::from_bytes(ctx_bin.as_slice()).map_err(|_| rustler::Error::BadArg)?;
    let aggnonce =
        AggNonce::from_bytes(aggnonce_bin.as_slice()).map_err(|_| rustler::Error::BadArg)?;

    let mut psigs = Vec::with_capacity(psigs_bin.len());
    for b in psigs_bin {
        let ps = MaybeScalar::from_slice(b.as_slice()).map_err(|_| rustler::Error::BadArg)?;
        psigs.push(ps);
    }

    let final_sig: CompactSignature =
        musig2::aggregate_partial_signatures(&ctx, &aggnonce, psigs, msg_bin.as_slice())
            .map_err(|_| rustler::Error::BadArg)?;

    let sig_bytes = final_sig.to_bytes();
    let mut out_sig = NewBinary::new(env, sig_bytes.len());
    out_sig.as_mut_slice().copy_from_slice(&sig_bytes);

    Ok(out_sig.into())
}

rustler::init!("ecu_musig2_nif");
