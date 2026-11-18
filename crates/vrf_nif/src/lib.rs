use rustler::{Atom, Binary, Env, types::binary::NewBinary};
use secp256kfun::{KeyPair, Point, Scalar};
use sha2::Digest;
use sigma_fun::generic_array::typenum::U16;
use vrf_fun::{VrfProof, rfc9381};
use vrf_rfc9381::{
    Proof, Prover, Verifier,
    ec::edwards25519::{
        EdVrfProof,
        elligator2::{EdVrfEdwards25519Ell2PublicKey, EdVrfEdwards25519Ell2SecretKey},
        tai::{EdVrfEdwards25519TaiPublicKey, EdVrfEdwards25519TaiSecretKey},
    },
};

rustler::atoms! {
    ok,
    error,
    badarg,
    verification_failed,
    unsupported_suite,
}

#[rustler::nif]
fn is_available_nif() -> bool {
    true
}

#[rustler::nif]
fn prove_nif<'a>(env: Env<'a>, suite: &str, sk: Binary, alpha: Binary) -> Result<Binary<'a>, Atom> {
    match suite {
        "edwards25519_sha512_ell2" => {
            let sk_obj =
                EdVrfEdwards25519Ell2SecretKey::from_slice(sk.as_slice()).map_err(|_| badarg())?;
            let proof = sk_obj.prove(alpha.as_slice()).map_err(|_| badarg())?;
            let pi_bytes = proof.encode_to_pi();
            let mut bin = NewBinary::new(env, pi_bytes.len());
            bin.as_mut_slice().copy_from_slice(&pi_bytes);
            Ok(bin.into())
        }
        "edwards25519_sha512_tai" => {
            let sk_obj =
                EdVrfEdwards25519TaiSecretKey::from_slice(sk.as_slice()).map_err(|_| badarg())?;
            let proof = sk_obj.prove(alpha.as_slice()).map_err(|_| badarg())?;
            let pi_bytes = proof.encode_to_pi();
            let mut bin = NewBinary::new(env, pi_bytes.len());
            bin.as_mut_slice().copy_from_slice(&pi_bytes);
            Ok(bin.into())
        }
        "secp256k1_sha256_tai" => {
            let sk_bytes: &[u8; 32] = sk.as_slice().try_into().map_err(|_| badarg())?;
            let sk_scalar = Scalar::from_bytes_mod_order(*sk_bytes)
                .non_zero()
                .ok_or_else(badarg)?;
            let kp = KeyPair::new(sk_scalar);
            let pk = kp.public_key();
            let pk_bytes = pk.to_bytes();
            let h = Point::hash_to_curve_rfc9381_tai::<sha2::Sha256>(alpha.as_slice(), &pk_bytes);
            let vrf = rfc9381::Rfc9381TaiVrf::<sha2::Sha256>::default();
            let proof = vrf.prove(&kp, h.normalize());
            let encoded = bincode::encode_to_vec(&proof, bincode::config::standard())
                .map_err(|_| badarg())?;
            let mut bin = NewBinary::new(env, encoded.len());
            bin.as_mut_slice().copy_from_slice(&encoded);
            Ok(bin.into())
        }
        _ => Err(unsupported_suite()),
    }
}

#[rustler::nif]
fn verify_nif<'a>(
    env: Env<'a>,
    suite: &str,
    pk: Binary,
    pi: Binary,
    alpha: Binary,
) -> Result<Binary<'a>, Atom> {
    match suite {
        "edwards25519_sha512_ell2" => {
            let pk_obj =
                EdVrfEdwards25519Ell2PublicKey::from_slice(pk.as_slice()).map_err(|_| badarg())?;
            let proof = EdVrfProof::decode_pi(pi.as_slice()).map_err(|_| badarg())?;
            let beta = pk_obj
                .verify(alpha.as_slice(), proof)
                .map_err(|_| verification_failed())?;
            let mut bin = NewBinary::new(env, beta.len());
            bin.as_mut_slice().copy_from_slice(&beta);
            Ok(bin.into())
        }
        "edwards25519_sha512_tai" => {
            let pk_obj =
                EdVrfEdwards25519TaiPublicKey::from_slice(pk.as_slice()).map_err(|_| badarg())?;
            let proof = EdVrfProof::decode_pi(pi.as_slice()).map_err(|_| badarg())?;
            let beta = pk_obj
                .verify(alpha.as_slice(), proof)
                .map_err(|_| verification_failed())?;
            let mut bin = NewBinary::new(env, beta.len());
            bin.as_mut_slice().copy_from_slice(&beta);
            Ok(bin.into())
        }
        "secp256k1_sha256_tai" => {
            let pk_bytes: &[u8; 33] = pk.as_slice().try_into().map_err(|_| badarg())?;
            let pk_pt = Point::from_bytes(*pk_bytes).ok_or_else(badarg)?;
            let (proof, len): (VrfProof<U16>, usize) =
                bincode::decode_from_slice(pi.as_slice(), bincode::config::standard())
                    .map_err(|_| badarg())?;
            if len != pi.len() {
                return Err(badarg());
            }
            let h =
                Point::hash_to_curve_rfc9381_tai::<sha2::Sha256>(alpha.as_slice(), pk.as_slice());
            let vrf = rfc9381::Rfc9381TaiVrf::<sha2::Sha256>::default();
            let verified = vrf
                .verify(pk_pt, h.normalize(), &proof)
                .ok_or_else(verification_failed)?;
            let beta = rfc9381::tai::output::<sha2::Sha256>(verified);
            let mut bin = NewBinary::new(env, beta.len());
            bin.as_mut_slice().copy_from_slice(&beta);
            Ok(bin.into())
        }
        _ => Err(unsupported_suite()),
    }
}

#[rustler::nif]
fn proof_to_hash_nif<'a>(env: Env<'a>, suite: &str, pi: Binary) -> Result<Binary<'a>, Atom> {
    match suite {
        "edwards25519_sha512_ell2" => {
            let proof = EdVrfProof::decode_pi(pi.as_slice()).map_err(|_| badarg())?;
            let beta = proof
                .proof_to_hash(vrf_rfc9381::Ciphersuite::ECVRF_EDWARDS25519_SHA512_ELL2)
                .map_err(|_| badarg())?;
            let mut bin = NewBinary::new(env, beta.len());
            bin.as_mut_slice().copy_from_slice(&beta);
            Ok(bin.into())
        }
        "edwards25519_sha512_tai" => {
            let proof = EdVrfProof::decode_pi(pi.as_slice()).map_err(|_| badarg())?;
            let beta = proof
                .proof_to_hash(vrf_rfc9381::Ciphersuite::ECVRF_EDWARDS25519_SHA512_TAI)
                .map_err(|_| badarg())?;
            let mut bin = NewBinary::new(env, beta.len());
            bin.as_mut_slice().copy_from_slice(&beta);
            Ok(bin.into())
        }
        "secp256k1_sha256_tai" => {
            let (proof, len): (VrfProof<U16>, usize) =
                bincode::decode_from_slice(pi.as_slice(), bincode::config::standard())
                    .map_err(|_| badarg())?;
            if len != pi.len() {
                return Err(badarg());
            }
            let gamma = proof.dangerously_access_gamma_without_verifying();
            let mut hasher = sha2::Sha256::new();
            hasher.update(&[0xFE, 0x03]);
            hasher.update(gamma.to_bytes().as_ref());
            hasher.update(&[0x00]);
            let beta = hasher.finalize();
            let mut bin = NewBinary::new(env, beta.len());
            bin.as_mut_slice().copy_from_slice(&beta);
            Ok(bin.into())
        }
        _ => Err(unsupported_suite()),
    }
}

rustler::init!("ecu_vrf_nif");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_vrf_bincode() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]).non_zero().unwrap();
        let kp = KeyPair::new(sk);
        let alpha = b"test message";
        let h =
            Point::hash_to_curve_rfc9381_tai::<sha2::Sha256>(alpha, &kp.public_key().to_bytes());
        let vrf = rfc9381::Rfc9381TaiVrf::<sha2::Sha256>::default();
        let proof = vrf.prove(&kp, h.normalize());
        let encoded = bincode::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        assert_eq!(encoded.len(), 81);
        let (decoded, len): (VrfProof<U16>, usize) =
            bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(len, 81);
        let verified = vrf
            .verify(kp.public_key(), h.normalize(), &decoded)
            .unwrap();
        let beta = rfc9381::tai::output::<sha2::Sha256>(verified);
        assert_eq!(beta.len(), 32);
    }

    #[test]
    fn test_ed25519_ell2_and_tai() {
        let sk_bytes = [9u8; 32];
        let alpha = b"test message";

        // Elligator 2
        let sk_ell2 = EdVrfEdwards25519Ell2SecretKey::from_slice(&sk_bytes).unwrap();
        let pk_ell2 = sk_ell2.verifier();
        let proof_ell2 = sk_ell2.prove(alpha).unwrap();
        let pi_ell2 = proof_ell2.encode_to_pi();
        assert_eq!(pi_ell2.len(), 80);
        let decoded_proof = EdVrfProof::decode_pi(&pi_ell2).unwrap();
        let beta_ell2 = pk_ell2.verify(alpha, decoded_proof).unwrap();
        assert_eq!(beta_ell2.len(), 64);

        // Try-and-Increment
        let sk_tai = EdVrfEdwards25519TaiSecretKey::from_slice(&sk_bytes).unwrap();
        let pk_tai = sk_tai.verifier();
        let proof_tai = sk_tai.prove(alpha).unwrap();
        let pi_tai = proof_tai.encode_to_pi();
        assert_eq!(pi_tai.len(), 80);
        let decoded_proof_tai = EdVrfProof::decode_pi(&pi_tai).unwrap();
        let beta_tai = pk_tai.verify(alpha, decoded_proof_tai).unwrap();
        assert_eq!(beta_tai.len(), 64);
    }
}
