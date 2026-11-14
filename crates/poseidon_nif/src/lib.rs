mod bls12_381_params;

use ark_bls12_381::Fr as FrBls;
use ark_bn254::Fr as FrBn;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use rustler::{Atom, Binary, Env, types::binary::NewBinary};

rustler::atoms! {
    ok,
    error,
    badarg,
    bls12_381,
    bn254,
}

#[rustler::nif]
fn is_available() -> bool {
    true
}

fn exp5<F: Field>(x: F) -> F {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

fn poseidon_bls12_381(inputs: &[&[u8; 32]]) -> Result<[u8; 32], ()> {
    let t = inputs.len() + 1;
    if t < 2 || t > 9 {
        return Err(());
    }

    let ark_bytes = bls12_381_params::get_params_c(t).ok_or(())?;
    let mds_bytes = bls12_381_params::get_params_m_flat(t).ok_or(())?;

    let rf = bls12_381_params::NROUNDSF;
    let rp = bls12_381_params::NROUNDSP[t - 2];
    let total_rounds = rf + rp;

    // Convert inputs to FrBls, checking they are within field modulus
    let mut state: Vec<FrBls> = Vec::with_capacity(t);
    state.push(FrBls::zero());

    for in_bytes in inputs {
        let fr = FrBls::from_be_bytes_mod_order(*in_bytes);
        // Verify canonical representation (< modulus)
        if &fr.into_bigint().to_bytes_be() != *in_bytes {
            return Err(());
        }
        state.push(fr);
    }

    // Convert MDS matrix to FrBls
    let mds: Vec<Vec<FrBls>> = mds_bytes
        .iter()
        .map(|row| {
            row.iter()
                .map(|b| FrBls::from_be_bytes_mod_order(b))
                .collect()
        })
        .collect();

    // Convert round constants to FrBls
    let ark: Vec<FrBls> = ark_bytes
        .iter()
        .map(|b| FrBls::from_be_bytes_mod_order(b))
        .collect();

    let half_rf = rf / 2;

    for r in 0..total_rounds {
        // 1. Add Round Constants (ARK)
        for i in 0..t {
            state[i] += ark[r * t + i];
        }

        // 2. S-Box
        let is_full = r < half_rf || r >= half_rf + rp;
        if is_full {
            for i in 0..t {
                state[i] = exp5(state[i]);
            }
        } else {
            state[0] = exp5(state[0]);
        }

        // 3. Mix
        let mut next_state = vec![FrBls::zero(); t];
        for i in 0..t {
            let mut acc = FrBls::zero();
            for j in 0..t {
                acc += mds[i][j] * state[j];
            }
            next_state[i] = acc;
        }
        state = next_state;
    }

    let out_bytes = state[0].into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out.copy_from_slice(&out_bytes);
    Ok(out)
}

fn poseidon_bn254(inputs: &[&[u8; 32]]) -> Result<[u8; 32], ()> {
    let nr_inputs = inputs.len();
    if nr_inputs < 1 || nr_inputs > 12 {
        return Err(());
    }

    // Verify canonical representation (< modulus)
    for in_bytes in inputs {
        let fr = FrBn::from_be_bytes_mod_order(*in_bytes);
        if &fr.into_bigint().to_bytes_be() != *in_bytes {
            return Err(());
        }
    }

    let mut hasher = Poseidon::<FrBn>::new_circom(nr_inputs).map_err(|_| ())?;
    let slice_refs: Vec<&[u8]> = inputs.iter().map(|b| &b[..]).collect();
    hasher.hash_bytes_be(&slice_refs).map_err(|_| ())
}

#[rustler::nif]
fn hash<'a>(env: Env<'a>, curve: Atom, inputs: Vec<Binary>) -> Result<Binary<'a>, Atom> {
    let mut in_arrays = Vec::with_capacity(inputs.len());
    for bin in &inputs {
        if bin.len() != 32 {
            return Err(badarg());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bin.as_slice());
        in_arrays.push(arr);
    }
    let in_refs: Vec<&[u8; 32]> = in_arrays.iter().collect();

    let res = if curve == bls12_381() {
        poseidon_bls12_381(&in_refs)
    } else if curve == bn254() {
        poseidon_bn254(&in_refs)
    } else {
        return Err(badarg());
    };

    match res {
        Ok(out) => {
            let mut bin = NewBinary::new(env, 32);
            bin.as_mut_slice().copy_from_slice(&out);
            Ok(bin.into())
        }
        Err(()) => Err(badarg()),
    }
}

#[rustler::nif]
fn hash3<'a>(env: Env<'a>, curve: Atom, a: Binary, b: Binary) -> Result<Binary<'a>, Atom> {
    if a.len() != 32 || b.len() != 32 {
        return Err(badarg());
    }
    let mut arr_a = [0u8; 32];
    let mut arr_b = [0u8; 32];
    arr_a.copy_from_slice(a.as_slice());
    arr_b.copy_from_slice(b.as_slice());

    let in_refs = [&arr_a, &arr_b];

    let res = if curve == bls12_381() {
        poseidon_bls12_381(&in_refs)
    } else if curve == bn254() {
        poseidon_bn254(&in_refs)
    } else {
        return Err(badarg());
    };

    match res {
        Ok(out) => {
            let mut bin = NewBinary::new(env, 32);
            bin.as_mut_slice().copy_from_slice(&out);
            Ok(bin.into())
        }
        Err(()) => Err(badarg()),
    }
}

rustler::init!("ecu_poseidon_nif");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls12_381_hash3_aeu_match() {
        // aeu_poseidon:hash3(1, 2)
        // Expected: 0x28cf112a14e976643aeec440f89bf94f61f74421b96a40a82efd978a3f89078a
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 1;
        b[31] = 2;

        let res = poseidon_bls12_381(&[&a, &b]).unwrap();
        let expected_hex = "28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a";
        let mut expected = [0u8; 32];
        for i in 0..32 {
            expected[i] = u8::from_str_radix(&expected_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(res, expected);
    }

    #[test]
    fn test_bn254_circom_match() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 1;
        b[31] = 2;

        let res = poseidon_bn254(&[&a, &b]).unwrap();
        let expected = [
            17, 92, 192, 245, 231, 214, 144, 65, 61, 246, 76, 107, 150, 98, 233, 207, 42, 54, 23,
            242, 116, 50, 69, 81, 158, 25, 96, 122, 68, 23, 24, 154,
        ];
        assert_eq!(res, expected);
    }
}
