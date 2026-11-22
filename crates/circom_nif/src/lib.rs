use num_bigint::BigUint;
use num_traits::Zero;
use r1cs_file::R1csFile;
use rustler::{Binary, Env, NewBinary, NifMap};
use std::io::Cursor;
use wtns_file::WtnsFile;

#[rustler::nif]
fn is_available() -> bool {
    true
}

#[derive(NifMap)]
pub struct R1csHeaderInfo<'a> {
    pub prime: Binary<'a>,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prvt_in: u32,
    pub n_labels: u64,
    pub n_constraints: u32,
}

#[derive(NifMap)]
pub struct WtnsHeaderInfo<'a> {
    pub prime: Binary<'a>,
    pub witness_len: u32,
}

#[rustler::nif]
fn r1cs_info<'a>(env: Env<'a>, bin: Binary<'a>) -> Result<R1csHeaderInfo<'a>, String> {
    let mut cursor = Cursor::new(bin.as_slice());
    let r1cs =
        R1csFile::<32>::read(&mut cursor).map_err(|e| format!("r1cs parse error: {:?}", e))?;

    let mut prime_bin = NewBinary::new(env, 32);
    let mut p_bytes = *r1cs.header.prime;
    p_bytes.reverse();
    prime_bin.as_mut_slice().copy_from_slice(&p_bytes);

    Ok(R1csHeaderInfo {
        prime: prime_bin.into(),
        n_wires: r1cs.header.n_wires,
        n_pub_out: r1cs.header.n_pub_out,
        n_pub_in: r1cs.header.n_pub_in,
        n_prvt_in: r1cs.header.n_prvt_in,
        n_labels: r1cs.header.n_labels,
        n_constraints: r1cs.header.n_constraints,
    })
}

#[rustler::nif]
fn wtns_info<'a>(env: Env<'a>, bin: Binary<'a>) -> Result<WtnsHeaderInfo<'a>, String> {
    let mut cursor = Cursor::new(bin.as_slice());
    let wtns =
        WtnsFile::<32>::read(&mut cursor).map_err(|e| format!("wtns parse error: {:?}", e))?;

    let mut prime_bin = NewBinary::new(env, 32);
    let mut p_bytes = *wtns.header.prime;
    p_bytes.reverse();
    prime_bin.as_mut_slice().copy_from_slice(&p_bytes);

    Ok(WtnsHeaderInfo {
        prime: prime_bin.into(),
        witness_len: wtns.header.witness_len,
    })
}

#[rustler::nif]
fn r1cs_roundtrip<'a>(env: Env<'a>, bin: Binary<'a>) -> Result<Binary<'a>, String> {
    let mut cursor = Cursor::new(bin.as_slice());
    let r1cs =
        R1csFile::<32>::read(&mut cursor).map_err(|e| format!("r1cs read error: {:?}", e))?;

    let mut out = Vec::new();
    r1cs.write(&mut out)
        .map_err(|e| format!("r1cs write error: {:?}", e))?;

    let mut res = NewBinary::new(env, out.len());
    res.as_mut_slice().copy_from_slice(&out);
    Ok(res.into())
}

#[rustler::nif]
fn wtns_roundtrip<'a>(env: Env<'a>, bin: Binary<'a>) -> Result<Binary<'a>, String> {
    let mut cursor = Cursor::new(bin.as_slice());
    let wtns =
        WtnsFile::<32>::read(&mut cursor).map_err(|e| format!("wtns read error: {:?}", e))?;

    let mut out = Vec::new();
    wtns.write(&mut out)
        .map_err(|e| format!("wtns write error: {:?}", e))?;

    let mut res = NewBinary::new(env, out.len());
    res.as_mut_slice().copy_from_slice(&out);
    Ok(res.into())
}

#[rustler::nif]
fn check_constraints(r1cs_bin: Binary, wtns_bin: Binary) -> Result<bool, String> {
    let mut r1cs_cur = Cursor::new(r1cs_bin.as_slice());
    let r1cs =
        R1csFile::<32>::read(&mut r1cs_cur).map_err(|e| format!("r1cs read error: {:?}", e))?;

    let mut wtns_cur = Cursor::new(wtns_bin.as_slice());
    let wtns =
        WtnsFile::<32>::read(&mut wtns_cur).map_err(|e| format!("wtns read error: {:?}", e))?;

    let prime = BigUint::from_bytes_le(&*r1cs.header.prime);
    let witness: Vec<BigUint> = wtns
        .witness
        .0
        .iter()
        .map(|fe| BigUint::from_bytes_le(&**fe))
        .collect();

    if witness.len() < r1cs.header.n_wires as usize {
        return Err(format!(
            "Witness length {} smaller than n_wires {}",
            witness.len(),
            r1cs.header.n_wires
        ));
    }

    for constraint in &r1cs.constraints.0 {
        let eval_lc = |lc: &Vec<(r1cs_file::FieldElement<32>, u32)>| -> BigUint {
            let mut sum = BigUint::zero();
            for (coeff, idx) in lc {
                let c = BigUint::from_bytes_le(&**coeff);
                let w = &witness[*idx as usize];
                sum = (sum + (c * w)) % &prime;
            }
            sum
        };

        let a = eval_lc(&constraint.0);
        let b = eval_lc(&constraint.1);
        let c = eval_lc(&constraint.2);

        if (a * b) % &prime != c {
            return Ok(false);
        }
    }

    Ok(true)
}

rustler::init!("ecu_circom_nif");
