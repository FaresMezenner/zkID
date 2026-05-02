use ark_bn254::{Fr, G1Projective};
use ark_ec::AdditiveGroup;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use num_bigint::{BigInt, BigUint, RandBigInt, Sign, ToBigUint};
use num_integer::Integer;
use num_prime::nt_funcs::is_prime;
use num_traits::One;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
pub fn random_elliptic_points_generator(
    size: u128,
) -> Result<Vec<G1Projective>, Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let mut points = Vec::new();
    for _ in 0..size {
        points.push(G1Projective::rand(&mut rng));
    }
    Ok(points)
}

pub fn commit(
    values: &Vec<i128>,
    points: &Vec<G1Projective>,
) -> Result<G1Projective, Box<dyn std::error::Error>> {
    Ok(points
        .iter()
        .zip(values.iter())
        .map(|(p, v)| *p * Fr::from(*v))
        .sum())
}

pub fn commit_fr(
    values: &Vec<Fr>,
    points: &Vec<G1Projective>,
) -> Result<G1Projective, Box<dyn std::error::Error>> {
    Ok(points.iter().zip(values.iter()).map(|(p, v)| *p * v).sum())
}

pub fn to_bits_le(value: u128, size: u128) -> Vec<i128> {
    (0..size)
        .map(|i| {
            if i < 128 {
                ((value >> (i as u32)) & 1) as i128
            } else {
                0 as i128
            }
        })
        .collect()
}

pub fn powers_vec(value: &Fr, n_bits: &u128) -> Vec<Fr> {
    let mut powers: Vec<Fr> = Vec::new();
    powers.push(Fr::ONE);
    for i in 1..(*n_bits) {
        powers.push(powers[(i - 1) as usize] * (*value));
    }
    powers
}

pub fn inner_product_fr(left: &Vec<Fr>, right: &Vec<Fr>) -> Fr {
    left.iter().zip(right).map(|(l, r)| (*l) * (*r)).sum()
}

pub fn compute_secondary_diagonals(
    points: &mut Vec<G1Projective>,
    values: &mut Vec<Fr>,
) -> (G1Projective, G1Projective) {
    if points.len() % 2 == 1 {
        points.push(G1Projective::ZERO);
    }
    if values.len() % 2 == 1 {
        values.push(Fr::ZERO);
    }

    let L = values
        .iter()
        .enumerate()
        .step_by(2)
        .map(|(i, value)| points[i + 1] * (*value))
        .sum();

    let R = points
        .iter()
        .enumerate()
        .step_by(2)
        .map(|(i, point)| *point * values[i + 1])
        .sum();
    (L, R)
}

pub fn fold_values(values: &mut Vec<Fr>, u: Fr) -> Vec<Fr> {
    if values.len() % 2 == 1 {
        values.push(Fr::ZERO);
    }
    let mut foldded = Vec::new();
    for chunk in values.chunks(2) {
        foldded.push(chunk[0] * u + chunk[1] * u.inverse().unwrap());
    }
    foldded
}
pub fn fold_points(points: &mut Vec<G1Projective>, u: Fr) -> Vec<G1Projective> {
    if points.len() % 2 == 1 {
        points.push(G1Projective::ZERO);
    }
    let mut foldded = Vec::new();
    for chunk in points.chunks(2) {
        foldded.push(chunk[0] * u + chunk[1] * u.inverse().unwrap());
    }
    foldded
}

pub fn point_to_bytes<G: CanonicalSerialize>(p: &G) -> Vec<u8> {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    buf
}

pub fn fr_to_bytes(f: &Fr) -> Vec<u8> {
    f.into_bigint().to_bytes_le()
}
pub fn fiat_shamir_challenge(inputs: &[&[u8]]) -> Fr {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input);
    }
    let hash = hasher.finalize();
    Fr::from_le_bytes_mod_order(&hash)
}

pub fn fiat_shamir_challenge_biguint(inputs: &[&[u8]]) -> BigUint {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input);
    }
    let hash = hasher.finalize();
    BigUint::from_bytes_le(&hash)
}

fn blake2b_32(data: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .hash(data)
        .as_bytes()
        .try_into()
        .expect("always 32 bytes")
}

pub fn hash_to_prime(data: &[u8]) -> BigUint {
    let hash: [u8; 32] = blake2b_32(data);
    let mut candidate = BigUint::from_bytes_le(&hash);

    // Ensure candidate is odd
    candidate |= BigUint::from(1u32);

    loop {
        if is_prime(&candidate, None).probably() {
            return candidate;
        }
        // Increment by 2 to stay odd
        candidate += 2u32;
    }
}

pub fn gen_prime(bits: u64) -> BigUint {
    loop {
        let mut candidate = OsRng.gen_biguint(bits);
        candidate |= BigUint::from(1u32); // force odd
        candidate |= BigUint::from(1u32) << (bits - 1) as usize; // force MSB set
        if is_prime(&candidate, None).probably() {
            return candidate;
        }
    }
}

pub fn gen_rsa_modulus(bits: u64) -> (BigUint, BigUint, BigUint) {
    let half = bits / 2;
    loop {
        let p = gen_prime(half);
        let q = gen_prime(half);
        if p != q {
            let n = &p * &q;
            return (n, p, q);
        }
    }
}

pub fn gen_generator(n: &BigUint) -> BigUint {
    loop {
        let r = OsRng.gen_biguint_below(n);
        if r > BigUint::from(1u32) && r.gcd(n).is_one() {
            return r.modpow(&BigUint::from(2u32), n); // g = r^2 mod N
        }
    }
}

pub fn bezout_coefficients(a: &BigUint, b: &BigUint) -> (BigInt, BigInt) {
    let a_int = BigInt::from_biguint(Sign::Plus, a.clone());
    let b_int = BigInt::from_biguint(Sign::Plus, b.clone());

    let ext_gcd = a_int.extended_gcd(&b_int);

    // For two distinct primes, gcd must be 1
    debug_assert!(
        ext_gcd.gcd.is_one(),
        "Inputs must be coprime (e.g., two distinct primes)"
    );

    (ext_gcd.x, ext_gcd.y)
}

pub fn fr_from_biguint_z(value_z: &BigUint) -> Fr {
    Fr::from_le_bytes_mod_order(&value_z.to_bytes_le())
}

pub fn fr_from_bigint_z(value_z: &BigInt) -> Fr {
    match value_z.sign() {
        Sign::Minus => {
            let abs_value_z = (-value_z)
                .to_biguint()
                .expect("absolute value is non-negative");
            -fr_from_biguint_z(&abs_value_z)
        }
        _ => {
            let non_negative_z = value_z
                .to_biguint()
                .expect("non-negative value should convert to BigUint");
            fr_from_biguint_z(&non_negative_z)
        }
    }
}

pub fn mod_inverse_z_n(value_zn: &BigUint, modulus_n: &BigUint) -> Option<BigUint> {
    let value_z = BigInt::from_biguint(Sign::Plus, value_zn.clone());
    let modulus_z = BigInt::from_biguint(Sign::Plus, modulus_n.clone());
    let egcd = value_z.extended_gcd(&modulus_z);
    if !egcd.gcd.is_one() {
        return None;
    }

    let mut inverse_z = egcd.x % &modulus_z;
    if inverse_z.sign() == Sign::Minus {
        inverse_z += &modulus_z;
    }
    inverse_z.to_biguint()
}

pub fn mod_pow_z_n_signed(base_zn: &BigUint, exponent_z: &BigInt, modulus_n: &BigUint) -> BigUint {
    if exponent_z.sign() == Sign::Minus {
        let inverse_zn = mod_inverse_z_n(base_zn, modulus_n)
            .expect("base must be invertible in Z_N for negative exponent");
        let abs_exponent_z = (-exponent_z)
            .to_biguint()
            .expect("absolute value is non-negative");
        inverse_zn.modpow(&abs_exponent_z, modulus_n)
    } else {
        let non_negative_exponent_z = exponent_z
            .to_biguint()
            .expect("non-negative value should convert to BigUint");
        base_zn.modpow(&non_negative_exponent_z, modulus_n)
    }
}
