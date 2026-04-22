use ark_bn254::{Fr, G1Projective};
use ark_ec::AdditiveGroup;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
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

pub fn point_to_bytes(p: &G1Projective) -> Vec<u8> {
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
