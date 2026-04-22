use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;

use crate::{
    core::{commit_fr, fiat_shamir_challenge, fold_points, fr_to_bytes, point_to_bytes},
    data::{BulletproofProverPublicValues, DigitalID, ProverPublicValues, PublicValues},
};

pub fn calculate_v_age(
    digital_id: &DigitalID,
    age_threshold: u128,
    n_bits: u128,
    current_timestamp: u128,
    public_values: &PublicValues,
) -> G1Projective {
    digital_id.v_birthday
        + public_values.G
            * Fr::from((age_threshold + ((1 << n_bits) - 1) - current_timestamp) as u128)
}

pub fn verify_bulletproof(
    bulletproof_prover_public_values: &BulletproofProverPublicValues,
    public_values: &PublicValues,
    V_age: G1Projective,
    n_bits: u128,
) {
    let y = fiat_shamir_challenge(&[
        &point_to_bytes(&bulletproof_prover_public_values.A),
        &point_to_bytes(&bulletproof_prover_public_values.S),
    ]);
    let z = fiat_shamir_challenge(&[
        &point_to_bytes(&bulletproof_prover_public_values.A),
        &point_to_bytes(&bulletproof_prover_public_values.S),
        &fr_to_bytes(&y),
    ]);
    let u_poly = fiat_shamir_challenge(&[
        &point_to_bytes(&bulletproof_prover_public_values.A),
        &point_to_bytes(&bulletproof_prover_public_values.S),
        &fr_to_bytes(&y),
        &fr_to_bytes(&z),
        &point_to_bytes(&bulletproof_prover_public_values.T_1),
        &point_to_bytes(&bulletproof_prover_public_values.T_2),
    ]);

    let delta_y_z = z * (Fr::ONE - z) * (0..n_bits).map(|i| y.pow([i as u64])).sum::<Fr>()
        - z * z * z * (0..n_bits).map(|i| Fr::from(1u128 << i)).sum::<Fr>();

    let mut G_vec = public_values.G_vec.clone();
    let mut H_vec = public_values.H_vec.clone();
    let H_vec_y_inv: Vec<G1Projective> = H_vec
        .iter()
        .enumerate()
        .map(|(i, h)| *h * y.inverse().unwrap().pow([i as u64]))
        .collect();
    // checking that t_u is evaluated using t(x)
    //
    assert_eq!(
        public_values.G * bulletproof_prover_public_values.t_u,
        V_age * z * z
            + public_values.G * delta_y_z
            + bulletproof_prover_public_values.T_1 * u_poly
            + bulletproof_prover_public_values.T_2 * u_poly.pow([2u64])
            + public_values.B * (-bulletproof_prover_public_values.pi_t)
    );

    // # checking that C is anchored with the commitments A and S so we build P correctly
    assert_eq!(
        bulletproof_prover_public_values.A + bulletproof_prover_public_values.S * u_poly
            - G_vec.iter().map(|g| *g * z).sum::<G1Projective>()
            + H_vec_y_inv
                .iter()
                .enumerate()
                .map(|(i, h_y_inv)| *h_y_inv
                    * (z * (y.pow([i as u64])) + z * z * Fr::from(1u128 << i)))
                .sum::<G1Projective>(),
        commit_fr(&bulletproof_prover_public_values.l_u, &G_vec).unwrap()
            + commit_fr(&bulletproof_prover_public_values.r_u, &H_vec_y_inv).unwrap()
            + public_values.B * bulletproof_prover_public_values.pi_l_r
    );
    let mut P =
        bulletproof_prover_public_values.C + public_values.Q * bulletproof_prover_public_values.t_u;

    // now verifying the inner product proof
    for i in 0..(bulletproof_prover_public_values.Ls.len()) {
        // building P, folding G_vec and H_vec
        let u = fiat_shamir_challenge(&[
            &point_to_bytes(&bulletproof_prover_public_values.Ls[i]),
            &point_to_bytes(&bulletproof_prover_public_values.Rs[i]),
        ]);
        P = bulletproof_prover_public_values.Ls[i] * u.pow([2u64])
            + P
            + bulletproof_prover_public_values.Rs[i] * u.inverse().unwrap().pow([2u64]);
        G_vec = fold_points(&mut G_vec, u.inverse().unwrap());
        H_vec = fold_points(&mut H_vec, u);
    }
    assert_eq!(
        P,
        G_vec[0] * bulletproof_prover_public_values.a
            + H_vec[0] * bulletproof_prover_public_values.b
            + public_values.Q
                * (bulletproof_prover_public_values.a * bulletproof_prover_public_values.b)
    )
}

pub fn verify_id(
    digital_id: &DigitalID,
    age_threshold: u128,
    n_bits: u128,
    current_timestamp: u128,
    public_values: &PublicValues,
    prover_public_values: &ProverPublicValues,
) {
    // the verifier must verify the id first
    digital_id.verify_signature(&public_values.public_key);

    let V_age = calculate_v_age(
        digital_id,
        age_threshold,
        n_bits,
        current_timestamp,
        public_values,
    );
    verify_bulletproof(
        &prover_public_values.age_verification_proof,
        public_values,
        V_age,
        n_bits,
    );
}
