use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use num_bigint::{BigInt, BigUint, Sign};

use crate::{
    core::{
        commit_fr, fiat_shamir_challenge, fiat_shamir_challenge_biguint, fold_points,
        fr_from_bigint_z, fr_from_biguint_z, fr_to_bytes, mod_pow_z_n_signed, point_to_bytes,
    },
    data::{BulletproofProverPublicValues, ProverPublicValues, PublicValues},
};

pub fn calculate_v_age(
    age_threshold: u128,
    n_bits: u128,
    public_values: &PublicValues,
    prover_public_values: &ProverPublicValues,
) -> G1Projective {
    prover_public_values.age_verification_proof.V_birthday
        + public_values.G
            * Fr::from(
                (age_threshold + ((1 << n_bits) - 1) - public_values.current_timestamp) as u128,
            )
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

fn verify_signature(
    public_values: &PublicValues,
    prover_public_values: &ProverPublicValues,
) -> BigUint {
    let c_z = fiat_shamir_challenge_biguint(&[
        &public_values.N.to_bytes_le(),
        &public_values.g.to_bytes_le(),
        &public_values.Acc.to_bytes_le(),
        &public_values.P.to_bytes_le(),
        &point_to_bytes(&public_values.public_key.0),
        &point_to_bytes(&public_values.public_key.1),
        &point_to_bytes(&public_values.public_key.2),
        &point_to_bytes(&prover_public_values.age_verification_proof.V_birthday),
        &point_to_bytes(&prover_public_values.signature.0),
        &point_to_bytes(&prover_public_values.signature.1),
        &point_to_bytes(&prover_public_values.signature_proving_values.A1),
        &point_to_bytes(&prover_public_values.signature_proving_values.A2),
        &prover_public_values
            .revocation_non_membership_proof
            .K
            .to_bytes_le(),
        &prover_public_values
            .revocation_non_membership_proof
            .T
            .to_bytes_le(),
    ]);
    let e_sigma1_pk2 = Bn254::pairing(prover_public_values.signature.0, public_values.public_key.1);
    let e_sigma1_pk3 = Bn254::pairing(prover_public_values.signature.0, public_values.public_key.2);
    let e_sigma2_g2 = Bn254::pairing(prover_public_values.signature.1, G2Projective::generator());
    let e_sigma1_pk1 = Bn254::pairing(prover_public_values.signature.0, public_values.public_key.0);
    let c_fr = fr_from_biguint_z(&c_z);
    let s_rev_fr = fr_from_bigint_z(&prover_public_values.signature_proving_values.s_rev);

    assert_eq!(
        e_sigma1_pk2 * prover_public_values.signature_proving_values.s_v
            + e_sigma1_pk3 * s_rev_fr
            + (e_sigma2_g2 - e_sigma1_pk1) * c_fr,
        prover_public_values.signature_proving_values.A2
    );
    assert_eq!(
        public_values.G * prover_public_values.signature_proving_values.s_v
            + public_values.B * prover_public_values.signature_proving_values.s_gamma
            + prover_public_values.age_verification_proof.V_birthday * c_fr,
        prover_public_values.signature_proving_values.A1
    );
    c_z
}

fn verify_revocation_non_membership(
    public_values: &PublicValues,
    prover_public_values: &ProverPublicValues,
    challenge_z: BigUint,
) {
    let c_z = BigInt::from_biguint(Sign::Plus, challenge_z);
    let s_rev_times_a_prime_z = &prover_public_values.signature_proving_values.s_rev
        * &prover_public_values.revocation_non_membership_proof.a_prime;
    let minus_c_times_b_prime_z =
        -(&c_z * &prover_public_values.revocation_non_membership_proof.b_prime);
    let minus_c_z = -c_z;

    let lhs = (mod_pow_z_n_signed(&public_values.g, &s_rev_times_a_prime_z, &public_values.N)
        * mod_pow_z_n_signed(
            &public_values.Acc,
            &minus_c_times_b_prime_z,
            &public_values.N,
        ))
        % &public_values.N;

    let rhs = (&prover_public_values.revocation_non_membership_proof.T
        * mod_pow_z_n_signed(
            &prover_public_values.revocation_non_membership_proof.K,
            &minus_c_z,
            &public_values.N,
        ))
        % &public_values.N;

    assert_eq!(lhs, rhs);
}

pub fn verify_id(
    age_threshold: u128,
    n_bits: u128,
    public_values: &PublicValues,
    prover_public_values: &ProverPublicValues,
) {
    // the verifier must verify the id first
    let challenge = verify_signature(public_values, prover_public_values);
    verify_revocation_non_membership(public_values, prover_public_values, challenge);

    let V_age = calculate_v_age(age_threshold, n_bits, public_values, prover_public_values);
    verify_bulletproof(
        &prover_public_values.age_verification_proof,
        public_values,
        V_age,
        n_bits,
    );
}
