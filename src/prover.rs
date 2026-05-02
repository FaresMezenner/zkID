use ark_bn254::Bn254;
use ark_bn254::{Fr, G1Projective};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_std::UniformRand;
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use rand::Rng;

use crate::core::{
    bezout_coefficients, commit, commit_fr, compute_secondary_diagonals, fiat_shamir_challenge,
    fiat_shamir_challenge_biguint, fold_points, fold_values, fr_from_biguint_z, fr_to_bytes,
    inner_product_fr, mod_pow_z_n_signed, point_to_bytes, powers_vec, to_bits_le,
};
use crate::data::NonMembershipProvingValues;
use crate::data::SignatureProvingValues;
use crate::data::{
    BulletproofProverPublicValues, ProverPrivateValues, ProverPublicValues, PublicValues,
    UserPrivateDetails,
};
use crate::prover;

pub fn random_linear_terms<R: Rng>(n_bits: &u128, rng: &mut R) -> Vec<Fr> {
    let mut terms: Vec<Fr> = Vec::new();
    for _ in 0..*n_bits {
        terms.push(Fr::rand(rng));
    }
    terms
}

pub fn calculate_a_s_v(
    value: u128,
    public_values: &PublicValues,
    prover_private_values: &mut ProverPrivateValues,
    n_bits: u128,
) -> (G1Projective, G1Projective, G1Projective) {
    let mut rng = rand::thread_rng();
    let aL = to_bits_le(value, n_bits);
    let aR: Vec<i128> = aL.iter().map(|bit| (*bit as i128) - 1).collect();
    let sL: Vec<Fr> = random_linear_terms(&n_bits, &mut rng);
    let sR: Vec<Fr> = random_linear_terms(&n_bits, &mut rng);

    prover_private_values.age_verification_proof.alpha = Some(Fr::rand(&mut rng));
    prover_private_values.age_verification_proof.beta = Some(Fr::rand(&mut rng));
    prover_private_values.age_verification_proof.gamma = Some(Fr::rand(&mut rng));

    let A = commit(&aR, &public_values.H_vec).unwrap()
        + commit(&aL, &public_values.G_vec).unwrap()
        + public_values.B * prover_private_values.age_verification_proof.alpha.unwrap();

    let S = commit_fr(&sR, &public_values.H_vec).unwrap()
        + commit_fr(&sL, &public_values.G_vec).unwrap()
        + public_values.B * prover_private_values.age_verification_proof.beta.unwrap();

    let V = public_values.G * Fr::from(value as i128)
        + public_values.B * prover_private_values.age_verification_proof.gamma.unwrap();

    prover_private_values.age_verification_proof.aL =
        Some(aL.iter().map(|v| Fr::from(*v)).collect());
    prover_private_values.age_verification_proof.aR =
        Some(aR.iter().map(|v| Fr::from(*v)).collect());
    prover_private_values.age_verification_proof.sL = Some(sL);
    prover_private_values.age_verification_proof.sR = Some(sR);
    (A, S, V)
}

pub fn logarithmic_inner_product_prover_values(
    Ls: &mut Vec<G1Projective>,
    Rs: &mut Vec<G1Projective>,
    a: &mut Vec<Fr>,
    b: &mut Vec<Fr>,
    G_vec: &mut Vec<G1Projective>,
    H_vec: &mut Vec<G1Projective>,
    Q: &G1Projective,
) -> (Fr, Fr) {
    if a.len() == 1 {
        assert!(
            a.len() == 1 && b.len() == 1 && G_vec.len() == 1 && H_vec.len() == 1,
            "A problem occured while calculating the bulletproof prover vlaues"
        );
        return (a[0], b[0]);
    }

    let mut b_Q = b.iter().map(|b_value| *Q * (*b_value)).collect();
    let (L_a, R_a) = compute_secondary_diagonals(G_vec, a);
    let (L_b, R_b) = compute_secondary_diagonals(H_vec, b);
    let (L_ab, R_ab) = compute_secondary_diagonals(&mut b_Q, a);

    Ls.push(L_a + R_b + L_ab);
    Rs.push(R_a + L_b + R_ab);

    // u is computed using fiat-shamir over L and R of this round
    let L = Ls.last().unwrap();
    let R = Rs.last().unwrap();
    let u = fiat_shamir_challenge(&[&point_to_bytes(L), &point_to_bytes(R)]);

    // here we calculate the values of the next iteration
    let mut a_prime = fold_values(a, u);
    let mut b_prime = fold_values(b, u.inverse().unwrap());
    let mut G_vec_prime = fold_points(G_vec, u.inverse().unwrap());
    let mut H_vec_prime = fold_points(H_vec, u);
    logarithmic_inner_product_prover_values(
        Ls,
        Rs,
        &mut a_prime,
        &mut b_prime,
        &mut G_vec_prime,
        &mut H_vec_prime,
        Q,
    )
}

pub fn calculate_proofs_values(
    age_threshold: u128,
    public_values: &PublicValues,
    prover_private_values: &mut ProverPrivateValues,
    n_bits: u128,
    user_private_details: &mut UserPrivateDetails,
) -> BulletproofProverPublicValues {
    let mut rng = rand::thread_rng();
    let v_age: u128 = age_threshold + ((1u128 << n_bits) - 1) - public_values.current_timestamp
        + (user_private_details.birthday.timestamp_millis() as u128);

    let (A, S, _) = prover::calculate_a_s_v(v_age, &public_values, prover_private_values, n_bits);
    let V_birthday = public_values.G
        * Fr::from(user_private_details.birthday.timestamp_millis() as i128)
        + public_values.B * prover_private_values.age_verification_proof.gamma.unwrap();

    // here we calculate y and z using fiat shammir
    let y = fiat_shamir_challenge(&[&point_to_bytes(&A), &point_to_bytes(&S)]);
    let z = fiat_shamir_challenge(&[&point_to_bytes(&A), &point_to_bytes(&S), &fr_to_bytes(&y)]);

    let y_n = powers_vec(&y, &n_bits);

    // now we calcuate the polynomials terms
    let l_const: Vec<Fr> = prover_private_values
        .age_verification_proof
        .aL
        .as_ref()
        .unwrap()
        .iter()
        .map(|v| *v - z)
        .collect();
    let r_const: Vec<Fr> = prover_private_values
        .age_verification_proof
        .aR
        .as_ref()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, v)| (*v + z) * y_n[i] + z * z * Fr::from(1u128 << i))
        .collect();

    let y_n_sR: Vec<Fr> = prover_private_values
        .age_verification_proof
        .sR
        .as_ref()
        .unwrap()
        .iter()
        .zip(y_n)
        .map(|(s_r, y_n)| (*s_r) * (y_n))
        .collect();

    let t_0 = inner_product_fr(&l_const, &r_const);
    let t_1 = inner_product_fr(&l_const, &y_n_sR)
        + inner_product_fr(
            &r_const,
            prover_private_values
                .age_verification_proof
                .sL
                .as_ref()
                .unwrap(),
        );
    let t_2 = inner_product_fr(
        prover_private_values
            .age_verification_proof
            .sL
            .as_ref()
            .unwrap(),
        &y_n_sR,
    );
    prover_private_values.age_verification_proof.t_0 = Some(t_0);
    prover_private_values.age_verification_proof.t_1 = Some(t_1);
    prover_private_values.age_verification_proof.t_2 = Some(t_2);

    let tau_1 = Fr::rand(&mut rng);
    let tau_2 = Fr::rand(&mut rng);
    let T_1 = public_values.G * t_1 + public_values.B * tau_1;
    let T_2 = public_values.G * t_2 + public_values.B * tau_2;

    // u is computed using fiat-shamir over the transcript so far
    let u = fiat_shamir_challenge(&[
        &point_to_bytes(&A),
        &point_to_bytes(&S),
        &fr_to_bytes(&y),
        &fr_to_bytes(&z),
        &point_to_bytes(&T_1),
        &point_to_bytes(&T_2),
    ]);
    let mut l_u: Vec<Fr> = l_const
        .iter()
        .zip(
            prover_private_values
                .age_verification_proof
                .sL
                .as_ref()
                .unwrap()
                .iter()
                .map(|s_l| (*s_l) * u)
                .collect::<Vec<Fr>>(),
        )
        .map(|(l, s_l_u)| *l + s_l_u)
        .collect();
    let mut r_u: Vec<Fr> = r_const
        .iter()
        .zip(y_n_sR.iter())
        .map(|(r, y_n_s_r)| *r + *y_n_s_r * u)
        .collect();

    let C: ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config> =
        commit_fr(&l_u, &public_values.G_vec).unwrap()
            + commit_fr(&r_u, &public_values.H_vec).unwrap();

    let t_u = t_0 + t_1 * u + t_2 * u * u;
    let pi_l_r = prover_private_values.age_verification_proof.alpha.unwrap()
        + prover_private_values.age_verification_proof.beta.unwrap() * u;
    let pi_t = z * z * prover_private_values.age_verification_proof.gamma.unwrap()
        + tau_1 * u
        + tau_2 * u * u;

    let mut Ls: Vec<G1Projective> = Vec::new();
    let mut Rs: Vec<G1Projective> = Vec::new();
    let (a, b) = logarithmic_inner_product_prover_values(
        &mut Ls,
        &mut Rs,
        &mut l_u,
        &mut r_u,
        &mut public_values.G_vec.clone(),
        &mut public_values.H_vec.clone(),
        &public_values.Q,
    );
    BulletproofProverPublicValues {
        A,
        C: C,
        S,
        Ls: Ls,
        Rs: Rs,
        T_1: T_1,
        T_2: T_2,
        V_birthday,
        l_u: l_u,
        pi_l_r: pi_l_r,
        pi_t: pi_t,
        r_u: r_u,
        t_u: t_u,
        a: a,
        b: b,
    }
}

fn re_randomize_signatur(
    current_signature: (G1Projective, G1Projective),
) -> (G1Projective, G1Projective) {
    let mut rng = rand::thread_rng();
    let t = Fr::rand(&mut rng);
    (current_signature.0 * t, current_signature.1 * t)
}

fn generate_signature_proving_values(
    signature: (G1Projective, G1Projective),
    public_values: &PublicValues,
    user_private_details: &UserPrivateDetails,
    prover_private_values: &ProverPrivateValues,
    V_birthday: &G1Projective,
    non_membership_proof: &NonMembershipProvingValues,
    r_rev_z: &BigUint,
) -> SignatureProvingValues {
    let mut rng = rand::thread_rng();
    let r_v_fr = Fr::rand(&mut rng);
    let r_gamma_fr = Fr::rand(&mut rng);
    let r_rev_fr = fr_from_biguint_z(r_rev_z);

    let A1 = public_values.G * r_v_fr + public_values.B * r_gamma_fr;
    let A2 = (Bn254::pairing(signature.0, public_values.public_key.1) * r_v_fr)
        + (Bn254::pairing(signature.0, public_values.public_key.2) * r_rev_fr);
    let c_z = fiat_shamir_challenge_biguint(&[
        &public_values.N.to_bytes_le(),
        &public_values.g.to_bytes_le(),
        &public_values.Acc.to_bytes_le(),
        &public_values.P.to_bytes_le(),
        &point_to_bytes(&public_values.public_key.0),
        &point_to_bytes(&public_values.public_key.1),
        &point_to_bytes(&public_values.public_key.2),
        &point_to_bytes(V_birthday),
        &point_to_bytes(&signature.0),
        &point_to_bytes(&signature.1),
        &point_to_bytes(&A1),
        &point_to_bytes(&A2),
        non_membership_proof.K.to_bytes_le().as_slice(),
        non_membership_proof.T.to_bytes_le().as_slice(),
    ]);
    let c_fr = fr_from_biguint_z(&c_z);
    let rev_id_z = prover_private_values
        .rev_id
        .as_ref()
        .expect("revocation ID must be available before proving");

    let s_v = r_v_fr - c_fr * Fr::from(user_private_details.birthday.timestamp_millis() as i128);
    let s_gamma = r_gamma_fr - c_fr * prover_private_values.age_verification_proof.gamma.unwrap();
    let s_rev = BigInt::from_biguint(Sign::Plus, r_rev_z.clone())
        - BigInt::from_biguint(Sign::Plus, c_z)
            * BigInt::from_biguint(Sign::Plus, rev_id_z.clone());

    SignatureProvingValues {
        A1,
        A2,
        s_gamma,
        s_v,
        s_rev,
    }
}

fn generate_non_membership_proving_values(
    public_values: &PublicValues,
    rev_id_z: &BigUint,
    r_rev_z: &BigUint,
) -> NonMembershipProvingValues {
    let mut rng = rand::thread_rng();
    let k_z = rng.gen_biguint(256);
    let K = public_values.g.modpow(&k_z, &public_values.N);
    let (a_z, b_z) = bezout_coefficients(rev_id_z, &public_values.P);
    let k_bigint_z = BigInt::from_biguint(Sign::Plus, k_z);
    let a_prime = &k_bigint_z * a_z;
    let b_prime = &k_bigint_z * b_z;

    let r_rev_bigint_z = BigInt::from_biguint(Sign::Plus, r_rev_z.clone());
    let t_exponent_z = &r_rev_bigint_z * &a_prime;
    let T = mod_pow_z_n_signed(&public_values.g, &t_exponent_z, &public_values.N);

    NonMembershipProvingValues {
        T,
        K,
        a_prime,
        b_prime,
    }
}

pub fn calculate_values(
    age_threshold: u128,
    public_values: &PublicValues,
    prover_private_values: &mut ProverPrivateValues,
    n_bits: u128,
    user_private_details: &mut UserPrivateDetails,
) -> ProverPublicValues {
    let age_verification_proof = calculate_proofs_values(
        age_threshold,
        public_values,
        prover_private_values,
        n_bits,
        user_private_details,
    );

    let rev_id_z = prover_private_values
        .rev_id
        .as_ref()
        .expect("revocation ID must be set by issuer before proving");
    let mut rng = rand::thread_rng();
    let r_rev_z = rng.gen_biguint(256);

    let non_membership_proof =
        generate_non_membership_proving_values(public_values, rev_id_z, &r_rev_z);

    let new_signature = re_randomize_signatur(prover_private_values.signature.unwrap());

    ProverPublicValues {
        signature_proving_values: generate_signature_proving_values(
            new_signature,
            public_values,
            user_private_details,
            prover_private_values,
            &age_verification_proof.V_birthday,
            &non_membership_proof,
            &r_rev_z,
        ),
        age_verification_proof,
        signature: new_signature,
        revocation_non_membership_proof: non_membership_proof,
    }
}
