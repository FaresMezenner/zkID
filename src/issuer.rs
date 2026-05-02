use crate::core::{
    fr_from_biguint_z, gen_generator, gen_rsa_modulus, hash_to_prime,
    random_elliptic_points_generator,
};
use crate::data::{IssuerPrivateValues, ProverPrivateValues, PublicValues, UserPrivateDetails};
use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use ark_std::UniformRand;
use chrono::Utc;
use num_bigint::{BigUint, RandBigInt};
use num_modular::ModularPow;

pub fn setup(
    n_bits: u128,
) -> Result<(IssuerPrivateValues, PublicValues), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let issuer_private_values = IssuerPrivateValues {
        private_key: (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)),
        revocation_key: rng.gen_biguint(256),
    };
    let (N, _p, _q) = gen_rsa_modulus(2048);
    let g = gen_generator(&N);
    let Acc: BigUint = g.clone();
    let P = BigUint::from(1u128);
    let public_values = PublicValues {
        public_key: (
            G2Projective::generator() * issuer_private_values.private_key.0,
            G2Projective::generator() * issuer_private_values.private_key.1,
            G2Projective::generator() * issuer_private_values.private_key.2,
        ),
        G: match random_elliptic_points_generator(1).unwrap().first() {
            Some(point) => *point,
            None => {
                panic!("No Point was generate")
            }
        },
        B: match random_elliptic_points_generator(1).unwrap().first() {
            Some(point) => *point,
            None => {
                panic!("No Point was generate")
            }
        },
        G_vec: random_elliptic_points_generator(n_bits).unwrap(),
        H_vec: random_elliptic_points_generator(n_bits).unwrap(),
        Q: match random_elliptic_points_generator(1).unwrap().first() {
            Some(point) => *point,
            None => {
                panic!("No Point was generate")
            }
        },
        current_timestamp: Utc::now().timestamp_millis() as u128,
        N,
        g,
        Acc,
        P,
    };

    Ok((issuer_private_values, public_values))
}

fn calculate_revocation_id(unique_id: &BigUint, revocation_key: &BigUint) -> BigUint {
    let mut value_to_hash = unique_id.to_bytes_le();
    value_to_hash.extend(revocation_key.to_bytes_le());
    hash_to_prime(value_to_hash.as_slice())
}

pub fn generate_digital_id(
    user_details_path: &str,
    issuer_private_values: &IssuerPrivateValues,
    prover_private_values: &mut ProverPrivateValues,
) -> Result<UserPrivateDetails, Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let unique_id = rng.gen_biguint(256);
    let revocation_id = calculate_revocation_id(&unique_id, &issuer_private_values.revocation_key);
    let revocation_id_fr = fr_from_biguint_z(&revocation_id);

    let json = std::fs::read_to_string(user_details_path)?;
    let user_details = UserPrivateDetails::from_json(&json)?;
    let birthday_timestamp = user_details.birthday.timestamp_millis() as i128;

    let h = G1Projective::rand(&mut rng);
    let signature = (
        h,
        h * (issuer_private_values.private_key.0
            + issuer_private_values.private_key.1 * Fr::from(birthday_timestamp)
            + issuer_private_values.private_key.2 * revocation_id_fr),
    );

    prover_private_values.signature = Some(signature);
    prover_private_values.rev_id = Some(revocation_id);
    prover_private_values.unique_id = Some(unique_id);

    Ok(user_details)
}

pub fn revoke_id(
    unique_id: &BigUint,
    public_values: &mut PublicValues,
    issuer_private_values: &IssuerPrivateValues,
) {
    let revocation_id = calculate_revocation_id(unique_id, &issuer_private_values.revocation_key);
    public_values.Acc = public_values
        .Acc
        .clone()
        .powm(&revocation_id, &public_values.N);
    public_values.P = public_values.P.clone() * revocation_id;
}
