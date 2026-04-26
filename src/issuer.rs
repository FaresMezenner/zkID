use crate::core::{commit, random_elliptic_points_generator};
use crate::data::{
    DigitalID, IssuerPrivateValues, ProverPrivateValues, PublicValues, UserPrivateDetails,
};
use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use ark_std::UniformRand;
use chrono::Utc;
use ed25519_dalek::SigningKey;

pub fn setup(
    n_bits: u128,
) -> Result<(IssuerPrivateValues, PublicValues), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let issuer_private_values = IssuerPrivateValues {
        private_key: (Fr::rand(&mut rng), Fr::rand(&mut rng)),
    };
    let public_values = PublicValues {
        public_key: (
            G2Projective::generator() * issuer_private_values.private_key.0,
            G2Projective::generator() * issuer_private_values.private_key.1,
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
    };

    Ok((issuer_private_values, public_values))
}

pub fn generate_digital_id(
    user_details_path: &str,
    issuer_private_values: &IssuerPrivateValues,
    prover_private_values: &mut ProverPrivateValues,
) -> Result<UserPrivateDetails, Box<dyn std::error::Error>> {
    let json = std::fs::read_to_string(user_details_path)?;
    let user_details = UserPrivateDetails::from_json(&json)?;
    let birthday_timestamp = user_details.birthday.timestamp_millis() as i128;

    let mut rng = rand::thread_rng();
    let h = G1Projective::rand(&mut rng);
    let signature = (
        h,
        h * (issuer_private_values.private_key.0
            + issuer_private_values.private_key.1 * Fr::from(birthday_timestamp)),
    );

    prover_private_values.signature = Some(signature);

    Ok(user_details)
}
