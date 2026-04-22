use crate::core::{commit, random_elliptic_points_generator};
use crate::data::{
    DigitalID, IssuerPrivateValues, ProverPrivateValues, PublicValues, UserPrivateDetails,
};
use ark_bn254::{Fr, G1Projective};
use ark_std::UniformRand;
use ed25519_dalek::SigningKey;

pub fn setup(
    n_bits: u128,
) -> Result<(IssuerPrivateValues, PublicValues), Box<dyn std::error::Error>> {
    let signing_key_bytes: [u8; 32] = rand::random();
    let issuer_private_values = IssuerPrivateValues {
        private_key: SigningKey::from_bytes(&signing_key_bytes),
    };
    let public_values = PublicValues {
        public_key: issuer_private_values.private_key.verifying_key(),
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
    };

    Ok((issuer_private_values, public_values))
}

pub fn generate_digital_id(
    user_details_path: &str,
    issuer_private_values: &IssuerPrivateValues,
    public_values: &PublicValues,
    prover_private_values: &mut ProverPrivateValues,
) -> Result<(DigitalID, UserPrivateDetails), Box<dyn std::error::Error>> {
    let json = std::fs::read_to_string(user_details_path)?;
    let user_details = UserPrivateDetails::from_json(&json)?;

    let gamma: Fr = Fr::rand(&mut rand::thread_rng());
    let v_birthday = commit(
        &vec![user_details.birthday.timestamp_millis() as i128],
        &vec![public_values.G],
    )
    .unwrap()
        + public_values.B * gamma;
    prover_private_values.age_verification_proof.gamma = Some(gamma);
    Ok((
        DigitalID::generate(v_birthday, &issuer_private_values.private_key).unwrap(),
        user_details,
    ))
}
