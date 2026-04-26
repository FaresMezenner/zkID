use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::pairing::PairingOutput;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use elliptic_curve::rand_core::le;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPrivateDetails {
    pub birthday: DateTime<Utc>,
}

pub struct PublicValues {
    pub public_key: (G2Projective, G2Projective),
    pub G: G1Projective,
    pub B: G1Projective,
    pub Q: G1Projective,
    pub G_vec: Vec<G1Projective>,
    pub H_vec: Vec<G1Projective>,
    pub current_timestamp: u128,
}

pub struct IssuerPrivateValues {
    pub private_key: (Fr, Fr),
}

pub struct BulletproofProverPrivateValues {
    pub alpha: Option<Fr>,
    pub beta: Option<Fr>,
    pub gamma: Option<Fr>,
    pub aL: Option<Vec<Fr>>,
    pub aR: Option<Vec<Fr>>,
    pub sL: Option<Vec<Fr>>,
    pub sR: Option<Vec<Fr>>,
    pub t_0: Option<Fr>,
    pub t_1: Option<Fr>,
    pub t_2: Option<Fr>,
}
pub struct BulletproofProverPublicValues {
    pub A: G1Projective,
    pub S: G1Projective,
    pub V_birthday: G1Projective,

    pub T_1: G1Projective,
    pub T_2: G1Projective,
    pub l_u: Vec<Fr>,
    pub r_u: Vec<Fr>,
    pub t_u: Fr,
    pub pi_l_r: Fr,
    pub pi_t: Fr,
    pub C: G1Projective,
    pub Ls: Vec<G1Projective>,
    pub Rs: Vec<G1Projective>,
    pub a: Fr,
    pub b: Fr,
}

pub struct ProverPrivateValues {
    pub age_verification_proof: BulletproofProverPrivateValues,
    pub signature: Option<(G1Projective, G1Projective)>,
}

pub struct SignatureProvingValues {
    pub A1: G1Projective,
    pub A2: PairingOutput<Bn254>,
    pub s_v: Fr,
    pub s_gamma: Fr,
}

pub struct ProverPublicValues {
    pub age_verification_proof: BulletproofProverPublicValues,
    pub signature: (G1Projective, G1Projective),
    pub signature_proving_values: SignatureProvingValues,
}

pub struct DigitalID {}

impl UserPrivateDetails {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl DigitalID {}

impl ProverPrivateValues {
    pub fn empty() -> ProverPrivateValues {
        ProverPrivateValues {
            age_verification_proof: BulletproofProverPrivateValues {
                alpha: None,
                beta: None,
                gamma: None,
                aL: None,
                aR: None,
                sL: None,
                sR: None,
                t_0: None,
                t_1: None,
                t_2: None,
            },
            signature: None,
        }
    }
}
