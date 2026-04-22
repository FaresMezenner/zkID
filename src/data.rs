use ark_bn254::{Fr, G1Projective};
use ark_serialize::CanonicalSerialize;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPrivateDetails {
    pub birthday: DateTime<Utc>,
}

pub struct PublicValues {
    pub public_key: VerifyingKey,
    pub G: G1Projective,
    pub B: G1Projective,
    pub Q: G1Projective,
    pub G_vec: Vec<G1Projective>,
    pub H_vec: Vec<G1Projective>,
}

pub struct IssuerPrivateValues {
    pub private_key: SigningKey,
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
    pub V: G1Projective,

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
}

pub struct ProverPublicValues {
    pub age_verification_proof: BulletproofProverPublicValues,
}

pub struct DigitalID {
    pub v_birthday: G1Projective,
    pub signature: Signature,
}

impl UserPrivateDetails {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl DigitalID {
    pub fn generate(
        v_birthday: G1Projective,
        private_key: &SigningKey,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut v_birthday_bytes = Vec::new();
        let _ = v_birthday.serialize_compressed(&mut v_birthday_bytes);
        Ok(DigitalID {
            v_birthday: v_birthday,
            signature: private_key.sign(&v_birthday_bytes),
        })
    }

    pub fn verify_signature(&self, public_key: &VerifyingKey) {
        let mut v_birthday_bytes = Vec::new();
        let _ = self.v_birthday.serialize_compressed(&mut v_birthday_bytes);
        assert!(
            public_key
                .verify(&v_birthday_bytes, &self.signature)
                .is_ok()
        );
    }
}

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
        }
    }
}
