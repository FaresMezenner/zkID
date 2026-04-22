use chrono::{DateTime, Duration, TimeDelta, Utc};

use crate::data::ProverPrivateValues;

mod core;
mod data;
mod issuer;
mod prover;
mod verifier;

fn main() {
    static n_bits: u128 = 100; // this vlaue must be at least log2 of the max age possible we want to verify, and since timestamps needs around 41 bits, 64>41 ia valid.
    let age_threshold: u128 = unit_conversions::time::years::to_milliseconds(18.0) as u128;
    let current_timestamp: u128 = Utc::now().timestamp_millis() as u128;
    // Step 0: Setting up the issuer, preparing the signature keys and the public values
    let (
        issuer_private_values, // must stay private for the issuer
        public_values,
    ) = issuer::setup(n_bits).unwrap();
    println!("Step 0: Issuer setup finished successfuly");

    // Step 1: The prover requests from the issuer to create a digital ID for it
    let mut prover_private_values = ProverPrivateValues::empty(); // this must be kept and protected by the prover
    let (
        digital_id,
        mut user_private_details, // this must be kept and protected by the prover
    ) = issuer::generate_digital_id(
        "data/prover_details.json",
        &issuer_private_values,
        &public_values,
        &mut prover_private_values,
    )
    .unwrap();
    println!("Step 1: Digital ID created successfully");

    // Step 2: The prover calculates the values of age threshold bulletproof

    let prover_public_values = prover::calculate_values(
        age_threshold,
        &public_values,
        &mut prover_private_values,
        n_bits,
        current_timestamp,
        &mut user_private_details,
    );
    println!("Step 2: Age threshold bulletproof prover values generated successfuly");
    //Step 3: The verifier verifies the ID and the bulletproof proof and accepts or rejects
    verifier::verify_id(
        &digital_id,
        age_threshold,
        n_bits,
        current_timestamp,
        &public_values,
        &prover_public_values,
    );

    println!("Step 3: ID verification passed");
}
