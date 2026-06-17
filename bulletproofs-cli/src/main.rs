use std::fs;
use std::process;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use clap::{Parser, Subcommand};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

const ALLOWED_BITS: [u64; 4] = [8, 16, 32, 64];

#[derive(Parser)]
#[command(name = "bulletproofs-cli")]
#[command(about = "Generate and verify Ristretto Bulletproof range proofs for Aptos", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(name = "prove")]
    Prove {
        #[arg(long)]
        value: u64,
        #[arg(long)]
        bits: u64,
        #[arg(long)]
        dst: String,
        #[arg(long, default_value = "proof.json")]
        out: String,
    },
    #[command(name = "verify")]
    Verify {
        #[arg(long = "commitment-hex")]
        commitment_hex: Option<String>,
        #[arg(long = "proof-hex")]
        proof_hex: Option<String>,
        #[arg(long)]
        input: Option<String>,
        #[arg(long)]
        bits: u64,
        #[arg(long)]
        dst: String,
    },
}

#[derive(Serialize, Deserialize)]
struct SecretMarker {
    secret_fields: Vec<String>,
    note: String,
}

#[derive(Serialize, Deserialize)]
struct ProveOutput {
    value: u64,
    num_bits: u64,
    dst_hex: String,
    commitment_hex: String,
    proof_hex: String,
    blinding_hex: String,
    secret: SecretMarker,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Prove {
            value,
            bits,
            dst,
            out,
        } => run_prove(value, bits, dst, out),
        Command::Verify {
            commitment_hex,
            proof_hex,
            input,
            bits,
            dst,
        } => run_verify(commitment_hex, proof_hex, input, bits, dst),
    }
}

fn run_prove(value: u64, bits: u64, dst: String, out: String) {
    let num_bits = match supported_bits(bits) {
        Some(n) => n,
        None => {
            eprintln!(
                "Unsupported num_bits: {}. Supported values are 8, 16, 32, 64.",
                bits
            );
            process::exit(1);
        }
    };

    if !value_fits_bits(value, num_bits) {
        eprintln!(
            "Value {} does not fit in {} bits. Expected value < 2^{}.",
            value, num_bits, num_bits
        );
        process::exit(1);
    }

    let mut rng = thread_rng();
    let blinding = Scalar::random(&mut rng);

    let bp_gens = BulletproofGens::new(num_bits as usize, 1);
    let pc_gens = PedersenGens::default();
    let mut transcript = make_transcript(&dst);

    let (proof, commitment) = match RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        value,
        &blinding,
        num_bits as usize,
    ) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("Failed to generate range proof: {err}");
            process::exit(1);
        }
    };

    let mut verify_transcript = make_transcript(&dst);
    if proof
        .verify_single(
            &bp_gens,
            &pc_gens,
            &mut verify_transcript,
            &commitment,
            num_bits as usize,
        )
        .is_err()
    {
        eprintln!("Local verification failed for generated proof. This should not happen.");
        process::exit(1);
    }

    let output = ProveOutput {
        value,
        num_bits: bits,
        dst_hex: hex::encode(dst.as_bytes()),
        commitment_hex: hex::encode(commitment.to_bytes()),
        proof_hex: hex::encode(proof.to_bytes()),
        blinding_hex: hex::encode(blinding.to_bytes()),
        secret: SecretMarker {
            secret_fields: vec!["value".to_string(), "blinding_hex".to_string()],
            note: "debug-only: this value and blinding factor are never meant to be sent on-chain."
                .to_string(),
        },
    };

    let output_json = serde_json::to_string_pretty(&output).unwrap();
    match fs::write(&out, output_json.as_bytes()) {
        Ok(()) => {
            println!("Proof data saved to {}", out);
            println!("{}", output_json);
        }
        Err(err) => {
            eprintln!("Failed to write output file {}: {}", out, err);
            process::exit(1);
        }
    }
}

fn run_verify(
    commitment_hex: Option<String>,
    proof_hex: Option<String>,
    input: Option<String>,
    bits: u64,
    dst: String,
) {
    let (mut commitment_hex, mut proof_hex, maybe_file_bits) = match (
        commitment_hex,
        proof_hex,
        input,
    ) {
        (Some(commitment_hex), Some(proof_hex), None) => {
            (Some(commitment_hex), Some(proof_hex), None)
        }
        (None, None, Some(input_path)) => {
            let body = match fs::read_to_string(&input_path) {
                Ok(v) => v,
                Err(_) => {
                    println!("false");
                    return;
                }
            };
            match serde_json::from_str::<ProveOutput>(&body) {
                Ok(data) => (
                    Some(data.commitment_hex),
                    Some(data.proof_hex),
                    Some(data.num_bits),
                ),
                Err(_) => {
                    println!("false");
                    return;
                }
            }
        }
        _ => {
            eprintln!(
                "Verification requires either --input <file> or both --commitment-hex and --proof-hex."
            );
            process::exit(1);
        }
    };

    let num_bits = match supported_bits(bits) {
        Some(n) => n,
        None => {
            eprintln!(
                "Unsupported num_bits: {}. Supported values are 8, 16, 32, 64.",
                bits
            );
            process::exit(1);
        }
    };

    if let Some(file_bits) = maybe_file_bits {
        if file_bits != bits {
            eprintln!("File num_bits ({file_bits}) does not match provided bits ({bits}).");
            println!("false");
            return;
        }
    }

    let commitment_hex = commitment_hex.take().unwrap();
    let proof_hex = proof_hex.take().unwrap();

    let commitment_bytes = match hex::decode(commitment_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            println!("false");
            return;
        }
    };

    if commitment_bytes.len() != 32 {
        println!("false");
        return;
    }

    let commitment = CompressedRistretto::from_slice(&commitment_bytes);
    if commitment.decompress().is_none() {
        println!("false");
        return;
    }

    let proof_bytes = match hex::decode(proof_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            println!("false");
            return;
        }
    };

    let proof = match RangeProof::from_bytes(&proof_bytes) {
        Ok(p) => p,
        Err(_) => {
            println!("false");
            return;
        }
    };

    let bp_gens = BulletproofGens::new(num_bits as usize, 1);
    let pc_gens = PedersenGens::default();
    let mut transcript = make_transcript(&dst);

    let is_valid = proof
        .verify_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &commitment,
            num_bits as usize,
        )
        .is_ok();

    println!("{}", if is_valid { "true" } else { "false" });
}

fn make_transcript(dst: &str) -> Transcript {
    // Aptos native verification uses the DST bytes directly as the Merlin transcript label.
    let label: &'static [u8] = Box::leak(dst.as_bytes().to_vec().into_boxed_slice());
    Transcript::new(label)
}

fn supported_bits(bits: u64) -> Option<u64> {
    if ALLOWED_BITS.contains(&bits) {
        Some(bits)
    } else {
        None
    }
}

fn value_fits_bits(value: u64, bits: u64) -> bool {
    bits == 64 || value < (1u64 << bits)
}

#[cfg(test)]
mod tests {
    use super::{supported_bits, value_fits_bits};

    #[test]
    fn supported_bits_are_restricted_to_aptos_bulletproof_ranges() {
        assert_eq!(supported_bits(8), Some(8));
        assert_eq!(supported_bits(16), Some(16));
        assert_eq!(supported_bits(32), Some(32));
        assert_eq!(supported_bits(64), Some(64));
        assert_eq!(supported_bits(7), None);
        assert_eq!(supported_bits(128), None);
    }

    #[test]
    fn value_must_fit_selected_range() {
        assert!(value_fits_bits(255, 8));
        assert!(!value_fits_bits(256, 8));
        assert!(value_fits_bits(u64::MAX, 64));
    }
}
