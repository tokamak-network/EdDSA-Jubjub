use lazy_static::lazy_static;
use num_bigint::BigInt;
use num_traits::Zero;

pub mod poseidon1;
pub mod poseidon10;
pub mod poseidon11;
pub mod poseidon12;
pub mod poseidon13;
pub mod poseidon14;
pub mod poseidon15;
pub mod poseidon16;
pub mod poseidon2;
pub mod poseidon3;
pub mod poseidon4;
pub mod poseidon5;
pub mod poseidon6;
pub mod poseidon7;
pub mod poseidon8;
pub mod poseidon9;

// bls 12381 Scalar Field Modulus
lazy_static! {
    pub static ref PRIME: BigInt = BigInt::parse_bytes(
        b"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        16
    )
    .expect("Failed to parse PRIME");
}
pub fn poseidon_permutation(
    inputs: &[BigInt],
    r_full: usize,
    r_partial: usize,
    round_constants: &[BigInt],
    mds: &[Vec<BigInt>],
) -> Vec<BigInt> {
    let t = inputs.len() + 1;
    let r_full_half = r_full / 2;

    // Initialize state: [0, ...inputs]
    let mut state: Vec<BigInt> = Vec::with_capacity(t);
    state.push(BigInt::zero());
    state.extend_from_slice(inputs);

    let mut round_constants_counter = 0;
    let five = BigInt::from(5u32);

    // --- First Full Rounds ---
    for _ in 0..r_full_half {
        // Add Round Constants
        for item in state.iter_mut().take(t) {
            *item = (&*item + &round_constants[round_constants_counter]) % &*PRIME;
            round_constants_counter += 1;
        }

        // S-box: state[j] ^ 5 % PRIME
        for item in state.iter_mut().take(t) {
            *item = item.modpow(&five, &PRIME);
        }

        // Mix Layer
        let mut matrix_output: Vec<BigInt> = Vec::with_capacity(t);
        for row in mds.iter().take(t) {
            let mut result = BigInt::zero();
            for (k, item) in state.iter().enumerate().take(t) {
                let product = &row[k] * item;
                result = (result + product) % &*PRIME;
            }
            matrix_output.push(result);
        }
        state = matrix_output;
    }

    // --- Partial Rounds ---
    for _ in 0..r_partial {
        // Add Round Constants
        for item in state.iter_mut().take(t) {
            *item = (&*item + &round_constants[round_constants_counter]) % &*PRIME;
            round_constants_counter += 1;
        }

        // S-box: Only for state[0]
        state[0] = state[0].modpow(&five, &PRIME);

        // Mix Layer
        let mut matrix_output: Vec<BigInt> = Vec::with_capacity(t);
        for row in mds.iter().take(t) {
            let mut result = BigInt::zero();
            for (k, item) in state.iter().enumerate().take(t) {
                let product = &row[k] * item;
                result = (result + product) % &*PRIME;
            }
            matrix_output.push(result);
        }
        state = matrix_output;
    }

    // --- Second Full Rounds ---
    for _ in 0..r_full_half {
        // Add Round Constants
        for item in state.iter_mut().take(t) {
            *item = (&*item + &round_constants[round_constants_counter]) % &*PRIME;
            round_constants_counter += 1;
        }

        // S-box: state[j] ^ 5 % PRIME
        for item in state.iter_mut().take(t) {
            *item = item.modpow(&five, &PRIME);
        }

        // Mix Layer
        let mut matrix_output: Vec<BigInt> = Vec::with_capacity(t);
        for row in mds.iter().take(t) {
            let mut result = BigInt::zero();
            for (k, item) in state.iter().enumerate().take(t) {
                let product = &row[k] * item;
                result = (result + product) % &*PRIME;
            }
            matrix_output.push(result);
        }
        state = matrix_output;
    }

    state
}
