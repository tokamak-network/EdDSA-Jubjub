pub mod instances;

use crate::instances::PRIME;
use crate::instances::poseidon2::poseidon2;
use num_bigint::{BigInt, Sign};
// Needed for from_str_radix
// Standard Poseidon Arity
const POSEIDON_INPUTS: usize = 2;

/// Converts bytes to BigInt and ensures it fits within the Finite Field.
/// EDGE CASE: If bytes > Modulus, we perform modulo reduction.
pub fn bytes_to_field_element(bytes: &[u8]) -> BigInt {
    let val = BigInt::from_bytes_be(Sign::Plus, bytes);
    val % &*PRIME
}

/// Strictly enforces output length.
/// EDGE CASE:
/// 1. If input is shorter, pad left with zeros.
/// 2. If input is longer, truncate from the left (keep least significant bytes).
pub fn set_length_left(bytes: &[u8], length: usize) -> Vec<u8> {
    if bytes.len() == length {
        return bytes.to_vec();
    }

    let mut result = vec![0u8; length];
    if bytes.len() < length {
        // Pad: Copy bytes to the end of the result buffer
        result[length - bytes.len()..].copy_from_slice(bytes);
    } else {
        // Truncate: Take the last `length` bytes
        result.copy_from_slice(&bytes[bytes.len() - length..]);
    }
    result
}

pub fn poseidon_raw(in_vals: &[BigInt]) -> Result<BigInt, String> {
    if in_vals.len() != POSEIDON_INPUTS {
        return Err(format!(
            "Expected an array with {} elements, but got {}",
            POSEIDON_INPUTS,
            in_vals.len()
        ));
    }

    // Safety check: Ensure inputs are actually field elements before hashing
    // (Optional: depends on if you trust the caller. We enforce it here for safety).
    let modulus = &*PRIME;
    for (i, val) in in_vals.iter().enumerate() {
        if modulus.lt(val) {
            return Err(format!("Input at index {} exceeds Field Modulus", i));
        }
    }

    poseidon2(in_vals)
}

pub fn poseidon_n(in_vals: &[BigInt]) -> Result<BigInt, String> {
    if in_vals.len() != POSEIDON_INPUTS {
        return Err(format!(
            "poseidon{} expected exactly {} values",
            POSEIDON_INPUTS, POSEIDON_INPUTS
        ));
    }
    poseidon_raw(in_vals)
}

pub fn poseidon_n2x_compress(in_vals: &[BigInt]) -> Result<BigInt, String> {
    if in_vals.len() != POSEIDON_INPUTS * POSEIDON_INPUTS {
        return Err(format!(
            "poseidon_compress expected exactly {} values",
            POSEIDON_INPUTS * POSEIDON_INPUTS
        ));
    }

    let mut interim = Vec::with_capacity(POSEIDON_INPUTS);
    for k in 0..POSEIDON_INPUTS {
        let children = &in_vals[k * POSEIDON_INPUTS..(k + 1) * POSEIDON_INPUTS];
        interim.push(poseidon_raw(children)?);
    }
    poseidon_raw(&interim)
}

//using poseidon2
pub fn poseidon_btree_hasher(msg: &[u8]) -> Result<Vec<u8>, String> {
    // EDGE CASE: Empty input
    // We hash [0, 0] to represent an empty state
    if msg.is_empty() {
        let result = poseidon_raw(&vec![BigInt::from(0); POSEIDON_INPUTS])?;
        return Ok(set_length_left(&result.to_bytes_be().1, 32));
    }

    // 1. Convert Bytes to Field Elements (BigInts)
    // We chunk by 32 bytes (256 bits).
    // Note: BN254 is ~254 bits. 32 bytes (256 bits) might overflow.
    // `bytes_to_field_element` handles the modulo reduction.
    let words: Vec<BigInt> = msg.chunks(32).map(bytes_to_field_element).collect();

    // The Folding Closure
    let fold = |arr: &[BigInt]| -> Result<Vec<BigInt>, String> {
        if arr.is_empty() {
            return Ok(vec![]);
        }

        // Integer math for ceiling division: (num + divisor - 1) / divisor
        let n1x_chunks = arr.len().div_ceil(POSEIDON_INPUTS);
        let n_padded_children = n1x_chunks * POSEIDON_INPUTS;

        // Optimization: Check if we can do a 2-layer compress (4 inputs -> 1 output)
        // Checks if total padded children is divisible by 4 (assuming POSEIDON_INPUTS=2)
        let mode2x = n_padded_children.is_multiple_of(POSEIDON_INPUTS * POSEIDON_INPUTS);

        let (place_function, n_children_per_hash) = if mode2x {
            (
                poseidon_n2x_compress as fn(&[BigInt]) -> Result<BigInt, String>,
                POSEIDON_INPUTS * POSEIDON_INPUTS,
            )
        } else {
            (
                poseidon_n as fn(&[BigInt]) -> Result<BigInt, String>,
                POSEIDON_INPUTS,
            )
        };

        let mut out = Vec::new();

        // Step through the array in chunks
        for child_id in (0..arr.len()).step_by(n_children_per_hash) {
            let mut chunk = Vec::with_capacity(n_children_per_hash);

            for local_child_id in 0..n_children_per_hash {
                let actual_idx = child_id + local_child_id;

                // EDGE CASE: Padding
                // If we run off the end of the array, we pad with BigInt(0)
                let val = if actual_idx < arr.len() {
                    arr[actual_idx].clone()
                } else {
                    BigInt::from(0)
                };
                chunk.push(val);
            }
            out.push(place_function(&chunk)?);
        }
        Ok(out)
    };

    // 2. Recursive Folding (Merkle Tree construction)
    let mut acc = fold(&words)?;

    // Iterate until we reach the Root (len == 1)
    while acc.len() > 1 {
        acc = fold(&acc)?;
    }

    // 3. Output formatting
    // Ensure we return exactly 32 bytes
    if let Some(root) = acc.first() {
        Ok(set_length_left(&root.to_bytes_be().1, 32))
    } else {
        Err("Internal Error: Hash calculation resulted in empty array".to_string())
    }
}
