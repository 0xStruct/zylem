//! SP1 proof verification compiled to WebAssembly: the calls a wallet would make.

use wasm_bindgen::prelude::*;

fn err(e: impl core::fmt::Debug) -> JsError {
    JsError::new(&format!("{e:?}"))
}

#[wasm_bindgen]
pub fn verify_plonk(proof: &[u8], public_values: &[u8], vkey_hash: &str) -> Result<(), JsError> {
    sp1_verifier::PlonkVerifier::verify(proof, public_values, vkey_hash, &sp1_verifier::PLONK_VK_BYTES).map_err(err)
}

#[wasm_bindgen]
pub fn verify_groth16(proof: &[u8], public_values: &[u8], vkey_hash: &str) -> Result<(), JsError> {
    sp1_verifier::Groth16Verifier::verify(proof, public_values, vkey_hash, &sp1_verifier::GROTH16_VK_BYTES).map_err(err)
}

/// `proof` is the bincode of the SDK's `SP1Proof::Compressed`, `vkey` the bincode of the
/// program key's KoalaBear digest.
#[cfg(feature = "compressed")]
#[wasm_bindgen]
pub fn verify_compressed(proof: &[u8], public_values: &[u8], vkey: &[u8]) -> Result<(), JsError> {
    sp1_verifier::compressed::SP1CompressedVerifierRaw::verify_with_public_values(proof, public_values, vkey).map_err(err)
}
