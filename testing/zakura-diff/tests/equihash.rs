//! Real testnet headers through Zylem's and Zakura's Equihash checks, unaltered and with
//! one byte changed in each part of the header: the verdicts must agree.

mod common;

use common::{rpc_hex_range, rpc_url};
use rand::{rngs::StdRng, Rng, SeedableRng};
use zakura_chain::{block::Header, parameters::Network, serialization::ZcashDeserializeInto};

fn zakura_ok(net: &Network, bytes: &[u8]) -> bool {
    match bytes.zcash_deserialize_into::<Header>() {
        Ok(h) => h.solution.check(&h, net).is_ok(),
        // A change that breaks parsing (for example the solution length) is a rejection.
        Err(_) => false,
    }
}

#[test]
fn equihash_verdicts_match_zakura() {
    let Some(url) = rpc_url() else { return };
    let net = Network::new_default_testnet();
    let mut rng = StdRng::seed_from_u64(7);
    // Around NU6, NU6.3 (Ironwood) and NU7 activation, and recent blocks.
    let ranges = [(2_975_900, 2_976_199), (4_133_900, 4_134_199), (4_464_900, 4_465_199), (4_520_000, 4_520_299)];
    let (mut valid, mut altered) = (0, 0);
    for (from, to) in ranges {
        for (i, header) in rpc_hex_range(&url, "getblockheader", from, to, serde_json::json!(false)).into_iter().enumerate() {
            let height = from + i as u64;
            assert!(zylem_header::check_equihash_solution(&header).is_ok(), "Zylem rejects real header {height}");
            assert!(zakura_ok(&net, &header), "Zakura rejects real header {height}");
            valid += 1;
            // One byte in: the Equihash input, the nonce, the solution length, the solution.
            for region in [0..108, 108..140, 140..143, 143..1_487] {
                let mut bad = header.clone();
                let at = rng.gen_range(region);
                bad[at] ^= 1 << rng.gen_range(0..8);
                let ours = zylem_header::check_equihash_solution(&bad).is_ok();
                assert_eq!(ours, zakura_ok(&net, &bad), "header {height} with byte {at} changed: verdicts differ");
                assert!(!ours, "header {height} with byte {at} changed still passes");
                altered += 1;
            }
        }
    }
    println!("{valid} real headers accepted and {altered} altered ones rejected by both");
}
