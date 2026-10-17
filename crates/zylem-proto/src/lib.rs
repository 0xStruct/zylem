//! Light-wallet protocol types (ZIP 307) with client and server stubs, and the Zylem
//! Ring format.

// The module tree mirrors the proto packages, because generated code refers to
// other packages by relative path.
#[allow(clippy::all)]
pub mod cash {
    pub mod z {
        pub mod wallet {
            pub mod sdk {
                pub mod rpc {
                    tonic::include_proto!("cash.z.wallet.sdk.rpc");
                }
            }
        }
    }
}

#[allow(clippy::all)]
pub mod zylem {
    pub mod v1 {
        tonic::include_proto!("zylem.v1");
    }
}

/// The light-wallet protocol: compact blocks and the `CompactTxStreamer` service.
pub use cash::z::wallet::sdk::rpc;
/// The Zylem Ring format.
pub use zylem::v1 as ring;

pub use prost::Message;
