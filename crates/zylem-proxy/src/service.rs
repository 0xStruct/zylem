//! The light-wallet protocol, answered from verified data.
//!
//! Blocks, tree states and subtree roots come from verified Rings. Calls that only a full
//! node can answer (full transactions, transparent lookups, broadcast, the mempool) go to
//! an upstream server; whatever of their answer can be checked against verified blocks is
//! checked.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
};

use futures::Stream;
use tokio::sync::{Mutex, RwLock};
use tonic::{transport::Channel, Request, Response, Status, Streaming};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zylem_core::{manifest::display_hash, tree::Pool};
use zylem_proto::rpc::{
    compact_tx_streamer_client::CompactTxStreamerClient, compact_tx_streamer_server::CompactTxStreamer, Address,
    AddressList, Balance, BlockId, BlockRange, ChainSpec, CompactBlock, CompactTx, Duration, Empty,
    GetAddressUtxosArg, GetAddressUtxosReply, GetAddressUtxosReplyList, GetMempoolTxRequest, GetSubtreeRootsArg,
    LightdInfo, PingResponse, RawTransaction, SendResponse, ShieldedProtocol, StandardFee, SubtreeRoot,
    TransparentAddressBlockFilter, TreeState, TxFilter,
};

use crate::{
    chain::{BlockEntry, Chain},
    filter::{filter, Pools},
};

type Upstream = CompactTxStreamerClient<Channel>;
type Boxed<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    /// Serve only verified data; reject anything that fails a check.
    Strict,
    /// Serve the upstream server's data, but check it and log every mismatch.
    Audit,
}

#[derive(Default)]
pub struct Stats {
    pub blocks_served: AtomicU64,
    pub rejected: AtomicU64,
    pub audit_checked: AtomicU64,
    pub audit_mismatches: AtomicU64,
    pub unverifiable: AtomicU64,
}

pub struct Proxy {
    pub chain: Arc<RwLock<Chain>>,
    pub upstream: Upstream,
    pub network: Network,
    pub mode: Mode,
    pub stats: Arc<Stats>,
    /// The tip policy's latest verdict.
    pub tip_status: Arc<RwLock<crate::tip::Status>>,
    pre_subtrees: Mutex<HashMap<Pool, Vec<SubtreeRoot>>>,
}

fn reject(stats: &Stats, what: String) -> Status {
    stats.rejected.fetch_add(1, Relaxed);
    tracing::warn!(target: "zylem", "REJECT {what}");
    Status::data_loss(format!("zylem: rejected {what}"))
}

fn net_name(n: &Network) -> &'static str {
    match n {
        Network::MainNetwork => "main",
        Network::TestNetwork => "test",
    }
}

fn pool_of(p: i32) -> Result<Pool, Status> {
    match ShieldedProtocol::try_from(p) {
        Ok(ShieldedProtocol::Sapling) => Ok(Pool::Sapling),
        Ok(ShieldedProtocol::Orchard) => Ok(Pool::Orchard),
        Ok(ShieldedProtocol::Ironwood) => Ok(Pool::Ironwood),
        Err(_) => Err(Status::invalid_argument("unknown shielded protocol")),
    }
}

fn tree_state(network: &Network, b: &BlockEntry) -> TreeState {
    let [sapling_tree, orchard_tree, ironwood_tree] = b.trees_after.to_tree_state();
    TreeState {
        network: net_name(network).into(),
        height: b.header.height,
        hash: display_hash(&b.header.hash),
        time: b.header.time,
        sapling_tree,
        orchard_tree,
        ironwood_tree,
    }
}

impl Proxy {
    pub fn new(
        chain: Arc<RwLock<Chain>>,
        upstream: Upstream,
        network: Network,
        mode: Mode,
        stats: Arc<Stats>,
        tip_status: Arc<RwLock<crate::tip::Status>>,
    ) -> Self {
        Proxy { chain, upstream, network, mode, stats, tip_status, pre_subtrees: Mutex::new(HashMap::new()) }
    }

    fn up(&self) -> Upstream {
        self.upstream.clone()
    }

    fn resolve(chain: &Chain, id: &BlockId) -> Option<u64> {
        if id.hash.len() == 32 {
            let h: [u8; 32] = id.hash[..].try_into().unwrap();
            chain.height_of(&h).or_else(|| {
                let mut r = h;
                r.reverse();
                chain.height_of(&r)
            })
        } else {
            Some(id.height)
        }
    }

    /// Checks that a full transaction claimed to be mined at `height` is one of that
    /// verified block's transactions. Returns false if the claim is outside the verified
    /// range (mempool, a fork, or older than the first Ring) and so cannot be checked.
    async fn check_mined_tx(&self, data: &[u8], height: u64, want: Option<&[u8]>) -> Result<bool, Status> {
        let branch = BranchId::for_height(&self.network, BlockHeight::from_u32(height.min(u32::MAX as u64) as u32));
        let tx = Transaction::read(data, branch).map_err(|e| reject(&self.stats, format!("unparseable transaction: {e}")))?;
        let txid: [u8; 32] = *tx.txid().as_ref();
        if let Some(w) = want {
            if w != txid.as_slice() {
                let mut r = txid;
                r.reverse();
                if w != r.as_slice() {
                    return Err(reject(&self.stats, "transaction whose ID differs from the one requested".into()));
                }
            }
        }
        if height == 0 || height == u64::MAX {
            self.stats.unverifiable.fetch_add(1, Relaxed);
            return Ok(false);
        }
        let chain = self.chain.read().await;
        match chain.get(height) {
            Some(b) if b.txids.contains(&txid) => Ok(true),
            Some(_) => Err(reject(&self.stats, format!("transaction claimed in block {height} but not in it"))),
            None => {
                self.stats.unverifiable.fetch_add(1, Relaxed);
                Ok(false)
            }
        }
    }

    /// Subtree roots completed before the first verified block: fetched upstream once,
    /// then checked against the verified frontier that commits to all of them.
    async fn pre_range_subtrees(&self, pool: Pool, proto: i32) -> Result<Vec<SubtreeRoot>, Status> {
        if let Some(v) = self.pre_subtrees.lock().await.get(&pool) {
            return Ok(v.clone());
        }
        let (before, first) = {
            let chain = self.chain.read().await;
            (chain.trees_before.clone(), chain.first)
        };
        let Some(before) = before else { return Ok(vec![]) };
        let complete = match pool {
            Pool::Sapling => before.sizes().sapling_commitment_tree_size,
            Pool::Orchard => before.sizes().orchard_commitment_tree_size,
            Pool::Ironwood => before.sizes().ironwood_commitment_tree_size,
        } as usize
            >> zylem_core::tree::SUBTREE_LEVEL;
        let mut roots: Vec<SubtreeRoot> = vec![];
        if complete > 0 {
            let mut s = self
                .up()
                .get_subtree_roots(GetSubtreeRootsArg { start_index: 0, shielded_protocol: proto, max_entries: complete as u32 })
                .await?
                .into_inner();
            while let Some(r) = s.message().await? {
                roots.push(r);
            }
        }
        roots.truncate(complete);
        let claimed: Vec<[u8; 32]> = roots
            .iter()
            .map(|r| r.root_hash[..].try_into().map_err(|_| Status::data_loss("subtree root size")))
            .collect::<Result<_, _>>()?;
        if let Err(e) = before.check_subtree_roots(pool, &claimed) {
            let what = format!("{pool:?} subtree roots before height {first}: {e}");
            if self.mode == Mode::Strict {
                return Err(reject(&self.stats, what));
            }
            self.stats.audit_mismatches.fetch_add(1, Relaxed);
            tracing::warn!(target: "zylem", "AUDIT mismatch: {what}");
        }
        self.pre_subtrees.lock().await.insert(pool, roots.clone());
        Ok(roots)
    }

    /// Verified blocks for a request, in the requested order, already filtered.
    async fn verified_range(&self, range: &BlockRange, nullifiers_only: bool) -> Result<Vec<CompactBlock>, Status> {
        let chain = self.chain.read().await;
        let (Some(s), Some(e)) = (range.start.as_ref(), range.end.as_ref()) else {
            return Err(Status::invalid_argument("range needs start and end"));
        };
        let (Some(a), Some(b)) = (Self::resolve(&chain, s), Self::resolve(&chain, e)) else {
            return Err(Status::not_found("unknown block hash"));
        };
        let pools = Pools::from_request(&range.pool_types);
        let heights: Vec<u64> = if a <= b { (a..=b).collect() } else { (b..=a).rev().collect() };
        let mut out = Vec::with_capacity(heights.len());
        for h in heights {
            let Some(entry) = chain.get(h) else {
                return Err(Status::out_of_range(format!(
                    "zylem: block {h} is outside the verified range {}..={}",
                    chain.first,
                    chain.tip().map(|t| t.header.height).unwrap_or(0)
                )));
            };
            out.push(filter(&entry.compact, pools, nullifiers_only));
        }
        self.stats.blocks_served.fetch_add(out.len() as u64, Relaxed);
        Ok(out)
    }

    async fn audit_block(&self, theirs: &CompactBlock, pools: Pools) {
        let chain = self.chain.read().await;
        let Some(entry) = chain.get(theirs.height) else {
            self.stats.unverifiable.fetch_add(1, Relaxed);
            return;
        };
        self.stats.audit_checked.fetch_add(1, Relaxed);
        let mut mine = filter(&entry.compact, pools, false);
        let mut theirs = theirs.clone();
        // Fields a server may leave out or fill differently without changing meaning.
        for b in [&mut mine, &mut theirs] {
            b.header.clear();
            for tx in &mut b.vtx {
                tx.fee = 0;
            }
        }
        if mine != theirs {
            self.stats.audit_mismatches.fetch_add(1, Relaxed);
            let field = if mine.hash != theirs.hash {
                "hash"
            } else if mine.vtx.len() != theirs.vtx.len() {
                "transaction count"
            } else if mine.chain_metadata != theirs.chain_metadata {
                "tree sizes"
            } else {
                "transaction data"
            };
            tracing::warn!(target: "zylem", "AUDIT mismatch at {}: {field}", theirs.height);
        }
    }

    fn boxed<T: Send + 'static>(items: Vec<T>) -> Boxed<T> {
        Box::pin(futures::stream::iter(items.into_iter().map(Ok)))
    }
}

#[tonic::async_trait]
impl CompactTxStreamer for Proxy {
    async fn get_latest_block(&self, req: Request<ChainSpec>) -> Result<Response<BlockId>, Status> {
        if self.mode == Mode::Audit {
            return self.up().get_latest_block(req.into_inner()).await;
        }
        // Wallets start every sync here, so a tip the policy rejects stops them visibly.
        let st = self.tip_status.read().await;
        if !st.ok() {
            return Err(Status::unavailable(format!("zylem: {}", st.summary())));
        }
        drop(st);
        let chain = self.chain.read().await;
        let tip = chain.tip().ok_or_else(|| Status::unavailable("zylem: nothing verified yet"))?;
        Ok(Response::new(BlockId { height: tip.header.height, hash: tip.header.hash.to_vec() }))
    }

    async fn get_block(&self, req: Request<BlockId>) -> Result<Response<CompactBlock>, Status> {
        let id = req.into_inner();
        let range = BlockRange { start: Some(id.clone()), end: Some(id), pool_types: vec![] };
        if self.mode == Mode::Audit {
            let b = self.up().get_block(range.start.clone().unwrap()).await?.into_inner();
            self.audit_block(&b, Pools::from_request(&[])).await;
            return Ok(Response::new(b));
        }
        Ok(Response::new(self.verified_range(&range, false).await?.remove(0)))
    }

    async fn get_block_nullifiers(&self, req: Request<BlockId>) -> Result<Response<CompactBlock>, Status> {
        let id = req.into_inner();
        let range = BlockRange { start: Some(id.clone()), end: Some(id), pool_types: vec![] };
        Ok(Response::new(self.verified_range(&range, true).await?.remove(0)))
    }

    type GetBlockRangeStream = Boxed<CompactBlock>;
    async fn get_block_range(&self, req: Request<BlockRange>) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        let range = req.into_inner();
        if self.mode == Mode::Audit {
            let pools = Pools::from_request(&range.pool_types);
            let mut s = self.up().get_block_range(range).await?.into_inner();
            let mut out = vec![];
            while let Some(b) = s.message().await? {
                self.audit_block(&b, pools).await;
                out.push(b);
            }
            tracing::info!(
                target: "zylem",
                "AUDIT {} blocks checked so far, {} mismatches, {} outside the verified range",
                self.stats.audit_checked.load(Relaxed),
                self.stats.audit_mismatches.load(Relaxed),
                self.stats.unverifiable.load(Relaxed)
            );
            return Ok(Response::new(Self::boxed(out)));
        }
        Ok(Response::new(Self::boxed(self.verified_range(&range, false).await?)))
    }

    type GetBlockRangeNullifiersStream = Boxed<CompactBlock>;
    async fn get_block_range_nullifiers(
        &self,
        req: Request<BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeNullifiersStream>, Status> {
        Ok(Response::new(Self::boxed(self.verified_range(&req.into_inner(), true).await?)))
    }

    async fn get_transaction(&self, req: Request<TxFilter>) -> Result<Response<RawTransaction>, Status> {
        let filter = req.into_inner();
        let raw = self.up().get_transaction(filter.clone()).await?.into_inner();
        let want = (!filter.hash.is_empty()).then_some(&filter.hash[..]);
        match self.check_mined_tx(&raw.data, raw.height, want).await {
            Ok(_) => Ok(Response::new(raw)),
            Err(e) if self.mode == Mode::Audit => {
                self.stats.audit_mismatches.fetch_add(1, Relaxed);
                tracing::warn!(target: "zylem", "AUDIT mismatch: {}", e.message());
                Ok(Response::new(raw))
            }
            Err(e) => Err(e),
        }
    }

    async fn send_transaction(&self, req: Request<RawTransaction>) -> Result<Response<SendResponse>, Status> {
        self.up().send_transaction(req.into_inner()).await
    }

    type GetTaddressTxidsStream = Boxed<RawTransaction>;
    async fn get_taddress_txids(
        &self,
        req: Request<TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTxidsStream>, Status> {
        let mut s = self.up().get_taddress_txids(req.into_inner()).await?.into_inner();
        let mut out = vec![];
        while let Some(t) = s.message().await? {
            // Each transaction is checked against its block; completeness cannot be.
            self.check_mined_tx(&t.data, t.height, None).await?;
            out.push(t);
        }
        Ok(Response::new(Self::boxed(out)))
    }

    type GetTaddressTransactionsStream = Boxed<RawTransaction>;
    async fn get_taddress_transactions(
        &self,
        req: Request<TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTransactionsStream>, Status> {
        let mut s = self.up().get_taddress_transactions(req.into_inner()).await?.into_inner();
        let mut out = vec![];
        while let Some(t) = s.message().await? {
            self.check_mined_tx(&t.data, t.height, None).await?;
            out.push(t);
        }
        Ok(Response::new(Self::boxed(out)))
    }

    async fn get_taddress_balance(&self, req: Request<AddressList>) -> Result<Response<Balance>, Status> {
        self.stats.unverifiable.fetch_add(1, Relaxed);
        self.up().get_taddress_balance(req.into_inner()).await
    }

    async fn get_taddress_balance_stream(&self, req: Request<Streaming<Address>>) -> Result<Response<Balance>, Status> {
        let mut s = req.into_inner();
        let mut addresses = vec![];
        while let Some(a) = s.message().await? {
            addresses.push(a.address);
        }
        self.stats.unverifiable.fetch_add(1, Relaxed);
        self.up().get_taddress_balance(AddressList { addresses }).await
    }

    type GetMempoolTxStream = Boxed<CompactTx>;
    async fn get_mempool_tx(&self, req: Request<GetMempoolTxRequest>) -> Result<Response<Self::GetMempoolTxStream>, Status> {
        let s = self.up().get_mempool_tx(req.into_inner()).await?.into_inner();
        Ok(Response::new(Box::pin(s)))
    }

    type GetMempoolStreamStream = Boxed<RawTransaction>;
    async fn get_mempool_stream(&self, req: Request<Empty>) -> Result<Response<Self::GetMempoolStreamStream>, Status> {
        let s = self.up().get_mempool_stream(req.into_inner()).await?.into_inner();
        Ok(Response::new(Box::pin(s)))
    }

    async fn get_tree_state(&self, req: Request<BlockId>) -> Result<Response<TreeState>, Status> {
        let id = req.into_inner();
        let chain = self.chain.read().await;
        let h = Self::resolve(&chain, &id).ok_or_else(|| Status::not_found("unknown block hash"))?;
        let mine = chain.get(h).map(|b| tree_state(&self.network, b));
        drop(chain);
        if self.mode == Mode::Audit {
            let theirs = self.up().get_tree_state(id).await?.into_inner();
            if let Some(mine) = &mine {
                self.stats.audit_checked.fetch_add(1, Relaxed);
                let roots = |t: &TreeState| {
                    zylem_core::tree::Trees::from_tree_state(&t.sapling_tree, &t.orchard_tree, &t.ironwood_tree).map(|t| t.roots())
                };
                if roots(mine).ok() != roots(&theirs).ok() {
                    self.stats.audit_mismatches.fetch_add(1, Relaxed);
                    tracing::warn!(target: "zylem", "AUDIT mismatch: tree state at {h}");
                }
            }
            return Ok(Response::new(theirs));
        }
        mine.map(Response::new).ok_or_else(|| Status::out_of_range(format!("zylem: block {h} is outside the verified range")))
    }

    async fn get_latest_tree_state(&self, _req: Request<Empty>) -> Result<Response<TreeState>, Status> {
        let chain = self.chain.read().await;
        let tip = chain.tip().ok_or_else(|| Status::unavailable("zylem: nothing verified yet"))?;
        Ok(Response::new(tree_state(&self.network, tip)))
    }

    type GetSubtreeRootsStream = Boxed<SubtreeRoot>;
    async fn get_subtree_roots(
        &self,
        req: Request<GetSubtreeRootsArg>,
    ) -> Result<Response<Self::GetSubtreeRootsStream>, Status> {
        let arg = req.into_inner();
        let pool = pool_of(arg.shielded_protocol)?;
        let mut roots = self.pre_range_subtrees(pool, arg.shielded_protocol).await?;
        {
            let chain = self.chain.read().await;
            for st in chain.subtrees.get(&pool).into_iter().flatten() {
                if st.index as usize != roots.len() {
                    return Err(reject(&self.stats, format!("{pool:?} subtree {} out of sequence", st.index)));
                }
                let hash = chain.get(st.height).map(|b| b.header.hash.to_vec()).unwrap_or_default();
                roots.push(SubtreeRoot { root_hash: st.root.to_vec(), completing_block_hash: hash, completing_block_height: st.height });
            }
        }
        let start = (arg.start_index as usize).min(roots.len());
        let mut out: Vec<SubtreeRoot> = roots.split_off(start);
        if arg.max_entries > 0 {
            out.truncate(arg.max_entries as usize);
        }
        Ok(Response::new(Self::boxed(out)))
    }

    async fn get_address_utxos(&self, req: Request<GetAddressUtxosArg>) -> Result<Response<GetAddressUtxosReplyList>, Status> {
        let list = self.up().get_address_utxos(req.into_inner()).await?.into_inner();
        for u in &list.address_utxos {
            self.check_utxo(u).await?;
        }
        Ok(Response::new(list))
    }

    type GetAddressUtxosStreamStream = Boxed<GetAddressUtxosReply>;
    async fn get_address_utxos_stream(
        &self,
        req: Request<GetAddressUtxosArg>,
    ) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        let mut s = self.up().get_address_utxos_stream(req.into_inner()).await?.into_inner();
        let mut out = vec![];
        while let Some(u) = s.message().await? {
            self.check_utxo(&u).await?;
            out.push(u);
        }
        Ok(Response::new(Self::boxed(out)))
    }

    async fn get_lightd_info(&self, req: Request<Empty>) -> Result<Response<LightdInfo>, Status> {
        let mut info = self.up().get_lightd_info(req.into_inner()).await?.into_inner();
        if info.chain_name != net_name(&self.network) {
            return Err(reject(&self.stats, format!("upstream is on {} not {}", info.chain_name, net_name(&self.network))));
        }
        if self.mode == Mode::Strict {
            let chain = self.chain.read().await;
            if let Some(tip) = chain.tip() {
                info.block_height = tip.header.height;
                info.estimated_height = info.estimated_height.max(tip.header.height);
            }
        }
        let tip = self.tip_status.read().await.summary();
        info.vendor = format!("zylem-proxy ({:?}, {tip}) over {}", self.mode, info.vendor);
        Ok(Response::new(info))
    }

    async fn get_standard_fee(&self, req: Request<Empty>) -> Result<Response<StandardFee>, Status> {
        self.up().get_standard_fee(req.into_inner()).await
    }

    async fn ping(&self, req: Request<Duration>) -> Result<Response<PingResponse>, Status> {
        self.up().ping(req.into_inner()).await
    }
}

impl Proxy {
    async fn check_utxo(&self, u: &GetAddressUtxosReply) -> Result<(), Status> {
        let chain = self.chain.read().await;
        let txid: [u8; 32] = u.txid[..].try_into().map_err(|_| Status::data_loss("txid size"))?;
        match chain.get(u.height) {
            Some(b) if b.txids.contains(&txid) => Ok(()),
            Some(_) => {
                let what = format!("UTXO claimed in block {} but its transaction is not there", u.height);
                if self.mode == Mode::Audit {
                    self.stats.audit_mismatches.fetch_add(1, Relaxed);
                    tracing::warn!(target: "zylem", "AUDIT mismatch: {what}");
                    Ok(())
                } else {
                    Err(reject(&self.stats, what))
                }
            }
            None => {
                self.stats.unverifiable.fetch_add(1, Relaxed);
                Ok(())
            }
        }
    }
}
