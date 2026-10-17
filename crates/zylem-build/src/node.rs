//! JSON-RPC client for a Zakura or Zebra node.

use anyhow::{anyhow, Context, Result};
use futures::{stream, StreamExt, TryStreamExt};
use serde_json::{json, Value};

/// Requests per JSON-RPC batch, and batches in flight.
const BATCH: u64 = 50;
const IN_FLIGHT: usize = 8;

#[derive(Clone)]
pub struct Node {
    url: String,
    client: reqwest::Client,
}

impl Node {
    pub fn new(url: &str) -> Self {
        Node {
            url: url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp: Value = self
            .client
            .post(&self.url)
            .basic_auth("zylem", Some("zylem"))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("{method} request"))?
            .json()
            .await
            .with_context(|| format!("{method} response"))?;
        if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(anyhow!("{method}: {err}"));
        }
        Ok(resp["result"].clone())
    }

    /// One JSON-RPC batch; results come back in request order.
    async fn batch(&self, method: &str, params: Vec<Value>) -> Result<Vec<Value>> {
        let body: Vec<Value> = params
            .into_iter()
            .enumerate()
            .map(|(i, p)| json!({"jsonrpc": "2.0", "id": i, "method": method, "params": p}))
            .collect();
        let n = body.len();
        let resp: Vec<Value> = self
            .client
            .post(&self.url)
            .basic_auth("zylem", Some("zylem"))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("{method} batch"))?
            .json()
            .await
            .with_context(|| format!("{method} batch response"))?;
        let mut out = vec![Value::Null; n];
        for r in resp {
            if let Some(err) = r.get("error").filter(|e| !e.is_null()) {
                return Err(anyhow!("{method}: {err}"));
            }
            let id = r["id"].as_u64().ok_or_else(|| anyhow!("{method}: response without id"))? as usize;
            out[id] = r["result"].clone();
        }
        Ok(out)
    }

    /// Hex results for every height in `[from, to]`, fetched in concurrent batches.
    async fn hex_range(&self, method: &'static str, from: u64, to: u64, extra: Value) -> Result<Vec<Vec<u8>>> {
        let starts: Vec<u64> = (from..=to).step_by(BATCH as usize).collect();
        let chunks: Vec<Vec<Vec<u8>>> = stream::iter(starts)
            .map(|s| {
                let extra = extra.clone();
                async move {
                    let e = (s + BATCH - 1).min(to);
                    let params = (s..=e).map(|h| json!([h.to_string(), extra])).collect();
                    let res = self.batch(method, params).await?;
                    res.into_iter()
                        .map(|v| {
                            let s = v.as_str().ok_or_else(|| anyhow!("{method}: not hex"))?;
                            Ok(hex::decode(s)?)
                        })
                        .collect::<Result<Vec<_>>>()
                }
            })
            .buffered(IN_FLIGHT)
            .try_collect()
            .await?;
        Ok(chunks.into_iter().flatten().collect())
    }

    pub async fn tip(&self) -> Result<u64> {
        self.call("getblockcount", json!([]))
            .await?
            .as_u64()
            .ok_or_else(|| anyhow!("getblockcount: not a number"))
    }

    pub async fn prune_height(&self) -> Result<u64> {
        let info = self.call("getblockchaininfo", json!([])).await?;
        Ok(info["pruneheight"].as_u64().unwrap_or(0))
    }

    /// Raw block bytes.
    pub async fn block(&self, height: u64) -> Result<Vec<u8>> {
        let hex = self.call("getblock", json!([height.to_string(), 0])).await?;
        Ok(hex::decode(hex.as_str().ok_or_else(|| anyhow!("getblock: not hex"))?)?)
    }

    /// Raw blocks for `[from, to]`.
    pub async fn blocks(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>> {
        self.hex_range("getblock", from, to, json!(0)).await
    }

    /// Raw 1,487-byte headers for `[from, to]`. Headers stay available below a pruned
    /// node's prune height.
    pub async fn headers(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>> {
        self.hex_range("getblockheader", from, to, json!(false)).await
    }

    /// Note commitment tree state after `height` as legacy tree hex, per pool.
    pub async fn tree_state(&self, height: u64) -> Result<[String; 3]> {
        let v = self.call("z_gettreestate", json!([height.to_string()])).await?;
        let get = |pool: &str| {
            v[pool]["commitments"]["finalState"].as_str().unwrap_or("").to_string()
        };
        Ok([get("sapling"), get("orchard"), get("ironwood")])
    }
}
