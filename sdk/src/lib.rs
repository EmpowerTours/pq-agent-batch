//! # pqagent — SDK for the pq-agent-batch proof-of-agency layer
//!
//! * [`keys`]: ML-DSA-65 agent keys (generation, pkHash, keystore with 0600 / optional encryption)
//! * [`action`]: packed orders, the exact signed message, the JSON submission format
//! * [`agent`]: high-level API mirroring the `pqagent` CLI (init / register / fund / balance / alert / sign / status)
//! * [`chain`]: minimal JSON-RPC + contract bindings
//! * [`batcher`]: reference batcher producing the zk-batch host's `--input` file
//!
//! Encoding and signing reuse `agent-batch-lib` (the code the SP1 guest runs), so parity with the
//! guest is by construction; golden tests pin parity with the contracts and the proved fixtures.

pub mod action;
pub mod agent;
pub mod batcher;
pub mod chain;
pub mod config;
pub mod keys;

pub use action::{ActionParams, Order, SignedAction};
pub use agent::{Agent, InitOptions};
pub use batcher::{BatchInput, BatchOptions};
pub use keys::AgentKey;
