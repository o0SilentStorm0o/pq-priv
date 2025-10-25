#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::format_push_string)]
#![allow(clippy::if_not_else)]
#![allow(clippy::ref_option)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::cloned_instead_of_copied)]

pub mod cfg;
pub mod mempool;
pub mod metrics;
pub mod relay;
pub mod rpc;
pub mod state;
pub mod storage_metrics_task;
pub mod sync;
pub mod tasks;

pub use cfg::NodeConfig;
pub use mempool::{TxPool, TxPoolConfig};
pub use metrics::{PrivacyMetrics, StorageMetrics};
pub use relay::Relay;
pub use rpc::{RpcContext, spawn_rpc_server};
pub use state::{ChainError, ChainEvent, ChainState};
pub use storage_metrics_task::run_storage_metrics_task;
pub use sync::SyncManager;
pub use tasks::{run_block_sync_task, run_chain_event_loop, run_peer_event_loop};
