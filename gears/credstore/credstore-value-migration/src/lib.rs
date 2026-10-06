// Created: 2026-10-02 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
#![doc = include_str!("../README.md")]

pub mod cleanup;
pub mod cli;
mod db;
pub mod env;
pub mod error;
pub mod fence;
pub mod legacy;
pub mod migrate;
pub mod report;
pub mod state;
pub mod stores;
pub mod verdict;

pub use cli::{run, run_from, run_with};
pub use error::MigrationError;
pub use legacy::{LegacyError, LegacyStore};
pub use report::Exit;
pub use state::{Phase, RowState};
pub use stores::{TOOL_ID, Tuning};
