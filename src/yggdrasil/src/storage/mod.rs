//! Storage engines for Yggdrasil knowledge graph

#[cfg(feature = "rocksdb")]
pub mod rocks;

#[cfg(feature = "rocksdb")]
pub use rocks::RocksYggdrasilStore;
