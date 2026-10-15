//! Cerberus Protocol Buffers
//!
//! Generated protobuf definitions for the Cerberus distributed cyber defense system.

#![allow(clippy::all)]

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/cerberus.v1.rs"));
}

pub use v1::*;

pub mod cerberus {
    pub mod v1 {
        pub use crate::v1::*;
    }
}