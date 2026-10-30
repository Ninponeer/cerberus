//! Fenrir Inference Backends
//!
//! Requires one of: bitnet, onnx, llama, candle, cuda, metal features.
//! Each backend pulls in C/C++ toolchain dependencies.

#[cfg(feature = "bitnet")]
pub mod bitnet;

#[cfg(feature = "candle")]
pub mod candle;

#[cfg(feature = "gguf")]
pub mod gguf;

#[cfg(feature = "onnx")]
pub mod onnx;

#[cfg(feature = "bitnet")]
pub use bitnet::{BitNetBackend, BitNetTokenizer};

#[cfg(feature = "candle")]
pub use candle::CandleBackend;

#[cfg(feature = "gguf")]
pub use gguf::GgufBackend;

#[cfg(feature = "onnx")]
pub use onnx::OnnxRuntime;
