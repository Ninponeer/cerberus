//! Fenrir Inference Backends

pub mod bitnet;
pub mod candle;
pub mod gguf;
pub mod onnx;

pub use bitnet::{BitNetBackend, BitNetTokenizer};
pub use candle::CandleBackend;
pub use gguf::GgufBackend;
pub use onnx::OnnxRuntime;