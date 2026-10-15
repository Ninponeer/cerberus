//! Telemetry event types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Platform types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    Container,
    IoT,
    Network,
}

/// Telemetry event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum EventType {
    ProcessCreate = 1,
    ProcessTerminate = 2,
    NetworkConnect = 3,
    NetworkAccept = 4,
    DnsQuery = 5,
    DnsResponse = 6,
    FileCreate = 7,
    FileModify = 8,
    FileDelete = 9,
    RegistrySet = 10,
    ImageLoad = 11,
    ThreadCreate = 12,
    MemoryAlloc = 13,
    AuthLogon = 14,
    AuthLogoff = 15,
    KernelCallback = 16,
}

/// Canonical telemetry event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: String,
    pub agent_id: String,
    pub timestamp_ns: i64,
    pub event_type: EventType,
    pub platform: Platform,
    pub payload: Vec<u8>,
    pub tags: HashMap<String, String>,
}

impl TelemetryEvent {
    pub fn new(
        agent_id: impl Into<String>,
        event_type: EventType,
        platform: Platform,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::now_v7().to_string(),
            agent_id: agent_id.into(),
            timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            event_type,
            platform,
            payload,
            tags: HashMap::new(),
        }
    }
}

/// Process creation event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCreate {
    pub pid: i32,
    pub ppid: i32,
    pub exe_path: String,
    pub cmdline: String,
    pub user_sid: String,
    pub session_id: String,
    pub exe_hash_sha256: Vec<u8>,
    pub parent_exe_hash: Vec<u8>,
    pub integrity_level: String,
    pub env_vars: HashMap<String, String>,
}

/// Network connection event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnect {
    pub src_ip: String,
    pub src_port: i32,
    pub dst_ip: String,
    pub dst_port: i32,
    pub protocol: String,
    pub pid: i32,
    pub process_exe: String,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub bytes_sent: i64,
    pub bytes_recv: i64,
}

/// DNS query event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub query: String,
    pub qtype: i32,
    pub response: Option<String>,
    pub rcode: i32,
    pub pid: i32,
    pub process_exe: String,
    pub server_ip: String,
}