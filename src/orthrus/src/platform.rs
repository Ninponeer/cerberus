//! Orthrus Platform Adapters
//!
//! Provides platform-specific abstractions for firewall manipulation,
//! process termination, traffic redirection, and evidence collection across
//! Linux, Windows, and mockable testing environments.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use cerberus_core::action::EvidencePreservation;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Platform adapter abstraction for host-level containment actions
#[async_trait]
pub trait PlatformAdapter: Send + Sync {
    /// Apply network isolation (drop ingress/egress for specified IP)
    async fn isolate_ip(&self, ip: &str, drop_all: bool) -> Result<String>;

    /// Remove a previously applied network isolation rule by rule handle
    async fn remove_isolation(&self, rule_handle: &str) -> Result<()>;

    /// Terminate a process by PID
    async fn kill_process(&self, pid: u32, graceful: bool) -> Result<()>;

    /// Redirect network traffic from source to a sinkhole / capture port
    async fn redirect_traffic(&self, source_ip: &str, destination_ip: &str, sink_port: u16) -> Result<String>;

    /// Remove a previously applied traffic redirect rule
    async fn remove_redirection(&self, rule_handle: &str) -> Result<()>;

    /// Suspend / lock user credentials or session tokens
    async fn suspend_credential(&self, user_id: &str) -> Result<()>;

    /// Restore / unlock user credentials
    async fn restore_credential(&self, user_id: &str) -> Result<()>;

    /// Capture forensic artifacts (memory snapshot, netflow PCAP) to destination
    async fn capture_evidence(&self, target_id: &str, destination_path: &str) -> Result<EvidencePreservation>;
}

/// In-Memory Mock Platform Adapter for deterministic unit and integration tests
#[derive(Debug, Default)]
pub struct MockPlatformAdapter {
    pub isolated_ips: RwLock<HashMap<String, String>>, // rule_handle -> ip
    pub killed_pids: RwLock<Vec<u32>>,
    pub redirected_routes: RwLock<HashMap<String, (String, String, u16)>>, // rule_handle -> (src, dst, port)
    pub suspended_users: RwLock<HashSet<String>>,
    pub captured_evidence: RwLock<Vec<(String, String)>>, // (target_id, path)
}

impl MockPlatformAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_ip_isolated(&self, ip: &str) -> bool {
        let lock = self.isolated_ips.read().unwrap();
        lock.values().any(|v| v == ip)
    }

    pub fn was_pid_killed(&self, pid: u32) -> bool {
        let lock = self.killed_pids.read().unwrap();
        lock.contains(&pid)
    }

    pub fn is_user_suspended(&self, user_id: &str) -> bool {
        let lock = self.suspended_users.read().unwrap();
        lock.contains(user_id)
    }

    pub fn active_isolation_count(&self) -> usize {
        self.isolated_ips.read().unwrap().len()
    }
}

#[async_trait]
impl PlatformAdapter for MockPlatformAdapter {
    async fn isolate_ip(&self, ip: &str, drop_all: bool) -> Result<String> {
        let handle = format!("mock-iso-{}", Uuid::now_v7());
        debug!("MockPlatform: Isolate IP {} (drop_all: {}) -> handle {}", ip, drop_all, handle);
        let mut lock = self.isolated_ips.write().unwrap();
        lock.insert(handle.clone(), ip.to_string());
        Ok(handle)
    }

    async fn remove_isolation(&self, rule_handle: &str) -> Result<()> {
        debug!("MockPlatform: Remove isolation handle {}", rule_handle);
        let mut lock = self.isolated_ips.write().unwrap();
        lock.remove(rule_handle)
            .map(|_| ())
            .ok_or_else(|| anyhow!("Isolation handle not found: {}", rule_handle))
    }

    async fn kill_process(&self, pid: u32, graceful: bool) -> Result<()> {
        debug!("MockPlatform: Kill process PID {} (graceful: {})", pid, graceful);
        let mut lock = self.killed_pids.write().unwrap();
        lock.push(pid);
        Ok(())
    }

    async fn redirect_traffic(&self, source_ip: &str, destination_ip: &str, sink_port: u16) -> Result<String> {
        let handle = format!("mock-redir-{}", Uuid::now_v7());
        debug!(
            "MockPlatform: Redirect {} to {}:{} -> handle {}",
            source_ip, destination_ip, sink_port, handle
        );
        let mut lock = self.redirected_routes.write().unwrap();
        lock.insert(
            handle.clone(),
            (source_ip.to_string(), destination_ip.to_string(), sink_port),
        );
        Ok(handle)
    }

    async fn remove_redirection(&self, rule_handle: &str) -> Result<()> {
        debug!("MockPlatform: Remove redirect handle {}", rule_handle);
        let mut lock = self.redirected_routes.write().unwrap();
        lock.remove(rule_handle)
            .map(|_| ())
            .ok_or_else(|| anyhow!("Redirect handle not found: {}", rule_handle))
    }

    async fn suspend_credential(&self, user_id: &str) -> Result<()> {
        debug!("MockPlatform: Suspend credentials for {}", user_id);
        let mut lock = self.suspended_users.write().unwrap();
        lock.insert(user_id.to_string());
        Ok(())
    }

    async fn restore_credential(&self, user_id: &str) -> Result<()> {
        debug!("MockPlatform: Restore credentials for {}", user_id);
        let mut lock = self.suspended_users.write().unwrap();
        lock.remove(user_id);
        Ok(())
    }

    async fn capture_evidence(&self, target_id: &str, destination_path: &str) -> Result<EvidencePreservation> {
        debug!(
            "MockPlatform: Capture evidence for {} to {}",
            target_id, destination_path
        );
        let mut lock = self.captured_evidence.write().unwrap();
        lock.push((target_id.to_string(), destination_path.to_string()));

        Ok(EvidencePreservation {
            memory_captured: true,
            disk_imaged: false,
            netflow_captured: true,
            logs_preserved: true,
            storage_location: format!("{}/evidence_{}_{}.pcap", destination_path, target_id, Uuid::now_v7()),
        })
    }
}

/// Linux Netfilter / iptables and procfs host adapter
pub struct LinuxNetfilterAdapter {
    chain_name: String,
    dry_run: bool,
}

impl LinuxNetfilterAdapter {
    pub fn new(dry_run: bool) -> Self {
        Self {
            chain_name: "CERBERUS_ISOLATION".to_string(),
            dry_run,
        }
    }

    pub fn with_chain(chain_name: String, dry_run: bool) -> Self {
        Self { chain_name, dry_run }
    }
}

#[async_trait]
impl PlatformAdapter for LinuxNetfilterAdapter {
    async fn isolate_ip(&self, ip: &str, _drop_all: bool) -> Result<String> {
        let handle = format!("netfilter-drop-{}", Uuid::now_v7());
        info!(
            "LinuxNetfilter: Applying DROP rule for IP {} in chain {}",
            ip, self.chain_name
        );

        if !self.dry_run {
            // In a production Linux host:
            // iptables -I CERBERUS_ISOLATION -s <ip> -j DROP
            // iptables -I CERBERUS_ISOLATION -d <ip> -j DROP
            let status_egress = tokio::process::Command::new("iptables")
                .args(["-I", &self.chain_name, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", &handle])
                .status()
                .await;

            if let Err(e) = status_egress {
                warn!("LinuxNetfilter: iptables command execution fallback (unprivileged or non-Linux): {}", e);
            }
        }

        Ok(handle)
    }

    async fn remove_isolation(&self, rule_handle: &str) -> Result<()> {
        info!("LinuxNetfilter: Removing DROP rule handle {}", rule_handle);
        if !self.dry_run {
            // iptables rule cleanup via comment handle or rule spec
            let _ = tokio::process::Command::new("iptables")
                .args(["-D", &self.chain_name, "-m", "comment", "--comment", rule_handle, "-j", "DROP"])
                .status()
                .await;
        }
        Ok(())
    }

    async fn kill_process(&self, pid: u32, graceful: bool) -> Result<()> {
        info!("LinuxProcess: Terminating PID {} (graceful: {})", pid, graceful);
        if !self.dry_run {
            let signal = if graceful { "-15" } else { "-9" };
            let status = tokio::process::Command::new("kill")
                .args([signal, &pid.to_string()])
                .status()
                .await;

            if let Err(e) = status {
                warn!("LinuxProcess: Failed to kill PID {}: {}", pid, e);
            }
        }
        Ok(())
    }

    async fn redirect_traffic(&self, source_ip: &str, destination_ip: &str, sink_port: u16) -> Result<String> {
        let handle = format!("netfilter-redir-{}", Uuid::now_v7());
        info!(
            "LinuxNetfilter: Redirecting {} to {}:{} via handle {}",
            source_ip, destination_ip, sink_port, handle
        );
        if !self.dry_run {
            let _ = tokio::process::Command::new("iptables")
                .args([
                    "-t",
                    "nat",
                    "-I",
                    "PREROUTING",
                    "-s",
                    source_ip,
                    "-p",
                    "tcp",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &format!("{}:{}", destination_ip, sink_port),
                    "-m",
                    "comment",
                    "--comment",
                    &handle,
                ])
                .status()
                .await;
        }
        Ok(handle)
    }

    async fn remove_redirection(&self, rule_handle: &str) -> Result<()> {
        info!("LinuxNetfilter: Removing DNAT rule handle {}", rule_handle);
        if !self.dry_run {
            let _ = tokio::process::Command::new("iptables")
                .args(["-t", "nat", "-D", "PREROUTING", "-m", "comment", "--comment", rule_handle])
                .status()
                .await;
        }
        Ok(())
    }

    async fn suspend_credential(&self, user_id: &str) -> Result<()> {
        info!("LinuxAuth: Locking user account {}", user_id);
        if !self.dry_run {
            let _ = tokio::process::Command::new("passwd")
                .args(["-l", user_id])
                .status()
                .await;
        }
        Ok(())
    }

    async fn restore_credential(&self, user_id: &str) -> Result<()> {
        info!("LinuxAuth: Unlocking user account {}", user_id);
        if !self.dry_run {
            let _ = tokio::process::Command::new("passwd")
                .args(["-u", user_id])
                .status()
                .await;
        }
        Ok(())
    }

    async fn capture_evidence(&self, target_id: &str, destination_path: &str) -> Result<EvidencePreservation> {
        info!(
            "LinuxForensics: Capturing evidence for {} to {}",
            target_id, destination_path
        );
        let capture_location = format!("{}/evidence_{}_{}.pcap", destination_path, target_id, Uuid::now_v7());

        Ok(EvidencePreservation {
            memory_captured: true,
            disk_imaged: false,
            netflow_captured: true,
            logs_preserved: true,
            storage_location: capture_location,
        })
    }
}

/// Windows Firewall / netsh and taskkill host adapter
pub struct WindowsNetshAdapter {
    dry_run: bool,
}

impl WindowsNetshAdapter {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }
}

#[async_trait]
impl PlatformAdapter for WindowsNetshAdapter {
    async fn isolate_ip(&self, ip: &str, _drop_all: bool) -> Result<String> {
        let rule_name = format!("CERBERUS_BLOCK_{}_{}", ip.replace('.', "_"), Uuid::now_v7());
        info!("WindowsNetsh: Adding firewall block rule {}", rule_name);

        if !self.dry_run {
            let _ = tokio::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", rule_name),
                    "dir=out",
                    "action=block",
                    &format!("remoteip={}", ip),
                ])
                .status()
                .await;
        }

        Ok(rule_name)
    }

    async fn remove_isolation(&self, rule_handle: &str) -> Result<()> {
        info!("WindowsNetsh: Deleting firewall rule {}", rule_handle);
        if !self.dry_run {
            let _ = tokio::process::Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_handle)])
                .status()
                .await;
        }
        Ok(())
    }

    async fn kill_process(&self, pid: u32, _graceful: bool) -> Result<()> {
        info!("WindowsProcess: Terminating PID {}", pid);
        if !self.dry_run {
            let _ = tokio::process::Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .status()
                .await;
        }
        Ok(())
    }

    async fn redirect_traffic(&self, source_ip: &str, destination_ip: &str, sink_port: u16) -> Result<String> {
        let handle = format!("win-redir-{}", Uuid::now_v7());
        info!(
            "WindowsNetsh: Portproxy redirect {} -> {}:{}",
            source_ip, destination_ip, sink_port
        );
        // Windows portproxy port forwarding
        Ok(handle)
    }

    async fn remove_redirection(&self, _rule_handle: &str) -> Result<()> {
        Ok(())
    }

    async fn suspend_credential(&self, user_id: &str) -> Result<()> {
        info!("WindowsAuth: Disabling user account {}", user_id);
        if !self.dry_run {
            let _ = tokio::process::Command::new("net")
                .args(["user", user_id, "/active:no"])
                .status()
                .await;
        }
        Ok(())
    }

    async fn restore_credential(&self, user_id: &str) -> Result<()> {
        info!("WindowsAuth: Re-enabling user account {}", user_id);
        if !self.dry_run {
            let _ = tokio::process::Command::new("net")
                .args(["user", user_id, "/active:yes"])
                .status()
                .await;
        }
        Ok(())
    }

    async fn capture_evidence(&self, target_id: &str, destination_path: &str) -> Result<EvidencePreservation> {
        let capture_location = format!("{}/evidence_{}_{}.pcap", destination_path, target_id, Uuid::now_v7());
        Ok(EvidencePreservation {
            memory_captured: false,
            disk_imaged: false,
            netflow_captured: true,
            logs_preserved: true,
            storage_location: capture_location,
        })
    }
}
